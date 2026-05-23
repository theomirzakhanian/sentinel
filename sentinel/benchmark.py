"""Benchmark harness: scan a corpus directory, optionally with labels, write CSV+JSON summary."""
import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from sentinel.models import Report, Signal
from sentinel.report import write_report
from sentinel.scanner import ScanOptions, scan_file

console = Console()

VERDICT_COLORS = {
    "ALLOW": "green",
    "BLOCK": "red",
    "UNKNOWN": "yellow",
    "TIMEOUT": "yellow",
    "ERROR": "red",
    "SKIPPED": "dim",
}

EXPECTED_TO_VERDICT = {
    "malicious": "BLOCK",
    "benign": "ALLOW",
    "block": "BLOCK",
    "allow": "ALLOW",
}


def _stage_signal(report: Report, stage: str) -> Signal | None:
    for s in report.signals:
        if s.stage == stage:
            return s
    return None


def _vt_detections(report: Report) -> str:
    sig = _stage_signal(report, "virustotal")
    if not sig or sig.verdict == "SKIPPED":
        return "-"
    stats = (sig.evidence or {}).get("stats") or {}
    mal = stats.get("malicious")
    susp = stats.get("suspicious")
    total = sum(int(stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected", "timeout"))
    if mal is None:
        return sig.verdict
    return f"{mal}+{susp}/{total}"


def _ai_mode(report: Report) -> str:
    sig = _stage_signal(report, "ai_review")
    if not sig:
        return "-"
    return str((sig.evidence or {}).get("mode") or "-")


def _ai_confidence(report: Report) -> str:
    sig = _stage_signal(report, "ai_review")
    if not sig or sig.score is None:
        return "-"
    return f"{sig.score:.2f}"


def _top_indicators(report: Report, n: int = 3) -> str:
    sig = _stage_signal(report, "ai_review")
    if not sig:
        return ""
    inds = (sig.evidence or {}).get("indicators") or []
    return " | ".join(str(i)[:80] for i in inds[:n])


def _load_labels(path: Path | None) -> dict[str, str]:
    if not path:
        return {}
    raw = json.loads(path.read_text())
    out: dict[str, str] = {}
    for name, label in raw.items():
        verdict = EXPECTED_TO_VERDICT.get(str(label).lower())
        if not verdict:
            raise ValueError(f"label for {name!r} must be malicious/benign (got {label!r})")
        out[name] = verdict
    return out


def _walk_corpus(corpus_dir: Path) -> list[Path]:
    samples: list[Path] = []
    for p in sorted(corpus_dir.rglob("*")):
        if not p.is_file():
            continue
        if p.name.startswith("."):
            continue
        if p.name in ("labels.json", "corpus.json"):
            continue
        samples.append(p)
    return samples


def _row_for(sample: Path, report: Report, expected: str | None) -> dict[str, Any]:
    vt = _stage_signal(report, "virustotal")
    tr = _stage_signal(report, "triage")
    ai = _stage_signal(report, "ai_review")
    final = report.final_verdict
    correct = None if expected is None else (final == expected)
    duration = (report.completed_at - report.started_at).total_seconds()
    return {
        "file": sample.name,
        "sha256": report.sha256,
        "size_bytes": report.size_bytes,
        "expected": expected or "-",
        "vt_verdict": vt.verdict if vt else "-",
        "vt_detections": _vt_detections(report),
        "triage_verdict": tr.verdict if tr else "-",
        "triage_score": (tr.score if tr and tr.score is not None else "-"),
        "ai_verdict": ai.verdict if ai else "-",
        "ai_mode": _ai_mode(report),
        "ai_confidence": _ai_confidence(report),
        "final_verdict": final,
        "correct": ("-" if correct is None else ("yes" if correct else "no")),
        "duration_s": f"{duration:.1f}",
        "top_indicators": _top_indicators(report),
    }


def _render_table(rows: list[dict[str, Any]], labels_provided: bool) -> Table:
    table = Table(title="Sentinel benchmark", show_lines=False)
    cols = [
        ("file", "cyan"),
        ("expected", "magenta") if labels_provided else None,
        ("vt", None),
        ("triage", None),
        ("ai", None),
        ("mode", "dim"),
        ("final", "bold"),
        ("correct", "bold") if labels_provided else None,
        ("dur", "dim"),
    ]
    cols = [c for c in cols if c is not None]
    for name, style in cols:
        table.add_column(name, style=style or "white")

    for r in rows:
        cells: list[str] = []
        cells.append(r["file"])
        if labels_provided:
            cells.append(r["expected"])
        cells.append(f"{r['vt_verdict']} {r['vt_detections']}")
        tri = r["triage_verdict"]
        if r["triage_score"] != "-":
            tri += f" ({r['triage_score']})"
        cells.append(tri)
        ai = r["ai_verdict"]
        if r["ai_confidence"] != "-":
            ai += f" ({r['ai_confidence']})"
        cells.append(ai)
        cells.append(r["ai_mode"])
        final = r["final_verdict"]
        color = VERDICT_COLORS.get(final, "white")
        cells.append(f"[{color}]{final}[/{color}]")
        if labels_provided:
            mark = r["correct"]
            mc = "green" if mark == "yes" else ("red" if mark == "no" else "dim")
            cells.append(f"[{mc}]{mark}[/{mc}]")
        cells.append(f"{r['duration_s']}s")
        table.add_row(*cells)
    return table


def _metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labeled = [r for r in rows if r["expected"] in ("ALLOW", "BLOCK")]
    if not labeled:
        return {}
    tp = sum(1 for r in labeled if r["expected"] == "BLOCK" and r["final_verdict"] == "BLOCK")
    fn = sum(1 for r in labeled if r["expected"] == "BLOCK" and r["final_verdict"] != "BLOCK")
    tn = sum(1 for r in labeled if r["expected"] == "ALLOW" and r["final_verdict"] == "ALLOW")
    fp = sum(1 for r in labeled if r["expected"] == "ALLOW" and r["final_verdict"] != "ALLOW")
    pos = tp + fn
    neg = tn + fp
    tpr = (tp / pos) if pos else None
    fpr = (fp / neg) if neg else None
    # Divergence from VT alone vs Sentinel combined
    vt_only_correct = 0
    sentinel_correct = 0
    for r in labeled:
        vt_v = r["vt_verdict"]
        vt_says_block = vt_v == "BLOCK"
        vt_correct = (vt_says_block and r["expected"] == "BLOCK") or (not vt_says_block and r["expected"] == "ALLOW")
        if vt_correct:
            vt_only_correct += 1
        if r["correct"] == "yes":
            sentinel_correct += 1
    return {
        "total_labeled": len(labeled),
        "true_positives": tp, "false_negatives": fn,
        "true_negatives": tn, "false_positives": fp,
        "tpr": tpr, "fpr": fpr,
        "vt_only_correct": vt_only_correct,
        "sentinel_correct": sentinel_correct,
    }


def benchmark_command(args: argparse.Namespace) -> int:
    corpus_dir = Path(args.corpus).resolve()
    if not corpus_dir.is_dir():
        console.print(f"[red]error:[/red] {corpus_dir} is not a directory")
        return 2

    labels_path = Path(args.labels).resolve() if args.labels else None
    labels = _load_labels(labels_path)
    samples = _walk_corpus(corpus_dir)
    if not samples:
        console.print(f"[red]error:[/red] no samples found in {corpus_dir}")
        return 2

    opts = ScanOptions(upload=args.upload, skip_triage=args.skip_triage, skip_ai=args.skip_ai)

    console.print(f"[bold]Sentinel benchmark[/bold] on {len(samples)} sample(s) from [cyan]{corpus_dir}[/cyan]")
    if labels:
        console.print(f"  labels: {labels_path} ({len(labels)} entries)")
    console.print()

    rows: list[dict[str, Any]] = []
    report_dir = Path(args.report_dir)
    for i, sample in enumerate(samples, 1):
        console.print(f"[{i}/{len(samples)}] {sample.name}...", end=" ")
        try:
            with console.status(f"scanning {sample.name}"):
                report = scan_file(sample, opts)
            write_report(report, report_dir)
        except Exception as e:
            console.print(f"[red]ERROR[/red] {e}")
            continue
        expected = labels.get(sample.name)
        color = VERDICT_COLORS.get(report.final_verdict, "white")
        console.print(f"[{color}]{report.final_verdict}[/{color}]")
        rows.append(_row_for(sample, report, expected))

    labels_provided = bool(labels)
    console.print()
    console.print(_render_table(rows, labels_provided))

    metrics = _metrics(rows)
    if metrics:
        tpr = metrics["tpr"]
        fpr = metrics["fpr"]
        console.print()
        console.print("[bold]Metrics[/bold]")
        console.print(f"  TPR (caught malicious): {metrics['true_positives']}/{metrics['true_positives'] + metrics['false_negatives']} "
                      f"= {tpr*100:.1f}%" if tpr is not None else "  TPR: N/A")
        console.print(f"  FPR (flagged benign):   {metrics['false_positives']}/{metrics['false_positives'] + metrics['true_negatives']} "
                      f"= {fpr*100:.1f}%" if fpr is not None else "  FPR: N/A")
        console.print(f"  VT-aggregate alone:     {metrics['vt_only_correct']}/{metrics['total_labeled']} correct")
        console.print(f"  Sentinel combined:      {metrics['sentinel_correct']}/{metrics['total_labeled']} correct")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    csv_path = out_dir / f"benchmark_{ts}.csv"
    json_path = out_dir / f"benchmark_{ts}.json"

    fieldnames = list(rows[0].keys()) if rows else []
    with csv_path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    json_path.write_text(json.dumps({
        "corpus": str(corpus_dir),
        "labels": str(labels_path) if labels_path else None,
        "started_at": ts,
        "rows": rows,
        "metrics": metrics,
    }, indent=2, default=str))

    console.print(f"\nCSV:  [dim]{csv_path}[/dim]")
    console.print(f"JSON: [dim]{json_path}[/dim]")

    if labels_provided and metrics:
        wrong = metrics["false_positives"] + metrics["false_negatives"]
        return 0 if wrong == 0 else 1
    return 0
