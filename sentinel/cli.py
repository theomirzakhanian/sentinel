import argparse
import sys
from pathlib import Path

from rich.console import Console

from sentinel.benchmark import benchmark_command
from sentinel.fetch_malware import DEFAULT_FILE_TYPES, DEFAULT_LIMIT, fetch_command
from sentinel.models import Signal
from sentinel.report import write_report
from sentinel.scanner import ScanOptions, scan_file


def serve_command(args: argparse.Namespace) -> int:
    from sentinel.daemon import serve
    serve(host=args.host, port=args.port)
    return 0

console = Console()

VERDICT_COLORS = {
    "ALLOW": "green",
    "BLOCK": "red",
    "UNKNOWN": "yellow",
    "TIMEOUT": "yellow",
    "ERROR": "red",
    "SKIPPED": "dim",
}

STAGE_LABELS = {
    "virustotal": "VirusTotal",
    "triage": "Triage sandbox",
    "ai_review": "AI deep dive",
}


def _print_signal(idx: int, total: int, sig: Signal) -> None:
    label = STAGE_LABELS.get(sig.stage, sig.stage)
    color = VERDICT_COLORS.get(sig.verdict, "white")
    dur = f" ({sig.duration_seconds:.1f}s)" if sig.duration_seconds else ""
    console.print(
        f"[{idx}/{total}] {label:<18} [{color}]{sig.verdict:<7}[/{color}] {sig.summary}{dur}"
    )


def scan_command(args: argparse.Namespace) -> int:
    file_path = Path(args.file).resolve()
    if not file_path.is_file():
        console.print(f"[red]error:[/red] {file_path} is not a file")
        return 2

    console.print(f"[bold]Sentinel[/bold] scanning [cyan]{file_path.name}[/cyan]")
    console.print(f"  path:   {file_path}")
    console.print(f"  size:   {file_path.stat().st_size:,} bytes\n")

    opts = ScanOptions(upload=args.upload, skip_triage=args.skip_triage, skip_ai=args.skip_ai)
    with console.status("Scanning..."):
        report = scan_file(file_path, opts)

    console.print(f"  sha256: {report.sha256}\n")
    for i, sig in enumerate(report.signals, 1):
        _print_signal(i, len(report.signals), sig)

    report_path = write_report(report, Path(args.report_dir))

    console.print()
    color = VERDICT_COLORS.get(report.final_verdict, "white")
    console.print(f"[{color} bold]VERDICT: {report.final_verdict}[/{color} bold]")
    for r in report.reasons:
        console.print(f"  - {r}")
    console.print(f"\nReport: [dim]{report_path}[/dim]")

    return 0 if report.final_verdict == "ALLOW" else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Guilty-until-proven-innocent file scanner (VirusTotal -> Triage -> AI/Ghidra).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Scan a single file")
    p_scan.add_argument("file", help="Path to file to scan")
    p_scan.add_argument("--upload", action="store_true",
                        help="Upload to VirusTotal if hash is unknown")
    p_scan.add_argument("--skip-triage", action="store_true",
                        help="Skip Hatching Triage sandbox stage")
    p_scan.add_argument("--skip-ai", action="store_true",
                        help="Skip AI deep dive stage (Ghidra + Claude)")
    p_scan.add_argument("--report-dir", default="./reports",
                        help="Directory for JSON reports (default: ./reports)")

    p_bench = sub.add_parser("benchmark", help="Scan a corpus directory and compare verdicts")
    p_bench.add_argument("corpus", help="Directory containing samples to scan")
    p_bench.add_argument("--labels", default=None,
                        help="JSON file mapping sample filename -> 'malicious'|'benign' (optional)")
    p_bench.add_argument("--upload", action="store_true",
                        help="Upload unknown hashes to VirusTotal")
    p_bench.add_argument("--skip-triage", action="store_true",
                        help="Skip Triage stage for all samples")
    p_bench.add_argument("--skip-ai", action="store_true",
                        help="Skip AI deep dive for all samples")
    p_bench.add_argument("--report-dir", default="./reports",
                        help="Where to write per-sample JSON reports (default: ./reports)")
    p_bench.add_argument("--out-dir", default="./benchmarks",
                        help="Where to write benchmark CSV/JSON summary (default: ./benchmarks)")

    p_serve = sub.add_parser("serve",
                             help="Run the local HTTP+SSE daemon (for the Electron UI)")
    p_serve.add_argument("--host", default="127.0.0.1",
                         help="Bind host (default 127.0.0.1; never bind public)")
    p_serve.add_argument("--port", type=int, default=7331,
                         help="Bind port (default 7331)")

    p_fetch = sub.add_parser("fetch-malware",
                             help="Pull recent ITW PE samples from MalwareBazaar")
    p_fetch.add_argument("out", help="Output corpus directory (created if missing)")
    p_fetch.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                         help=f"Max samples to fetch (default {DEFAULT_LIMIT})")
    p_fetch.add_argument("--tag",
                         help="Filter by MalwareBazaar tag (e.g. AsyncRAT, Lumma)")
    p_fetch.add_argument("--family",
                         help="Filter by MB signature/family (e.g. AgentTesla, RedLine)")
    p_fetch.add_argument("--types", default=DEFAULT_FILE_TYPES,
                         help=f"Comma-separated file types (default {DEFAULT_FILE_TYPES})")
    p_fetch.add_argument("--dry-run", action="store_true",
                         help="List candidates without downloading (no API key needed)")

    args = parser.parse_args()
    if args.cmd == "scan":
        sys.exit(scan_command(args))
    if args.cmd == "benchmark":
        sys.exit(benchmark_command(args))
    if args.cmd == "fetch-malware":
        sys.exit(fetch_command(args))
    if args.cmd == "serve":
        sys.exit(serve_command(args))


if __name__ == "__main__":
    main()
