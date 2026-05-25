"""Bootstrap the SentinelNet corpus from existing reports/.

Walks every JSON report and, for any scan that has a Ghidra dump with
decompiled functions, ingests it into the SentinelNet SQLite DB. After
ingest, runs a smoke test that re-queries the corpus for one of its own
functions and prints the top match — sanity check that store + query work
end-to-end.

Usage: .venv/bin/python scripts/sentinelnet_bootstrap.py [reports_dir]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from sentinel.sentinelnet import (
    query_function,
    stats,
    store_scan,
)


def ingest_report(path: Path) -> tuple[int, str | None]:
    """Returns (functions_stored, sha256 or None if skipped)."""
    try:
        r = json.loads(path.read_text())
    except Exception as e:
        print(f"  skip {path.name}: parse error {e}")
        return 0, None

    ai = next((s for s in r.get("signals", []) if s.get("stage") == "ai_review"), None)
    if not ai:
        return 0, None
    ev = ai.get("evidence") or {}
    dump = (ev.get("ghidra_dump") or {})
    decompiled = dump.get("decompiled") or {}
    if not decompiled:
        return 0, None

    sha = r.get("sha256")
    if not sha:
        return 0, None

    stored = store_scan(
        file_sha256=sha,
        file_name=r.get("file_name") or path.name,
        verdict=r.get("final_verdict") or "ALLOW",
        decompiled=decompiled,
        malware_class=ev.get("malware_class") or [],
        malware_family=ev.get("malware_family"),
        capabilities=ev.get("capabilities") or [],
    )
    return stored, sha


def main() -> int:
    reports_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("reports")
    if not reports_dir.is_dir():
        print(f"reports dir not found: {reports_dir}")
        return 1

    files = sorted(reports_dir.glob("*.json"))
    print(f"Scanning {len(files)} report(s) under {reports_dir}/")

    total_funcs = 0
    total_files = 0
    last_sha: str | None = None
    last_decompiled: dict[str, str] | None = None

    for f in files:
        stored, sha = ingest_report(f)
        if stored == 0:
            continue
        total_funcs += stored
        total_files += 1
        last_sha = sha
        # Remember the decompiled blob from the last ingested file for the smoke test
        try:
            r = json.loads(f.read_text())
            ai = next((s for s in r["signals"] if s["stage"] == "ai_review"), None)
            last_decompiled = ((ai or {}).get("evidence") or {}).get("ghidra_dump", {}).get("decompiled")
        except Exception:
            pass
        print(f"  ingested {f.name}: {stored} function(s) for {sha[:12]}")

    print()
    print(f"Done. Ingested {total_funcs} function(s) from {total_files} report(s).")
    print()

    print("Corpus stats:")
    s = stats()
    for k, v in s.items():
        print(f"  {k}: {v}")
    print()

    # Smoke test: take one function from the last ingested report and query
    # the corpus for it. We expect the top hit to be the function itself
    # (similarity 1.0), proving end-to-end store+query works. We don't
    # exclude its own SHA — the point of the smoke test is to confirm
    # round-trip fidelity, not to test cross-sample matching.
    if last_decompiled:
        fn_name, src = next(iter(last_decompiled.items()))
        print(f"Smoke test: querying corpus for {fn_name} (from {last_sha[:12] if last_sha else '?'})")
        hits = query_function(src, top_k=3, threshold=0.20)
        if not hits:
            print("  no matches (unexpected — round-trip should have hit itself)")
            return 2
        for h in hits:
            print(
                f"  {h.similarity:.3f}  {h.file_name[:40]:<40}  {h.function_name}"
                f"  [{h.verdict}]"
                + (f"  family={h.malware_family}" if h.malware_family else "")
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
