from datetime import datetime, timezone
from pathlib import Path

from sentinel.models import Report


def write_report(report: Report, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out_dir / f"{ts}_{report.sha256[:12]}.json"
    path.write_text(report.model_dump_json(indent=2))
    return path
