"""Pure scan_file() — runs the three stages, returns a Report.

Supports optional progress callback (on_event) and cancellation
(cancel_event: threading.Event). Cancellation is checked between stages —
in-flight subprocess (Ghidra, Claude) won't be killed mid-execution, but the
next stage won't start once cancel is set.
"""
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from sentinel.config import optional
from sentinel.hashing import hash_file
from sentinel.llm.claude_cli import ClaudeCLIProvider
from sentinel.models import Report, Signal
from sentinel.stages import ai_review, triage, virustotal
from sentinel.verdict import aggregate

EventCallback = Callable[[str, dict], None]


class CancelledError(RuntimeError):
    """Raised when cancel_event is set between stages."""


@dataclass
class ScanOptions:
    upload: bool = False
    skip_triage: bool = False
    skip_ai: bool = False


def _skipped(stage: str, reason: str) -> Signal:
    return Signal(stage=stage, verdict="SKIPPED", summary=reason)


def _safe(stage: str, fn) -> Signal:
    try:
        return fn()
    except KeyboardInterrupt:
        raise
    except Exception as e:
        return Signal(stage=stage, verdict="ERROR", summary=str(e))


def scan_file(
    file_path: Path,
    opts: ScanOptions,
    *,
    on_event: EventCallback | None = None,
    cancel_event: threading.Event | None = None,
) -> Report:
    file_path = file_path.resolve()
    if not file_path.is_file():
        raise FileNotFoundError(f"{file_path} is not a file")

    def emit(event_type: str, data: dict) -> None:
        if on_event is not None:
            try:
                on_event(event_type, data)
            except Exception:
                pass

    def check_cancel() -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise CancelledError("scan cancelled")

    started_at = datetime.now(timezone.utc)
    hashes = hash_file(file_path)
    size = file_path.stat().st_size

    emit("scan.started", {
        "file_path": str(file_path),
        "file_name": file_path.name,
        "size_bytes": size,
        "sha256": hashes["sha256"],
    })

    signals: list[Signal] = []

    # Stage 1: VirusTotal
    check_cancel()
    emit("stage.started", {"stage": "virustotal"})
    sig = _safe(
        "virustotal",
        lambda: virustotal.scan(file_path, hashes["sha256"], upload=opts.upload),
    )
    signals.append(sig)
    emit("stage.finished", {"stage": "virustotal", "signal": sig.model_dump(mode="json")})

    # Stage 2: Triage
    check_cancel()
    emit("stage.started", {"stage": "triage"})
    if opts.skip_triage:
        sig = _skipped("triage", "--skip-triage")
    elif not optional("TRIAGE_API_KEY"):
        sig = _skipped("triage", "TRIAGE_API_KEY not set")
    else:
        sig = _safe("triage", lambda: triage.scan(file_path))
    signals.append(sig)
    emit("stage.finished", {"stage": "triage", "signal": sig.model_dump(mode="json")})

    # Stage 3: AI review
    check_cancel()
    emit("stage.started", {"stage": "ai_review"})
    if opts.skip_ai:
        sig = _skipped("ai_review", "--skip-ai")
    else:
        provider = ClaudeCLIProvider(
            binary=optional("SENTINEL_CLAUDE_BIN", "claude"),
            model=optional("SENTINEL_CLAUDE_MODEL"),
        )
        sig = ai_review.scan(file_path, signals, provider)
    signals.append(sig)
    emit("stage.finished", {"stage": "ai_review", "signal": sig.model_dump(mode="json")})

    final = aggregate(signals)
    completed_at = datetime.now(timezone.utc)

    report = Report(
        file_path=str(file_path),
        file_name=file_path.name,
        sha256=hashes["sha256"],
        sha1=hashes["sha1"],
        md5=hashes["md5"],
        size_bytes=size,
        started_at=started_at,
        completed_at=completed_at,
        signals=signals,
        final_verdict=final.verdict,
        reasons=final.reasons,
    )

    emit("verdict.final", {
        "final_verdict": report.final_verdict,
        "score": final.score,
        "reasons": report.reasons,
    })
    return report
