import time
from pathlib import Path

from sentinel.llm.base import LLMProvider
from sentinel.models import Signal


def scan(file_path: Path, prior_signals: list[Signal], provider: LLMProvider) -> Signal:
    start = time.monotonic()
    context = _format_prior(prior_signals)
    try:
        result = provider.review(file_path=file_path, context=context)
    except Exception as e:
        return Signal(
            stage="ai_review",
            verdict="ERROR",
            summary=f"provider error: {e}",
            evidence={"error": str(e)},
            duration_seconds=time.monotonic() - start,
        )

    raw_verdict = str(result.get("verdict") or "").upper()
    if raw_verdict == "BLOCK":
        verdict = "BLOCK"
    elif raw_verdict == "ALLOW":
        verdict = "ALLOW"
    else:
        verdict = "ERROR"

    confidence = result.get("confidence")
    reasoning = result.get("reasoning") or ""
    indicators = result.get("indicators") or []
    mode = result.get("_mode", "unknown")

    # New AI fields
    file_description = result.get("file_description") or ""
    malware_class = result.get("malware_class") or []
    malware_family = result.get("malware_family")
    capabilities = result.get("capabilities") or []

    mode_tag = f"({mode}) "
    summary = mode_tag + (reasoning[:160] if reasoning else f"verdict={raw_verdict or 'unparsed'}")

    evidence: dict = {
        "mode": mode,
        "verdict": raw_verdict,
        "confidence": confidence,
        "reasoning": reasoning,
        "indicators": indicators,
        "functions_reviewed": result.get("functions_reviewed", []),
        "file_description": file_description,
        "malware_class": malware_class,
        "malware_family": malware_family,
        "capabilities": capabilities,
    }
    # Headless mode includes the Ghidra dump (decompiled + meta_flags) so the
    # UI can render the actual code Claude reviewed.
    dump = result.get("_dump")
    if dump:
        evidence["ghidra_dump"] = dump

    return Signal(
        stage="ai_review",
        verdict=verdict,
        score=float(confidence) if isinstance(confidence, (int, float)) else None,
        summary=summary,
        evidence=evidence,
        duration_seconds=time.monotonic() - start,
    )


def _format_prior(signals: list[Signal]) -> str:
    if not signals:
        return "(no upstream stages ran)"
    lines: list[str] = []
    for s in signals:
        lines.append(f"- {s.stage}: {s.verdict} -- {s.summary}")
        for k, v in list(s.evidence.items())[:6]:
            snippet = str(v)
            if len(snippet) > 240:
                snippet = snippet[:240] + "..."
            lines.append(f"    {k}: {snippet}")
    return "\n".join(lines)
