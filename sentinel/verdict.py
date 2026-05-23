"""Weighted-score aggregator.

Each non-SKIPPED signal contributes a score in [-1, +1] (positive = malicious).
Weighted sum exceeding BLOCK_THRESHOLD => BLOCK.

Calibration (informally validated against current corpus):
  - VT noise floor: detection ratio < 4% treated as 0 (single-engine FPs like
    Gridinsoft hitting jq.exe at 1/70 stop dominating the verdict).
  - VT ALLOW is mild negative (-0.3) — clean VT is evidence but not proof of
    innocence (FUD malware passes VT cleanly).
  - AI score = ±confidence (signed by verdict). Confident AI ALLOW outweighs
    noisy VT BLOCK.
  - Triage score: 5+/10 -> proportional positive contribution.
"""
from sentinel.models import Aggregated, Signal

WEIGHTS = {
    "virustotal": 0.40,
    "ai_review": 0.35,
    "triage": 0.25,
}
DEFAULT_WEIGHT = 0.20

BLOCK_THRESHOLD = 0.15
VT_NOISE_FLOOR = 0.04         # detection ratio below this counts as 0
VT_BLOCK_BOOST = 2.0          # 50% detection => 1.0 max
VT_ALLOW_PENALTY = -0.30      # clean VT mild benign signal
TRIAGE_ALLOW_PENALTY = -0.30


def _vt_score(s: Signal) -> float:
    if s.verdict == "ALLOW":
        return VT_ALLOW_PENALTY
    if s.verdict == "BLOCK":
        stats = (s.evidence or {}).get("stats") or {}
        mal = int(stats.get("malicious", 0))
        susp = int(stats.get("suspicious", 0))
        total = sum(int(stats.get(k, 0)) for k in
                    ("malicious", "suspicious", "harmless", "undetected", "timeout"))
        if total == 0:
            return 0.0
        ratio = (mal + susp) / total
        if ratio < VT_NOISE_FLOOR:
            return 0.0
        return min(ratio * VT_BLOCK_BOOST, 1.0)
    return 0.0  # UNKNOWN/TIMEOUT/ERROR


def _ai_score(s: Signal) -> float:
    confidence = s.score if s.score is not None else 0.5
    confidence = max(0.0, min(1.0, float(confidence)))
    if s.verdict == "ALLOW":
        return -confidence
    if s.verdict == "BLOCK":
        return confidence
    return 0.0


def _triage_score(s: Signal) -> float:
    if s.verdict == "ALLOW":
        return TRIAGE_ALLOW_PENALTY
    if s.verdict == "BLOCK":
        raw = s.score if s.score is not None else 5.0
        return min(float(raw) / 10.0, 1.0)
    return 0.0


def _signal_score(s: Signal) -> float:
    if s.stage == "virustotal":
        return _vt_score(s)
    if s.stage == "ai_review":
        return _ai_score(s)
    if s.stage == "triage":
        return _triage_score(s)
    return 0.0


def aggregate(signals: list[Signal]) -> Aggregated:
    total = 0.0
    reasons: list[str] = []
    for s in signals:
        if s.verdict == "SKIPPED":
            reasons.append(f"{s.stage}: SKIPPED ({s.summary}) [+0.000]")
            continue
        raw = _signal_score(s)
        weight = WEIGHTS.get(s.stage, DEFAULT_WEIGHT)
        contribution = raw * weight
        total += contribution
        sign = "+" if contribution >= 0 else ""
        reasons.append(
            f"{s.stage}: {s.verdict} ({s.summary}) [{sign}{contribution:.3f}]"
        )

    verdict = "BLOCK" if total >= BLOCK_THRESHOLD else "ALLOW"
    reasons.append(f"weighted score: {total:+.3f}  threshold: {BLOCK_THRESHOLD:+.3f}  => {verdict}")
    return Aggregated(verdict=verdict, reasons=reasons, score=total)
