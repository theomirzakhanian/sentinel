from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

VerdictLiteral = Literal["ALLOW", "BLOCK", "UNKNOWN", "TIMEOUT", "ERROR", "SKIPPED"]
FinalVerdict = Literal["ALLOW", "BLOCK"]


class Signal(BaseModel):
    stage: str
    verdict: VerdictLiteral
    score: float | None = None
    summary: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    duration_seconds: float | None = None


class Aggregated(BaseModel):
    verdict: FinalVerdict
    reasons: list[str]
    score: float | None = None  # weighted score: >0 leans malicious, <0 benign


class Report(BaseModel):
    file_path: str
    file_name: str
    sha256: str
    sha1: str
    md5: str
    size_bytes: int
    started_at: datetime
    completed_at: datetime
    signals: list[Signal]
    final_verdict: FinalVerdict
    reasons: list[str]
