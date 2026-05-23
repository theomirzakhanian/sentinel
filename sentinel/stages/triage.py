import json
import time
from pathlib import Path

import requests

from sentinel.config import optional, required
from sentinel.models import Signal

DEFAULT_BASE = "https://api.tria.ge/v0"
POLL_INTERVAL = 10
POLL_TIMEOUT = 600
BLOCK_SCORE = 5


def scan(file_path: Path) -> Signal:
    start = time.monotonic()
    api_key = required("TRIAGE_API_KEY")
    base = optional("TRIAGE_BASE_URL", DEFAULT_BASE)
    headers = {"Authorization": f"Bearer {api_key}"}

    with file_path.open("rb") as f:
        files = {
            "_json": (
                None,
                json.dumps({"kind": "file", "interactive": False}),
                "application/json",
            ),
            "file": (file_path.name, f, "application/octet-stream"),
        }
        r = requests.post(f"{base}/samples", headers=headers, files=files, timeout=120)
    r.raise_for_status()
    sample_id = r.json()["id"]

    deadline = time.monotonic() + POLL_TIMEOUT
    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL)
        r = requests.get(f"{base}/samples/{sample_id}", headers=headers, timeout=30)
        r.raise_for_status()
        status = r.json().get("status")
        if status == "reported":
            break
        if status in ("failed", "error"):
            return Signal(
                stage="triage",
                verdict="ERROR",
                summary=f"Triage reported status={status}",
                evidence={"sample_id": sample_id, "status": status},
                duration_seconds=time.monotonic() - start,
            )
    else:
        return Signal(
            stage="triage",
            verdict="TIMEOUT",
            summary=f"sandbox did not complete within {POLL_TIMEOUT}s",
            evidence={"sample_id": sample_id},
            duration_seconds=time.monotonic() - start,
        )

    r = requests.get(f"{base}/samples/{sample_id}/summary", headers=headers, timeout=30)
    r.raise_for_status()
    return _signal_from_summary(r.json(), sample_id, duration=time.monotonic() - start)


def _signal_from_summary(data: dict, sample_id: str, *, duration: float) -> Signal:
    score = data.get("score") or 0
    tasks = data.get("tasks") or {}
    signatures: list[str] = []
    families: list[str] = []
    for task in tasks.values():
        for sig in task.get("signatures") or []:
            name = sig.get("name")
            if name and name not in signatures:
                signatures.append(name)
        for tgt in task.get("targets") or []:
            for fam in tgt.get("family") or []:
                if fam and fam not in families:
                    families.append(fam)

    verdict = "BLOCK" if score >= BLOCK_SCORE else "ALLOW"
    summary = f"score {score}/10"
    if families:
        summary += f", family: {', '.join(families[:3])}"
    elif signatures:
        summary += f", {len(signatures)} signature(s)"

    return Signal(
        stage="triage",
        verdict=verdict,
        score=float(score),
        summary=summary,
        evidence={
            "sample_id": sample_id,
            "score": score,
            "families": families,
            "signatures": signatures[:25],
        },
        duration_seconds=duration,
    )
