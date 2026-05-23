import time
from pathlib import Path

import requests

from sentinel.config import required
from sentinel.models import Signal

BASE = "https://www.virustotal.com/api/v3"
POLL_INTERVAL = 5
POLL_TIMEOUT = 300


def scan(file_path: Path, sha256: str, *, upload: bool = False) -> Signal:
    start = time.monotonic()
    api_key = required("VT_API_KEY")
    headers = {"x-apikey": api_key, "accept": "application/json"}

    r = requests.get(f"{BASE}/files/{sha256}", headers=headers, timeout=30)
    if r.status_code == 200:
        return _signal_from_file(r.json(), duration=time.monotonic() - start)
    if r.status_code != 404:
        r.raise_for_status()

    if not upload:
        return Signal(
            stage="virustotal",
            verdict="UNKNOWN",
            summary="hash not in VirusTotal database (re-run with --upload to submit)",
            evidence={"sha256": sha256},
            duration_seconds=time.monotonic() - start,
        )

    with file_path.open("rb") as f:
        files = {"file": (file_path.name, f, "application/octet-stream")}
        r = requests.post(f"{BASE}/files", headers=headers, files=files, timeout=300)
    r.raise_for_status()
    analysis_id = r.json()["data"]["id"]

    deadline = time.monotonic() + POLL_TIMEOUT
    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL)
        r = requests.get(f"{BASE}/analyses/{analysis_id}", headers=headers, timeout=30)
        r.raise_for_status()
        attrs = r.json()["data"]["attributes"]
        if attrs.get("status") == "completed":
            return _signal_from_analysis(
                attrs.get("stats", {}),
                sha256,
                duration=time.monotonic() - start,
            )

    return Signal(
        stage="virustotal",
        verdict="TIMEOUT",
        summary=f"analysis did not complete within {POLL_TIMEOUT}s",
        evidence={"analysis_id": analysis_id, "sha256": sha256},
        duration_seconds=time.monotonic() - start,
    )


def _signal_from_file(payload: dict, *, duration: float) -> Signal:
    attrs = payload["data"]["attributes"]
    extras = {
        "names": attrs.get("names", [])[:5],
        "first_submission_date": attrs.get("first_submission_date"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "reputation": attrs.get("reputation"),
        "type_description": attrs.get("type_description"),
        "signature_info": attrs.get("signature_info", {}),
    }
    return _signal_from_analysis(
        attrs.get("last_analysis_stats", {}),
        attrs.get("sha256", ""),
        duration=duration,
        extras=extras,
    )


def _signal_from_analysis(
    stats: dict,
    sha256: str,
    *,
    duration: float,
    extras: dict | None = None,
) -> Signal:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    timeout = int(stats.get("timeout", 0))
    total = malicious + suspicious + harmless + undetected + timeout
    verdict = "BLOCK" if (malicious + suspicious) > 0 else "ALLOW"
    summary = f"{malicious}/{total} malicious, {suspicious} suspicious"
    evidence: dict = {"stats": stats, "sha256": sha256}
    if extras:
        evidence.update(extras)
    return Signal(
        stage="virustotal",
        verdict=verdict,
        score=float(malicious + suspicious),
        summary=summary,
        evidence=evidence,
        duration_seconds=duration,
    )
