"""Wrapper around Ghidra's analyzeHeadless CLI.

Runs the headless analyzer on a target binary with sentinel_dump.py as a PostScript,
returns the parsed JSON dump. No GUI, no MCP plugin required.
"""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

DEFAULT_GHIDRA_HOMES = [
    "/opt/homebrew/Cellar/ghidra/12.0.4/libexec",
    "/opt/homebrew/opt/ghidra/libexec",
    "/Applications/ghidra/libexec",
]
DEFAULT_TIMEOUT = 600


def find_analyze_headless() -> str | None:
    explicit = os.environ.get("GHIDRA_HOME")
    candidates = []
    if explicit:
        candidates.append(Path(explicit) / "support" / "analyzeHeadless")
    candidates.extend(Path(h) / "support" / "analyzeHeadless" for h in DEFAULT_GHIDRA_HOMES)
    on_path = shutil.which("analyzeHeadless")
    if on_path:
        candidates.append(Path(on_path))
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return str(c)
    return None


def script_dir() -> Path:
    return Path(__file__).parent / "ghidra_scripts"


def analyze(file_path: Path, *, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Run analyzeHeadless on file_path, return the JSON dump produced by sentinel_dump.py."""
    binary = find_analyze_headless()
    if not binary:
        raise FileNotFoundError(
            "analyzeHeadless not found (looked in $GHIDRA_HOME and Homebrew paths). "
            "Set GHIDRA_HOME to the Ghidra libexec directory."
        )

    scripts = script_dir()
    if not (scripts / "sentinel_dump.py").is_file():
        raise FileNotFoundError(f"sentinel_dump.py missing in {scripts}")

    with tempfile.TemporaryDirectory(prefix="sentinel-ghidra-") as tmp:
        dump_path = Path(tmp) / "dump.json"
        env = os.environ.copy()
        env["SENTINEL_DUMP_PATH"] = str(dump_path)

        cmd = [
            binary,
            tmp,
            "sentinel_scan",
            "-import", str(file_path),
            "-scriptPath", str(scripts),
            "-postScript", "sentinel_dump.py",
            "-deleteProject",
            "-readOnly",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"analyzeHeadless timed out after {timeout}s") from e

        if not dump_path.is_file():
            tail = (result.stderr or result.stdout or "")[-800:]
            raise RuntimeError(
                f"analyzeHeadless did not produce a dump (exit={result.returncode}).\n"
                f"Last output:\n{tail}"
            )

        with dump_path.open() as fh:
            return json.load(fh)
