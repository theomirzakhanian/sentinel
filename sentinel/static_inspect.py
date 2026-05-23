"""Cross-platform static binary inspection without Ghidra.

Used as the AI deep-dive context when GhidraMCP is unavailable. Shells out to
common binutils (file, strings, otool, nm, objdump) and captures bounded output.
"""
import os
import re
import shutil
import subprocess
from pathlib import Path

STRING_LIMIT = 250
SYMBOL_LIMIT = 120
CMD_TIMEOUT = 20

SUSPICIOUS_API_PATTERNS = [
    r"VirtualAlloc(Ex)?",
    r"WriteProcessMemory",
    r"CreateRemoteThread(Ex)?",
    r"NtCreateThreadEx",
    r"QueueUserAPC",
    r"SetWindowsHookEx",
    r"WinHttp(Open|Connect|SendRequest)",
    r"InternetOpen(A|W)?",
    r"URLDownloadToFile",
    r"LoadLibrary(A|W|Ex)?",
    r"GetProcAddress",
    r"RegSetValueEx",
    r"CryptEncrypt",
    r"IsDebuggerPresent",
    r"CheckRemoteDebuggerPresent",
    r"NtQueryInformationProcess",
    r"\\\\\\.\\\\(pipe|PHYSICALDRIVE)",
    r"powershell(\.exe)?",
    r"cmd(\.exe)?\s+/c",
]
SUSPICIOUS_STRING_PATTERNS = [
    r"https?://[^\s\"'<>]{6,}",
    r"\b\d{1,3}(\.\d{1,3}){3}\b",
    r"\bcmd\.exe\b",
    r"\bpowershell\b",
    r"\bbase64\b",
    r"\bSeDebugPrivilege\b",
    r"\bUAC\b",
    r"\bRunAs\b",
    r"AppData\\Roaming",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
]


def _run(cmd: list[str]) -> str:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=CMD_TIMEOUT, check=False,
            errors="replace",
        )
        return (r.stdout or "") + (r.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return f"<{cmd[0]} unavailable: {e}>"


def _truncate_lines(text: str, max_lines: int) -> str:
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    return "\n".join(lines[:max_lines]) + f"\n... ({len(lines) - max_lines} more lines truncated)"


def _find_matches(text: str, patterns: list[str], cap: int = 40) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
    for line in text.splitlines():
        for rx in compiled:
            for m in rx.findall(line):
                hit = m if isinstance(m, str) else m[0]
                if hit and hit not in seen:
                    seen.add(hit)
                    found.append(hit)
                    if len(found) >= cap:
                        return found
    return found


def inspect(file_path: Path) -> dict:
    path = str(file_path)
    have = {tool: shutil.which(tool) is not None for tool in ("file", "strings", "otool", "nm", "objdump")}

    file_out = _run(["file", "-b", path]) if have["file"] else ""
    strings_out = ""
    if have["strings"]:
        strings_out = _truncate_lines(_run(["strings", "-a", "-n", "8", path]), STRING_LIMIT)

    libs_out = ""
    if have["otool"]:
        libs_out = _run(["otool", "-L", path])
    elif have["objdump"]:
        libs_out = _run(["objdump", "-p", path])
    libs_out = _truncate_lines(libs_out, 60)

    symbols_out = ""
    if have["nm"]:
        symbols_out = _truncate_lines(_run(["nm", "-gU", path]), SYMBOL_LIMIT)

    header_out = ""
    if have["otool"]:
        header_out = _truncate_lines(_run(["otool", "-hv", path]), 20)
    elif have["objdump"]:
        header_out = _truncate_lines(_run(["objdump", "-h", path]), 30)

    api_hits = _find_matches(strings_out + "\n" + symbols_out, SUSPICIOUS_API_PATTERNS)
    string_hits = _find_matches(strings_out, SUSPICIOUS_STRING_PATTERNS)

    size = os.path.getsize(path)

    return {
        "size_bytes": size,
        "file_type": file_out.strip(),
        "header": header_out.strip(),
        "linked_libraries": libs_out.strip(),
        "symbols_global_undefined": symbols_out.strip(),
        "strings_sample": strings_out.strip(),
        "suspicious_api_hits": api_hits,
        "suspicious_string_hits": string_hits,
        "tools_available": have,
    }
