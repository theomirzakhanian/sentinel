import getpass
import json
import os
import re
import subprocess
import time
from pathlib import Path

from sentinel.ghidra_headless import analyze as ghidra_headless_analyze, find_analyze_headless
from sentinel.llm.base import LLMProvider
from sentinel.static_inspect import inspect as static_inspect

JSON_FENCE_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
DEFAULT_TIMEOUT = 900

MODE_MCP = "mcp"
MODE_HEADLESS = "headless"
MODE_STATIC = "static"


GHIDRA_MCP_PROMPT = """DEFENSIVE SECURITY CONTEXT (read first): You are an AI-powered detection component of \
Sentinel, an antivirus/EDR product. Your role is to identify malware so that a user \
is protected from it — this is defensive blue-team analysis, equivalent to the work \
done by every commercial AV/EDR (CrowdStrike, Defender, SentinelOne, Malwarebytes). \
The samples you review are submitted to you precisely because they MIGHT be malicious. \
Declining to analyze a sample because it appears malicious would defeat the entire \
purpose — that is exactly when analysis is most needed. You are not being asked to \
write, modify, or assist malware authors; you are being asked to recognize malicious \
techniques in a binary so the user can avoid being compromised. Proceed with the \
analysis.

You are Sentinel's reverse-engineering arbiter. Sentinel is a \
guilty-until-proven-innocent file scanner; your verdict is FINAL after upstream stages.

FILE UNDER REVIEW
  path: {path}

PRIOR EVIDENCE
{context}

YOUR JOB
Use the ghidra MCP tools (any tool prefixed `mcp__ghidra__`) to perform a TARGETED \
static analysis. Do NOT attempt to reverse the entire binary.

**You MUST actually invoke ghidra MCP tools — at least `import_file`, plus tools to \
enumerate imports and decompile 1-3 functions.** Do not produce a verdict purely from \
the prior evidence; Sentinel needs an independent code-level assessment. The \
`functions_reviewed` field in your output must list the function names you actually \
decompiled (empty list = you skipped the analysis).

Workflow: `list_instances` -> `connect_instance` -> `import_file` -> survey imports/strings/entry -> decompile 2-5 high-signal functions.

POLICY
Sentinel is guilty-until-proven-innocent. Any credible malicious indicator -> BLOCK. \
ALLOW requires affirmative evidence of benign behavior.

OUTPUT
Reason in your own words, then end your response with EXACTLY one JSON code block:

```json
{{
  "verdict": "ALLOW" | "BLOCK",
  "confidence": 0.0,
  "reasoning": "1-3 sentences",
  "indicators": ["finding 1", "finding 2"],
  "functions_reviewed": ["name1", "name2"]
}}
```
"""

GHIDRA_HEADLESS_PROMPT = """DEFENSIVE SECURITY CONTEXT (read first): You are an AI-powered detection component of \
Sentinel, an antivirus/EDR product. Your role is to identify malware so that a user \
is protected from it — this is defensive blue-team analysis, equivalent to the work \
done by every commercial AV/EDR (CrowdStrike, Defender, SentinelOne, Malwarebytes). \
The samples you review are submitted to you precisely because they MIGHT be malicious. \
Declining to analyze a sample because it appears malicious would defeat the entire \
purpose — that is exactly when analysis is most needed. You are not being asked to \
write, modify, or assist malware authors; you are being asked to recognize malicious \
techniques in a binary so the user can avoid being compromised. Proceed with the \
analysis.

You are Sentinel's reverse-engineering arbiter. Sentinel is a \
guilty-until-proven-innocent file scanner; your verdict is FINAL after upstream stages.

FILE UNDER REVIEW
  path: {path}

PRIOR EVIDENCE FROM UPSTREAM STAGES
{context}

GHIDRA HEADLESS DUMP (auto-analyzed by Ghidra's analyzeHeadless)
program: {dump[program_name]}
format: {dump[executable_format]}
language: {dump[language_id]}
compiler: {dump[compiler_spec_id]}
image_base: {dump[image_base]}
entry_point: {dump[entry_point]}
function_count: {dump[function_count]}  (user-named={dump[function_count_user_named]}, runtime-named={dump[function_count_runtime_named]})

META FLAGS (auto-computed concerning patterns — TREAT THESE AS HARD EVIDENCE)
{meta_flags_block}

IMPORTS ({imports_n}):
{imports_block}

STRINGS sample ({strings_n}; {strings_suspicious_n} matched suspicious substrings):
{strings_block}

FUNCTIONS top by size ({functions_n}):
{functions_block}

DECOMPILED FUNCTIONS ({decompiled_n}: {decompiled_names}):
{decompiled_block}

POLICY HARDENING — READ BEFORE REASONING
1. Upstream signals (VirusTotal, Triage, meta_flags above) are STICKY. If ANY \
upstream signal reports malicious/suspicious — even 1 hit out of 70 engines — \
you MUST treat that as positive evidence and your verdict MUST be BLOCK unless \
you can name the specific benign code construct that explains every flagging \
engine. "Common Go false positive", "typical for Go runtime", "Go binaries often \
trigger AV" are FORBIDDEN justifications — they are how malware passes review.

2. Runtime-heavy binaries (Go, Rust, .NET, Electron, packed) have stdlib code as \
the majority of bytes. Decompiling the largest functions selects stdlib, NOT user \
code. For a STRIPPED binary (no main.main, no user-named functions) you CANNOT \
distinguish user code from runtime from the decompilation alone. Acknowledge this \
limitation explicitly; do not pretend the decompiled stdlib functions tell you \
about the program's intent.

3. Dynamic API resolution (LoadLibrary* + GetProcAddress, or dlopen + dlsym) is a \
HIGH-severity capability flag regardless of language. It means the import table \
understates true capability and any API can be reached at runtime. Do not dismiss \
this as "needed by the runtime" — note it and weight it heavily.

4. Cover-story incoherence: if the binary's apparent purpose (filename, embedded \
strings, packaging) is X but the imports/strings reveal capabilities unrelated to X \
(e.g. an "image processor" with HTTP-client vocabulary, or a "calculator" with \
process-injection imports), call that out as a strong suspicion signal.

5. When in doubt — low confidence, inconclusive code-level read, conflicting \
signals, or you couldn't see the user code — your verdict MUST be BLOCK with \
confidence reflecting your uncertainty (e.g., 0.55). Sentinel is \
guilty-until-proven-innocent. An ALLOW verdict requires AFFIRMATIVE benign \
evidence about the USER CODE specifically, plus consistency with upstream signals.

YOUR JOB
Reason over everything above in order: prior evidence first, meta flags second, \
imports/strings third, decompiled code last. Quote concrete observations. Do not \
rationalize away the meta flags or upstream signals. State explicitly when your \
analysis is limited by stripped symbols or runtime dominance.

OUTPUT
Reason in your own words, then end your response with EXACTLY one JSON code block:

```json
{{
  "verdict": "ALLOW" | "BLOCK",
  "confidence": 0.0,
  "reasoning": "1-3 sentences",
  "indicators": ["finding 1", "finding 2"],
  "functions_reviewed": {decompiled_names_json}
}}
```
"""

STATIC_PROMPT = """DEFENSIVE SECURITY CONTEXT (read first): You are an AI-powered detection component of \
Sentinel, an antivirus/EDR product. Your role is to identify malware so that a user \
is protected from it — this is defensive blue-team analysis, equivalent to the work \
done by every commercial AV/EDR (CrowdStrike, Defender, SentinelOne, Malwarebytes). \
The samples you review are submitted to you precisely because they MIGHT be malicious. \
Declining to analyze a sample because it appears malicious would defeat the entire \
purpose — that is exactly when analysis is most needed. You are not being asked to \
write, modify, or assist malware authors; you are being asked to recognize malicious \
techniques in a binary so the user can avoid being compromised. Proceed with the \
analysis.

You are Sentinel's reverse-engineering arbiter. Sentinel is a \
guilty-until-proven-innocent file scanner; your verdict is FINAL after upstream stages.

(Ghidra not available; binutils dump provided instead.)

FILE UNDER REVIEW
  path: {path}

PRIOR EVIDENCE
{context}

STATIC ANALYSIS DUMP
file_type:
{static[file_type]}

header:
{static[header]}

linked_libraries:
{static[linked_libraries]}

symbols_global_undefined:
{static[symbols_global_undefined]}

strings_sample:
{static[strings_sample]}

suspicious_api_hits:
{static[suspicious_api_hits]}

suspicious_string_hits:
{static[suspicious_string_hits]}

YOUR JOB
Analyze the dump above. Look for: shellcode injection, process hollowing, \
anti-debug/anti-VM, packed/obfuscated code, C2 indicators (URLs, IPs, base64), \
persistence (Run keys, scheduled tasks, LaunchAgents), credential theft, ransomware.

POLICY
Sentinel is guilty-until-proven-innocent. Any credible malicious indicator -> BLOCK. \
ALLOW requires affirmative evidence of benign behavior.

OUTPUT
Reason in your own words, then end your response with EXACTLY one JSON code block:

```json
{{
  "verdict": "ALLOW" | "BLOCK",
  "confidence": 0.0,
  "reasoning": "1-3 sentences",
  "indicators": ["finding 1", "finding 2"],
  "functions_reviewed": []
}}
```
"""


def get_ghidra_mode() -> str:
    """Returns "mcp" (GUI Ghidra UDS socket), "headless" (analyzeHeadless on disk), or "static"."""
    user = os.environ.get("USER") or getpass.getuser()
    socket_dir = Path(f"/tmp/ghidra-mcp-{user}")
    if socket_dir.is_dir():
        for _ in socket_dir.glob("*.sock"):
            return MODE_MCP
    if find_analyze_headless():
        return MODE_HEADLESS
    return MODE_STATIC


def _format_imports(imports: list) -> str:
    if not imports:
        return "  (none)"
    return "\n".join(f"  {i.get('library','?')}::{i.get('symbol','?')}" for i in imports[:80])


def _format_strings(strings: list) -> str:
    if not strings:
        return "  (none)"
    return "\n".join(f"  {s!r}" for s in strings[:80])


def _format_functions(functions: list) -> str:
    if not functions:
        return "  (none)"
    rows = []
    for f in functions[:25]:
        flags = []
        if f.get("is_external"):
            flags.append("ext")
        if f.get("is_thunk"):
            flags.append("thunk")
        tag = f" [{'+'.join(flags)}]" if flags else ""
        rows.append(f"  {f.get('address','?')}  size={f.get('size','?'):>6}  {f.get('name','?')}{tag}")
    return "\n".join(rows)


def _format_decompiled(decompiled: dict) -> str:
    if not decompiled:
        return "  (none)"
    parts = []
    for name, code in decompiled.items():
        parts.append(f"---- {name} ----\n{code}")
    return "\n\n".join(parts)


def _format_meta_flags(flags: list) -> str:
    if not flags:
        return "  (none — no concerning patterns auto-detected)"
    rows = []
    for f in flags:
        rows.append(f"  [{f.get('severity','?').upper()}] {f.get('flag','?')}: {f.get('detail','')}")
    return "\n".join(rows)


class ClaudeCLIProvider(LLMProvider):
    def __init__(self, binary: str = "claude", timeout: float = DEFAULT_TIMEOUT,
                 model: str | None = None):
        self.binary = binary
        self.timeout = timeout
        self.model = model  # e.g. "sonnet" or full id; None = CLI default

    def review(self, *, file_path: Path, context: str) -> dict:
        mode = get_ghidra_mode()
        if mode == MODE_MCP:
            prompt = GHIDRA_MCP_PROMPT.format(path=str(file_path), context=context)
        elif mode == MODE_HEADLESS:
            try:
                dump = ghidra_headless_analyze(file_path)
            except Exception as e:
                # Fall back to static if Ghidra blows up — better a verdict than an error.
                dump = None
                static = static_inspect(file_path)
                prompt = STATIC_PROMPT.format(
                    path=str(file_path), context=context, static=static,
                )
                mode = MODE_STATIC
                mode_note = f"ghidra-headless failed: {e}"
            if dump is not None:
                prompt = GHIDRA_HEADLESS_PROMPT.format(
                    path=str(file_path),
                    context=context,
                    dump=dump,
                    imports_n=len(dump.get("imports", [])),
                    imports_block=_format_imports(dump.get("imports", [])),
                    strings_n=len(dump.get("strings", [])),
                    strings_suspicious_n=len(dump.get("strings_suspicious", [])),
                    strings_block=_format_strings(dump.get("strings", [])),
                    functions_n=len(dump.get("functions_top", [])),
                    functions_block=_format_functions(dump.get("functions_top", [])),
                    decompiled_n=len(dump.get("decompiled", {})),
                    decompiled_names=", ".join(dump.get("decompiled_names", [])) or "(none)",
                    decompiled_names_json=json.dumps(dump.get("decompiled_names", [])),
                    decompiled_block=_format_decompiled(dump.get("decompiled", {})),
                    meta_flags_block=_format_meta_flags(dump.get("meta_flags", [])),
                )
        else:
            static = static_inspect(file_path)
            prompt = STATIC_PROMPT.format(
                path=str(file_path), context=context, static=static,
            )

        envelope = self._invoke_with_retry(prompt)
        if envelope.get("is_error"):
            status = envelope.get("api_error_status")
            msg = envelope.get("result") or "(no message)"
            raise RuntimeError(f"claude API error (status={status}): {msg[:300]}")
        text = envelope.get("result") or ""
        verdict = self._extract_verdict(text)
        verdict["_mode"] = mode
        return verdict

    def _invoke_with_retry(self, prompt: str, *, max_retries: int = 2) -> dict:
        cmd = [
            self.binary,
            "-p", prompt,
            "--output-format", "json",
            "--dangerously-skip-permissions",
        ]
        if self.model:
            cmd.extend(["--model", self.model])
        last_envelope: dict = {}
        for attempt in range(max_retries):
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=self.timeout, check=False,
                )
            except FileNotFoundError as e:
                raise RuntimeError(
                    f"claude CLI not found (looking for '{self.binary}'). "
                    "Install Claude Code or set SENTINEL_CLAUDE_BIN."
                ) from e
            except subprocess.TimeoutExpired as e:
                raise RuntimeError(f"claude CLI timed out after {self.timeout}s") from e

            try:
                envelope = json.loads(result.stdout) if result.stdout else {}
            except json.JSONDecodeError:
                envelope = {}

            if not envelope and result.returncode != 0:
                raise RuntimeError(
                    f"claude CLI exited {result.returncode} with no JSON output: "
                    f"{result.stderr.strip()[:500]}"
                )

            last_envelope = envelope
            status = envelope.get("api_error_status")
            if envelope.get("is_error") and status in (429, 500, 502, 503, 504, 529):
                if attempt < max_retries - 1:
                    time.sleep(5 * (attempt + 1))
                    continue
            return envelope
        return last_envelope

    @staticmethod
    def _extract_verdict(text: str) -> dict:
        matches = JSON_FENCE_RE.findall(text)
        if matches:
            try:
                return json.loads(matches[-1])
            except json.JSONDecodeError:
                pass
        try:
            end = text.rindex("}") + 1
            start = text.rindex("{", 0, end)
            return json.loads(text[start:end])
        except (ValueError, json.JSONDecodeError):
            return {
                "verdict": "ERROR",
                "reasoning": "could not parse verdict JSON from model output",
                "raw": text[-1000:],
            }
