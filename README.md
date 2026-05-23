# Sentinel

A guilty-until-proven-innocent file scanner that combines VirusTotal's multi-engine
verdict with AI reasoning over Ghidra-decompiled code. Built as an experimental
v0 — not production AV.

```
┌──────┐    ┌────────────┐    ┌──────────────────────┐    ┌────────────┐
│ file │ -> │ VirusTotal │ -> │ AI deep dive         │ -> │ verdict    │
└──────┘    │ (hash +    │    │ (Ghidra headless +   │    │ (weighted  │
            │  optional  │    │  Claude reasoning)   │    │  ALLOW or  │
            │  upload)   │    │                      │    │  BLOCK)    │
            └────────────┘    └──────────────────────┘    └────────────┘
```

Three signals — VirusTotal aggregate, optional Hatching Triage sandbox, and an AI
review of Ghidra's decompilation — are combined by a weighted aggregator with a
configurable BLOCK threshold. Default policy treats any non-ALLOW signal as
sticky positive evidence and requires affirmative benign evidence to allow.

## Status

**Experimental v0.** Catches real ITW samples; surfaces real false-positive
risks; the architecture is sound but rough. Tested on macOS arm64; cross-platform
in principle.

## Architecture

```
sentinel/                 Python package — the scanner + daemon
├── stages/
│   ├── virustotal.py     SHA-256 lookup; optional upload + poll
│   ├── triage.py         Hatching Triage sandbox (optional)
│   └── ai_review.py      Wraps the LLM provider, returns Signal
├── llm/
│   ├── base.py           LLMProvider interface
│   └── claude_cli.py     Shells out to `claude -p`, parses verdict JSON
├── ghidra_headless.py    Wraps Ghidra's analyzeHeadless CLI
├── ghidra_scripts/
│   └── sentinel_dump.py  Jython PostScript — dumps imports, strings,
│                         decompiled functions, meta-flags to JSON
├── static_inspect.py     binutils fallback when Ghidra is unavailable
├── verdict.py            Weighted-score aggregator
├── scanner.py            Pure scan_file() — used by CLI + daemon
├── cli.py                argparse: scan | benchmark | fetch-malware | serve
├── benchmark.py          Corpus-mode runner with TPR/FPR metrics
├── fetch_malware.py      Pulls samples from MalwareBazaar
└── daemon.py             Flask HTTP + SSE server (backs the UI)

ui/                       Electron + Vite + React + TS + Tailwind
├── src/main/             Main process (spawns daemon, IPC)
├── src/preload/          contextBridge for daemon URL + file picker
└── src/renderer/         React UI — drop zone, scan view, verdict view
```

The AI deep dive has three modes, auto-detected:

1. **`mcp`** — GUI Ghidra with the GhidraMCP plugin exposes a UDS socket. Claude
   drives `mcp__ghidra__*` tools live.
2. **`headless`** — `analyzeHeadless` on disk. `sentinel/ghidra_headless.py`
   shells out and runs `sentinel_dump.py` as a PostScript to extract everything.
   This is the default working mode.
3. **`static`** — neither available; fall back to `file`/`strings`/`otool`/`nm`.

## Setup

### Python scanner

```bash
git clone <this-repo> Sentinel
cd Sentinel

python3 -m venv .venv
source .venv/bin/activate
pip install -e .

cp .env.example .env
# fill in VT_API_KEY at minimum
```

### Ghidra (for AI deep dive)

macOS (Homebrew):

```bash
brew install --cask ghidra
```

Sentinel auto-detects `analyzeHeadless` at common paths (Homebrew cellar,
`$GHIDRA_HOME/support/`). If yours is elsewhere, set `GHIDRA_HOME`.

### UI (optional — CLI works standalone)

```bash
cd ui
npm install
npm run dev    # opens the Electron window
```

The Electron main process auto-spawns the daemon (`sentinel serve`) on a free
port and the renderer talks to it via SSE.

## CLI usage

```bash
# Scan one file (hash lookup only, no VT upload)
sentinel scan /path/to/binary

# Scan + upload to VirusTotal if hash is unknown
sentinel scan --upload /path/to/binary

# Skip stages selectively
sentinel scan --skip-triage --skip-ai /path/to/binary

# Benchmark a corpus
sentinel benchmark corpus/bench --labels corpus/bench/labels.json

# Pull recent ITW samples from MalwareBazaar (requires free API key)
sentinel fetch-malware corpus/malware --limit 10

# Run the local HTTP daemon (used by the UI)
sentinel serve --host 127.0.0.1 --port 7331
```

Exit codes: `0` allow · `1` block · `2` usage error.

## Configuration

Environment variables (set in `.env`):

| Variable | Required | Notes |
|---|---|---|
| `VT_API_KEY` | yes | https://www.virustotal.com/gui/my-apikey (free) |
| `TRIAGE_API_KEY` | no | https://tria.ge/account/api (optional, gates the sandbox stage) |
| `MALWAREBAZAAR_API_KEY` | no | https://bazaar.abuse.ch/account/ (required for `fetch-malware`) |
| `SENTINEL_CLAUDE_BIN` | no | Path to the `claude` CLI binary (defaults to PATH lookup) |
| `SENTINEL_CLAUDE_MODEL` | no | Override (`sonnet`, etc.) if Opus refuses on legit malware |
| `GHIDRA_HOME` | no | Ghidra libexec dir; auto-detected on Homebrew macOS |

## How the verdict is computed

Each signal contributes a score in `[-1, +1]` (positive = malicious). Weighted
sum exceeding `BLOCK_THRESHOLD = 0.15` blocks. Defaults in `sentinel/verdict.py`:

| Stage | Weight | Notes |
|---|---|---|
| VirusTotal | 0.40 | Detection ratio scaled `× 2`; ratios below 4% suppressed as noise (single-engine FPs) |
| AI deep dive | 0.35 | `±confidence` signed by the AI's ALLOW/BLOCK verdict |
| Triage | 0.25 | Score/10 if BLOCK; mild negative if ALLOW |

A clean VT result is mild negative evidence (`-0.30`) — it counts against
blocking, but doesn't override a confident AI BLOCK (the FUD-malware case).

## Limitations

- **Stripped Go binaries**: `main.main` is invisible without symbols. The
  `ghidra_scripts/sentinel_dump.py` picker has heuristics for this (call-graph
  walk from entry, suspicious-API caller scan, meta-flags) but cannot reliably
  read user code in heavily stripped/obfuscated Go.
- **Large binaries (>50MB)**: Ghidra `analyzeHeadless` can be slow or unstable;
  Sentinel falls back to `static` mode in that case.
- **Anthropic API refusals**: Opus occasionally refuses to analyze malware on
  Usage Policy grounds even with a defensive-research preamble. Sentinel retries
  and surfaces the error; `SENTINEL_CLAUDE_MODEL=sonnet` is the workaround.
- **Daemon distribution**: the Electron app currently spawns the Python venv's
  CLI. Packaging Python + Sentinel as a single distributable is a future task.

## License

MIT — see [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md) for disclosure policy and the test-corpus
warnings (real malware samples in `corpus/` are gitignored — they should never
be committed).
