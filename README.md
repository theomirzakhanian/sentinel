# Sentinel

An experimental file scanner that treats every binary as guilty until something proves otherwise. Combines VirusTotal, optional Hatching Triage, and an AI that reads Ghidra-decompiled code to figure out what a file actually does.

Not production AV. A weekend-scale v0 that catches real malware and surfaces the AI's reasoning end-to-end, including the decompiled functions it actually read.

```
file in
   │
   ▼
VirusTotal lookup ──▶ Triage sandbox (optional) ──▶ Ghidra headless + Claude
                                                        │
                                                        ▼
                                              weighted verdict + reasons
```

## The interesting stage

Most AV is signature matching plus some heuristics. Sentinel does the signature part too (VirusTotal aggregates 70+ engines), but the part worth talking about is the third stage.

For each scan, Ghidra's `analyzeHeadless` runs on the binary and writes out a JSON dump: imports, strings, and the decompiled C of selected functions. Before any of that gets to Claude, Sentinel computes meta-flags for concerning patterns it can spot mechanically — dynamic API resolution combos (`LoadLibrary` + `GetProcAddress`), the full process-injection primitive set, network vocabulary in strings that doesn't match the filename's apparent purpose. Then the whole package goes to Claude with a prompt that forbids it from explaining away upstream signals as "Go false positives" or "needed by the runtime."

What comes back is a verdict plus a file description, a malware class (stealer, RAT, backdoor, loader, ransomware, packer...), a named family when one is recognizable, and a list of capabilities the code actually has. The UI shows you the decompiled C of the functions Claude reviewed so you can check its work.

## Honest limitations (worth saying up front)

- The bundled CLI for the LLM stage is Claude Code. If you do not have it on your PATH, the AI stage breaks. An Anthropic API provider is sketched but not wired.
- Anthropic occasionally refuses to analyze malware even with the defensive-context preamble. Sentinel retries and surfaces the error. `SENTINEL_CLAUDE_MODEL=sonnet` usually gets through when Opus does not.
- Ghidra is slow on big binaries. Anything over about 50 MB takes a couple of minutes per scan. The picker falls back to a binutils-only mode if Ghidra crashes.
- The Electron app currently launches the Python CLI as a subprocess. Distribution as a single signed installer is a separate piece of work.

## Setup

### Scanner

```bash
git clone https://github.com/theomirzakhanian/sentinel
cd sentinel

python3 -m venv .venv
source .venv/bin/activate
pip install -e .

cp .env.example .env
# fill in VT_API_KEY at minimum; the others are optional
```

### Ghidra

macOS with Homebrew:

```bash
brew install --cask ghidra
```

Sentinel finds `analyzeHeadless` automatically at the standard Homebrew paths. Set `GHIDRA_HOME` if yours lives elsewhere.

### UI

```bash
cd ui
npm install
npm run dev
```

The Electron main process starts `sentinel serve` on a free port and the renderer talks to it via SSE.

## CLI

```bash
sentinel scan ./binary                          # default: VT hash lookup only
sentinel scan --upload ./binary                 # upload to VT if hash is unknown
sentinel scan --skip-ai ./binary                # fast path: VT only
sentinel benchmark corpus/ --labels labels.json # batch over a directory
sentinel fetch-malware corpus/malware --limit 10 # pull recent ITW samples
sentinel serve                                  # local daemon for the UI
```

Exit codes: 0 allow, 1 block, 2 usage error.

## Layout

```
sentinel/
├── stages/
│   ├── virustotal.py        SHA-256 lookup + optional upload
│   ├── triage.py            Hatching Triage submit + poll
│   └── ai_review.py         Wraps the LLM provider into a Signal
├── llm/
│   ├── base.py              Abstract provider interface
│   └── claude_cli.py        Shells out to `claude -p`, parses JSON verdict
├── ghidra_headless.py       Wrapper around analyzeHeadless
├── ghidra_scripts/
│   └── sentinel_dump.py     Jython postscript: imports, strings, decompiled
│                            C, meta-flags, Go pclntab name recovery
├── static_inspect.py        Binutils fallback when Ghidra is unavailable
├── verdict.py               Weighted-score aggregator
├── scanner.py               Pure scan_file() used by CLI and daemon
├── benchmark.py             Corpus runner with TPR/FPR metrics
├── fetch_malware.py         MalwareBazaar pull
├── cli.py                   argparse: scan / benchmark / fetch-malware / serve
└── daemon.py                Flask + SSE for the UI

ui/
├── src/main/                Electron main (spawns daemon, IPC, app icon)
├── src/preload/             contextBridge: daemon URL + file picker
└── src/renderer/            React + Vite + Tailwind
    ├── App.tsx              Sidebar shell + page router
    └── components/
        ├── Sidebar.tsx           Brand, nav, rotating tagline
        ├── OverviewPage.tsx      Big shield + stats + Quick Scan CTA
        ├── ScanInProgress.tsx    Live stage view with score gauge
        ├── VerdictScreen.tsx     Hero verdict + signal cards
        ├── AnalysisCard.tsx      File description, class badges, capabilities
        ├── CodeReviewCard.tsx    Meta-flags + decompiled C per function
        ├── HistoryPage.tsx       Past scans, clickable
        └── SettingsPage.tsx      Read-only daemon config + .env path
```

## How verdicts add up

Each stage produces a score in `[-1, +1]` (positive = malicious). The aggregator weights them and BLOCKs if the total clears 0.15.

VirusTotal is weighted 0.40 with detection ratio scaled ×2, and anything below 4% gets suppressed as noise — that one rule alone fixed jq.exe getting blocked because a single engine called it a trojan. AI deep dive carries 0.35, signed by the AI's verdict with confidence as magnitude. Triage carries 0.25.

A clean VT result is mild negative evidence (-0.30) but not enough to override a confident AI BLOCK. That's the whole point: catching FUD malware that VT misses while not over-blocking when one heuristic engine misfires.

## Go binaries get the full treatment

Stripped Go is the hardest case for static AV. Symbols are gone, so picker heuristics fail and you end up decompiling Go's scheduler instead of the user's `main.main`.

Sentinel parses Go's pclntab (the function-name table the runtime uses for stack traces). On a recent test sample claiming to be an image processor, this turned six anonymous `FUN_xxxxxx` decompilations into `main.shellLoop`, `main.uploadFile`, `main.generateImage`, `main.processImage` — instantly making the cover/payload split visible. Handles the Go 1.18+ and 1.20+ pclntab layouts and rebuilds `textStart` from the .text section for PIE binaries.

## Configuration

Set in `.env`:

| Variable | Required | Where to get it |
|---|---|---|
| `VT_API_KEY` | yes | https://www.virustotal.com/gui/my-apikey |
| `TRIAGE_API_KEY` | no | https://tria.ge/account/api (gates the sandbox stage) |
| `MALWAREBAZAAR_API_KEY` | no | https://bazaar.abuse.ch/account/ (for `fetch-malware`) |
| `SENTINEL_CLAUDE_BIN` | no | Defaults to `claude` on PATH |
| `SENTINEL_CLAUDE_MODEL` | no | Override Opus with `sonnet` if you hit refusals |
| `GHIDRA_HOME` | no | Auto-detected on macOS Homebrew |

## License

MIT — see [LICENSE](LICENSE).

## Security notes

See [SECURITY.md](SECURITY.md). The `corpus/` directory is gitignored because it is meant to hold actual malware samples for benchmarking. Do not commit it. Do not put it in iCloud or Dropbox. macOS XProtect may quarantine downloaded samples; strip the attribute with `xattr -dr com.apple.quarantine corpus/malware/` if needed.

`--upload` to VirusTotal makes the sample public. Default is hash lookup only. Decompiled fragments of any scanned file are sent to Anthropic when the AI stage runs; do not scan things you consider private.
