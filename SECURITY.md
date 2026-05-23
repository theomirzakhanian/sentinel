# Security

## This is a defensive security tool

Sentinel is built for **defensive security research and personal file scanning**
— equivalent in intent to commercial AV/EDR products. It performs static
analysis only and never executes the files it scans.

## Reporting a vulnerability

If you find a security issue in Sentinel itself (e.g., a way to make the
scanner crash or exfiltrate data while analyzing a crafted binary), please open
a private GitHub Security Advisory rather than a public issue.

## Operational warnings

### Real malware in `corpus/`

The `corpus/` directory is intended to hold **real, in-the-wild malware
samples** used for benchmarking detection. It is gitignored and **must never
be committed** to a public or shared repository. Specifically:

- `corpus/malware/*` — samples downloaded via `sentinel fetch-malware` (from
  MalwareBazaar) are real ITW binaries.
- `corpus/bench/*` — the mixed benchmark corpus including the malware samples.

If you fork this repository:

1. Verify `corpus/` is gitignored before your first commit (`git status` should
   not list any `mal_*.exe`).
2. Do not share these files outside research/AV contexts.
3. Do not put `corpus/` inside iCloud Drive, Dropbox, or any cloud-synced
   folder — your provider's AV will quarantine the files and (worse) your
   files will be uploaded to a third party.
4. On macOS, samples may be auto-quarantined by XProtect. Strip the attribute
   with `xattr -dr com.apple.quarantine corpus/malware/` if needed.

### Reports may contain sensitive metadata

`reports/*.json` includes file paths, SHA-256s, and VT detection details for
every file you have scanned. If you scan personal binaries, those reports
identify them. The directory is gitignored by default.

### API keys

`.env` contains live API keys (VirusTotal, MalwareBazaar, optionally Triage).
It is gitignored. `.env.example` is the template for sharing.

### VirusTotal uploads

The `--upload` flag (CLI) submits the binary to VirusTotal's public corpus.
**Once uploaded, samples are accessible to other VT users and partners.** Do
not upload binaries you consider private or that contain sensitive data
(internal company tools, work-in-progress reverse-engineering subjects, etc.).
Default behavior is hash lookup only — no upload.

### Anthropic / Claude API usage

Sentinel's AI deep dive sends prompts that include:

- File path and SHA-256
- Ghidra-decompiled function source (real C from the binary)
- Strings and imports from the binary
- VirusTotal stats

These go to Anthropic via the `claude` CLI. If the binary contains sensitive
content (proprietary code, intellectual property), be aware that decompiled
fragments will be transmitted to and processed by Anthropic. See
[Anthropic's Usage Policy](https://www.anthropic.com/legal/aup).

### Ghidra subprocess

`sentinel/ghidra_headless.py` shells out to `analyzeHeadless` with the target
file as an `-import` argument. Ghidra has had historical
vulnerabilities in its import parsers; a crafted malicious binary could in
theory exploit those. Keep your Ghidra installation up to date.

### Default policy is paranoid

Sentinel defaults to "guilty until proven innocent" — `UNKNOWN`, `TIMEOUT`,
and `ERROR` signals are treated as evidence to BLOCK unless other signals
provide affirmative benign evidence. This is intentional; do not loosen the
threshold (`BLOCK_THRESHOLD` in `verdict.py`) without understanding the FPR
implications on your corpus.
