# Sentinel just went 49 for 50 against real malware

I built Sentinel as a "guilty until proven innocent" file scanner. Three stages, weighted aggregator, AI reasoning over actual decompiled code instead of vibes. Last night I finally pointed it at a serious test set and watched it work.

The setup was simple. 50 Windows binaries. 25 real malware samples pulled straight from MalwareBazaar's recent queue (AsyncRAT, AgentTesla, CoinMiner, a bunch of loaders and stealers). 25 benign command line tools pulled from GitHub releases (fd, bat, fzf, age, gron, jq, ripgrep, that whole crowd). Every file got renamed to `sample_01.exe` through `sample_50.exe` and shuffled with a fixed seed. The scanner saw nothing but the index. No hints, no filename leakage, no way to cheat.

**49 out of 50 correct. Every single piece of malware caught. One false positive on a Rust disk usage tool.**

That number deserves to sit there for a second.

## Beating VirusTotal at its own job

Here is the part I am most proud of. VirusTotal alone, taking any engine detection as a block, would have scored 41 out of 50. Sentinel scored 49. That eight file gap is not noise. It is eight real benign binaries that VT had at least one detection on, that a person looking at a raw VT report would have to manually triage, and that Sentinel correctly cleared on its own by actually reading the code.

Those eight were btop4win, bandwhich, fzf, fd, age, jq, choose, and gron. Popular open source tools that occasionally trip a low quality AV engine. In every case Sentinel's AI stage looked at the decompiled Ghidra output, recognized what the binary actually does, and overrode the VT noise with high confidence (0.85 to 0.92 across the board).

This is exactly the use case I built Sentinel for. VT is a great signal but a terrible verdict. Sentinel turns it into a verdict.

## The 25 malware samples, all caught

Recall was 100 percent. No false negatives. Not one piece of malware slipped through.

Some of these were nasty. `mal_b23e7c88614b` was an 87 MB binary that took Ghidra nine minutes to chew through. Sentinel still nailed it at 0.99 confidence. Two AsyncRAT samples, multiple AgentTesla variants, a CoinMiner, a thread injection loader, all caught.

The malware verdicts were mostly above 0.95 AI confidence. The aggregator did not have to think hard about most of these.

## The one miss, and why I am OK with it

The false positive was `dust.exe`. Dust is a Rust CLI that walks the filesystem to show you what is taking up disk space. Totally benign. VT flagged it 2 out of 66. Sentinel blocked it at 0.58 AI confidence, the lowest block score in the whole run.

The reason is genuinely interesting. Dust uses a Rust crate called `sysinfo` that pulls in `OpenProcess`, `Process32First`, `Module32First`, and `ReadProcessMemory` on Windows. Those are the exact APIs a process scanner or memory inspector would use. The AI saw a binary whose strings advertised a disk usage CLI but whose imports looked like a process enumerator, and it called the mismatch.

It was wrong. But the heuristic was not crazy. It is the kind of mistake a careful human analyst could make if they did not happen to know about sysinfo's Windows implementation. And it blocked at 0.58, which is the AI's way of saying "I am unsure about this one." With a slightly tighter aggregator threshold, dust would have squeaked through.

I would rather have a scanner that errs cautious on one weird Rust binary than one that lets a stealer through.

## What this run actually showed

Three things.

One. The "guilty until proven innocent" design works. Sentinel reaches for evidence before reaching for a verdict, and the evidence is the actual decompiled code, not signatures or heuristics.

Two. The aggregator math is doing real work. VirusTotal alone got 8 of those benign tools wrong. Sentinel's aggregator weighed VT against the AI's read of the code and got them right. That is the whole point.

Three. The headless Ghidra plus Claude pipeline scales. 50 samples, including some 87 MB monsters, all the way through with no human in the loop, about two hours wall time. The longest single scan was under ten minutes. Most finished in two.

## What this run did not show

I want to be honest about scope. 50 files is small. The malware leans Windows PE and recent in the wild. There is no .NET, no JavaScript droppers, no Office macros, no packed VMProtect binaries. The benign side is also narrow, mostly small CLI tools, no installers, no Electron apps, no games. The next benchmark needs to be bigger and weirder.

But for a 50 file head to head, scored on a shuffled corpus with no filename leakage, on a build I shipped this week:

**Sentinel: 49.  VirusTotal aggregate: 41.  Real malware caught: 25 of 25.**

I will take it.

## Reproducing this

The fetcher, shuffler, and benchmark harness are all in the repo.

```bash
# pull 22 small benign CLI binaries from GitHub releases
.venv/bin/python scripts/fetch_benign.py

# pull 25 fresh malware samples from MalwareBazaar (needs MALWAREBAZAAR_API_KEY)
.venv/bin/python -m sentinel fetch-malware --limit 25 corpus/malware

# shuffle and rename to neutral sample_NN.exe
.venv/bin/python scripts/build_bench50.py

# run the benchmark
.venv/bin/python -m sentinel benchmark corpus/bench50 \
    --labels corpus/bench50/labels.json \
    --report-dir reports \
    --out-dir benchmarks
```

You will not get the exact same 50 files (MalwareBazaar's recent queue rolls) but you will get a comparable corpus.

## Artifacts

Every scan wrote a full report to `reports/`, so they all show up in the UI's history tab. The benchmark harness dropped a CSV and JSON in `benchmarks/` with per sample verdicts, VT detection counts, AI confidence scores, and top indicators for every file. The renamed corpus and original name mapping are in `corpus/bench50/`. And because each scan stored its decompiled functions into SentinelNet, the corpus just grew by around 300 fingerprinted functions. The next scan that touches one of these binaries will see similarity hits show up in the Related Samples card.
