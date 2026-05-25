"""Build the 50-file benchmark corpus with neutral filenames.

Picks 25 benign from corpus/benign + corpus/bench/{gh,jq,rg}.exe and 25
malware from corpus/malware/. Shuffles all 50 with a fixed seed and copies
them into corpus/bench50/ as sample_01.exe ... sample_50.exe. Writes:

  corpus/bench50/labels.json   — sample_NN.exe -> "malicious" | "benign"
  corpus/bench50/manifest.json — sample_NN.exe -> {original, sha256, size, source}

The neutral names prevent the AI from pattern-matching on filenames
(mal_xxxxx jumps out hard). The benchmark harness will only ever see the
neutral name.
"""
from __future__ import annotations

import hashlib
import json
import random
import shutil
from pathlib import Path

SEED = 1337
N_BENIGN = 25
N_MAL = 25
OUT = Path("corpus/bench50")

BENIGN_DIRS = [Path("corpus/benign")]
BENIGN_EXTRA = [
    Path("corpus/bench/gh.exe"),
    Path("corpus/bench/jq.exe"),
    Path("corpus/bench/rg.exe"),
]
MALWARE_DIRS = [Path("corpus/malware")]


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def collect(dirs: list[Path], extras: list[Path] | None = None) -> list[Path]:
    """Return a list of unique .exe files (dedup by sha256, prefer first seen)."""
    seen: dict[str, Path] = {}
    pool: list[Path] = []
    for d in dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.exe")):
            pool.append(p)
    for p in extras or []:
        if p.is_file():
            pool.append(p)
    out: list[Path] = []
    for p in pool:
        digest = sha256(p)
        if digest in seen:
            continue
        seen[digest] = p
        out.append(p)
    return out


def main() -> int:
    if OUT.exists():
        for p in OUT.iterdir():
            p.unlink()
    else:
        OUT.mkdir(parents=True)

    benign = collect(BENIGN_DIRS, BENIGN_EXTRA)
    malware = collect(MALWARE_DIRS)

    print(f"Unique benign:  {len(benign)}")
    print(f"Unique malware: {len(malware)}")

    if len(benign) < N_BENIGN:
        print(f"  ERROR: need {N_BENIGN} benign, have {len(benign)}")
        return 1
    if len(malware) < N_MAL:
        print(f"  ERROR: need {N_MAL} malware, have {len(malware)}")
        return 1

    rng = random.Random(SEED)
    benign_sel = rng.sample(benign, N_BENIGN)
    malware_sel = rng.sample(malware, N_MAL)
    deck: list[tuple[Path, str]] = (
        [(p, "benign") for p in benign_sel] + [(p, "malicious") for p in malware_sel]
    )
    rng.shuffle(deck)

    labels: dict[str, str] = {}
    manifest: dict[str, dict] = {}
    for i, (src, label) in enumerate(deck, start=1):
        name = f"sample_{i:02d}.exe"
        dst = OUT / name
        shutil.copy2(src, dst)
        digest = sha256(dst)
        labels[name] = label
        manifest[name] = {
            "original": src.name,
            "source_dir": str(src.parent),
            "sha256": digest,
            "size_bytes": dst.stat().st_size,
        }
        marker = "MAL" if label == "malicious" else "ben"
        print(f"  {name}  [{marker}]  <- {src.name}  ({dst.stat().st_size // 1024} KB)")

    (OUT / "labels.json").write_text(json.dumps(labels, indent=2, sort_keys=True))
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))

    n_b = sum(1 for v in labels.values() if v == "benign")
    n_m = sum(1 for v in labels.values() if v == "malicious")
    print()
    print(f"Wrote {len(labels)} samples to {OUT}/")
    print(f"  benign:    {n_b}")
    print(f"  malicious: {n_m}")
    print(f"  labels:    {OUT}/labels.json")
    print(f"  manifest:  {OUT}/manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
