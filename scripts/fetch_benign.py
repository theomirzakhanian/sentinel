"""Fetch ~22 small, popular open-source Windows CLI binaries to use as
benign samples in the Sentinel benchmark.

For each repo, queries GitHub for the latest release, finds a Windows x86_64
asset, downloads it, and extracts a single .exe into corpus/benign/.

Set GITHUB_TOKEN in env to raise the rate limit (5000/hr vs 60/hr).
"""
from __future__ import annotations

import io
import os
import re
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import requests
from rich.console import Console

console = Console()

OUT_DIR = Path("corpus/benign")
TIMEOUT = 60
UA = "sentinel-benchmark/0.1"

# (owner/repo, exe basename we want extracted, asset-name regex)
# We pick small, single-binary CLI tools (most under 10 MB on Windows).
TARGETS: list[tuple[str, str, str]] = [
    ("sharkdp/fd",            "fd.exe",        r"fd-.*-x86_64-pc-windows-(msvc|gnu)\.zip$"),
    ("sharkdp/bat",           "bat.exe",       r"bat-.*-x86_64-pc-windows-(msvc|gnu)\.zip$"),
    ("sharkdp/hyperfine",     "hyperfine.exe", r"hyperfine-.*-x86_64-pc-windows-(msvc|gnu)\.zip$"),
    ("sharkdp/hexyl",         "hexyl.exe",     r"hexyl-.*-x86_64-pc-windows-(msvc|gnu)\.zip$"),
    ("sharkdp/pastel",        "pastel.exe",    r"pastel-.*-x86_64-pc-windows-(msvc|gnu)\.zip$"),
    ("bootandy/dust",         "dust.exe",      r"dust-.*-x86_64-pc-windows-(msvc|gnu)\.zip$"),
    ("dalance/procs",         "procs.exe",     r"procs-.*-x86_64-windows\.zip$"),
    ("chmln/sd",              "sd.exe",        r"sd-.*-x86_64-pc-windows-(msvc|gnu)\.zip$"),
    ("XAMPPRocky/tokei",      "tokei.exe",     r"tokei-x86_64-pc-windows-(msvc|gnu)\.exe$"),
    ("tomnomnom/gron",        "gron.exe",      r"gron-windows-amd64-.*\.zip$"),
    ("theryangeary/choose",   "choose.exe",    r"choose-x86_64-pc-windows-(msvc|gnu)\.exe$"),
    ("casey/just",            "just.exe",      r"just-.*-x86_64-pc-windows-(msvc|gnu)\.zip$"),
    ("charmbracelet/gum",     "gum.exe",       r"gum_.*_Windows_x86_64\.zip$"),
    ("charmbracelet/glow",    "glow.exe",      r"glow_.*_Windows_x86_64\.zip$"),
    ("FiloSottile/age",       "age.exe",       r"age-.*-windows-amd64\.zip$"),
    ("junegunn/fzf",          "fzf.exe",       r"fzf-.*-windows_amd64\.zip$"),
    ("ducaale/xh",            "xh.exe",        r"xh-.*-x86_64-pc-windows-(msvc|gnu)\.zip$"),
    ("dandavison/delta",      "delta.exe",     r"delta-.*-x86_64-pc-windows-(msvc|gnu)\.zip$"),
    ("starship/starship",     "starship.exe",  r"starship-x86_64-pc-windows-(msvc|gnu)\.zip$"),
    ("ajeetdsouza/zoxide",    "zoxide.exe",    r"zoxide-.*-x86_64-pc-windows-(msvc|gnu)\.zip$"),
    ("imsnif/bandwhich",      "bandwhich.exe", r"bandwhich-v.*-x86_64-pc-windows-(msvc|gnu)\.zip$"),
    ("aristocratos/btop4win", "btop4win.exe",  r"btop4win.*\.zip$"),
]


def _gh_headers() -> dict[str, str]:
    h = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def latest_release(repo: str) -> dict:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    r = requests.get(url, headers=_gh_headers(), timeout=TIMEOUT)
    if r.status_code == 404:
        # Some repos only publish pre-releases; fall back to releases list
        r = requests.get(
            f"https://api.github.com/repos/{repo}/releases?per_page=5",
            headers=_gh_headers(),
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if not data:
            raise RuntimeError(f"{repo}: no releases")
        return data[0]
    r.raise_for_status()
    return r.json()


def pick_asset(rel: dict, pattern: str) -> dict:
    pat = re.compile(pattern)
    for a in rel.get("assets") or []:
        if pat.search(a["name"]):
            return a
    names = [a["name"] for a in (rel.get("assets") or [])]
    raise RuntimeError(f"no asset matching /{pattern}/ in {names[:5]}...")


def download_asset(asset: dict) -> bytes:
    url = asset["browser_download_url"]
    r = requests.get(url, headers={"User-Agent": UA}, timeout=TIMEOUT * 4, stream=True)
    r.raise_for_status()
    return r.content


def extract_exe(blob: bytes, asset_name: str, want_basename: str) -> bytes:
    """Pull `want_basename` (or, failing that, the first .exe) out of the archive."""
    if asset_name.endswith(".exe"):
        return blob

    if asset_name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            names = zf.namelist()
            target = next((n for n in names if Path(n).name.lower() == want_basename.lower()), None)
            if target is None:
                target = next((n for n in names if n.lower().endswith(".exe")), None)
            if target is None:
                raise RuntimeError(f"no .exe in zip; entries: {names[:6]}")
            return zf.read(target)

    if asset_name.endswith((".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            for m in tf.getmembers():
                if m.isfile() and m.name.lower().endswith(".exe"):
                    f = tf.extractfile(m)
                    if f is None:
                        continue
                    return f.read()
        raise RuntimeError("no .exe in tar.gz")

    raise RuntimeError(f"unsupported archive type: {asset_name}")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    console.print(f"[bold]Fetching {len(TARGETS)} benign Windows binaries[/bold] -> [cyan]{OUT_DIR}[/cyan]")
    if not os.environ.get("GITHUB_TOKEN"):
        console.print("[dim]Tip: set GITHUB_TOKEN to raise the 60/hr unauthenticated rate limit.[/dim]")

    ok = 0
    fail = 0
    skipped = 0
    for i, (repo, basename, pat) in enumerate(TARGETS, 1):
        out_path = OUT_DIR / basename
        if out_path.exists() and out_path.stat().st_size > 0:
            console.print(f"  [{i:2}/{len(TARGETS)}] {repo}: [dim]already have {basename}[/dim]")
            skipped += 1
            continue
        try:
            rel = latest_release(repo)
            asset = pick_asset(rel, pat)
            console.print(f"  [{i:2}/{len(TARGETS)}] {repo}: downloading {asset['name']} ({asset.get('size', 0)//1024} KB)...", end=" ")
            blob = download_asset(asset)
            exe = extract_exe(blob, asset["name"], basename)
            out_path.write_bytes(exe)
            console.print(f"[green]ok[/green] -> {basename} ({len(exe)//1024} KB)")
            ok += 1
        except Exception as e:
            console.print(f"  [{i:2}/{len(TARGETS)}] {repo}: [red]FAIL[/red] {e}")
            fail += 1
        time.sleep(0.3)  # be nice to github

    console.print()
    console.print(f"[bold]Done.[/bold] downloaded={ok}, skipped={skipped}, failed={fail}")
    have = sorted(p.name for p in OUT_DIR.glob("*.exe"))
    console.print(f"  corpus/benign/ now has {len(have)} .exe files")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
