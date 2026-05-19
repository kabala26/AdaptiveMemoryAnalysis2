#!/usr/bin/env python3
"""
Download and install the Volatility 3 Windows symbol pack.

The archive (~600 MB) is fetched from the Volatility Foundation's servers and
extracted directly into the first writable directory in volatility3.symbols.__path__,
which is the same location Volatility searches when loading ISF files at runtime.

Usage (run from the project root):
    venv/bin/python download_symbols.py          # recommended
    python download_symbols.py                   # if venv is already activated
"""

import os
import sys
import zipfile
import urllib.request
import tempfile
from pathlib import Path

SYMBOLS_URL = (
    "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip"
)


def _get_target_dir() -> Path:
    """Return the best writable symbol directory for the active Python environment."""
    try:
        from volatility3 import symbols as _vol_syms
        for p in _vol_syms.__path__:
            path = Path(p)
            try:
                path.mkdir(parents=True, exist_ok=True)
                if os.access(path, os.W_OK):
                    return path
            except PermissionError:
                pass
    except ImportError:
        pass
    # Fallback: project-local cache that _setup() also registers
    fallback = Path(__file__).parent / "models" / "symbols"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def _progress(block_num: int, block_size: int, total: int) -> None:
    done = block_num * block_size
    if total > 0:
        pct = min(100.0, done * 100.0 / total)
        bar = "█" * int(pct // 2) + "░" * (50 - int(pct // 2))
        sys.stdout.write(
            f"\r  [{bar}] {pct:5.1f}%  "
            f"{done // (1 << 20):,} / {total // (1 << 20):,} MB"
        )
    else:
        sys.stdout.write(f"\r  {done // (1 << 20):,} MB downloaded…")
    sys.stdout.flush()


def main() -> None:
    print("Volatility 3 Windows symbol pack installer")
    print("=" * 50)

    target_dir = _get_target_dir()
    print(f"Target directory : {target_dir}")
    print(f"Download URL     : {SYMBOLS_URL}")
    print()

    # Check existing symbols
    existing = list((target_dir / "windows").rglob("*.json.xz")) if (target_dir / "windows").exists() else []
    if existing:
        print(f"Found {len(existing)} existing symbol file(s) in {target_dir / 'windows'}")
        ans = input("Re-download and overwrite? [y/N] ").strip().lower()
        if ans != "y":
            print("Aborted.")
            return
        print()

    # Download to a temp file
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".zip", prefix="vol3-symbols-")
    os.close(tmp_fd)

    try:
        print("Downloading…")
        urllib.request.urlretrieve(SYMBOLS_URL, tmp_path, reporthook=_progress)
        print()  # newline after progress bar

        zip_size_mb = os.path.getsize(tmp_path) / (1 << 20)
        print(f"\nDownloaded {zip_size_mb:.1f} MB  →  extracting…")

        with zipfile.ZipFile(tmp_path, "r") as zf:
            members = zf.namelist()
            total   = len(members)
            for i, name in enumerate(members, 1):
                zf.extract(name, target_dir)
                if i % 200 == 0 or i == total:
                    sys.stdout.write(f"\r  Extracting {i}/{total} files…")
                    sys.stdout.flush()
        print()

    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    # Report result
    installed = list((target_dir / "windows").rglob("*.json.xz"))
    print(f"\nInstalled {len(installed)} symbol file(s) into:\n  {target_dir / 'windows'}")
    print("\nVolatility 3 can now analyse Windows memory dumps without network access.")


if __name__ == "__main__":
    main()
