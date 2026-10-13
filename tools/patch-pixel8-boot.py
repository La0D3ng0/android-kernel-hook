#!/usr/bin/env python3
"""Prepare a temporary KernelPatch boot candidate for the exact Pixel 8 build."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
from pathlib import Path


STOCK_SHA256 = "625fa1f84ccf0707fe7859a005797db1495d2f01b58d9dc4708d9a26c2f7dd30"
STOCK_KERNEL_SHA256 = "02deebb82bda93be7eaaa4e85cf02c58f858a33a05ab4d19367bb1c0a4714559"
KPIMG_SHA256 = "e9cc3f6fd11076735db4c3bd3026f74be7839957deaf2d01a5c17753c338514e"
KPTOOLS_SHA256 = "49f624f02afeb23c8c1d3c437f996c85f127fc9bc3f026f1e9182c866a6e57f0"
KERNEL_VERSION = "6.1.145-android14-11-gfa1d6308d1fe-ab14691759"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_hash(path: Path, expected: str) -> None:
    actual = sha256_file(path)
    if actual != expected:
        raise SystemExit(f"SHA-256 mismatch for {path}: {actual}")


def inspect(kptools: Path, image: Path) -> str:
    result = subprocess.run(
        [str(kptools), "-l", "-i", str(image)],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stock_boot", type=Path)
    parser.add_argument("stock_kernel", type=Path)
    parser.add_argument("kpimg", type=Path)
    parser.add_argument("kptools", type=Path)
    parser.add_argument("superkey_file", type=Path)
    parser.add_argument("patched_boot", type=Path)
    args = parser.parse_args()
    for name in ("stock_boot", "stock_kernel", "kpimg", "kptools",
                 "superkey_file", "patched_boot"):
        setattr(args, name, getattr(args, name).resolve())

    check_hash(args.stock_boot, STOCK_SHA256)
    check_hash(args.stock_kernel, STOCK_KERNEL_SHA256)
    check_hash(args.kpimg, KPIMG_SHA256)
    check_hash(args.kptools, KPTOOLS_SHA256)
    if args.patched_boot.exists():
        raise SystemExit(f"refusing to overwrite {args.patched_boot}")
    with args.stock_boot.open("rb") as source:
        magic = source.read(8)
    if magic != b"ANDROID!":
        raise SystemExit("stock image is not an Android boot image")

    key = args.superkey_file.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[A-Za-z0-9]{8,63}", key):
        raise SystemExit("SuperKey must be 8-63 ASCII letters and digits")

    stock_info = inspect(args.kptools, args.stock_kernel)
    if KERNEL_VERSION not in stock_info or "patched=false" not in stock_info:
        raise SystemExit("stock boot inspection does not match the running kernel")

    patch = subprocess.run(
        [str(args.kptools), "-p", "-i", str(args.stock_boot),
         "-s", key, "-k", str(args.kpimg), "-o", str(args.patched_boot)],
        capture_output=True,
        text=True,
    )
    if patch.returncode != 0:
        details = (patch.stdout + patch.stderr).replace(key, "<redacted>")
        raise SystemExit(f"kptools patch failed ({patch.returncode}):\n{details}")
    verify_dir = args.patched_boot.parent / (args.patched_boot.stem + "-verify")
    verify_dir.mkdir(exist_ok=False)
    subprocess.run([str(args.kptools), "unpack", str(args.patched_boot)],
                   cwd=verify_dir, check=True, capture_output=True, text=True)
    patched_info = inspect(args.kptools, verify_dir / "kernel")
    if "patched=true" not in patched_info or "version=0xd09" not in patched_info:
        raise SystemExit("patched boot inspection failed")
    with args.patched_boot.open("rb") as source:
        magic = source.read(8)
    if magic != b"ANDROID!":
        raise SystemExit("patched image is not an Android boot image")
    if args.patched_boot.stat().st_size > 64 * 1024 * 1024:
        raise SystemExit("patched image exceeds the boot partition size")

    print(f"stock sha256={STOCK_SHA256}")
    print(f"patched sha256={sha256_file(args.patched_boot)}")
    print(f"patched size={args.patched_boot.stat().st_size}")
    print("patched=true kpimg_version=0xd09")


if __name__ == "__main__":
    main()
