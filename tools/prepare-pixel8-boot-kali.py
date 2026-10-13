#!/usr/bin/env python3
"""Build and verify a temporary Pixel 8 KernelPatch boot image on Kali."""

import argparse
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path


STOCK_SHA256 = "625fa1f84ccf0707fe7859a005797db1495d2f01b58d9dc4708d9a26c2f7dd30"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(command: list[str], key: str, cwd: Path | None = None) -> str:
    result = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False)
    safe_output = result.stdout.replace(key, "<redacted-superkey>")
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {safe_output}")
    return safe_output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--kpimg", type=Path, required=True)
    parser.add_argument("--kptools", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    key = args.key_file.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[A-Za-z0-9]{32,64}", key):
        raise RuntimeError("debug SuperKey format is invalid")
    if sha256(args.stock) != STOCK_SHA256:
        raise RuntimeError("stock boot SHA-256 mismatch")
    if not args.kpimg.is_file() or not args.kptools.is_file():
        raise RuntimeError("KernelPatch image or tools are missing")
    args.out.parent.mkdir(parents=True, exist_ok=True)

    run([str(args.kptools), "-p", "-i", str(args.stock), "-S", key,
         "-k", str(args.kpimg), "-o", str(args.out)], key)
    if not args.out.is_file() or args.out.stat().st_size != args.stock.stat().st_size:
        raise RuntimeError("patched boot size is invalid")

    with tempfile.TemporaryDirectory(prefix="rtgum-pixel8-verify-") as temp:
        temp_path = Path(temp)
        run([str(args.kptools), "unpack", str(args.out)], key, cwd=temp_path)
        kernel = temp_path / "kernel"
        if not kernel.is_file():
            raise RuntimeError("patched kernel was not extracted")
        info = run([str(args.kptools), "-l", "-i", str(kernel)], key)
        if "patched=true" not in info or "version=0xd09" not in info:
            raise RuntimeError("patched image version verification failed")
        expected_root_hash = hashlib.sha256(key.encode("ascii")).hexdigest()
        if f"root_superkey={expected_root_hash}" not in info:
            raise RuntimeError("patched image root SuperKey hash verification failed")
        if "Linux version 6.1.145-android14-11-gfa1d6308d1fe" not in info:
            raise RuntimeError("patched kernel banner mismatch")

    print(f"kpimg_sha256={sha256(args.kpimg)}")
    print(f"boot_sha256={sha256(args.out)}")
    print("verified=shiba-cp1a.260405.005-kp0.13.9 temporary boot")


if __name__ == "__main__":
    main()
