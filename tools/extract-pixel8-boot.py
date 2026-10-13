#!/usr/bin/env python3
"""Extract the matching Pixel 8 boot image without copying the nested ZIP."""

from __future__ import annotations

import argparse
import hashlib
import io
import shutil
import struct
import zipfile
from pathlib import Path


BUILD = "cp1a.260405.005"
FACTORY_SHA256 = "f88d5199ff51e3ac4e502a08d0a6f82a32b4ba68009982c3a6e4d5b69ce1f950"
INNER_NAME = f"shiba-{BUILD}/image-shiba-{BUILD}.zip"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class FileSlice(io.RawIOBase):
    def __init__(self, stream: io.BufferedReader, start: int, size: int):
        self.stream = stream
        self.start = start
        self.size = size
        self.position = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.position

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_CUR:
            offset += self.position
        elif whence == io.SEEK_END:
            offset += self.size
        elif whence != io.SEEK_SET:
            raise ValueError("invalid seek mode")
        if offset < 0 or offset > self.size:
            raise ValueError("seek outside nested ZIP")
        self.position = offset
        return offset

    def read(self, size: int = -1) -> bytes:
        remaining = self.size - self.position
        if size < 0 or size > remaining:
            size = remaining
        self.stream.seek(self.start + self.position)
        data = self.stream.read(size)
        self.position += len(data)
        return data


def stored_data_offset(stream: io.BufferedReader, member: zipfile.ZipInfo) -> int:
    if member.compress_type != zipfile.ZIP_STORED:
        raise ValueError("nested image ZIP is compressed; direct extraction is unavailable")
    stream.seek(member.header_offset)
    header = stream.read(30)
    if len(header) != 30 or header[:4] != b"PK\x03\x04":
        raise ValueError("invalid nested ZIP local header")
    name_length, extra_length = struct.unpack_from("<HH", header, 26)
    return member.header_offset + 30 + name_length + extra_length


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("factory_zip", type=Path)
    parser.add_argument("boot_img", type=Path)
    args = parser.parse_args()

    actual = sha256_file(args.factory_zip)
    if actual != FACTORY_SHA256:
        raise SystemExit(f"factory SHA-256 mismatch: {actual}")

    with zipfile.ZipFile(args.factory_zip) as factory:
        member = factory.getinfo(INNER_NAME)
        with args.factory_zip.open("rb") as source:
            start = stored_data_offset(source, member)
            nested_slice = FileSlice(source, start, member.file_size)
            with zipfile.ZipFile(nested_slice) as images:
                boot = images.getinfo("boot.img")
                if boot.file_size <= 0 or boot.file_size > 64 * 1024 * 1024:
                    raise ValueError(f"unexpected boot.img size: {boot.file_size}")
                with images.open(boot) as contents, args.boot_img.open("xb") as output:
                    shutil.copyfileobj(contents, output, length=4 * 1024 * 1024)

    print(f"boot.img size={args.boot_img.stat().st_size}")
    print(f"boot.img sha256={sha256_file(args.boot_img)}")
    print(f"boot.img path={args.boot_img}")


if __name__ == "__main__":
    main()
