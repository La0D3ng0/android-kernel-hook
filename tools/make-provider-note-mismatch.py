#!/usr/bin/env python3
"""Flip one GNU build ID byte in a device library for a loader identity test."""

import argparse
from pathlib import Path
import struct


def align4(value: int) -> int:
    return (value + 3) & ~3


def make_fixture(source: Path, destination: Path) -> None:
    if source.resolve() == destination.resolve():
        raise ValueError("source and destination must differ")
    data = bytearray(source.read_bytes())
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("expected little-endian AArch64 ELF64")
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    program_entry_size, program_count = struct.unpack_from("<HH", data, 54)
    if program_entry_size != 56 or not 0 < program_count <= 64:
        raise ValueError("unsupported program header table")

    changed = 0
    for index in range(program_count):
        header = program_offset + index * program_entry_size
        if struct.unpack_from("<I", data, header)[0] != 4:  # PT_NOTE
            continue
        note_offset = struct.unpack_from("<Q", data, header + 8)[0]
        note_size = struct.unpack_from("<Q", data, header + 32)[0]
        note_end = note_offset + note_size
        if note_end > len(data):
            raise ValueError("PT_NOTE exceeds the file")
        cursor = note_offset
        while cursor + 12 <= note_end:
            name_size, desc_size, kind = struct.unpack_from("<III", data, cursor)
            name_offset = cursor + 12
            desc_offset = name_offset + align4(name_size)
            next_note = desc_offset + align4(desc_size)
            if next_note > note_end:
                raise ValueError("malformed PT_NOTE entry")
            if data[name_offset:name_offset + name_size] == b"GNU\0" and kind == 3:
                if desc_size == 0:
                    raise ValueError("empty GNU build ID")
                data[desc_offset] ^= 1
                changed += 1
            cursor = next_note
    if changed != 1:
        raise ValueError(f"expected exactly one GNU build ID, got {changed}")
    destination.write_bytes(data)
    print(f"provider-note-mismatch fixture: {destination}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    make_fixture(arguments.source, arguments.destination)
