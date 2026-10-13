#!/usr/bin/env python3
"""Make a controlled ELF version-mismatch fixture from the Pixel 8 payload.

Only the DT_VERNEED name and its ELF hash change. The imported symbol,
provider name, relocation table, and executable code remain identical.
"""

import argparse
from pathlib import Path
import struct


def elf_hash(name: bytes) -> int:
    value = 0
    for byte in name:
        value = (value << 4) + byte
        high = value & 0xF0000000
        if high:
            value ^= high >> 24
        value &= ~high
    return value


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
    loads = []
    dynamic = None
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        kind = struct.unpack_from("<I", data, offset)[0]
        file_offset, virtual_address = struct.unpack_from("<QQ", data, offset + 8)
        file_size = struct.unpack_from("<Q", data, offset + 32)[0]
        if kind == 1:
            loads.append((virtual_address, file_offset, file_size))
        elif kind == 2:
            dynamic = (file_offset, file_size)
    if dynamic is None:
        raise ValueError("PT_DYNAMIC is missing")

    def file_position(address: int, size: int) -> int:
        for virtual_address, file_offset, file_size in loads:
            if virtual_address <= address and size <= file_size - (address - virtual_address):
                result = file_offset + address - virtual_address
                if result + size <= len(data):
                    return result
        raise ValueError("ELF virtual address is outside file-backed PT_LOAD")

    tags = {}
    for offset in range(dynamic[0], dynamic[0] + dynamic[1], 16):
        tag, value = struct.unpack_from("<QQ", data, offset)
        if tag == 0:
            break
        tags[tag] = value
    string_table = tags[5]
    string_size = tags[10]
    verneed = tags[0x6FFFFFFE]
    verneed_count = tags[0x6FFFFFFF]
    if not 0 < verneed_count <= 64:
        raise ValueError("unsupported DT_VERNEEDNUM")
    string_file_offset = file_position(string_table, string_size)

    def string_at(offset: int) -> bytes:
        if offset >= string_size:
            raise ValueError("string offset exceeds DT_STRSZ")
        start = string_file_offset + offset
        end = data.find(b"\0", start, string_file_offset + string_size)
        if end < 0:
            raise ValueError("unterminated dynamic string")
        return bytes(data[start:end])

    record_address = verneed
    changed = 0
    for record in range(verneed_count):
        need = file_position(record_address, 16)
        version, aux_count, provider_offset, aux_delta, next_delta = struct.unpack_from(
            "<HHIII", data, need
        )
        if version != 1 or not 0 < aux_count <= 64 or aux_delta < 16:
            raise ValueError("malformed Elf64_Verneed")
        provider = string_at(provider_offset)
        aux_address = record_address + aux_delta
        for aux in range(aux_count):
            entry = file_position(aux_address, 16)
            old_hash, _, version_index, name_offset, next_aux = struct.unpack_from(
                "<IHHII", data, entry
            )
            name = string_at(name_offset)
            if provider == b"libc.so" and name == b"LIBC" and (version_index & 0x7FFF) > 1:
                if old_hash != elf_hash(name):
                    raise ValueError("unexpected original version hash")
                replacement = b"LIFC"
                position = file_position(string_table + name_offset, len(name) + 1)
                data[position:position + len(name)] = replacement
                struct.pack_into("<I", data, entry, elf_hash(replacement))
                changed += 1
            if aux + 1 < aux_count:
                if next_aux < 16:
                    raise ValueError("malformed Elf64_Vernaux chain")
                aux_address += next_aux
        if record + 1 < verneed_count:
            if next_delta < 16:
                raise ValueError("malformed Elf64_Verneed chain")
            record_address += next_delta
    if changed != 1:
        raise ValueError(f"expected exactly one libc.so/LIBC requirement, got {changed}")
    destination.write_bytes(data)
    print(f"version-mismatch fixture: {destination}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    make_fixture(arguments.source, arguments.destination)
