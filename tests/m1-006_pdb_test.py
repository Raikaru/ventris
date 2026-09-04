#!/usr/bin/env python3
"""Validate real LLVM-produced PE/PDB pairs and reject damaged symbol databases."""
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
from gen_corpus import strip_pe_debug, validate_pe_twin


def stream_positions(data):
    """Locate stream bytes independently for corruption tests."""
    block_size, _, _, directory_size, _, block_map = struct.unpack_from("<6I", data, 32)
    blocks = struct.unpack_from(f"<{(directory_size + block_size - 1) // block_size}I",
                                data, block_map * block_size)
    directory = b"".join(data[b * block_size:(b + 1) * block_size] for b in blocks)[:directory_size]
    count = struct.unpack_from("<I", directory)[0]
    sizes = struct.unpack_from(f"<{count}I", directory, 4)
    cursor = 4 + 4 * count
    streams = []
    for size in sizes:
        if size == 0xffffffff:
            streams.append([])
            continue
        count = (size + block_size - 1) // block_size
        blocks = struct.unpack_from(f"<{count}I", directory, cursor)
        cursor += 4 * count
        streams.append([b * block_size + i for b in blocks for i in range(block_size)][:size])
    return streams


class PdbIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="m1-006-pdb-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        source = cls.directory / "sample.c"
        source.write_text("__declspec(noinline) int add(int a, int b) { return a+b; }\n"
                          "int entry(void) { return add(1, 2); }\n")
        obj = cls.directory / "sample.obj"
        cls.twin = cls.directory / "sample.unstripped.exe"
        cls.primary = cls.directory / "sample.exe"
        cls.pdb = cls.directory / "sample.pdb"
        subprocess.run(["clang", "--target=x86_64-pc-windows-msvc", "-g", "-gcodeview",
                        "-c", str(source), "-o", str(obj)], check=True)
        subprocess.run(["lld-link", "/entry:entry", "/subsystem:console", "/nodefaultlib",
                        "/debug", "/opt:noref", f"/pdb:{cls.pdb}", f"/out:{cls.twin}", str(obj)], check=True)
        shutil.copy2(cls.twin, cls.primary)
        strip_pe_debug(cls.primary)
        cls.original = cls.pdb.read_bytes()
        cls.streams = stream_positions(cls.original)

    def tearDown(self):
        self.pdb.write_bytes(self.original)

    def test_real_linker_symbols_are_available(self):
        count = validate_pe_twin(self.primary, self.twin, self.pdb)
        self.assertGreaterEqual(count, 2)

    def test_invalid_pdb_is_rejected(self):
        def header_only(data):
            return data[:32]

        def truncated(data):
            return data[:-1]

        def invalid_directory_block(data):
            block_size, _, blocks, _, _, block_map = struct.unpack_from("<6I", data, 32)
            struct.pack_into("<I", data, block_map * block_size, blocks)
            return data

        def wrong_guid(data):
            data[self.streams[1][12]] ^= 1
            return data

        def wrong_age(data):
            data[self.streams[1][8]] ^= 1
            return data

        def missing_symbols(data):
            for pos in self.streams[3][20:22]:
                data[pos] = 255
            return data

        def malformed_symbol_record(data):
            index = int.from_bytes(bytes(data[p] for p in self.streams[3][20:22]), "little")
            for pos in self.streams[index][:2]:
                data[pos] = 255
            return data

        for mutate in (header_only, truncated, invalid_directory_block, wrong_guid,
                       wrong_age, missing_symbols, malformed_symbol_record):
            with self.subTest(mutation=mutate.__name__):
                self.pdb.write_bytes(mutate(bytearray(self.original)))
                with self.assertRaises((AssertionError, ValueError)):
                    validate_pe_twin(self.primary, self.twin, self.pdb)


if __name__ == "__main__":
    unittest.main()
