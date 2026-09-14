"""Opt-in live regression for long x86 REP execution under pinned QEMU.

This is intentionally separate from the synthetic callback-sequence unit test.
Run it in the provider container with::

    ZKCFA_RUN_PINNED_QEMU_REP=1 \
      PYTHONPATH=. python3 -m unittest discover -s tests \
      -p 'test_rep_qemu_integration.py' -v
"""

from __future__ import annotations

import os
import struct
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from static.normalize import main as normalize_main
from static.normalize import parse_plugin_map, parse_trace
from static.provision import main as provision_main


QEMU_REVISION = "667e1fff878326c35c7f5146072e60a63a9a41c8"
RUN_LIVE = os.environ.get("ZKCFA_RUN_PINNED_QEMU_REP") == "1"


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _long_rep_elf(path: Path) -> None:
    """Write a tiny static x86-64 ELF without relying on a guest compiler."""
    text_address = 0x401000
    root_address = text_address + 0x20
    data_address = 0x402000
    repeat_count = 0x20000

    call_displacement = root_address - (text_address + 5)
    start = (
        b"\xe8" + struct.pack("<i", call_displacement)
        + b"\xb8\x3c\x00\x00\x00"  # mov $60, %eax
        + b"\x31\xff"                  # xor %edi, %edi
        + b"\x0f\x05"                  # syscall
    )
    root = (
        b"\xfc"                                      # cld
        + b"\x48\xbe" + struct.pack("<Q", data_address)
        + b"\x48\xbf" + struct.pack("<Q", data_address + repeat_count)
        + b"\xb9" + struct.pack("<I", repeat_count)
        + b"\xf3\xa4"                               # rep movsb
        + b"\xc3"                                     # ret
    )
    text = start + b"\x90" * (root_address - text_address - len(start)) + root
    data = bytes(repeat_count * 2)

    text_offset = 0x1000
    data_offset = 0x2000
    symbol_names = b"\x00_start\x00rep_scope\x00"
    start_name = 1
    root_name = symbol_names.index(b"rep_scope")
    symbols = b"".join((
        bytes(24),
        struct.pack("<IBBHQQ", start_name, 0x12, 0, 1, text_address, len(start)),
        struct.pack("<IBBHQQ", root_name, 0x12, 0, 1, root_address, len(root)),
    ))

    section_names = bytearray(b"\x00")
    section_name_offsets: dict[str, int] = {}
    for name in (".text", ".data", ".symtab", ".strtab", ".shstrtab"):
        section_name_offsets[name] = len(section_names)
        section_names.extend(name.encode("ascii") + b"\x00")

    symtab_offset = _align(data_offset + len(data), 8)
    strtab_offset = symtab_offset + len(symbols)
    shstrtab_offset = strtab_offset + len(symbol_names)
    section_table_offset = _align(shstrtab_offset + len(section_names), 8)
    section_count = 6
    image = bytearray(section_table_offset + section_count * 64)

    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + bytes(8)
    image[:64] = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        2,          # ET_EXEC
        62,         # EM_X86_64
        1,
        text_address,
        64,
        section_table_offset,
        0,
        64,
        56,
        2,
        64,
        section_count,
        5,
    )
    image[64:120] = struct.pack(
        "<IIQQQQQQ",
        1, 5, text_offset, text_address, text_address, len(text), len(text), 0x1000,
    )
    image[120:176] = struct.pack(
        "<IIQQQQQQ",
        1, 6, data_offset, data_address, data_address, len(data), len(data), 0x1000,
    )
    image[text_offset:text_offset + len(text)] = text
    image[data_offset:data_offset + len(data)] = data
    image[symtab_offset:symtab_offset + len(symbols)] = symbols
    image[strtab_offset:strtab_offset + len(symbol_names)] = symbol_names
    image[shstrtab_offset:shstrtab_offset + len(section_names)] = section_names

    section_headers = (
        bytes(64),
        struct.pack(
            "<IIQQQQIIQQ", section_name_offsets[".text"], 1, 0x6,
            text_address, text_offset, len(text), 0, 0, 16, 0,
        ),
        struct.pack(
            "<IIQQQQIIQQ", section_name_offsets[".data"], 1, 0x3,
            data_address, data_offset, len(data), 0, 0, 4096, 0,
        ),
        struct.pack(
            "<IIQQQQIIQQ", section_name_offsets[".symtab"], 2, 0,
            0, symtab_offset, len(symbols), 4, 1, 8, 24,
        ),
        struct.pack(
            "<IIQQQQIIQQ", section_name_offsets[".strtab"], 3, 0,
            0, strtab_offset, len(symbol_names), 0, 0, 1, 0,
        ),
        struct.pack(
            "<IIQQQQIIQQ", section_name_offsets[".shstrtab"], 3, 0,
            0, shstrtab_offset, len(section_names), 0, 0, 1, 0,
        ),
    )
    for index, header in enumerate(section_headers):
        offset = section_table_offset + index * 64
        image[offset:offset + 64] = header
    path.write_bytes(image)
    path.chmod(0o700)


@unittest.skipUnless(
    RUN_LIVE,
    "set ZKCFA_RUN_PINNED_QEMU_REP=1 to run the live pinned-QEMU REP test",
)
class PinnedQemuLongRepIntegrationTests(unittest.TestCase):
    def test_live_qemu_self_reentry_is_accepted_only_for_static_repeat_kind(self) -> None:
        provider = Path(__file__).resolve().parents[1]
        qemu_source = Path(os.environ.get("ZKCFA_QEMU_SOURCE", "/opt/qemu"))
        qemu = Path(
            os.environ.get(
                "ZKCFA_QEMU_X86_64",
                str(qemu_source / "build/qemu-x86_64"),
            )
        )
        revision = subprocess.run(
            ["git", "-C", str(qemu_source), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(revision, QEMU_REVISION)
        self.assertTrue(qemu.is_file(), f"missing pinned QEMU executable: {qemu}")

        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            binary = work / "long-rep-x86_64"
            plugin = work / "trace_scope.so"
            artifacts = work / "artifacts"
            trace_path = work / "trace.log"
            _long_rep_elf(binary)

            glib_flags = subprocess.run(
                ["pkg-config", "--cflags", "--libs", "glib-2.0"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.split()
            subprocess.run(
                [
                    os.environ.get("CC", "gcc"),
                    "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror",
                    f"-I{qemu_source / 'include'}", "-DQEMU_PLUGIN",
                    str(provider / "qemu/trace_scope.c"), "-o", str(plugin),
                    *glib_flags,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            with redirect_stdout(StringIO()):
                provision_main([
                    "--architecture", "x86_64",
                    "--canonical-bias", "0",
                    "--root-symbol", "rep_scope",
                    "--caller-symbol", "_start",
                    "--application", "long-rep",
                    "--elf", str(binary),
                    "--out-dir", str(artifacts),
                ])

            subprocess.run(
                [
                    str(qemu),
                    "-plugin",
                    f"{plugin},map={artifacts / 'plugin-map.txt'},log={trace_path}",
                    str(binary),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            plugin_map = parse_plugin_map(artifacts / "plugin-map.txt")
            trace = parse_trace(trace_path)
            repeat_pcs = {
                pc for pc, instruction in plugin_map.instructions.items()
                if instruction.kind == "repeat"
            }
            self.assertEqual(len(repeat_pcs), 1)
            repeat_pc = next(iter(repeat_pcs))
            same_pc_callbacks = sum(
                left == right == repeat_pc
                for left, right in zip(trace.pcs, trace.pcs[1:])
            )
            self.assertGreaterEqual(
                same_pc_callbacks,
                1,
                "the live trace did not exercise QEMU long-REP self-reentry",
            )

            with redirect_stdout(StringIO()):
                normalize_main([
                    "--map", str(artifacts / "plugin-map.txt"),
                    "--trace", str(trace_path),
                    "--typed-cfg", str(artifacts / "typed_cfg"),
                    "--translator", str(artifacts / "translator"),
                    "--static-manifest", str(artifacts / "static-manifest.json"),
                    "--output", str(artifacts / "recorded_path"),
                    "--evidence", str(artifacts / "evidence.json"),
                ])
            self.assertTrue((artifacts / "recorded_path").is_file())


if __name__ == "__main__":
    unittest.main()
