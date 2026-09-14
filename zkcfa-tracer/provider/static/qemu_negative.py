#!/usr/bin/env python3
"""Exercise the C plugin's byte and return-boundary fail-closed paths."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from .normalize import parse_trace
from .runtime_dependencies import qemu_environment


def tamper_root_encoding(source: Path, output: Path) -> int:
    lines = source.read_text().splitlines()
    root_lines = [line for line in lines if line.startswith("root_entry ")]
    if len(root_lines) != 1:
        raise ValueError("plugin map must contain exactly one root_entry")
    root = int(root_lines[0].split()[1], 0)
    changed = False
    rendered: list[str] = []
    for line in lines:
        fields = line.split()
        if fields[:1] == ["insn"] and int(fields[1], 0) == root:
            if changed or len(fields) != 7:
                raise ValueError("plugin map has a malformed or duplicate root instruction")
            encoding = bytearray.fromhex(fields[6])
            encoding[0] ^= 1
            fields[6] = encoding.hex()
            line = " ".join(fields)
            changed = True
        rendered.append(line)
    if not changed:
        raise ValueError("plugin map does not contain the root instruction")
    output.write_text("\n".join(rendered) + "\n")
    return root


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--sysroot", type=Path)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    tampered_map = args.work / "plugin-map-tampered.txt"
    trace = args.work / "trace-tampered.log"
    root = tamper_root_encoding(args.map, tampered_map)
    command = [str(args.qemu)]
    if args.sysroot is not None:
        command.extend(["-L", str(args.sysroot)])
    command.extend(
        [
            "-plugin",
            f"{args.plugin},map={tampered_map},log={trace}",
            str(args.binary),
        ]
    )
    result = subprocess.run(
        command,
        check=False,
        env=qemu_environment(),
    )
    text = trace.read_text()
    if (
        not (
            f"boundary_error expected_root=0x{root:x}" in text
            or f"boundary_error runtime_root_mismatch pc=0x{root:x}" in text
        )
        or "complete=0 runtime_code_match=0" not in text
    ):
        raise RuntimeError("C plugin did not fail closed on the tampered root encoding")
    try:
        parse_trace(trace)
    except ValueError:
        trace.chmod(0o600)
        tampered_map.chmod(0o600)
        return_mismatch_checked = False
        if "boundary_mode external_entry" in args.map.read_text().splitlines():
            return_trace = args.work / "trace-return-mismatch.log"
            return_command = [str(args.qemu)]
            if args.sysroot is not None:
                return_command.extend(["-L", str(args.sysroot)])
            return_command.extend(
                [
                    "-plugin",
                    (
                        f"{args.plugin},map={args.map},log={return_trace},"
                        "test-force-return-mismatch=1"
                    ),
                    str(args.binary),
                ]
            )
            return_result = subprocess.run(
                return_command, check=False, env=qemu_environment()
            )
            return_text = return_trace.read_text()
            if (
                "boundary_error expected=" not in return_text
                or "complete=0 runtime_code_match=1" not in return_text
            ):
                raise RuntimeError("C plugin did not reject the wrong return continuation")
            try:
                parse_trace(return_trace)
            except ValueError:
                return_trace.chmod(0o600)
                return_mismatch_checked = True
            else:
                raise RuntimeError("normalizer accepted the wrong return continuation")

        result_path = args.work / "qemu-negative.json"
        result_path.write_text(
            json.dumps(
                {
                    "schema": "zkcfa.qemu.negative-test",
                    "pass": True,
                    "tampered_root": f"0x{root:x}",
                    "trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
                    "failure": "runtime instruction bytes differ from signed static map",
                    "captured_return_mismatch_rejected": return_mismatch_checked,
                    "guest_exit_code_byte_mismatch_run": result.returncode,
                    "guest_exit_code_return_mismatch_run": (
                        return_result.returncode if return_mismatch_checked else None
                    ),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        result_path.chmod(0o600)
        print("actual QEMU byte and return-continuation mismatches rejected")
        return 0
    raise RuntimeError("normalizer accepted the tampered QEMU trace")


if __name__ == "__main__":
    raise SystemExit(main())
