#!/usr/bin/env python3
"""Require the C plugin to reject hidden primary-ELF execution in an external call."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from .normalize import parse_trace
from .provision import (
    ScopePolicy,
    apply_runtime_dependencies,
    load_x86_64_elf,
    provision_program,
    render_artifacts,
)
from .runtime_dependencies import qemu_environment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--sysroot", type=Path, required=True)
    parser.add_argument("--plugin", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--preload", type=Path, required=True)
    parser.add_argument("--runtime-dependencies", type=Path, required=True)
    parser.add_argument("--runtime-profile", required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()

    args.work.mkdir(parents=True, exist_ok=True)
    artifacts = args.work / "registry"
    program = apply_runtime_dependencies(
        load_x86_64_elf(args.binary), args.runtime_dependencies, args.runtime_profile
    )
    provisioned = provision_program(
        program,
        ScopePolicy(
            root_symbol="main",
            caller_symbol="external-loader",
            external_entry=True,
            max_out_degree=8,
        ),
    )
    render_artifacts(
        program, provisioned, artifacts, application="external-reentry-negative"
    )
    trace = args.work / "trace.log"
    result = subprocess.run(
        [
            str(args.qemu),
            "-L",
            str(args.sysroot),
            "-E",
            f"LD_PRELOAD={args.preload.resolve()}",
            "-plugin",
            f"{args.plugin},map={artifacts / 'plugin-map.txt'},log={trace}",
            str(args.binary),
        ],
        check=False,
        env=qemu_environment(),
    )
    text = trace.read_text()
    if (
        "boundary_error external_reentry_expected=" not in text
        or "complete=0 runtime_code_match=1" not in text
    ):
        raise RuntimeError(
            "C plugin did not reject the DSO's out-of-closure primary-ELF re-entry"
        )
    try:
        parse_trace(trace)
    except ValueError:
        pass
    else:
        raise RuntimeError("normalizer accepted the hidden primary-ELF re-entry")

    report = {
        "schema": "zkcfa.qemu.external-reentry-test",
        "pass": True,
        "guest_exit_code": result.returncode,
        "failure": "preloaded libc interposer re-entered the primary ELF before exact return",
        "preload_sha256": hashlib.sha256(args.preload.read_bytes()).hexdigest(),
        "trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
    }
    output = args.work / "qemu-external-reentry-negative.json"
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    trace.chmod(0o600)
    output.chmod(0o600)
    print("actual QEMU primary-ELF re-entry rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
