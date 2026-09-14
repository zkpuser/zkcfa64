#!/usr/bin/env python3
"""Measure the pinned amd64 loader/DSOs used by opaque external-call gates."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


FILES = (
    "lib64/ld-linux-x86-64.so.2",
    "lib/x86_64-linux-gnu/libc.so.6",
    "lib/x86_64-linux-gnu/libm.so.6",
)


def qemu_environment() -> dict[str, str]:
    """Return the complete, deliberately minimal host/guest QEMU environment.

    QEMU linux-user forwards its own environment to the guest.  Constructing
    this mapping from scratch prevents inherited loader controls such as
    ``LD_PRELOAD``, ``LD_LIBRARY_PATH``, ``LD_AUDIT``, ``GLIBC_TUNABLES``, and
    ``QEMU_LD_PREFIX`` from changing the measured runtime policy.
    """
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "LD_BIND_NOW": "1",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sysroot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", args.profile) is None:
        raise ValueError("runtime profile must be a lowercase stable identifier")
    measured: list[dict[str, str]] = []
    for relative in FILES:
        path = args.sysroot / relative
        if not path.is_file():
            raise ValueError(f"runtime dependency is absent: {relative}")
        measured.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    payload = {
        "schema": "zkcfa.runtime-dependencies",
        "runtime_profile": args.profile,
        "binding": "eager",
        "environment": {"LD_BIND_NOW": "1"},
        "files": measured,
        "loader_scope": "trusted-out-of-scope",
    }
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
