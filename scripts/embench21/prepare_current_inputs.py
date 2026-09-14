#!/usr/bin/env python3
"""Acquire fresh complete QEMU inputs for the 21-application paper suite.

The script runs inside the maintained provider image. The caller supplies a
campaign directory containing hash-gated x86-64 binaries, the materialized
recovery-aware vendor manifest, and Ubuntu 20/22 runtime sysroots.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from static.runtime_dependencies import qemu_environment


APPLICATIONS = (
    "aha-mont64",
    "crc32",
    "cubic",
    "edn",
    "huffbench",
    "matmult-int",
    "md5sum",
    "minver",
    "nbody",
    "nettle-aes",
    "nettle-sha256",
    "nsichneu",
    "picojpeg",
    "primecount",
    "sglib-combined",
    "slre",
    "st",
    "statemate",
    "tarfind",
    "ud",
    "wikisort",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(
    command: list[str],
    *,
    cwd: Path,
    log: Path,
    env: dict[str, str] | None = None,
) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("xb") as output:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if completed.returncode != 0:
        detail = log.read_text(encoding="utf-8", errors="replace")[-4000:]
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n{detail}"
        )


def load_manifest(path: Path) -> dict[str, dict[str, object]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    rows = document.get("applications") if isinstance(document, dict) else None
    if (
        not isinstance(rows, list)
        or tuple(row.get("name") for row in rows if isinstance(row, dict))
        != APPLICATIONS
    ):
        raise ValueError("vendor manifest is not the ordered 21-application suite")
    return {str(row["name"]): row for row in rows}


def build_plugin(provider: Path, output: Path, qemu_source: Path) -> None:
    flags = subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "glib-2.0"], text=True
    ).split()
    run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            f"-I{qemu_source / 'include'}",
            "-DQEMU_PLUGIN",
            str(provider / "qemu/trace_scope.c"),
            "-o",
            str(output),
            *flags,
        ],
        cwd=provider,
        log=output.with_suffix(".build.log"),
    )


def materialize_current_policy(
    source: Path, destination: Path, application: str, elf_sha256: str
) -> None:
    archived = json.loads(source.read_text(encoding="utf-8"))
    if (
        not isinstance(archived, dict)
        or archived.get("schema")
        not in {"zkcfa.indirect-target-policy.v1", "zkcfa.indirect-target-policy"}
        or archived.get("application") != application
        or archived.get("elf_sha256") != elf_sha256
        or not isinstance(archived.get("indirect_calls"), dict)
        or not isinstance(archived.get("indirect_jumps"), dict)
    ):
        raise ValueError(f"{application}: indirect policy identity mismatch")
    current = {
        "schema": "zkcfa.indirect-target-policy",
        "application": application,
        "elf_sha256": elf_sha256,
        "indirect_calls": archived["indirect_calls"],
        "indirect_jumps": archived["indirect_jumps"],
    }
    destination.write_text(
        json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--provider", type=Path, default=Path("/provider"))
    parser.add_argument("--qemu-source", type=Path, default=Path("/opt/qemu"))
    args = parser.parse_args()

    campaign = args.campaign.resolve()
    provider = args.provider.resolve()
    qemu_source = args.qemu_source.resolve()
    qemu = qemu_source / "build/qemu-x86_64"
    inputs = campaign / "inputs"
    if inputs.exists() or inputs.is_symlink():
        raise FileExistsError("campaign inputs must not already exist")
    inputs.mkdir(parents=True, mode=0o700)

    manifest_path = campaign / "vendor/manifest.json"
    manifest = load_manifest(manifest_path)
    runtime_manifests: dict[str, Path] = {}
    for profile in ("ubuntu20", "ubuntu22"):
        sysroot = campaign / "sysroots" / profile
        output = sysroot / "runtime-dependencies.json"
        run(
            [
                sys.executable,
                "-m",
                "static.runtime_dependencies",
                "--sysroot",
                str(sysroot),
                "--output",
                str(output),
                "--profile",
                profile,
            ],
            cwd=provider,
            log=campaign / "logs" / f"runtime-{profile}.log",
        )
        runtime_manifests[profile] = output

    plugin = campaign / "trace_scope.so"
    build_plugin(provider, plugin, qemu_source)

    outcomes: list[dict[str, object]] = []
    for index, application in enumerate(APPLICATIONS, 1):
        row = manifest[application]
        profile = str(row["runtime_profile"])
        app = inputs / application
        artifacts = app / "artifacts"
        logs = app / "logs"
        artifacts.mkdir(parents=True, mode=0o700)
        source_binary = campaign / "bin" / application
        binary = app / application
        shutil.copyfile(source_binary, binary)
        binary.chmod(0o500)
        actual_elf = sha256(binary)
        if actual_elf != row.get("elf_sha256"):
            raise ValueError(f"{application}: built ELF differs from manifest")

        provision = [
            sys.executable,
            "-m",
            "static.provision",
            "--architecture",
            "x86_64",
            "--canonical-bias",
            "0x400000",
            "--external-entry",
            "--root-symbol",
            "main",
            "--caller-symbol",
            "external-loader",
            "--application",
            application,
            "--elf",
            str(binary),
            "--out-dir",
            str(artifacts),
            "--max-out-degree",
            "64",
            "--runtime-dependencies",
            str(runtime_manifests[profile]),
            "--runtime-profile",
            profile,
        ]
        policy = row.get("indirect_policy")
        if policy is not None:
            current_policy = app / "indirect-policy.json"
            materialize_current_policy(
                campaign / "vendor" / str(policy),
                current_policy,
                application,
                actual_elf,
            )
            provision.extend(("--indirect-policy", str(current_policy)))
        run(provision, cwd=provider, log=logs / "provision.log")

        trace = app / "trace.log"
        run(
            [
                str(qemu),
                "-L",
                str(campaign / "sysroots" / profile),
                "-plugin",
                f"{plugin},map={artifacts / 'plugin-map.txt'},log={trace}",
                str(binary),
            ],
            cwd=provider,
            log=logs / "qemu.log",
            env=qemu_environment(),
        )
        trace.chmod(0o600)
        evidence = artifacts / "evidence.json"
        run(
            [
                sys.executable,
                "-m",
                "static.normalize",
                "--map",
                str(artifacts / "plugin-map.txt"),
                "--trace",
                str(trace),
                "--typed-cfg",
                str(artifacts / "typed_cfg"),
                "--translator",
                str(artifacts / "translator"),
                "--static-manifest",
                str(artifacts / "static-manifest.json"),
                "--output",
                str(artifacts / "recorded_path"),
                "--evidence",
                str(evidence),
            ],
            cwd=provider,
            log=logs / "normalize.log",
        )
        evidence_doc = json.loads(evidence.read_text(encoding="utf-8"))
        boundary = evidence_doc.get("boundary")
        if not isinstance(boundary, dict) or boundary.get("complete") is not True:
            raise ValueError(f"{application}: trace boundary is incomplete")
        rows = len((artifacts / "recorded_path").read_text(encoding="utf-8").splitlines())
        outcome = {
            "application": application,
            "elf_sha256": actual_elf,
            "trace_sha256": sha256(trace),
            "translator_sha256": sha256(artifacts / "translator"),
            "typed_cfg_sha256": sha256(artifacts / "typed_cfg"),
            "recorded_path_sha256": sha256(artifacts / "recorded_path"),
            "evidence_sha256": sha256(evidence),
            "rows": rows,
            "runtime_profile": profile,
        }
        outcomes.append(outcome)
        print(
            json.dumps(
                {"application": application, "index": index, "rows": rows},
                sort_keys=True,
            ),
            flush=True,
        )

    summary = {
        "schema": "zkcfa.embench21-current-inputs.v1",
        "applications": outcomes,
        "provider_source_sha256": sha256(provider / "static/provision.py"),
        "qemu_revision": subprocess.check_output(
            ["git", "-C", str(qemu_source), "rev-parse", "HEAD"], text=True
        ).strip(),
        "trace_plugin_sha256": sha256(plugin),
        "runtime_dependencies_sha256": {
            profile: sha256(path) for profile, path in runtime_manifests.items()
        },
    }
    (campaign / "inputs.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    print(json.dumps({"applications": len(outcomes), "schema": summary["schema"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
