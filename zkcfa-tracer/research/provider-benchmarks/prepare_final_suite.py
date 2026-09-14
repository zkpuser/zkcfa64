#!/usr/bin/env python3
"""Re-provision and normalize the 21 paper inputs with the maintained provider."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path


APPLICATIONS = (
    "aha-mont64", "crc32", "cubic", "edn", "huffbench", "matmult-int",
    "md5sum", "minver", "nbody", "nettle-aes", "nettle-sha256", "nsichneu",
    "picojpeg", "primecount", "sglib-combined", "slre", "st", "statemate",
    "tarfind", "ud", "wikisort",
)
RECOVERY = {"picojpeg", "sglib-combined"}
INDIRECT = {"picojpeg", "sglib-combined", "wikisort"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command: list[str], *, cwd: Path, log: Path) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("xb") as output:
        completed = subprocess.run(
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if completed.returncode != 0:
        detail = log.read_text(encoding="utf-8", errors="replace")[-3000:]
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n{detail}"
        )


def stable_policy(source: Path, destination: Path, application: str, elf_hash: str) -> None:
    archived = json.loads(source.read_text(encoding="utf-8"))
    if (
        not isinstance(archived, dict)
        or archived.get("schema") != "zkcfa.indirect-target-policy.v1"
        or archived.get("application") != application
        or archived.get("elf_sha256") != elf_hash
    ):
        raise ValueError(f"{application}: archived indirect policy identity mismatch")
    policy = {
        "schema": "zkcfa.indirect-target-policy",
        "application": application,
        "elf_sha256": elf_hash,
        "indirect_calls": archived.get("indirect_calls"),
        "indirect_jumps": archived.get("indirect_jumps"),
    }
    destination.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", type=Path, required=True)
    parser.add_argument("--baseline-inputs", type=Path, required=True)
    parser.add_argument("--recovery-inputs", type=Path, required=True)
    parser.add_argument("--image-vendor", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    provider = args.provider.resolve()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("suite output must be absent or empty")
    output.mkdir(parents=True, mode=0o700, exist_ok=True)

    sys.path.insert(0, str(provider))
    from static.runtime_dependencies import FILES  # noqa: PLC0415

    runtime_manifests: dict[str, Path] = {}
    for profile in ("ubuntu20", "ubuntu22"):
        source_root = args.runtime_root / profile
        destination_root = output / "runtime" / profile
        for relative in FILES:
            destination = destination_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_root / relative, destination)
        manifest = destination_root / "runtime-dependencies.json"
        run(
            [
                sys.executable, "-m", "static.runtime_dependencies", "--profile", profile,
                "--sysroot", str(destination_root), "--output", str(manifest),
            ],
            cwd=provider,
            log=output / "logs" / f"runtime-{profile}.log",
        )
        runtime_manifests[profile] = manifest

    outcomes: list[dict[str, object]] = []
    for application in APPLICATIONS:
        source = (
            args.recovery_inputs / application
            if application in RECOVERY
            else args.baseline_inputs / application
        )
        source_artifacts = source / "artifacts"
        app = output / "inputs" / application
        artifacts = app / "artifacts"
        logs = app / "logs"
        artifacts.mkdir(parents=True)
        binary = app / application
        trace = app / "trace.log"
        shutil.copyfile(source / application, binary)
        shutil.copyfile(source / "trace.log", trace)
        binary.chmod(0o500)
        trace.chmod(0o600)
        elf_hash = sha256(binary)
        profile = "ubuntu22" if application == "crc32" else "ubuntu20"
        command = [
            sys.executable, "-m", "static.provision", "--architecture", "x86_64",
            "--canonical-bias", "0x400000", "--external-entry", "--root-symbol", "main",
            "--caller-symbol", "external-loader", "--application", application,
            "--elf", str(binary), "--out-dir", str(artifacts), "--max-out-degree", "64",
            "--runtime-dependencies", str(runtime_manifests[profile]),
            "--runtime-profile", profile,
        ]
        if application in INDIRECT:
            policy = app / "indirect-policy.json"
            stable_policy(
                args.image_vendor / "policies" / f"{application}.json",
                policy,
                application,
                elf_hash,
            )
            command.extend(("--indirect-policy", str(policy)))
        run(command, cwd=provider, log=logs / "provision.log")
        run(
            [
                sys.executable, "-m", "static.normalize", "--map",
                str(artifacts / "plugin-map.txt"), "--trace", str(trace), "--typed-cfg",
                str(artifacts / "typed_cfg"), "--translator", str(artifacts / "translator"),
                "--static-manifest", str(artifacts / "static-manifest.json"), "--output",
                str(artifacts / "recorded_path"), "--evidence", str(artifacts / "evidence.json"),
            ],
            cwd=provider,
            log=logs / "normalize.log",
        )
        if (artifacts / "recorded_path").read_bytes() != (
            source_artifacts / "recorded_path"
        ).read_bytes():
            raise ValueError(f"{application}: maintained normalization changed the path")
        evidence = json.loads((artifacts / "evidence.json").read_text())
        boundary = evidence.get("boundary") if isinstance(evidence, dict) else None
        if not isinstance(boundary, dict) or boundary.get("complete") is not True:
            raise ValueError(f"{application}: final evidence is incomplete")
        rows = len((artifacts / "recorded_path").read_text().splitlines())
        outcomes.append(
            {
                "application": application,
                "binary_sha256": elf_hash,
                "trace_sha256": sha256(trace),
                "translator_sha256": sha256(artifacts / "translator"),
                "typed_cfg_sha256": sha256(artifacts / "typed_cfg"),
                "recorded_path_sha256": sha256(artifacts / "recorded_path"),
                "evidence_sha256": sha256(artifacts / "evidence.json"),
                "static_manifest_sha256": sha256(artifacts / "static-manifest.json"),
                "rows": rows,
                "runtime_profile": profile,
            }
        )
    result = {
        "schema": "zkcfa.research.final-inputs",
        "applications": outcomes,
        "runtime_dependencies_sha256": {
            profile: sha256(path) for profile, path in runtime_manifests.items()
        },
    }
    (output / "inputs.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    print(json.dumps({"applications": len(outcomes), "schema": result["schema"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
