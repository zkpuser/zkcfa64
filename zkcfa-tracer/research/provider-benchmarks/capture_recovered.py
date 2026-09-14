#!/usr/bin/env python3
"""Recapture complete QEMU paths for the two audited Embench recovery variants."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from research.atomic_publish import copy_regular_once, rename_noreplace


APPLICATIONS = {
    "picojpeg": "14d9fb046c074bd4a3fd22ce4daa117e76fb4b97a856c4e81edcf84ab42810b7",
    "sglib-combined": "64984e2551069ef2e849e05c83419bdc075b0af93b25d35ad5d2db571674bdeb",
}
QEMU_REVISION = "667e1fff878326c35c7f5146072e60a63a9a41c8"
ARCHIVED_POLICY_SCHEMA = "zkcfa.indirect-target-policy.v1"
POLICY_SCHEMA = "zkcfa.indirect-target-policy"
HANDOFF_SCHEMA = "zkcfa.research.same-elf-zekra-handoff.v1"
HANDOFF_FILES = {
    "main": "{application}",
    "recovery-provenance.json": "recovery-provenance.json",
    "ours/indirect-policy.json": "indirect-policy.json",
    "ours/plugin-map.txt": "artifacts/plugin-map.txt",
    "ours/recorded_path": "artifacts/recorded_path",
    "ours/static-manifest.json": "artifacts/static-manifest.json",
    "ours/trace-evidence.json": "artifacts/evidence.json",
    "ours/trace.log": "trace.log",
    "ours/translator": "artifacts/translator",
    "ours/typed_cfg": "artifacts/typed_cfg",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def read_regular_json(path: Path, label: str) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular, non-symlink file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not readable UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def complete_boundary(evidence: dict[str, object]) -> dict[str, object]:
    boundary = evidence.get("boundary")
    if (
        evidence.get("runtime_code_match") is not True
        or not isinstance(boundary, dict)
        or boundary.get("complete") is not True
        or boundary.get("external_root_entry_observed") is not True
        or boundary.get("root_entry_observed") is not True
        or boundary.get("root_return_observed") is not True
        or boundary.get("captured_return_continuation_matched") is not True
        or boundary.get("scope_exit_observed") is not True
    ):
        raise ValueError("trace evidence has no complete measured main boundary")
    return boundary


def recorded_path_rows(path: Path) -> int:
    try:
        rows = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise ValueError("recorded_path is not readable ASCII") from error
    if (
        not rows
        or rows[0].split()
        != ["initial_node=SCOPE_RETURN", "final_node=SCOPE_RETURN"]
    ):
        raise ValueError("recorded_path has no complete scope endpoint header")
    return len(rows)


def handoff_sources(capture_root: Path, application: str) -> dict[str, Path]:
    app_root = capture_root / application
    return {
        target: app_root / source.format(application=application)
        for target, source in HANDOFF_FILES.items()
    }


def copy_regular(source: Path, destination: Path, *, executable: bool = False) -> None:
    copy_regular_once(
        source, destination, mode=0o555 if executable else 0o444
    )


def render_sha256sums(files: dict[str, dict[str, object]]) -> str:
    return "".join(f"{files[name]['sha256']}  {name}\n" for name in sorted(files))


def validate_dynamic_bindings(
    bundle: Path,
    expected_elf: str,
    evidence: dict[str, object],
    files: dict[str, object],
) -> None:
    plugin_map = bundle / "ours/plugin-map.txt"
    trace = bundle / "ours/trace.log"
    try:
        map_lines = plugin_map.read_text(encoding="ascii").splitlines()
        trace_lines = trace.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise ValueError("plugin map or QEMU trace is not readable ASCII") from error
    map_elf_rows = [
        line for line in map_lines if line.startswith("elf_sha256 ")
    ]
    map_trace_rows = [
        line for line in map_lines if line.startswith("trace_schema ")
    ]
    trace_header = re.fullmatch(
        r"zkcfa\.scope\.trace elf_sha256=([0-9a-f]{64})"
        r"(?: runtime_bias=0x[0-9a-f]+)?",
        trace_lines[0] if trace_lines else "",
    )
    trace_end = re.fullmatch(
        r"end count=(\d+) complete=1 runtime_code_match=1",
        trace_lines[-1] if trace_lines else "",
    )
    event_count = evidence.get("event_count")
    external_count = evidence.get("external_call_count")
    if (
        evidence.get("schema") != "zkcfa.raw.evidence"
        or evidence.get("recorded_path_sha256")
        != files["ours/recorded_path"]["sha256"]
        or evidence.get("typed_cfg_sha256")
        != files["ours/typed_cfg"]["sha256"]
        or type(event_count) is not int
        or event_count < 1
        or type(external_count) is not int
        or external_count < 0
        or map_lines[:1] != ["zkcfa.provider.map"]
        or map_elf_rows != [f"elf_sha256 {expected_elf}"]
        or map_trace_rows != ["trace_schema zkcfa.scope.trace"]
        or trace_header is None
        or trace_header.group(1) != expected_elf
        or trace_end is None
        or int(trace_end.group(1)) != event_count
        or sum(line.startswith("insn ") for line in trace_lines) != event_count
        or sum(line.startswith("external_call ") for line in trace_lines)
        != external_count
        or not any(
            line.startswith("scope_exit ")
            and line.endswith(" return_continuation_matched=1")
            for line in trace_lines
        )
    ):
        raise ValueError("QEMU trace, plugin map, path, and evidence bindings differ")


def verify_handoff(bundle: Path) -> dict[str, object]:
    manifest = read_regular_json(bundle / "manifest.json", "handoff manifest")
    files = manifest.get("files")
    boundary = manifest.get("boundary")
    zekra_input = manifest.get("zekra_input")
    ours_path = manifest.get("ours_recorded_path")
    capture_identity = manifest.get("capture_identity")
    application = manifest.get("application")
    expected_elf = manifest.get("elf_sha256")
    if (
        manifest.get("schema") != HANDOFF_SCHEMA
        or application not in APPLICATIONS
        or expected_elf != APPLICATIONS.get(application)
        or not isinstance(files, dict)
        or set(files) != set(HANDOFF_FILES)
        or not isinstance(boundary, dict)
        or boundary.get("complete") is not True
        or manifest.get("guest_exit_status") != 0
        or not isinstance(zekra_input, dict)
        or zekra_input.get("path") != "main"
        or zekra_input.get("recompile") is not False
        or zekra_input.get("sha256") != expected_elf
        or not isinstance(ours_path, dict)
        or ours_path.get("path") != "ours/recorded_path"
        or not isinstance(capture_identity, dict)
        or not is_hex(capture_identity.get("plugin_sha256"), 64)
        or not is_hex(capture_identity.get("qemu_revision"), 40)
        or not is_hex(capture_identity.get("recovery_provenance_sha256"), 64)
        or not is_hex(capture_identity.get("runtime_dependencies_sha256"), 64)
    ):
        raise ValueError("incomplete or unsupported same-ELF handoff contract")
    actual_files: set[str] = set()
    for path in bundle.rglob("*"):
        if path.is_symlink():
            raise ValueError("handoff contains a symlink")
        if path.is_file():
            actual_files.add(path.relative_to(bundle).as_posix())
    if actual_files != {"manifest.json", "SHA256SUMS", *files}:
        raise ValueError("handoff file set differs")
    for relative, row in files.items():
        path = bundle / relative
        if (
            not isinstance(row, dict)
            or set(row) != {"bytes", "sha256"}
            or type(row.get("bytes")) is not int
            or row["bytes"] != path.stat().st_size
            or not is_hex(row.get("sha256"), 64)
            or row.get("sha256") != sha256(path)
        ):
            raise ValueError(f"handoff measurement differs: {relative}")
    if files["main"]["sha256"] != expected_elf:
        raise ValueError("handoff ELF measurement differs")
    evidence = read_regular_json(
        bundle / "ours/trace-evidence.json", "bundled trace evidence"
    )
    validate_dynamic_bindings(bundle, expected_elf, evidence, files)
    static_manifest = read_regular_json(
        bundle / "ours/static-manifest.json", "bundled static manifest"
    )
    recovery_provenance = read_regular_json(
        bundle / "recovery-provenance.json", "bundled recovery provenance"
    )
    indirect_policy = static_manifest.get("indirect_target_policy")
    provenance_apps = recovery_provenance.get("applications")
    recovered_row = (
        next(
            (
                item
                for item in provenance_apps
                if isinstance(item, dict) and item.get("name") == application
            ),
            None,
        )
        if isinstance(provenance_apps, list)
        else None
    )
    if (
        complete_boundary(evidence) != boundary
        or static_manifest.get("application") != application
        or static_manifest.get("elf_sha256") != expected_elf
        or static_manifest.get("plugin_map_sha256")
        != files["ours/plugin-map.txt"]["sha256"]
        or static_manifest.get("translator_sha256")
        != files["ours/translator"]["sha256"]
        or static_manifest.get("typed_cfg_sha256")
        != files["ours/typed_cfg"]["sha256"]
        or static_manifest.get("runtime_dependencies_sha256")
        != capture_identity.get("runtime_dependencies_sha256")
        or not isinstance(indirect_policy, dict)
        or indirect_policy.get("policy_sha256")
        != files["ours/indirect-policy.json"]["sha256"]
        or capture_identity.get("recovery_provenance_sha256")
        != files["recovery-provenance.json"]["sha256"]
        or recovery_provenance.get("identity")
        != "base ZEKRA source revision plus audited recovery overlay"
        or recovered_row != manifest.get("source_variant")
        or ours_path.get("sha256") != files["ours/recorded_path"]["sha256"]
        or ours_path.get("rows_including_header")
        != recorded_path_rows(bundle / "ours/recorded_path")
    ):
        raise ValueError("ELF, static policy, path, and boundary bindings differ")
    checksum_files = dict(files)
    checksum_files["manifest.json"] = {
        "bytes": (bundle / "manifest.json").stat().st_size,
        "sha256": sha256(bundle / "manifest.json"),
    }
    sums = bundle / "SHA256SUMS"
    if (
        sums.is_symlink()
        or not sums.is_file()
        or sums.read_text(encoding="ascii") != render_sha256sums(checksum_files)
    ):
        raise ValueError("handoff SHA256SUMS differs")
    return manifest


def create_handoff(
    capture_root: Path,
    application: str,
    expected_elf: str,
    *,
    capture_identity: dict[str, object],
    source_variant: dict[str, object],
) -> dict[str, object]:
    if APPLICATIONS.get(application) != expected_elf:
        raise ValueError(f"{application}: unsupported recovery ELF identity")
    sources = handoff_sources(capture_root, application)
    evidence = read_regular_json(
        sources["ours/trace-evidence.json"], f"{application} trace evidence"
    )
    boundary = complete_boundary(evidence)
    static_manifest = read_regular_json(
        sources["ours/static-manifest.json"], f"{application} static manifest"
    )
    if (
        sha256(sources["main"]) != expected_elf
        or static_manifest.get("application") != application
        or static_manifest.get("elf_sha256") != expected_elf
        or source_variant.get("name") != application
        or source_variant.get("recovered_elf_sha256") != expected_elf
    ):
        raise ValueError(f"{application}: source, static policy, and ELF identities differ")
    parent = capture_root / "same-elf-zekra-handoff"
    parent.mkdir(mode=0o700, exist_ok=True)
    destination = parent / application
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"{application}: refusing to overwrite handoff")
    staging = Path(tempfile.mkdtemp(prefix=f".{application}.", dir=parent))
    staging.chmod(0o700)
    try:
        files: dict[str, dict[str, object]] = {}
        for target, source in sources.items():
            copied = staging / target
            copy_regular(source, copied, executable=target == "main")
            files[target] = {
                "bytes": copied.stat().st_size,
                "sha256": sha256(copied),
            }
        if (
            static_manifest.get("plugin_map_sha256")
            != files["ours/plugin-map.txt"]["sha256"]
            or static_manifest.get("translator_sha256")
            != files["ours/translator"]["sha256"]
            or static_manifest.get("typed_cfg_sha256")
            != files["ours/typed_cfg"]["sha256"]
            or static_manifest.get("runtime_dependencies_sha256")
            != capture_identity.get("runtime_dependencies_sha256")
            or not isinstance(static_manifest.get("indirect_target_policy"), dict)
            or static_manifest["indirect_target_policy"].get("policy_sha256")
            != files["ours/indirect-policy.json"]["sha256"]
        ):
            raise ValueError(f"{application}: copied static artifact binding differs")
        manifest = {
            "application": application,
            "attestation_caveat": (
                "This is a same-ELF comparison handoff, not a legacy dense signed bundle."
            ),
            "boundary": boundary,
            "capture_identity": capture_identity,
            "elf_sha256": expected_elf,
            "files": files,
            "guest_exit_status": 0,
            "ours_recorded_path": {
                "path": "ours/recorded_path",
                "rows_including_header": recorded_path_rows(
                    staging / "ours/recorded_path"
                ),
                "sha256": files["ours/recorded_path"]["sha256"],
            },
            "schema": HANDOFF_SCHEMA,
            "source_variant": source_variant,
            "zekra_input": {
                "path": "main",
                "recompile": False,
                "requirement": (
                    "Load these exact ELF bytes in ZEKRA. Recompiling source changes the "
                    "comparison identity."
                ),
                "sha256": expected_elf,
            },
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="ascii"
        )
        checksum_files = dict(files)
        checksum_files["manifest.json"] = {
            "bytes": (staging / "manifest.json").stat().st_size,
            "sha256": sha256(staging / "manifest.json"),
        }
        (staging / "SHA256SUMS").write_text(
            render_sha256sums(checksum_files), encoding="ascii"
        )
        (staging / "SHA256SUMS").chmod(0o444)
        verified = verify_handoff(staging)
        rename_noreplace(staging, destination)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return {
        "bundle": str(destination.relative_to(capture_root)),
        "manifest_sha256": sha256(destination / "manifest.json"),
        "recorded_path_rows": verified["ours_recorded_path"]["rows_including_header"],
        "sha256sums_sha256": sha256(destination / "SHA256SUMS"),
        "verified": True,
        "zekra_input_elf_sha256": expected_elf,
    }


def run(command: list[str], *, cwd: Path, log: Path, env: dict[str, str] | None = None) -> None:
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
        detail = log.read_text(encoding="utf-8", errors="replace")[-2000:]
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n{detail}"
        )


def stable_policy(source: Path, destination: Path, application: str, elf_hash: str) -> None:
    archived = json.loads(source.read_text(encoding="utf-8"))
    if (
        not isinstance(archived, dict)
        or archived.get("schema") != ARCHIVED_POLICY_SCHEMA
        or archived.get("application") != application
        or archived.get("elf_sha256") != elf_hash
    ):
        raise ValueError(f"{application}: archived recovery policy identity mismatch")
    policy = {
        "schema": POLICY_SCHEMA,
        "application": application,
        "elf_sha256": elf_hash,
        "indirect_calls": archived.get("indirect_calls"),
        "indirect_jumps": archived.get("indirect_jumps"),
    }
    destination.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", type=Path, required=True)
    parser.add_argument("--image-vendor", type=Path, required=True)
    parser.add_argument("--sysroot", type=Path, required=True)
    parser.add_argument("--qemu-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    provider = args.provider.resolve()
    output = args.output.resolve()
    try:
        actual_qemu_revision = subprocess.check_output(
            ["git", "-C", str(args.qemu_source), "rev-parse", "HEAD"],
            text=True,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("cannot measure the QEMU source revision") from error
    if actual_qemu_revision != QEMU_REVISION:
        raise ValueError("QEMU source revision differs from the recovery capture pin")
    if output.exists() and any(output.iterdir()):
        raise ValueError("capture output must be absent or empty")
    output.mkdir(parents=True, mode=0o700, exist_ok=True)

    recovery_provenance_path = args.image_vendor / "recovery-provenance.json"
    recovery_provenance = read_regular_json(
        recovery_provenance_path, "materialized recovery provenance"
    )
    provenance_apps = recovery_provenance.get("applications")
    source_variants = (
        {
            item.get("name"): item
            for item in provenance_apps
            if isinstance(item, dict)
        }
        if isinstance(provenance_apps, list)
        else {}
    )
    if (
        recovery_provenance.get("identity")
        != "base ZEKRA source revision plus audited recovery overlay"
        or set(source_variants) != set(APPLICATIONS)
        or any(
            source_variants[name].get("recovered_elf_sha256") != expected
            for name, expected in APPLICATIONS.items()
        )
    ):
        raise ValueError("materialized recovery provenance does not bind both ELFs")

    sys.path.insert(0, str(provider))
    from static.runtime_dependencies import FILES, qemu_environment  # noqa: PLC0415

    selected_sysroot = output / "runtime-root"
    for relative in FILES:
        source = args.sysroot / relative
        destination = selected_sysroot / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    runtime = selected_sysroot / "runtime-dependencies.json"
    run(
        [
            sys.executable,
            "-m",
            "static.runtime_dependencies",
            "--profile",
            "ubuntu20",
            "--sysroot",
            str(selected_sysroot),
            "--output",
            str(runtime),
        ],
        cwd=provider,
        log=output / "logs/runtime.log",
    )
    plugin = output / "trace_scope.so"
    flags = subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "glib-2.0"], text=True
    ).split()
    run(
        [
            "gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror",
            f"-I{args.qemu_source / 'include'}", "-DQEMU_PLUGIN",
            str(provider / "qemu/trace_scope.c"), "-o", str(plugin), *flags,
        ],
        cwd=provider,
        log=output / "logs/plugin.log",
    )
    capture_identity = {
        "plugin_sha256": sha256(plugin),
        "qemu_revision": actual_qemu_revision,
        "recovery_provenance_sha256": sha256(recovery_provenance_path),
        "runtime_dependencies_sha256": sha256(runtime),
    }

    outcomes: list[dict[str, object]] = []
    for application, expected_elf in APPLICATIONS.items():
        app = output / application
        artifacts = app / "artifacts"
        logs = app / "logs"
        artifacts.mkdir(parents=True)
        recovery_copy = app / "recovery-provenance.json"
        shutil.copyfile(recovery_provenance_path, recovery_copy)
        recovery_copy.chmod(0o400)
        binary = app / application
        image_binary = args.image_vendor / "bin" / application
        if sha256(image_binary) != expected_elf:
            raise ValueError(f"{application}: recovery ELF digest mismatch")
        shutil.copyfile(image_binary, binary)
        binary.chmod(0o500)
        policy = app / "indirect-policy.json"
        stable_policy(
            args.image_vendor / "policies" / f"{application}.json",
            policy,
            application,
            expected_elf,
        )
        run(
            [
                sys.executable, "-m", "static.provision", "--architecture", "x86_64",
                "--canonical-bias", "0x400000", "--external-entry", "--root-symbol", "main",
                "--caller-symbol", "external-loader", "--application", application,
                "--elf", str(binary), "--out-dir", str(artifacts), "--max-out-degree", "64",
                "--runtime-dependencies", str(runtime), "--runtime-profile", "ubuntu20",
                "--indirect-policy", str(policy),
            ],
            cwd=provider,
            log=logs / "provision.log",
        )
        trace = app / "trace.log"
        run(
            [
                str(args.qemu_source / "build/qemu-x86_64"), "-L", str(selected_sysroot),
                "-plugin", f"{plugin},map={artifacts / 'plugin-map.txt'},log={trace}",
                str(binary),
            ],
            cwd=provider,
            log=logs / "qemu.log",
            env=qemu_environment(),
        )
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
        evidence = read_regular_json(
            artifacts / "evidence.json", f"{application} trace evidence"
        )
        boundary = complete_boundary(evidence)
        rows = len((artifacts / "recorded_path").read_text().splitlines())
        outcome = {
            "application": application,
            "binary_sha256": sha256(binary),
            "evidence_sha256": sha256(artifacts / "evidence.json"),
            "guest_exit_status": 0,
            "plugin_map_sha256": sha256(artifacts / "plugin-map.txt"),
            "policy_sha256": sha256(policy),
            "recorded_path_sha256": sha256(artifacts / "recorded_path"),
            "rows": rows,
            "static_manifest_sha256": sha256(artifacts / "static-manifest.json"),
            "trace_sha256": sha256(trace),
            "translator_sha256": sha256(artifacts / "translator"),
            "typed_cfg_sha256": sha256(artifacts / "typed_cfg"),
            "boundary": boundary,
        }
        outcome["same_elf_zekra_handoff"] = create_handoff(
            output,
            application,
            expected_elf,
            capture_identity=capture_identity,
            source_variant=dict(source_variants[application]),
        )
        outcomes.append(outcome)
    result = {
        "schema": "zkcfa.research.recovery-capture",
        **capture_identity,
        "same_elf_zekra_handoffs_ready": all(
            item["same_elf_zekra_handoff"]["verified"] is True for item in outcomes
        ),
        "applications": outcomes,
    }
    (output / "capture.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
