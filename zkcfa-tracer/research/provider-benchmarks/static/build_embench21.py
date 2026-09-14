#!/usr/bin/env python3
"""Rebuild the exact ZEKRA Embench x86-64 ELF set from a pinned manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


TOOLCHAIN_FIELDS = {
    "apt_snapshot",
    "argv_prefix",
    "argv_suffix",
    "base_image",
    "gcc_fullversion",
    "runtime_profile",
    "source_order",
}


def load_manifest_document(vendor: Path) -> dict[str, Any]:
    """Load and fully validate the pinned 21-application build manifest."""
    manifest = json.loads((vendor / "manifest.json").read_text())
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "applications",
            "canonical_bias",
            "root_symbol",
            "schema",
            "source_revision",
            "toolchains",
        }
        or manifest.get("schema") != "zkcfa.embench21-manifest.v1"
        or manifest.get("canonical_bias") != "0x400000"
        or manifest.get("root_symbol") != "main"
        or not isinstance(manifest.get("source_revision"), str)
        or re.fullmatch(r"[0-9a-f]{40}", manifest["source_revision"]) is None
    ):
        raise ValueError("unsupported Embench build manifest")
    toolchains = manifest.get("toolchains")
    if not isinstance(toolchains, dict) or set(toolchains) != {
        "ubuntu20-gcc9",
        "ubuntu22-gcc11",
    }:
        raise ValueError("Embench build manifest has unsupported toolchains")
    for name, spec in toolchains.items():
        if (
            not isinstance(spec, dict)
            or set(spec) != TOOLCHAIN_FIELDS
            or spec.get("argv_prefix") != ["gcc", "-o", "${OUTPUT}"]
            or spec.get("argv_suffix")
            != ["-Os", "-g0", "-lm", "-fno-optimize-sibling-calls"]
            or spec.get("source_order")
            != "explicit per-application manifest order"
            or spec.get("apt_snapshot") != "20260701T000000Z"
            or not isinstance(spec.get("base_image"), str)
            or not spec["base_image"].startswith("ubuntu:")
            or not isinstance(spec.get("gcc_fullversion"), str)
            or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", spec["gcc_fullversion"])
            is None
            or not isinstance(spec.get("runtime_profile"), str)
            or re.fullmatch(r"ubuntu(20|22)", spec["runtime_profile"]) is None
        ):
            raise ValueError(f"unsupported toolchain entry: {name}")
    applications = manifest.get("applications")
    if not isinstance(applications, list) or len(applications) != 21:
        raise ValueError("Embench build manifest must contain exactly 21 applications")
    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    for item in applications:
        if not isinstance(item, dict):
            raise ValueError("malformed application build entry")
        name = item.get("name")
        sources = item.get("sources")
        expected = item.get("elf_sha256")
        toolchain = item.get("toolchain")
        runtime_profile = item.get("runtime_profile")
        allowed_fields = {
            "elf_sha256",
            "name",
            "runtime_profile",
            "sources",
            "toolchain",
        }
        if "indirect_policy" in item:
            allowed_fields.add("indirect_policy")
        if (
            set(item) != allowed_fields
            or not isinstance(name, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", name)
            or name in seen
            or not isinstance(sources, list)
            or not sources
            or not all(
                isinstance(source, str) and Path(source).name == source
                for source in sources
            )
            or len(sources) != len(set(sources))
            or not isinstance(expected, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected)
            or toolchain not in toolchains
            or runtime_profile != toolchains[toolchain]["runtime_profile"]
        ):
            raise ValueError("invalid application build entry")
        policy = item.get("indirect_policy")
        if policy is not None and (
            not isinstance(policy, str)
            or Path(policy).is_absolute()
            or ".." in Path(policy).parts
            or not policy.startswith("policies/")
        ):
            raise ValueError(f"{name}: unsafe indirect policy path")
        seen.add(name)
        validated.append(item)
    manifest["applications"] = validated
    return manifest


def load_manifest(vendor: Path) -> list[dict[str, Any]]:
    """Compatibility API returning the strictly validated application rows."""
    return load_manifest_document(vendor)["applications"]


def build_application(item: dict[str, Any], vendor: Path, output: Path) -> None:
    """Build one manifest entry and hash-gate its exact output ELF."""
    name = item["name"]
    sources = item["sources"]
    expected = item["elf_sha256"]
    source_root = vendor / "source/embench-iot-applications"
    app_root = source_root / name
    actual_c = sorted(path.name for path in app_root.glob("*.c"))
    if actual_c != sorted(sources):
        raise ValueError(f"{name}: manifest must list every C input exactly once")
    inputs: list[str] = []
    for source in sources:
        if not isinstance(source, str) or Path(source).name != source:
            raise ValueError(f"{name}: unsafe source name")
        path = app_root / source
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"{name}: source input is absent or symlinked: {source}")
        inputs.append(f"./embench-iot-applications/{name}/{source}")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise ValueError(f"{name}: refusing to overwrite build output")
    command = [
        "gcc",
        "-o",
        str(output.absolute()),
        *inputs,
        "-Os",
        "-g0",
        "-lm",
        "-fno-optimize-sibling-calls",
    ]
    subprocess.run(command, check=True, cwd=vendor / "source")
    actual = sha256(output)
    if actual != expected:
        raise ValueError(
            f"{name}: rebuilt ELF SHA-256 {actual} differs from pinned {expected}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vendor", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--application")
    parser.add_argument("--toolchain", required=True)
    args = parser.parse_args()
    manifest = load_manifest_document(args.vendor)
    toolchains = manifest["toolchains"]
    if args.toolchain not in toolchains:
        raise ValueError(f"unknown Embench toolchain: {args.toolchain}")
    actual_gcc = subprocess.check_output(
        ["gcc", "-dumpfullversion"], text=True
    ).strip()
    if actual_gcc != toolchains[args.toolchain]["gcc_fullversion"]:
        raise ValueError(
            f"toolchain {args.toolchain} requires GCC "
            f"{toolchains[args.toolchain]['gcc_fullversion']}, got {actual_gcc}"
        )
    applications = [
        item
        for item in manifest["applications"]
        if item["toolchain"] == args.toolchain
    ]
    if args.application is not None:
        applications = [item for item in applications if item["name"] == args.application]
        if not applications:
            raise ValueError(f"unknown Embench application: {args.application}")
    args.output.mkdir(parents=True, exist_ok=True)
    for item in applications:
        build_application(item, args.vendor, args.output / item["name"])
    print(f"rebuilt and hash-gated {len(applications)} ZEKRA Embench x86-64 ELFs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
