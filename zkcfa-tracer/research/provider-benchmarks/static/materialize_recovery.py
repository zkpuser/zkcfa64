#!/usr/bin/env python3
"""Materialize a hash-bound Embench recovery overlay without changing its base tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


OVERLAY_SCHEMA = "zkcfa.embench21-recovery-overlay.v1"
PROVENANCE_SCHEMA = "zkcfa.embench21-recovery-provenance.v1"
MANIFEST_SCHEMA = "zkcfa.embench21-manifest.v1"
POLICY_SCHEMA = "zkcfa.indirect-target-policy.v1"
HEX32 = re.compile(r"[0-9a-f]{64}")
HEX20 = re.compile(r"[0-9a-f]{40}")
APP_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
SAFE_RELATIVE = re.compile(r"[A-Za-z0-9._/-]+")
HUNK_HEADER = re.compile(
    r"@@ -(?P<old_start>[0-9]+)(?:,(?P<old_count>[0-9]+))? "
    r"\+(?P<new_start>[0-9]+)(?:,(?P<new_count>[0-9]+))? @@(?: .*)?"
)

OVERLAY_FIELDS = {
    "applications",
    "base_manifest_sha256",
    "base_source_revision",
    "schema",
    "upstream_reference",
}
UPSTREAM_FIELDS = {"commit", "repository", "tag"}
APPLICATION_FIELDS = {
    "base_source_sha256",
    "name",
    "patch",
    "patch_sha256",
    "policy",
    "policy_sha256",
    "reason",
    "recovered_elf_sha256",
    "recovered_source_sha256",
    "source",
    "upstream_source_sha256",
}
POLICY_FIELDS = {
    "application",
    "elf_sha256",
    "indirect_calls",
    "indirect_jumps",
    "rationale",
    "schema",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(_read_regular(path, str(path)))


def _read_regular(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    return path.read_bytes()


def _parse_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not canonical UTF-8 JSON") from error


def _relative_path(root: Path, raw: object, label: str) -> Path:
    if not isinstance(raw, str) or SAFE_RELATIVE.fullmatch(raw) is None:
        raise ValueError(f"{label} is not a safe relative path")
    relative = PurePosixPath(raw)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.as_posix() != raw
    ):
        raise ValueError(f"{label} is not a normalized relative path")
    candidate = root.joinpath(*relative.parts)
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"{label} escapes the vendor root") from error
    return candidate


def _validate_no_symlinks(root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("vendor root must be a regular directory")
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"vendor tree contains a symlink: {path.relative_to(root)}")


def _validate_overlay(document: Any) -> list[dict[str, Any]]:
    if (
        not isinstance(document, dict)
        or set(document) != OVERLAY_FIELDS
        or document.get("schema") != OVERLAY_SCHEMA
        or not isinstance(document.get("base_manifest_sha256"), str)
        or HEX32.fullmatch(document["base_manifest_sha256"]) is None
        or not isinstance(document.get("base_source_revision"), str)
        or HEX20.fullmatch(document["base_source_revision"]) is None
    ):
        raise ValueError("unsupported Embench recovery overlay")
    upstream = document.get("upstream_reference")
    if (
        not isinstance(upstream, dict)
        or set(upstream) != UPSTREAM_FIELDS
        or not isinstance(upstream.get("commit"), str)
        or HEX20.fullmatch(upstream["commit"]) is None
        or not isinstance(upstream.get("repository"), str)
        or not upstream["repository"].startswith("https://")
        or not isinstance(upstream.get("tag"), str)
        or not upstream["tag"]
    ):
        raise ValueError("invalid recovery upstream reference")
    applications = document.get("applications")
    if not isinstance(applications, list) or not applications:
        raise ValueError("recovery overlay must contain at least one application")
    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    for item in applications:
        if not isinstance(item, dict) or set(item) != APPLICATION_FIELDS:
            raise ValueError("invalid recovery application entry")
        name = item.get("name")
        if (
            not isinstance(name, str)
            or APP_NAME.fullmatch(name) is None
            or name in seen
            or any(
                not isinstance(item.get(field), str)
                or HEX32.fullmatch(item[field]) is None
                for field in (
                    "base_source_sha256",
                    "patch_sha256",
                    "policy_sha256",
                    "recovered_elf_sha256",
                    "recovered_source_sha256",
                    "upstream_source_sha256",
                )
            )
            or not isinstance(item.get("reason"), str)
            or not item["reason"].strip()
        ):
            raise ValueError("invalid recovery application values")
        source = PurePosixPath(item["source"])
        patch = PurePosixPath(item["patch"])
        policy = PurePosixPath(item["policy"])
        if (
            source.parent
            != PurePosixPath("source/embench-iot-applications") / name
            or source.suffix != ".c"
            or patch != PurePosixPath(f"recovery/patches/{name}.patch")
            or policy != PurePosixPath(f"recovery/policies/{name}.json")
        ):
            raise ValueError(f"{name}: recovery paths do not match the application")
        seen.add(name)
        validated.append(item)
    return validated


def apply_unified_patch(original: bytes, patch: bytes, target: str) -> bytes:
    """Apply the strict, single-file subset of unified diff used by recovery."""
    try:
        original_lines = original.decode("utf-8").splitlines(keepends=True)
        patch_lines = patch.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError as error:
        raise ValueError("recovery source and patch must be UTF-8") from error
    if any("\r" in line for line in patch_lines):
        raise ValueError("recovery patch must use LF line endings")
    expected_old = f"--- {target}\n"
    expected_new = f"+++ {target}\n"
    if len(patch_lines) < 3 or patch_lines[:2] != [expected_old, expected_new]:
        raise ValueError("recovery patch targets a different source file")

    result: list[str] = []
    old_cursor = 0
    patch_cursor = 2
    hunks = 0
    while patch_cursor < len(patch_lines):
        header = patch_lines[patch_cursor]
        match = HUNK_HEADER.fullmatch(header[:-1] if header.endswith("\n") else header)
        if match is None:
            raise ValueError("malformed unified-diff hunk header")
        hunks += 1
        old_start = int(match.group("old_start"))
        old_count = int(match.group("old_count") or "1")
        new_count = int(match.group("new_count") or "1")
        hunk_start = old_start - 1 if old_start else 0
        if hunk_start < old_cursor or hunk_start > len(original_lines):
            raise ValueError("recovery patch hunk is out of order or out of range")
        result.extend(original_lines[old_cursor:hunk_start])
        old_index = hunk_start
        observed_old = 0
        observed_new = 0
        patch_cursor += 1
        while patch_cursor < len(patch_lines) and not patch_lines[
            patch_cursor
        ].startswith("@@ "):
            line = patch_lines[patch_cursor]
            if not line or line[0] not in {" ", "+", "-"}:
                raise ValueError("unsupported unified-diff record")
            payload = line[1:]
            if line[0] in {" ", "-"}:
                if old_index >= len(original_lines) or original_lines[old_index] != payload:
                    raise ValueError("recovery patch context does not match base source")
                old_index += 1
                observed_old += 1
            if line[0] in {" ", "+"}:
                result.append(payload)
                observed_new += 1
            patch_cursor += 1
        if observed_old != old_count or observed_new != new_count:
            raise ValueError("recovery patch hunk line count differs from its header")
        old_cursor = old_index
    if hunks == 0:
        raise ValueError("recovery patch contains no hunks")
    result.extend(original_lines[old_cursor:])
    return "".join(result).encode("utf-8")


def _validate_policy(data: bytes, name: str, elf_sha256: str) -> None:
    policy = _parse_json(data, f"{name} recovery policy")
    if (
        not isinstance(policy, dict)
        or set(policy) != POLICY_FIELDS
        or policy.get("schema") != POLICY_SCHEMA
        or policy.get("application") != name
        or policy.get("elf_sha256") != elf_sha256
        or not isinstance(policy.get("indirect_calls"), dict)
        or not isinstance(policy.get("indirect_jumps"), dict)
        or not isinstance(policy.get("rationale"), str)
        or not policy["rationale"]
    ):
        raise ValueError(f"{name}: invalid recovery indirect-target policy")


def _write_json(path: Path, document: object) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def materialize_recovery(vendor: Path, overlay_path: Path, output: Path) -> dict[str, Any]:
    if vendor.is_symlink():
        raise ValueError("vendor root must not be a symlink")
    if overlay_path.is_symlink():
        raise ValueError("recovery overlay must not be a symlink")
    if output.is_symlink():
        raise ValueError("recovery output must not be a symlink")
    vendor = vendor.resolve()
    overlay_path = overlay_path.resolve()
    output_parent = output.parent.resolve()
    output = output_parent / output.name
    _validate_no_symlinks(vendor)
    expected_overlay = (vendor / "recovery/overlay.json").resolve()
    if overlay_path != expected_overlay:
        raise ValueError("overlay must be vendor/recovery/overlay.json")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing to overwrite recovery output")
    if output_parent.is_symlink() or not output_parent.is_dir():
        raise ValueError("recovery output parent must be a regular directory")
    try:
        output.relative_to(vendor)
    except ValueError:
        pass
    else:
        raise ValueError("recovery output must be outside the immutable vendor root")

    overlay_bytes = _read_regular(overlay_path, "recovery overlay")
    overlay = _parse_json(overlay_bytes, "recovery overlay")
    applications = _validate_overlay(overlay)
    manifest_path = vendor / "manifest.json"
    manifest_bytes = _read_regular(manifest_path, "base vendor manifest")
    if sha256_bytes(manifest_bytes) != overlay["base_manifest_sha256"]:
        raise ValueError("base vendor manifest SHA-256 differs from recovery overlay")
    manifest = _parse_json(manifest_bytes, "base vendor manifest")
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("source_revision") != overlay["base_source_revision"]
        or not isinstance(manifest.get("applications"), list)
    ):
        raise ValueError("base vendor manifest identity differs from recovery overlay")
    manifest_apps = {
        item.get("name"): item
        for item in manifest["applications"]
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    if len(manifest_apps) != len(manifest["applications"]):
        raise ValueError("base vendor manifest has malformed or duplicate applications")

    prepared: list[tuple[dict[str, Any], bytes, bytes, bytes]] = []
    for item in applications:
        name = item["name"]
        manifest_app = manifest_apps.get(name)
        if (
            not isinstance(manifest_app, dict)
            or manifest_app.get("indirect_policy") != f"policies/{name}.json"
            or item["source"].rsplit("/", 1)[-1]
            not in manifest_app.get("sources", [])
        ):
            raise ValueError(f"{name}: recovery entry does not match base manifest")
        source_path = _relative_path(vendor, item["source"], f"{name} source")
        patch_path = _relative_path(vendor, item["patch"], f"{name} patch")
        policy_path = _relative_path(vendor, item["policy"], f"{name} policy")
        source_bytes = _read_regular(source_path, f"{name} base source")
        patch_bytes = _read_regular(patch_path, f"{name} patch")
        policy_bytes = _read_regular(policy_path, f"{name} recovery policy")
        if sha256_bytes(source_bytes) != item["base_source_sha256"]:
            raise ValueError(f"{name}: base source SHA-256 differs from recovery overlay")
        if sha256_bytes(patch_bytes) != item["patch_sha256"]:
            raise ValueError(f"{name}: patch SHA-256 differs from recovery overlay")
        if sha256_bytes(policy_bytes) != item["policy_sha256"]:
            raise ValueError(f"{name}: policy SHA-256 differs from recovery overlay")
        recovered = apply_unified_patch(source_bytes, patch_bytes, item["source"])
        if sha256_bytes(recovered) != item["recovered_source_sha256"]:
            raise ValueError(f"{name}: recovered source SHA-256 differs from overlay")
        _validate_policy(policy_bytes, name, item["recovered_elf_sha256"])
        prepared.append((item, recovered, policy_bytes, patch_bytes))

    def ignore_generated(directory: str, names: list[str]) -> set[str]:
        if Path(directory).resolve() == vendor and "bin" in names:
            return {"bin"}
        return set()

    with tempfile.TemporaryDirectory(
        prefix=f".{output.name}.materializing-", dir=output_parent
    ) as temporary:
        materialized = Path(temporary) / "tree"
        shutil.copytree(vendor, materialized, ignore=ignore_generated)
        provenance_apps = []
        for item, recovered, policy_bytes, _ in prepared:
            source_output = _relative_path(
                materialized, item["source"], f"{item['name']} materialized source"
            )
            source_output.write_bytes(recovered)
            policy_output = materialized / f"policies/{item['name']}.json"
            policy_output.write_bytes(policy_bytes)
            manifest_apps[item["name"]]["elf_sha256"] = item["recovered_elf_sha256"]
            provenance_apps.append(
                {
                    key: item[key]
                    for key in (
                        "base_source_sha256",
                        "name",
                        "patch_sha256",
                        "policy_sha256",
                        "recovered_elf_sha256",
                        "recovered_source_sha256",
                        "source",
                        "upstream_source_sha256",
                    )
                }
            )
        materialized_manifest = materialized / "manifest.json"
        _write_json(materialized_manifest, manifest)
        provenance = {
            "applications": provenance_apps,
            "base_manifest_sha256": overlay["base_manifest_sha256"],
            "base_source_revision": overlay["base_source_revision"],
            "identity": "base ZEKRA source revision plus audited recovery overlay",
            "materialized_manifest_sha256": sha256(materialized_manifest),
            "overlay_sha256": sha256_bytes(overlay_bytes),
            "schema": PROVENANCE_SCHEMA,
            "upstream_reference": overlay["upstream_reference"],
        }
        _write_json(materialized / "recovery-provenance.json", provenance)
        if output.exists() or output.is_symlink():
            raise ValueError("recovery output appeared during materialization")
        materialized.rename(output)
    return provenance


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vendor", type=Path, required=True)
    parser.add_argument("--overlay", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    provenance = materialize_recovery(args.vendor, args.overlay, args.output)
    print(
        "materialized hash-gated Embench recovery overlay "
        f"{provenance['overlay_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
