#!/usr/bin/env python3
"""Materialize functional-oracle repairs on a verified recovery source tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from research.atomic_publish import rename_noreplace


try:
    from .materialize_recovery import apply_unified_patch
except ImportError:  # Direct execution from the static/ directory.
    from materialize_recovery import apply_unified_patch


OVERLAY_SCHEMA = "zkcfa.embench21-functional-oracle-overlay.v1"
PROVENANCE_SCHEMA = "zkcfa.embench21-functional-oracle-provenance.v1"
RECOVERY_PROVENANCE_SCHEMA = "zkcfa.embench21-recovery-provenance.v1"
MANIFEST_SCHEMA = "zkcfa.embench21-manifest.v1"
RECOVERY_IDENTITY = "base ZEKRA source revision plus audited recovery overlay"
FUNCTIONAL_IDENTITY = (
    "materialized recovery tree plus audited functional-oracle overlay"
)
BOOTSTRAP_ELF = "BOOTSTRAP_REQUIRED"
FUNCTIONAL_APPLICATIONS = (
    "matmult-int",
    "nbody",
    "primecount",
    "slre",
)

HEX32 = re.compile(r"[0-9a-f]{64}")
HEX20 = re.compile(r"[0-9a-f]{40}")
APP_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
SAFE_RELATIVE = re.compile(r"[A-Za-z0-9._/-]+")

OVERLAY_FIELDS = {"applications", "base", "schema"}
BASE_FIELDS = {
    "manifest_sha256",
    "recovery_identity",
    "recovery_overlay_sha256",
    "recovery_provenance_sha256",
    "source_revision",
}
APPLICATION_FIELDS = {
    "base_elf_sha256",
    "base_source_sha256",
    "expected_guest_exit_status",
    "functional_elf_sha256",
    "functional_source_sha256",
    "name",
    "observed_benchmark_result",
    "patch",
    "patch_sha256",
    "reason",
    "repaired_oracle",
    "source",
    "stale_oracle",
}
RECOVERY_PROVENANCE_FIELDS = {
    "applications",
    "base_manifest_sha256",
    "base_source_revision",
    "identity",
    "materialized_manifest_sha256",
    "overlay_sha256",
    "schema",
    "upstream_reference",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    return path.read_bytes()


def sha256(path: Path) -> str:
    return sha256_bytes(_read_regular(path, str(path)))


def _parse_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not canonical UTF-8 JSON") from error


def _write_json(path: Path, document: object) -> None:
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _validate_no_symlinks(root: Path, label: str) -> None:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"{label} must be a regular directory")
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"{label} contains a symlink: {path.relative_to(root)}")


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
        raise ValueError(f"{label} escapes its root") from error
    return candidate


def _validate_overlay(document: Any) -> tuple[list[dict[str, Any]], bool]:
    if (
        not isinstance(document, dict)
        or set(document) != OVERLAY_FIELDS
        or document.get("schema") != OVERLAY_SCHEMA
    ):
        raise ValueError("unsupported Embench functional-oracle overlay")
    base = document.get("base")
    if (
        not isinstance(base, dict)
        or set(base) != BASE_FIELDS
        or any(
            not isinstance(base.get(field), str)
            or HEX32.fullmatch(base[field]) is None
            for field in (
                "manifest_sha256",
                "recovery_overlay_sha256",
                "recovery_provenance_sha256",
            )
        )
        or not isinstance(base.get("source_revision"), str)
        or HEX20.fullmatch(base["source_revision"]) is None
        or base.get("recovery_identity") != RECOVERY_IDENTITY
    ):
        raise ValueError("invalid functional-oracle base identity")

    applications = document.get("applications")
    if not isinstance(applications, list) or len(applications) != len(
        FUNCTIONAL_APPLICATIONS
    ):
        raise ValueError("functional-oracle overlay must contain exactly four apps")
    validated: list[dict[str, Any]] = []
    seen: list[str] = []
    pins: list[str] = []
    for item in applications:
        if not isinstance(item, dict) or set(item) != APPLICATION_FIELDS:
            raise ValueError("invalid functional-oracle application entry")
        name = item.get("name")
        if (
            not isinstance(name, str)
            or APP_NAME.fullmatch(name) is None
            or name in seen
            or any(
                not isinstance(item.get(field), str)
                or HEX32.fullmatch(item[field]) is None
                for field in (
                    "base_elf_sha256",
                    "base_source_sha256",
                    "functional_source_sha256",
                    "patch_sha256",
                )
            )
            or item.get("expected_guest_exit_status") != 0
            or any(
                not isinstance(item.get(field), str) or not item[field].strip()
                for field in (
                    "observed_benchmark_result",
                    "reason",
                    "repaired_oracle",
                    "stale_oracle",
                )
            )
        ):
            raise ValueError("invalid functional-oracle application values")
        pin = item.get("functional_elf_sha256")
        if not isinstance(pin, str) or (
            pin != BOOTSTRAP_ELF and HEX32.fullmatch(pin) is None
        ):
            raise ValueError(f"{name}: invalid functional ELF pin")
        source = PurePosixPath(item.get("source", ""))
        patch = PurePosixPath(item.get("patch", ""))
        if (
            source.parent
            != PurePosixPath("source/embench-iot-applications") / name
            or source.suffix != ".c"
            or patch != PurePosixPath(f"patches/{name}.patch")
        ):
            raise ValueError(f"{name}: functional-oracle paths do not match app")
        seen.append(name)
        pins.append(pin)
        validated.append(item)
    if tuple(seen) != FUNCTIONAL_APPLICATIONS:
        raise ValueError("functional-oracle applications are missing or out of order")
    pending = [pin == BOOTSTRAP_ELF for pin in pins]
    if any(pending) and not all(pending):
        raise ValueError("functional ELF pins must be either all pinned or all pending")
    return validated, all(pending)


def _validate_manifest(document: Any, source_revision: str) -> dict[str, dict[str, Any]]:
    if (
        not isinstance(document, dict)
        or document.get("schema") != MANIFEST_SCHEMA
        or document.get("source_revision") != source_revision
        or not isinstance(document.get("applications"), list)
        or len(document["applications"]) != 21
    ):
        raise ValueError("recovery manifest identity is invalid")
    applications: dict[str, dict[str, Any]] = {}
    for item in document["applications"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("name"), str)
            or item["name"] in applications
            or not isinstance(item.get("sources"), list)
            or not isinstance(item.get("elf_sha256"), str)
            or HEX32.fullmatch(item["elf_sha256"]) is None
        ):
            raise ValueError("recovery manifest contains malformed applications")
        applications[item["name"]] = item
    return applications


def _validate_recovery_provenance(
    document: Any, manifest_sha256: str, overlay: dict[str, Any]
) -> None:
    base = overlay["base"]
    if (
        not isinstance(document, dict)
        or set(document) != RECOVERY_PROVENANCE_FIELDS
        or document.get("schema") != RECOVERY_PROVENANCE_SCHEMA
        or document.get("identity") != base["recovery_identity"]
        or document.get("base_source_revision") != base["source_revision"]
        or document.get("materialized_manifest_sha256") != manifest_sha256
        or document.get("overlay_sha256") != base["recovery_overlay_sha256"]
        or not isinstance(document.get("applications"), list)
    ):
        raise ValueError("recovery provenance identity is invalid")


def materialize_functional_oracle(
    recovered: Path,
    overlay_path: Path,
    output: Path,
    *,
    bootstrap_source_only: bool = False,
) -> dict[str, Any]:
    """Apply the checked source repairs and emit a composite provenance record.

    A pending overlay is rejected by default.  The explicit bootstrap mode emits
    deliberately invalid manifest ELF pins, so a normal suite build cannot mistake
    stale base binaries for the repaired programs.
    """

    if recovered.is_symlink():
        raise ValueError("recovery root must not be a symlink")
    if overlay_path.is_symlink():
        raise ValueError("functional-oracle overlay must not be a symlink")
    if output.is_symlink():
        raise ValueError("functional-oracle output must not be a symlink")
    recovered = recovered.resolve()
    overlay_path = overlay_path.resolve()
    overlay_root = overlay_path.parent
    output_parent = output.parent.resolve()
    output = output_parent / output.name
    _validate_no_symlinks(recovered, "recovery tree")
    _validate_no_symlinks(overlay_root, "functional-oracle overlay tree")
    if overlay_path != overlay_root / "overlay.json":
        raise ValueError("functional-oracle overlay must be named overlay.json")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing to overwrite functional-oracle output")
    if output_parent.is_symlink() or not output_parent.is_dir():
        raise ValueError("functional-oracle output parent must be a regular directory")
    for forbidden, label in (
        (recovered, "recovery input"),
        (overlay_root, "functional-oracle overlay tree"),
    ):
        try:
            output.relative_to(forbidden)
        except ValueError:
            pass
        else:
            raise ValueError(f"functional-oracle output must be outside {label}")
    if (recovered / "bin").exists() or (recovered / "bin").is_symlink():
        raise ValueError("recovery input must not contain stale built ELFs")
    if (recovered / "functional-oracle").exists():
        raise ValueError("recovery input already contains a functional-oracle overlay")

    overlay_bytes = _read_regular(overlay_path, "functional-oracle overlay")
    overlay = _parse_json(overlay_bytes, "functional-oracle overlay")
    applications, pending = _validate_overlay(overlay)
    manifest_path = recovered / "manifest.json"
    manifest_bytes = _read_regular(manifest_path, "recovery manifest")
    if sha256_bytes(manifest_bytes) != overlay["base"]["manifest_sha256"]:
        raise ValueError("recovery manifest SHA-256 differs from functional overlay")
    manifest = _parse_json(manifest_bytes, "recovery manifest")
    manifest_apps = _validate_manifest(manifest, overlay["base"]["source_revision"])

    recovery_provenance_path = recovered / "recovery-provenance.json"
    recovery_provenance_bytes = _read_regular(
        recovery_provenance_path, "recovery provenance"
    )
    if (
        sha256_bytes(recovery_provenance_bytes)
        != overlay["base"]["recovery_provenance_sha256"]
    ):
        raise ValueError(
            "recovery provenance SHA-256 differs from functional overlay"
        )
    recovery_provenance = _parse_json(
        recovery_provenance_bytes, "recovery provenance"
    )
    _validate_recovery_provenance(
        recovery_provenance, overlay["base"]["manifest_sha256"], overlay
    )

    prepared: list[tuple[dict[str, Any], bytes]] = []
    for item in applications:
        name = item["name"]
        manifest_app = manifest_apps.get(name)
        source_name = item["source"].rsplit("/", 1)[-1]
        if (
            not isinstance(manifest_app, dict)
            or manifest_app.get("elf_sha256") != item["base_elf_sha256"]
            or source_name not in manifest_app.get("sources", [])
        ):
            raise ValueError(f"{name}: entry does not match recovery manifest")
        source_path = _relative_path(recovered, item["source"], f"{name} source")
        patch_path = _relative_path(overlay_root, item["patch"], f"{name} patch")
        source_bytes = _read_regular(source_path, f"{name} recovery source")
        patch_bytes = _read_regular(patch_path, f"{name} functional patch")
        if sha256_bytes(source_bytes) != item["base_source_sha256"]:
            raise ValueError(f"{name}: base source SHA-256 differs from overlay")
        if sha256_bytes(patch_bytes) != item["patch_sha256"]:
            raise ValueError(f"{name}: patch SHA-256 differs from overlay")
        functional_source = apply_unified_patch(
            source_bytes, patch_bytes, item["source"]
        )
        if sha256_bytes(functional_source) != item["functional_source_sha256"]:
            raise ValueError(f"{name}: functional source SHA-256 differs from overlay")
        prepared.append((item, functional_source))

    if pending and not bootstrap_source_only:
        raise ValueError(
            "functional ELF hashes are unpinned; use --bootstrap-source-only "
            "only to obtain sources for the pinned GCC build"
        )
    if not pending and bootstrap_source_only:
        raise ValueError("bootstrap mode is forbidden once functional ELF hashes are pinned")

    with tempfile.TemporaryDirectory(
        prefix=f".{output.name}.materializing-", dir=output_parent
    ) as temporary:
        materialized = Path(temporary) / "tree"
        shutil.copytree(recovered, materialized)
        provenance_apps = []
        for item, functional_source in prepared:
            source_output = _relative_path(
                materialized,
                item["source"],
                f"{item['name']} materialized functional source",
            )
            source_output.write_bytes(functional_source)
            manifest_apps[item["name"]]["elf_sha256"] = item[
                "functional_elf_sha256"
            ]
            provenance_apps.append(
                {
                    key: item[key]
                    for key in (
                        "base_elf_sha256",
                        "base_source_sha256",
                        "expected_guest_exit_status",
                        "functional_elf_sha256",
                        "functional_source_sha256",
                        "name",
                        "patch_sha256",
                        "source",
                    )
                }
            )
        materialized_manifest = materialized / "manifest.json"
        _write_json(materialized_manifest, manifest)
        shutil.copytree(overlay_root, materialized / "functional-oracle")
        unresolved = list(FUNCTIONAL_APPLICATIONS) if pending else []
        provenance = {
            "applications": provenance_apps,
            "base_manifest_sha256": overlay["base"]["manifest_sha256"],
            "base_recovery_overlay_sha256": overlay["base"]
            ["recovery_overlay_sha256"],
            "base_recovery_provenance_sha256": overlay["base"]
            ["recovery_provenance_sha256"],
            "functional_manifest_sha256": sha256(materialized_manifest),
            "identity": FUNCTIONAL_IDENTITY,
            "mode": "source-bootstrap" if pending else "pinned",
            "overlay_sha256": sha256_bytes(overlay_bytes),
            "schema": PROVENANCE_SCHEMA,
            "source_revision": overlay["base"]["source_revision"],
            "unresolved_elf_applications": unresolved,
        }
        _write_json(
            materialized / "functional-oracle-provenance.json", provenance
        )
        try:
            rename_noreplace(materialized, output)
        except FileExistsError as error:
            raise ValueError(
                "functional-oracle output appeared during materialization"
            ) from error
    return provenance


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recovered", type=Path, required=True)
    parser.add_argument("--overlay", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--bootstrap-source-only",
        action="store_true",
        help=(
            "explicitly materialize pending sources with invalid ELF-pin sentinels; "
            "normal suite builders will reject the resulting manifest"
        ),
    )
    args = parser.parse_args()
    provenance = materialize_functional_oracle(
        args.recovered,
        args.overlay,
        args.output,
        bootstrap_source_only=args.bootstrap_source_only,
    )
    print(
        "materialized hash-gated Embench functional-oracle overlay "
        f"{provenance['overlay_sha256']} ({provenance['mode']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
