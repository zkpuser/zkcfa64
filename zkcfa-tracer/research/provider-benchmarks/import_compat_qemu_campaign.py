#!/usr/bin/env python3
"""Import one published compat/QEMU campaign as complete-path proof inputs.

The compat campaign is diagnostic, so this importer does not trust its summary
alone.  It closes the recursive checksum manifests against a caller-supplied
root digest, revalidates every complete QEMU binding and exact QEMU revision,
binds the input snapshot byte-for-byte to a separately supplied trusted suite,
and regenerates every path with a read-once snapshot of trusted local provider
sources.  It copies only proof-relevant regular files and atomically publishes
the legacy layout consumed by ``sign-bundles.py``.  It never creates signed
bundles or a shadow path; shadow inputs must be projected later from the
imported complete registry.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence


REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from research.atomic_publish import copy_regular_once, rename_noreplace


CAMPAIGN_SCHEMA = "zkcfa.zekra-compat-qemu-campaign.v1"
INPUT_SCHEMA = CAMPAIGN_SCHEMA + ".inputs"
RUNTIME_MANIFEST_SNAPSHOT_SCHEMA = CAMPAIGN_SCHEMA + ".runtime-manifests"
QEMU_SCHEMA = CAMPAIGN_SCHEMA + ".qemu"
QEMU_ENVIRONMENT_SCHEMA = QEMU_SCHEMA + ".environment"
COMPAT_SCHEMA = CAMPAIGN_SCHEMA + ".compat"
COMPARISON_SCHEMA = CAMPAIGN_SCHEMA + ".comparison"
SUITE_SCHEMA = "zkcfa.embench21-manifest.v1"
TRACER_SCHEMA = "zkcfa.tracer.campaign"
EXPECTED_QEMU_REVISION = "667e1fff878326c35c7f5146072e60a63a9a41c8"
DEFAULT_PROVIDER_ROOT = REPO / "provider"
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
TRACE_HEADER = re.compile(
    rb"zkcfa\.scope\.trace elf_sha256=([0-9a-f]{64})"
    rb"(?: runtime_bias=0x[0-9a-f]+)?"
)
TRACE_END = re.compile(rb"end count=(\d+) complete=1 runtime_code_match=1")

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
INDIRECT_APPLICATIONS = frozenset({"picojpeg", "sglib-combined", "wikisort"})
PROVIDER_SOURCE_FILES = frozenset(
    {
        "qemu/trace_scope.c",
        "static/normalize.py",
        "static/provision.py",
        "static/runtime_dependencies.py",
    }
)
TRUSTED_PROVIDER_FILES = (
    "qemu/trace_scope.c",
    "static/__init__.py",
    "static/normalize.py",
    "static/provision.py",
    "static/runtime_dependencies.py",
)
PROVENANCE_FILES = (
    "recovery-provenance.json",
    "functional-oracle-provenance.json",
)
RUNTIME_PROFILES = ("ubuntu20", "ubuntu22")
RUNTIME_DEPENDENCY_FILES = (
    "lib64/ld-linux-x86-64.so.2",
    "lib/x86_64-linux-gnu/libc.so.6",
    "lib/x86_64-linux-gnu/libm.so.6",
)
RUNTIME_MANIFEST_FIELDS = {
    "binding",
    "environment",
    "files",
    "loader_scope",
    "runtime_profile",
    "schema",
}
REGISTRY_FILES = (
    "evidence.json",
    "plugin-map.txt",
    "recorded_path",
    "static-manifest.json",
    "translator",
    "typed_cfg",
)
QEMU_LOG_FILES = frozenset(
    {"logs/normalize.log", "logs/provision.log", "logs/qemu.log"}
)
EXPECTED_CLAIMS = {
    "single_snapshotted_elf_per_application_for_both_lanes": True,
    "all_guest_exit_status_zero": True,
    "all_qemu_boundaries_complete": True,
    "all_compat_executions_complete": True,
    "all_fresh_same_elf_comparisons_accepted": True,
    "diagnostic_only": True,
    "proof_input": False,
    "eligible_for_signing": False,
}


class CampaignImportError(RuntimeError):
    """The source campaign is not a closed, complete import candidate."""


@dataclass(frozen=True)
class Measurement:
    sha256: str
    bytes: int


@dataclass(frozen=True)
class TrustedProvider:
    source_root: Path
    snapshot_root: Path
    measurements: Mapping[str, Measurement]
    identity_sha256: str
    normalizer: Any
    module_prefix: str


@dataclass(frozen=True)
class Application:
    name: str
    elf_sha256: str
    runtime_profile: str
    indirect_policy: str | None


@dataclass(frozen=True)
class ValidatedCampaign:
    root: Path
    trusted_suite_root: Path
    trusted_suite_measurements: Mapping[str, Measurement]
    campaign: dict[str, Any]
    input_manifest: dict[str, Any]
    qemu_summary: dict[str, Any]
    qemu_environment: dict[str, Any]
    applications: tuple[Application, ...]
    qemu_results: Mapping[str, dict[str, Any]]
    measurements: Mapping[str, Measurement]
    trusted_provider_root: Path
    trusted_provider_measurements: Mapping[str, Measurement]
    trusted_provider_identity_sha256: str
    expected_qemu_revision: str
    expected_campaign_sha256s_sha256: str


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def measure_regular(path: Path) -> Measurement:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CampaignImportError(f"cannot open regular input {path}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CampaignImportError(f"input is not a regular file: {path}")
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            total += len(block)
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after):
            raise CampaignImportError(f"input changed while measured: {path}")
        return Measurement(digest.hexdigest(), total)
    finally:
        os.close(descriptor)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json(value: object) -> str:
    """Render strict canonical JSON so booleans cannot compare equal to integers."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise CampaignImportError("evidence is not strict canonical JSON") from error


def _trusted_provider_identity(
    measurements: Mapping[str, Measurement],
) -> str:
    payload = {
        "schema": "zkcfa.trusted-provider-source-set.v1",
        "files": {
            name: {
                "bytes": measurements[name].bytes,
                "sha256": measurements[name].sha256,
            }
            for name in TRUSTED_PROVIDER_FILES
        },
    }
    return sha256_bytes(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    )


def _load_trusted_normalizer(snapshot_root: Path) -> tuple[Any, str]:
    module_suffix = sha256_bytes(os.fsencode(snapshot_root))[:24]
    package_name = f"_zkcfa_trusted_provider_{module_suffix}"
    package_path = snapshot_root / "static"
    package_spec = importlib.util.spec_from_file_location(
        package_name,
        package_path / "__init__.py",
        submodule_search_locations=[str(package_path)],
    )
    if package_spec is None or package_spec.loader is None:
        raise CampaignImportError("cannot load trusted provider package snapshot")
    package = importlib.util.module_from_spec(package_spec)
    sys.modules[package_name] = package
    try:
        package_spec.loader.exec_module(package)
        normalize_name = f"{package_name}.normalize"
        normalize_spec = importlib.util.spec_from_file_location(
            normalize_name, package_path / "normalize.py"
        )
        if normalize_spec is None or normalize_spec.loader is None:
            raise CampaignImportError("cannot load trusted provider normalizer snapshot")
        normalizer = importlib.util.module_from_spec(normalize_spec)
        sys.modules[normalize_name] = normalizer
        normalize_spec.loader.exec_module(normalizer)
    except Exception:
        for name in tuple(sys.modules):
            if name == package_name or name.startswith(f"{package_name}."):
                del sys.modules[name]
        raise
    return normalizer, package_name


def _snapshot_trusted_provider(source: Path, destination: Path) -> TrustedProvider:
    source_root = source.absolute()
    _require_directory(source_root, "trusted provider root")
    _require_directory(source_root / "qemu", "trusted provider QEMU sources")
    _require_directory(source_root / "static", "trusted provider static sources")
    snapshot_root = destination / "provider"
    measurements: dict[str, Measurement] = {}
    try:
        for name in TRUSTED_PROVIDER_FILES:
            copied = snapshot_root.joinpath(*PurePosixPath(name).parts)
            copy_regular_once(
                source_root.joinpath(*PurePosixPath(name).parts), copied, mode=0o400
            )
            measurements[name] = measure_regular(copied)
    except (OSError, ValueError) as error:
        raise CampaignImportError(
            f"cannot snapshot trusted provider source set: {error}"
        ) from error
    normalizer, module_prefix = _load_trusted_normalizer(snapshot_root)
    return TrustedProvider(
        source_root=source_root,
        snapshot_root=snapshot_root,
        measurements=measurements,
        identity_sha256=_trusted_provider_identity(measurements),
        normalizer=normalizer,
        module_prefix=module_prefix,
    )


def _unload_trusted_provider(provider: TrustedProvider) -> None:
    for name in tuple(sys.modules):
        if name == provider.module_prefix or name.startswith(
            f"{provider.module_prefix}."
        ):
            del sys.modules[name]


def _safe_relative(value: object, label: str) -> str:
    if not isinstance(value, str) or "\\" in value:
        raise CampaignImportError(f"{label} is not a safe relative path")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.as_posix() != value
    ):
        raise CampaignImportError(f"{label} is not a normalized relative path")
    return value


def _rooted(root: Path, relative: object, label: str) -> Path:
    safe = _safe_relative(relative, label)
    return root.joinpath(*PurePosixPath(safe).parts)


def _require_directory(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise CampaignImportError(f"{label} is not a regular directory: {path}")


def _require_entries(path: Path, expected: set[str], label: str) -> None:
    _require_directory(path, label)
    actual = {entry.name for entry in path.iterdir()}
    if actual != expected:
        raise CampaignImportError(f"{label} entry set differs")


def recursive_regular_files(root: Path, *, omit: Iterable[str] = ()) -> list[str]:
    _require_directory(root, "artifact root")
    omitted = set(omit)
    result: list[str] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise CampaignImportError(f"artifact tree contains a symlink: {path}")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if relative not in omitted:
                result.append(relative)
        elif not path.is_dir():
            raise CampaignImportError(f"artifact tree contains a special file: {path}")
    return sorted(result)


def parse_sha256sums(path: Path) -> dict[str, str]:
    raw = _read_regular_bytes(path)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise CampaignImportError(f"SHA256SUMS is not ASCII: {path}") from error
    if not text.endswith("\n"):
        raise CampaignImportError(f"SHA256SUMS lacks its final newline: {path}")
    result: dict[str, str] = {}
    order: list[str] = []
    for row in text.splitlines():
        digest, separator, name = row.partition("  ")
        if not separator or HEX64.fullmatch(digest) is None or name in result:
            raise CampaignImportError(f"malformed SHA256SUMS row: {row!r}")
        _safe_relative(name, "SHA256SUMS path")
        if name == "SHA256SUMS":
            raise CampaignImportError("SHA256SUMS must not include itself")
        result[name] = digest
        order.append(name)
    if not result:
        raise CampaignImportError(f"SHA256SUMS is empty: {path}")
    if order != sorted(order):
        raise CampaignImportError(f"SHA256SUMS is not canonically ordered: {path}")
    return result


def verify_root_bundle(root: Path) -> dict[str, Measurement]:
    _require_directory(root, "published campaign")
    expected = parse_sha256sums(root / "SHA256SUMS")
    before = recursive_regular_files(root, omit={"SHA256SUMS"})
    if set(expected) != set(before):
        raise CampaignImportError("campaign SHA256SUMS inventory differs")
    measured: dict[str, Measurement] = {}
    for name, digest in expected.items():
        measurement = measure_regular(_rooted(root, name, "SHA256SUMS path"))
        if measurement.sha256 != digest:
            raise CampaignImportError(f"SHA-256 mismatch for {name}")
        measured[name] = measurement
    after = recursive_regular_files(root, omit={"SHA256SUMS"})
    if before != after:
        raise CampaignImportError("campaign file inventory changed while measured")
    return measured


def verify_nested_bundle(
    campaign_root: Path,
    nested_root: Path,
    campaign_measurements: Mapping[str, Measurement],
) -> dict[str, str]:
    _require_directory(nested_root, "nested checksum bundle")
    expected = parse_sha256sums(nested_root / "SHA256SUMS")
    actual = recursive_regular_files(nested_root, omit={"SHA256SUMS"})
    if set(expected) != set(actual):
        raise CampaignImportError(
            f"nested SHA256SUMS inventory differs: {nested_root}"
        )
    prefix = nested_root.relative_to(campaign_root).as_posix()
    for name, digest in expected.items():
        campaign_name = f"{prefix}/{name}"
        measured = campaign_measurements.get(campaign_name)
        if measured is None or measured.sha256 != digest:
            raise CampaignImportError(
                f"nested SHA-256 differs from campaign manifest: {campaign_name}"
            )
    return expected


def _read_regular_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CampaignImportError(f"cannot read regular file {path}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CampaignImportError(f"input is not a regular file: {path}")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after):
            raise CampaignImportError(f"input changed while read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_bound_json(
    campaign_root: Path,
    relative: str,
    measurements: Mapping[str, Measurement],
    label: str,
) -> dict[str, Any]:
    expected = measurements.get(relative)
    if expected is None:
        raise CampaignImportError(f"{label} is absent from campaign SHA256SUMS")
    raw = _read_regular_bytes(_rooted(campaign_root, relative, label))
    if len(raw) != expected.bytes or sha256_bytes(raw) != expected.sha256:
        raise CampaignImportError(f"{label} changed after campaign validation")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CampaignImportError(f"{label} is not UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise CampaignImportError(f"{label} is not a JSON object")
    return value


def read_bound_bytes(
    campaign_root: Path,
    relative: str,
    measurements: Mapping[str, Measurement],
    label: str,
) -> bytes:
    expected = measurements.get(relative)
    if expected is None:
        raise CampaignImportError(f"{label} is absent from campaign SHA256SUMS")
    raw = _read_regular_bytes(_rooted(campaign_root, relative, label))
    if len(raw) != expected.bytes or sha256_bytes(raw) != expected.sha256:
        raise CampaignImportError(f"{label} changed after campaign validation")
    return raw


def _ordered_application_rows(value: object, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != len(APPLICATIONS):
        raise CampaignImportError(f"{label} does not contain exactly 21 rows")
    if any(not isinstance(row, dict) for row in value):
        raise CampaignImportError(f"{label} contains a non-object row")
    rows = [row for row in value if isinstance(row, dict)]
    if tuple(row.get("application") for row in rows) != APPLICATIONS:
        raise CampaignImportError(f"{label} is not in canonical Embench21 order")
    return rows


def validate_suite_manifest(manifest: dict[str, Any]) -> tuple[Application, ...]:
    rows = manifest.get("applications")
    if manifest.get("schema") != SUITE_SCHEMA or not isinstance(rows, list):
        raise CampaignImportError("unsupported input suite manifest")
    if len(rows) != len(APPLICATIONS) or any(not isinstance(row, dict) for row in rows):
        raise CampaignImportError("input suite manifest is not the complete 21-app set")
    if tuple(row.get("name") for row in rows if isinstance(row, dict)) != APPLICATIONS:
        raise CampaignImportError("input suite manifest order differs from Embench21")
    toolchains = manifest.get("toolchains")
    if not isinstance(toolchains, dict):
        raise CampaignImportError("input suite manifest has no toolchain bindings")
    applications: list[Application] = []
    indirect: set[str] = set()
    for row in rows:
        assert isinstance(row, dict)
        name = row.get("name")
        digest = row.get("elf_sha256")
        profile = row.get("runtime_profile")
        policy = row.get("indirect_policy")
        toolchain = toolchains.get(row.get("toolchain"))
        if (
            not isinstance(name, str)
            or not isinstance(digest, str)
            or HEX64.fullmatch(digest) is None
            or profile not in {"ubuntu20", "ubuntu22"}
            or (policy is not None and not isinstance(policy, str))
            or not isinstance(toolchain, dict)
            or toolchain.get("runtime_profile") != profile
        ):
            raise CampaignImportError(f"{name}: malformed suite identity")
        if policy is not None:
            _safe_relative(policy, f"{name} indirect policy")
            indirect.add(name)
        applications.append(Application(name, digest, profile, policy))
    if indirect != set(INDIRECT_APPLICATIONS):
        raise CampaignImportError("suite indirect-policy application set differs")
    return tuple(applications)


def validate_trusted_suite(
    campaign_root: Path,
    suite_root: Path,
    applications: tuple[Application, ...],
    campaign_measurements: Mapping[str, Measurement],
    input_checksums: Mapping[str, str],
) -> dict[str, Measurement]:
    """Bind the self-sealed snapshot to a separately supplied trusted suite."""

    trusted = suite_root.absolute()
    _require_directory(trusted, "trusted suite root")
    try:
        trusted.relative_to(campaign_root)
    except ValueError:
        pass
    else:
        raise CampaignImportError(
            "trusted suite root must be external to the published campaign"
        )
    trusted_manifest_raw = _read_regular_bytes(trusted / "manifest.json")
    try:
        trusted_manifest = json.loads(trusted_manifest_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CampaignImportError("trusted suite manifest is not UTF-8 JSON") from error
    if not isinstance(trusted_manifest, dict):
        raise CampaignImportError("trusted suite manifest is not a JSON object")
    trusted_applications = validate_suite_manifest(trusted_manifest)
    if trusted_applications != applications:
        raise CampaignImportError("trusted suite identities differ from campaign snapshot")

    expected = {
        "manifest.json",
        *(f"bin/{app.name}" for app in applications),
        *(
            app.indirect_policy
            for app in applications
            if app.indirect_policy is not None
        ),
    }
    for name in PROVENANCE_FILES:
        candidate = trusted / name
        if candidate.exists() or candidate.is_symlink():
            expected.add(name)
    if set(input_checksums) - {"input-manifest.json"} != expected:
        raise CampaignImportError(
            "campaign input snapshot does not exactly mirror the trusted suite"
        )

    trusted_measurements: dict[str, Measurement] = {}
    for name in sorted(expected):
        trusted_path = _rooted(trusted, name, "trusted suite file")
        campaign_name = f"inputs/{name}"
        trusted_measurement = measure_regular(trusted_path)
        campaign_measurement = campaign_measurements.get(campaign_name)
        if (
            campaign_measurement != trusted_measurement
            or input_checksums.get(name) != trusted_measurement.sha256
            or _read_regular_bytes(trusted_path)
            != _read_regular_bytes(_rooted(campaign_root, campaign_name, "input snapshot"))
        ):
            raise CampaignImportError(
                f"trusted suite bytes differ from campaign snapshot: {name}"
            )
        trusted_measurements[name] = trusted_measurement
    return trusted_measurements


def _validate_runtime_dependency_manifest(
    manifest: dict[str, Any], profile: str
) -> None:
    files = manifest.get("files")
    if (
        set(manifest) != RUNTIME_MANIFEST_FIELDS
        or manifest.get("schema") != "zkcfa.runtime-dependencies"
        or manifest.get("runtime_profile") != profile
        or manifest.get("binding") != "eager"
        or manifest.get("loader_scope") != "trusted-out-of-scope"
        or manifest.get("environment") != {"LD_BIND_NOW": "1"}
        or not isinstance(files, list)
        or len(files) != len(RUNTIME_DEPENDENCY_FILES)
    ):
        raise CampaignImportError(f"{profile}: runtime dependency manifest differs")
    paths: list[str] = []
    for row in files:
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "sha256"}
            or not isinstance(row.get("sha256"), str)
            or HEX64.fullmatch(row["sha256"]) is None
        ):
            raise CampaignImportError(f"{profile}: malformed runtime dependency row")
        paths.append(_safe_relative(row.get("path"), f"{profile} runtime path"))
    if tuple(paths) != RUNTIME_DEPENDENCY_FILES:
        raise CampaignImportError(f"{profile}: runtime dependency inventory differs")


def validate_runtime_snapshot(
    root: Path,
    campaign: dict[str, Any],
    measurements: Mapping[str, Measurement],
    runtime_checksums: Mapping[str, str],
) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    snapshot = read_bound_json(
        root,
        "runtime-manifests/manifest.json",
        measurements,
        "runtime manifest snapshot",
    )
    if campaign.get("runtime_manifest_snapshot") != snapshot:
        raise CampaignImportError("campaign runtime snapshot differs from its bound file")
    if (
        campaign.get("runtime_manifest_snapshot_sha256sums")
        != measurements["runtime-manifests/SHA256SUMS"].sha256
    ):
        raise CampaignImportError("campaign runtime SHA256SUMS pin differs")
    profiles = snapshot.get("profiles")
    if (
        snapshot.get("schema") != RUNTIME_MANIFEST_SNAPSHOT_SCHEMA
        or snapshot.get("snapshot") != "read-once-regular-file-copy-v1"
        or not isinstance(profiles, dict)
        or set(profiles) != set(RUNTIME_PROFILES)
    ):
        raise CampaignImportError("runtime manifest snapshot contract differs")
    expected = {
        "manifest.json",
        *(f"{profile}/runtime-dependencies.json" for profile in RUNTIME_PROFILES),
    }
    if set(runtime_checksums) != expected:
        raise CampaignImportError("runtime manifest snapshot inventory differs")

    result: dict[str, str] = {}
    manifests: dict[str, dict[str, Any]] = {}
    for profile in RUNTIME_PROFILES:
        relative = f"{profile}/runtime-dependencies.json"
        row = profiles.get(profile)
        measurement = measurements.get(f"runtime-manifests/{relative}")
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "source", "bytes", "sha256"}
            or row.get("path") != relative
            or not isinstance(row.get("source"), str)
            or not Path(row["source"]).is_absolute()
            or type(row.get("bytes")) is not int
            or measurement is None
            or row.get("bytes") != measurement.bytes
            or row.get("sha256") != measurement.sha256
            or runtime_checksums.get(relative) != measurement.sha256
        ):
            raise CampaignImportError(f"{profile}: runtime snapshot binding differs")
        manifest = read_bound_json(
            root,
            f"runtime-manifests/{relative}",
            measurements,
            f"{profile} runtime dependency manifest",
        )
        _validate_runtime_dependency_manifest(manifest, profile)
        result[profile] = measurement.sha256
        manifests[profile] = manifest
    return result, manifests


def validate_input_snapshot(
    root: Path,
    campaign: dict[str, Any],
    measurements: Mapping[str, Measurement],
    input_checksums: Mapping[str, str],
) -> tuple[dict[str, Any], tuple[Application, ...]]:
    input_manifest = read_bound_json(
        root, "inputs/input-manifest.json", measurements, "input snapshot manifest"
    )
    if campaign.get("input_snapshot") != input_manifest:
        raise CampaignImportError("campaign input_snapshot differs from its bound file")
    if (
        campaign.get("input_snapshot_sha256sums")
        != measurements["inputs/SHA256SUMS"].sha256
    ):
        raise CampaignImportError("campaign input SHA256SUMS pin differs")
    if (
        input_manifest.get("schema") != INPUT_SCHEMA
        or input_manifest.get("applications") != list(APPLICATIONS)
        or input_manifest.get("snapshot") != "read-once-regular-file-copy-v1"
    ):
        raise CampaignImportError("input snapshot contract differs")
    inventory = input_manifest.get("files")
    if not isinstance(inventory, dict):
        raise CampaignImportError("input snapshot file inventory is absent")
    expected_inventory = set(input_checksums) - {"input-manifest.json"}
    if set(inventory) != expected_inventory:
        raise CampaignImportError("input snapshot inventory differs from SHA256SUMS")
    for name, row in inventory.items():
        if not isinstance(row, dict) or set(row) != {"bytes", "sha256"}:
            raise CampaignImportError(f"input inventory row is malformed: {name}")
        measurement = measurements.get(f"inputs/{name}")
        if (
            measurement is None
            or row.get("sha256") != input_checksums.get(name)
            or row.get("sha256") != measurement.sha256
            or type(row.get("bytes")) is not int
            or row.get("bytes") != measurement.bytes
        ):
            raise CampaignImportError(f"input inventory measurement differs: {name}")

    suite = read_bound_json(root, "inputs/manifest.json", measurements, "suite manifest")
    applications = validate_suite_manifest(suite)
    for app in applications:
        binary_name = f"inputs/bin/{app.name}"
        binary = measurements.get(binary_name)
        if binary is None or binary.sha256 != app.elf_sha256:
            raise CampaignImportError(f"{app.name}: snapshotted ELF hash differs")
        if app.indirect_policy is not None:
            policy_name = f"inputs/{app.indirect_policy}"
            policy_document = read_bound_json(
                root, policy_name, measurements, f"{app.name} indirect policy"
            )
            if (
                policy_document.get("schema")
                not in {
                    "zkcfa.indirect-target-policy.v1",
                    "zkcfa.indirect-target-policy",
                }
                or policy_document.get("application") != app.name
                or policy_document.get("elf_sha256") != app.elf_sha256
                or not isinstance(policy_document.get("indirect_calls"), dict)
                or not isinstance(policy_document.get("indirect_jumps"), dict)
            ):
                raise CampaignImportError(f"{app.name}: input policy binding differs")
    return input_manifest, applications


def _complete_boundary(evidence: dict[str, Any]) -> dict[str, Any]:
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
        raise CampaignImportError("QEMU evidence lacks a complete measured main boundary")
    return boundary


def _validate_dynamic_trace(
    plugin_map: bytes,
    trace: bytes,
    elf_sha256: str,
    event_count: int,
    external_call_count: int,
) -> None:
    try:
        map_lines = plugin_map.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise CampaignImportError("QEMU plugin map is not ASCII") from error
    elf_rows = [line for line in map_lines if line.startswith("elf_sha256 ")]
    schema_rows = [line for line in map_lines if line.startswith("trace_schema ")]
    trace_lines = trace.splitlines()
    header = TRACE_HEADER.fullmatch(trace_lines[0] if trace_lines else b"")
    ending = TRACE_END.fullmatch(trace_lines[-1] if trace_lines else b"")
    if (
        map_lines[:1] != ["zkcfa.provider.map"]
        or elf_rows != [f"elf_sha256 {elf_sha256}"]
        or schema_rows != ["trace_schema zkcfa.scope.trace"]
        or header is None
        or header.group(1).decode("ascii") != elf_sha256
        or ending is None
        or int(ending.group(1)) != event_count
        or sum(line.startswith(b"insn ") for line in trace_lines) != event_count
        or sum(line.startswith(b"external_call ") for line in trace_lines)
        != external_call_count
        or not any(
            line.startswith(b"scope_exit ")
            and line.endswith(b" return_continuation_matched=1")
            for line in trace_lines
        )
    ):
        raise CampaignImportError("QEMU trace/plugin-map/event bindings differ")


def _regenerate_recorded_path_and_evidence(
    root: Path,
    app: Application,
    measurements: Mapping[str, Measurement],
    trusted_provider: TrustedProvider,
) -> tuple[bytes, dict[str, Any]]:
    prefix = f"qemu/{app.name}"
    sources = {
        "plugin-map.txt": read_bound_bytes(
            root,
            f"{prefix}/artifacts/plugin-map.txt",
            measurements,
            f"{app.name} plugin map",
        ),
        "trace.log": read_bound_bytes(
            root,
            f"{prefix}/trace.log",
            measurements,
            f"{app.name} QEMU trace",
        ),
        "typed_cfg": read_bound_bytes(
            root,
            f"{prefix}/artifacts/typed_cfg",
            measurements,
            f"{app.name} typed CFG",
        ),
        "translator": read_bound_bytes(
            root,
            f"{prefix}/artifacts/translator",
            measurements,
            f"{app.name} translator",
        ),
        "static-manifest.json": read_bound_bytes(
            root,
            f"{prefix}/artifacts/static-manifest.json",
            measurements,
            f"{app.name} static manifest",
        ),
    }
    with tempfile.TemporaryDirectory(prefix=f".zkcfa-normalize-{app.name}-") as raw:
        private = Path(raw)
        paths: dict[str, Path] = {}
        for name, contents in sources.items():
            path = private / name
            with path.open("xb") as stream:
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
            path.chmod(0o400)
            paths[name] = path
        try:
            plugin_map = trusted_provider.normalizer.parse_plugin_map(
                paths["plugin-map.txt"]
            )
            trace = trusted_provider.normalizer.parse_trace(paths["trace.log"])
            operations = trusted_provider.normalizer.normalize(
                plugin_map,
                trace,
                trusted_provider.normalizer.load_typed_cfg(paths["typed_cfg"]),
                trusted_provider.normalizer.load_translator(paths["translator"]),
            )
            rendered = trusted_provider.normalizer.render_recorded_path(operations)
            rendered_bytes = rendered.encode("ascii")
            recorded_path = private / "recorded_path"
            with recorded_path.open("xb") as stream:
                stream.write(rendered_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            regenerated_evidence = trusted_provider.normalizer.build_trace_evidence(
                plugin_map=plugin_map,
                trace=trace,
                recorded_path=recorded_path,
                typed_cfg=paths["typed_cfg"],
                expected_typed_cfg_sha256=sha256_bytes(sources["typed_cfg"]),
                translator=paths["translator"],
                static_manifest=paths["static-manifest.json"],
                plugin_map_path=paths["plugin-map.txt"],
            )
        except Exception as error:
            raise CampaignImportError(
                f"{app.name}: trusted provider path/evidence regeneration failed: {error}"
            ) from error
    if not isinstance(regenerated_evidence, dict):
        raise CampaignImportError(
            f"{app.name}: trusted provider returned non-object trace evidence"
        )
    return rendered_bytes, regenerated_evidence


def _validate_static_bindings(
    static_manifest: dict[str, Any],
    evidence: dict[str, Any],
    boundary: dict[str, Any],
    app: Application,
    artifact_measurements: Mapping[str, Measurement],
    runtime_manifest_sha256: str,
    runtime_manifest: dict[str, Any],
    indirect_policy_sha256: str | None,
) -> None:
    scope = static_manifest.get("scope_policy")
    external = static_manifest.get("external_call_policy")
    runtime = external.get("runtime_dependencies") if isinstance(external, dict) else None
    if (
        static_manifest.get("schema") != "zkcfa.static"
        or static_manifest.get("application") != app.name
        or static_manifest.get("architecture") != "x86_64"
        or static_manifest.get("elf_sha256") != app.elf_sha256
        or static_manifest.get("runtime_profile") != app.runtime_profile
        or static_manifest.get("runtime_dependencies_sha256")
        != runtime_manifest_sha256
        or static_manifest.get("proof_path_compression") != "none"
        or static_manifest.get("trace_schema") != "zkcfa.scope.trace"
        or static_manifest.get("plugin_map_sha256")
        != artifact_measurements["plugin-map.txt"].sha256
        or static_manifest.get("translator_sha256")
        != artifact_measurements["translator"].sha256
        or static_manifest.get("typed_cfg_sha256")
        != artifact_measurements["typed_cfg"].sha256
        or evidence.get("schema") != "zkcfa.raw.evidence"
        or evidence.get("recorded_path_sha256")
        != artifact_measurements["recorded_path"].sha256
        or evidence.get("typed_cfg_sha256")
        != artifact_measurements["typed_cfg"].sha256
        or not isinstance(scope, dict)
        or scope.get("root_symbol") != "main"
        or scope.get("external_entry") is not True
        or scope.get("require_complete_entry_exit") is not True
        or scope.get("boundary_kind") != boundary.get("boundary_kind")
        or scope.get("root_address") != boundary.get("root_address")
        or scope.get("scope_call_address") != boundary.get("scope_call_address")
        or scope.get("scope_return_address") != boundary.get("scope_exit_address")
        or not isinstance(runtime, dict)
        or runtime != runtime_manifest
    ):
        raise CampaignImportError(f"{app.name}: evidence/static artifact bindings differ")
    static_policy = static_manifest.get("indirect_target_policy")
    if indirect_policy_sha256 is None:
        if static_policy != {
            "schema": "zkcfa.indirect-target-policy",
            "policy_sha256": None,
            "calls": {},
            "jumps": {},
        }:
            raise CampaignImportError(f"{app.name}: unexpected indirect policy binding")
    elif (
        not isinstance(static_policy, dict)
        or static_policy.get("schema") != "zkcfa.indirect-target-policy"
        or static_policy.get("policy_sha256") != indirect_policy_sha256
        or not isinstance(static_policy.get("calls"), dict)
        or not isinstance(static_policy.get("jumps"), dict)
    ):
        raise CampaignImportError(f"{app.name}: static indirect-policy binding differs")


def _validate_qemu_application(
    root: Path,
    app: Application,
    qemu_row: dict[str, Any],
    measurements: Mapping[str, Measurement],
    local_checksums: Mapping[str, str],
    runtime_bindings: Mapping[str, Any],
    runtime_manifests: Mapping[str, dict[str, Any]],
    trusted_provider: TrustedProvider,
) -> None:
    prefix = f"qemu/{app.name}"
    manifest = read_bound_json(
        root, f"{prefix}/manifest.json", measurements, f"{app.name} QEMU manifest"
    )
    if manifest != qemu_row:
        raise CampaignImportError(f"{app.name}: QEMU capture row differs from manifest")
    input_row = manifest.get("input")
    boundary = manifest.get("boundary")
    if (
        manifest.get("application") != app.name
        or manifest.get("status") != "COMPLETE"
        or type(manifest.get("guest_exit_status")) is not int
        or manifest.get("guest_exit_status") != 0
        or not isinstance(input_row, dict)
        or input_row.get("copied_by_lane") is not False
        or input_row.get("recompiled") is not False
        or any(
            input_row.get(name) != app.elf_sha256
            for name in (
                "sha256_before",
                "sha256_immediately_before_execution",
                "sha256_after_capture",
            )
        )
    ):
        raise CampaignImportError(f"{app.name}: QEMU status/three ELF measurements differ")
    if (
        not isinstance(boundary, dict)
        or type(manifest.get("event_count")) is not int
        or manifest["event_count"] < 1
        or type(manifest.get("external_call_count")) is not int
        or manifest["external_call_count"] < 0
        or type(manifest.get("elapsed_seconds")) not in {int, float}
        or not math.isfinite(float(manifest["elapsed_seconds"]))
        or float(manifest["elapsed_seconds"]) < 0
    ):
        raise CampaignImportError(f"{app.name}: QEMU counts or boundary are malformed")

    expected_files = {
        *(f"artifacts/{name}" for name in REGISTRY_FILES),
        *QEMU_LOG_FILES,
        "trace.log",
    }
    if app.indirect_policy is not None:
        expected_files.add("indirect-policy.json")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != expected_files:
        raise CampaignImportError(f"{app.name}: QEMU file inventory differs")
    if set(local_checksums) != {*expected_files, "manifest.json"}:
        raise CampaignImportError(f"{app.name}: application SHA256SUMS differs")
    for name, row in files.items():
        measurement = measurements.get(f"{prefix}/{name}")
        if (
            not isinstance(row, dict)
            or set(row) != {"bytes", "sha256"}
            or measurement is None
            or row.get("sha256") != local_checksums.get(name)
            or row.get("sha256") != measurement.sha256
            or type(row.get("bytes")) is not int
            or row.get("bytes") != measurement.bytes
        ):
            raise CampaignImportError(f"{app.name}: QEMU file measurement differs: {name}")

    artifact_measurements = {
        name: measurements[f"{prefix}/artifacts/{name}"] for name in REGISTRY_FILES
    }
    evidence = read_bound_json(
        root,
        f"{prefix}/artifacts/evidence.json",
        measurements,
        f"{app.name} QEMU evidence",
    )
    measured_boundary = _complete_boundary(evidence)
    if boundary != measured_boundary:
        raise CampaignImportError(f"{app.name}: manifest/evidence boundary differs")
    event_count = evidence.get("event_count")
    external_count = evidence.get("external_call_count")
    if (
        event_count != manifest.get("event_count")
        or external_count != manifest.get("external_call_count")
        or type(event_count) is not int
        or event_count < 1
        or type(external_count) is not int
        or external_count < 0
    ):
        raise CampaignImportError(f"{app.name}: manifest/evidence event counts differ")

    recorded_path = read_bound_bytes(
        root,
        f"{prefix}/artifacts/recorded_path",
        measurements,
        f"{app.name} recorded path",
    )
    try:
        path_lines = recorded_path.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise CampaignImportError(f"{app.name}: recorded path is not ASCII") from error
    if (
        not path_lines
        or path_lines[0].split()
        != ["initial_node=SCOPE_RETURN", "final_node=SCOPE_RETURN"]
        or manifest.get("recorded_path_rows_including_header") != len(path_lines)
    ):
        raise CampaignImportError(f"{app.name}: complete recorded-path binding differs")

    plugin_map = read_bound_bytes(
        root,
        f"{prefix}/artifacts/plugin-map.txt",
        measurements,
        f"{app.name} plugin map",
    )
    trace = read_bound_bytes(
        root,
        f"{prefix}/trace.log",
        measurements,
        f"{app.name} QEMU trace",
    )
    _validate_dynamic_trace(
        plugin_map, trace, app.elf_sha256, event_count, external_count
    )
    static_manifest = read_bound_json(
        root,
        f"{prefix}/artifacts/static-manifest.json",
        measurements,
        f"{app.name} static manifest",
    )
    runtime_binding = runtime_bindings.get(app.runtime_profile)
    if (
        not isinstance(runtime_binding, dict)
        or not isinstance(runtime_binding.get("manifest_sha256"), str)
        or HEX64.fullmatch(runtime_binding["manifest_sha256"]) is None
    ):
        raise CampaignImportError(f"{app.name}: runtime binding is absent")
    policy_sha256: str | None = None
    if app.indirect_policy is not None:
        policy_name = f"{prefix}/indirect-policy.json"
        policy_sha256 = measurements[policy_name].sha256
        policy = read_bound_json(
            root, policy_name, measurements, f"{app.name} canonical indirect policy"
        )
        source_policy = read_bound_json(
            root,
            f"inputs/{app.indirect_policy}",
            measurements,
            f"{app.name} snapshotted indirect policy",
        )
        expected_policy = {
            "schema": "zkcfa.indirect-target-policy",
            "application": app.name,
            "elf_sha256": app.elf_sha256,
            "indirect_calls": source_policy.get("indirect_calls"),
            "indirect_jumps": source_policy.get("indirect_jumps"),
        }
        if (
            policy != expected_policy
            or not isinstance(policy.get("indirect_calls"), dict)
            or not isinstance(policy.get("indirect_jumps"), dict)
        ):
            raise CampaignImportError(f"{app.name}: canonical QEMU policy differs")
    _validate_static_bindings(
        static_manifest,
        evidence,
        boundary,
        app,
        artifact_measurements,
        runtime_binding["manifest_sha256"],
        runtime_manifests[app.runtime_profile],
        policy_sha256,
    )
    regenerated, regenerated_evidence = _regenerate_recorded_path_and_evidence(
        root, app, measurements, trusted_provider
    )
    if regenerated != recorded_path:
        raise CampaignImportError(
            f"{app.name}: recorded path differs byte-for-byte from trusted "
            "provider normalization of the bound raw trace"
        )
    if canonical_json(regenerated_evidence) != canonical_json(evidence):
        raise CampaignImportError(
            f"{app.name}: trace evidence differs from trusted provider recomputation"
        )


def _validate_lane_summaries(
    root: Path,
    campaign: dict[str, Any],
    measurements: Mapping[str, Measurement],
) -> None:
    lanes = campaign.get("lanes")
    if not isinstance(lanes, dict) or set(lanes) != {"qemu", "compat", "comparison"}:
        raise CampaignImportError("campaign lane set differs")
    pins = {
        "qemu": ("qemu/capture.json", "qemu/SHA256SUMS", "complete", 21),
        "compat": ("compat/capture.json", "compat/SHA256SUMS", "complete", 21),
        "comparison": (
            "comparison/summary.json",
            "comparison/SHA256SUMS",
            "accepted",
            21,
        ),
    }
    for lane, (summary_name, sums_name, count_name, count) in pins.items():
        row = lanes.get(lane)
        if (
            not isinstance(row, dict)
            or type(row.get(count_name)) is not int
            or row.get(count_name) != count
        ):
            raise CampaignImportError(f"campaign {lane} lane count differs")
        summary_key = "summary_sha256" if lane == "comparison" else "capture_sha256"
        if (
            row.get(summary_key) != measurements[summary_name].sha256
            or row.get("sha256sums") != measurements[sums_name].sha256
        ):
            raise CampaignImportError(f"campaign {lane} lane hash pin differs")

    compat = read_bound_json(root, "compat/capture.json", measurements, "compat summary")
    comparison = read_bound_json(
        root, "comparison/summary.json", measurements, "comparison summary"
    )
    compat_rows = _ordered_application_rows(compat.get("applications"), "compat summary")
    comparison_rows = _ordered_application_rows(
        comparison.get("applications"), "comparison summary"
    )
    if (
        compat.get("schema") != COMPAT_SCHEMA
        or type(compat.get("complete")) is not int
        or compat.get("complete") != 21
        or type(compat.get("failed")) is not int
        or compat.get("failed") != 0
        or compat.get("inputs_unchanged") is not True
        or any(row.get("status") != "COMPLETE" for row in compat_rows)
    ):
        raise CampaignImportError("compat lane is not 21/21 COMPLETE")
    if (
        comparison.get("schema") != COMPARISON_SCHEMA
        or type(comparison.get("accepted")) is not int
        or comparison.get("accepted") != 21
        or type(comparison.get("failed")) is not int
        or comparison.get("failed") != 0
        or comparison.get("all_fresh_same_elf_comparisons_accepted") is not True
        or any(
            row.get("status") != "ACCEPT"
            or row.get("comparison_accepts") is not True
            for row in comparison_rows
        )
    ):
        raise CampaignImportError("comparison lane is not 21/21 ACCEPT")


def _validate_campaign_snapshot(
    source: Path,
    trusted_suite: Path,
    trusted_provider: TrustedProvider,
    expected_qemu_revision: str,
    expected_campaign_sha256s_sha256: str,
) -> ValidatedCampaign:
    root = source.absolute()
    if HEX64.fullmatch(expected_campaign_sha256s_sha256) is None:
        raise CampaignImportError("expected campaign SHA256SUMS hash is not SHA-256")
    actual_campaign_sha256s_sha256 = measure_regular(root / "SHA256SUMS").sha256
    if actual_campaign_sha256s_sha256 != expected_campaign_sha256s_sha256:
        raise CampaignImportError(
            "published campaign SHA256SUMS differs from the caller-provided trust root"
        )
    measurements = verify_root_bundle(root)
    _require_entries(
        root,
        {
            "SHA256SUMS",
            "campaign.json",
            "comparison",
            "compat",
            "inputs",
            "logs",
            "qemu",
            "runtime-manifests",
        },
        "published campaign root",
    )
    campaign = read_bound_json(root, "campaign.json", measurements, "campaign manifest")
    if (
        campaign.get("schema") != CAMPAIGN_SCHEMA
        or campaign.get("status") != "COMPLETE"
        or campaign.get("applications") != list(APPLICATIONS)
        or type(campaign.get("application_count")) is not int
        or campaign.get("application_count") != len(APPLICATIONS)
    ):
        raise CampaignImportError("campaign is not a canonical COMPLETE 21-app run")
    claims = campaign.get("claims")
    if not isinstance(claims, dict) or any(
        claims.get(name) is not expected for name, expected in EXPECTED_CLAIMS.items()
    ):
        raise CampaignImportError("campaign publication claims differ")

    input_checksums = verify_nested_bundle(
        root, root / "inputs", measurements
    )
    runtime_checksums = verify_nested_bundle(
        root, root / "runtime-manifests", measurements
    )
    qemu_checksums = verify_nested_bundle(root, root / "qemu", measurements)
    verify_nested_bundle(root, root / "compat", measurements)
    verify_nested_bundle(root, root / "comparison", measurements)
    _validate_lane_summaries(root, campaign, measurements)
    input_manifest, applications = validate_input_snapshot(
        root, campaign, measurements, input_checksums
    )
    trusted_suite_measurements = validate_trusted_suite(
        root,
        trusted_suite,
        applications,
        measurements,
        input_checksums,
    )
    runtime_manifest_hashes, runtime_manifests = validate_runtime_snapshot(
        root, campaign, measurements, runtime_checksums
    )

    qemu_summary = read_bound_json(
        root, "qemu/capture.json", measurements, "QEMU capture summary"
    )
    qemu_rows = _ordered_application_rows(
        qemu_summary.get("applications"), "QEMU capture summary"
    )
    if (
        qemu_summary.get("schema") != QEMU_SCHEMA
        or type(qemu_summary.get("complete")) is not int
        or qemu_summary.get("complete") != 21
        or type(qemu_summary.get("failed")) is not int
        or qemu_summary.get("failed") != 0
        or qemu_summary.get("inputs_unchanged") is not True
    ):
        raise CampaignImportError("QEMU lane is not 21/21 COMPLETE")
    expected_hashes = {app.name: app.elf_sha256 for app in applications}
    if qemu_summary.get("input_hashes_after") != expected_hashes:
        raise CampaignImportError("QEMU post-capture input hashes differ")
    if set(qemu_checksums) != {
        "capture.json",
        "environment/environment.json",
        "environment/plugin-build.log",
        "environment/trace_scope.so",
        *(f"{app.name}/{name}" for app in applications for name in (
            *(f"artifacts/{artifact}" for artifact in REGISTRY_FILES),
            *QEMU_LOG_FILES,
            "trace.log",
            "manifest.json",
            "SHA256SUMS",
        )),
        *(f"{app.name}/indirect-policy.json" for app in applications if app.indirect_policy),
    }:
        raise CampaignImportError("QEMU lane file inventory differs")
    _require_entries(
        root / "qemu",
        {"SHA256SUMS", "capture.json", "environment", *APPLICATIONS},
        "QEMU lane root",
    )
    _require_entries(
        root / "qemu/environment",
        {"environment.json", "plugin-build.log", "trace_scope.so"},
        "QEMU environment",
    )

    environment = read_bound_json(
        root,
        "qemu/environment/environment.json",
        measurements,
        "QEMU environment",
    )
    qemu_revision = qemu_summary.get("qemu_revision")
    runtime_bindings = qemu_summary.get("runtime_bindings")
    provider_sources = environment.get("provider_sources")
    implementations = campaign.get("implementations")
    if qemu_revision != expected_qemu_revision:
        raise CampaignImportError(
            "QEMU revision differs from the exact caller-trusted commit"
        )
    if (
        environment.get("schema") != QEMU_ENVIRONMENT_SCHEMA
        or not isinstance(qemu_revision, str)
        or HEX40.fullmatch(qemu_revision) is None
        or environment.get("qemu_revision") != qemu_revision
        or not isinstance(implementations, dict)
        or implementations.get("qemu_revision") != qemu_revision
        or environment.get("plugin_sha256")
        != measurements["qemu/environment/trace_scope.so"].sha256
        or qemu_summary.get("trace_plugin_sha256")
        != environment.get("plugin_sha256")
        or not isinstance(runtime_bindings, dict)
        or runtime_bindings != environment.get("runtime_bindings")
        or set(runtime_bindings) != {"ubuntu20", "ubuntu22"}
        or not isinstance(provider_sources, dict)
        or set(provider_sources) != PROVIDER_SOURCE_FILES
        or any(
            not isinstance(value, str) or HEX64.fullmatch(value) is None
            for value in provider_sources.values()
        )
        or any(
            provider_sources.get(name)
            != trusted_provider.measurements[name].sha256
            for name in PROVIDER_SOURCE_FILES
        )
        or any(
            not isinstance(runtime_bindings.get(profile), dict)
            or runtime_bindings[profile].get("manifest_sha256")
            != runtime_manifest_hashes[profile]
            for profile in RUNTIME_PROFILES
        )
    ):
        raise CampaignImportError("QEMU environment/source/runtime bindings differ")

    qemu_results = {row["application"]: row for row in qemu_rows}
    for app in applications:
        expected_app_entries = {
            "SHA256SUMS",
            "artifacts",
            "logs",
            "manifest.json",
            "trace.log",
        }
        if app.indirect_policy is not None:
            expected_app_entries.add("indirect-policy.json")
        _require_entries(
            root / "qemu" / app.name,
            expected_app_entries,
            f"{app.name} QEMU bundle",
        )
        _require_entries(
            root / "qemu" / app.name / "artifacts",
            set(REGISTRY_FILES),
            f"{app.name} QEMU artifacts",
        )
        _require_entries(
            root / "qemu" / app.name / "logs",
            {"normalize.log", "provision.log", "qemu.log"},
            f"{app.name} QEMU logs",
        )
        local_checksums = verify_nested_bundle(
            root, root / "qemu" / app.name, measurements
        )
        _validate_qemu_application(
            root,
            app,
            qemu_results[app.name],
            measurements,
            local_checksums,
            runtime_bindings,
            runtime_manifests,
            trusted_provider,
        )
    return ValidatedCampaign(
        root=root,
        trusted_suite_root=trusted_suite.absolute(),
        trusted_suite_measurements=trusted_suite_measurements,
        campaign=campaign,
        input_manifest=input_manifest,
        qemu_summary=qemu_summary,
        qemu_environment=environment,
        applications=applications,
        qemu_results=qemu_results,
        measurements=measurements,
        trusted_provider_root=trusted_provider.source_root,
        trusted_provider_measurements=trusted_provider.measurements,
        trusted_provider_identity_sha256=trusted_provider.identity_sha256,
        expected_qemu_revision=expected_qemu_revision,
        expected_campaign_sha256s_sha256=expected_campaign_sha256s_sha256,
    )


def validate_campaign(
    source: Path,
    trusted_suite: Path,
    *,
    expected_campaign_sha256s_sha256: str,
    provider_root: Path = DEFAULT_PROVIDER_ROOT,
    expected_qemu_revision: str = EXPECTED_QEMU_REVISION,
) -> ValidatedCampaign:
    if HEX40.fullmatch(expected_qemu_revision) is None:
        raise CampaignImportError("expected QEMU revision is not a 40-hex commit ID")
    source_root = source.absolute()
    provider_source_root = provider_root.absolute()
    try:
        provider_source_root.relative_to(source_root)
    except ValueError:
        pass
    else:
        raise CampaignImportError(
            "trusted provider root must be external to the published campaign"
        )
    with tempfile.TemporaryDirectory(prefix=".zkcfa-trusted-provider-") as temporary:
        trusted_provider = _snapshot_trusted_provider(
            provider_source_root, Path(temporary)
        )
        try:
            return _validate_campaign_snapshot(
                source_root,
                trusted_suite.absolute(),
                trusted_provider,
                expected_qemu_revision,
                expected_campaign_sha256s_sha256,
            )
        finally:
            _unload_trusted_provider(trusted_provider)


def write_json_new(path: Path, value: object) -> None:
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)


def _copy_bound(
    source: Path, destination: Path, expected_sha256: str, *, mode: int
) -> Measurement:
    copy_regular_once(source, destination, mode=mode)
    measured = measure_regular(destination)
    if measured.sha256 != expected_sha256:
        raise CampaignImportError(f"copied input hash differs: {source}")
    return measured


def _validate_imported_output(root: Path, summary: dict[str, Any]) -> None:
    if set(path.name for path in root.iterdir()) != {*APPLICATIONS, "tracer-results.json"}:
        raise CampaignImportError("staged legacy campaign root inventory differs")
    if (
        summary.get("schema") != TRACER_SCHEMA
        or summary.get("application_count") != 21
        or summary.get("passed") != 21
        or summary.get("failed") != 0
        or tuple(row.get("application") for row in summary.get("results", []))
        != APPLICATIONS
    ):
        raise CampaignImportError("staged tracer summary differs")
    for expected in summary["results"]:
        application = expected["application"]
        app_root = root / application
        tracer = app_root / "tracer"
        registry = tracer / "registry"
        if set(path.name for path in app_root.iterdir()) != {"tracer", "trace-result.json"}:
            raise CampaignImportError(f"{application}: staged application inventory differs")
        if set(path.name for path in tracer.iterdir()) != {
            application,
            "trace.log",
            "registry",
        } or set(path.name for path in registry.iterdir()) != set(REGISTRY_FILES):
            raise CampaignImportError(f"{application}: staged tracer inventory differs")
        saved = json.loads((app_root / "trace-result.json").read_text(encoding="ascii"))
        if saved != expected or saved.get("status") != "PASS":
            raise CampaignImportError(f"{application}: staged trace result differs")
        paths = {
            "binary_sha256": tracer / application,
            "trace_sha256": tracer / "trace.log",
            "evidence_sha256": registry / "evidence.json",
            "plugin_map_sha256": registry / "plugin-map.txt",
            "recorded_path_sha256": registry / "recorded_path",
            "static_manifest_sha256": registry / "static-manifest.json",
            "translator_sha256": registry / "translator",
            "typed_cfg_sha256": registry / "typed_cfg",
        }
        hashes = saved.get("hashes")
        if not isinstance(hashes, dict) or any(
            measure_regular(path).sha256 != hashes.get(name)
            for name, path in paths.items()
        ):
            raise CampaignImportError(f"{application}: staged tracer hash differs")


def import_campaign(
    source: Path,
    destination: Path,
    trusted_suite: Path,
    *,
    expected_campaign_sha256s_sha256: str,
    provider_root: Path = DEFAULT_PROVIDER_ROOT,
    expected_qemu_revision: str = EXPECTED_QEMU_REVISION,
) -> dict[str, Any]:
    target = destination.absolute()
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"refusing to overwrite import output: {target}")
    source_root = source.absolute()
    try:
        target.relative_to(source_root)
    except ValueError:
        pass
    else:
        raise CampaignImportError("import output must not be inside its source campaign")
    trusted_suite_root = trusted_suite.absolute()
    try:
        target.relative_to(trusted_suite_root)
    except ValueError:
        pass
    else:
        raise CampaignImportError("import output must not be inside its trusted suite")
    validated = validate_campaign(
        source_root,
        trusted_suite_root,
        expected_campaign_sha256s_sha256=expected_campaign_sha256s_sha256,
        provider_root=provider_root,
        expected_qemu_revision=expected_qemu_revision,
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{target.name}.import-", dir=target.parent
    ) as temporary:
        staging = Path(temporary) / "publish"
        staging.mkdir(mode=0o700)
        results: list[dict[str, Any]] = []
        for app in validated.applications:
            qemu = validated.root / "qemu" / app.name
            app_root = staging / app.name
            tracer = app_root / "tracer"
            registry = tracer / "registry"
            registry.mkdir(parents=True, mode=0o700)
            binary_measurement = _copy_bound(
                validated.root / "inputs/bin" / app.name,
                tracer / app.name,
                app.elf_sha256,
                mode=0o500,
            )
            trace_measurement = _copy_bound(
                qemu / "trace.log",
                tracer / "trace.log",
                validated.measurements[f"qemu/{app.name}/trace.log"].sha256,
                mode=0o600,
            )
            artifact_measurements: dict[str, Measurement] = {}
            for name in REGISTRY_FILES:
                artifact_measurements[name] = _copy_bound(
                    qemu / "artifacts" / name,
                    registry / name,
                    validated.measurements[
                        f"qemu/{app.name}/artifacts/{name}"
                    ].sha256,
                    mode=0o600,
                )
            source_result = validated.qemu_results[app.name]
            hashes = {
                "binary_sha256": binary_measurement.sha256,
                "trace_sha256": trace_measurement.sha256,
                "translator_sha256": artifact_measurements["translator"].sha256,
                "typed_cfg_sha256": artifact_measurements["typed_cfg"].sha256,
                "recorded_path_sha256": artifact_measurements["recorded_path"].sha256,
                "plugin_map_sha256": artifact_measurements["plugin-map.txt"].sha256,
                "evidence_sha256": artifact_measurements["evidence.json"].sha256,
                "static_manifest_sha256": artifact_measurements[
                    "static-manifest.json"
                ].sha256,
            }
            result = {
                "application": app.name,
                "status": "PASS",
                "guest_exit_status": 0,
                "runtime_profile": app.runtime_profile,
                "rows": source_result["recorded_path_rows_including_header"],
                "event_count": source_result["event_count"],
                "external_call_count": source_result["external_call_count"],
                "boundary": source_result["boundary"],
                "hashes": hashes,
                "reference_differences": {},
                "elapsed_ms": float(source_result["elapsed_seconds"]) * 1000,
                "source_qemu_manifest_sha256": validated.measurements[
                    f"qemu/{app.name}/manifest.json"
                ].sha256,
                "source_qemu_sha256sums_sha256": validated.measurements[
                    f"qemu/{app.name}/SHA256SUMS"
                ].sha256,
            }
            write_json_new(app_root / "trace-result.json", result)
            results.append(result)

        provider_sources = {
            name: validated.trusted_provider_measurements[name].sha256
            for name in sorted(PROVIDER_SOURCE_FILES)
        }
        trusted_provider_files = {
            name: {
                "bytes": validated.trusted_provider_measurements[name].bytes,
                "sha256": validated.trusted_provider_measurements[name].sha256,
            }
            for name in TRUSTED_PROVIDER_FILES
        }
        summary = {
            "schema": TRACER_SCHEMA,
            "application_count": len(APPLICATIONS),
            "passed": len(APPLICATIONS),
            "failed": 0,
            "tracer_revision": (
                "provider-source-set-sha256:"
                f"{validated.trusted_provider_identity_sha256}"
            ),
            "provider_sources_sha256": provider_sources,
            "qemu_revision": validated.qemu_summary["qemu_revision"],
            "trusted_provider": {
                "path": str(validated.trusted_provider_root),
                "identity_sha256": validated.trusted_provider_identity_sha256,
                "files": trusted_provider_files,
                "snapshot": "read-once-regular-file-copy-v1",
            },
            "trace_plugin_sha256": validated.qemu_summary["trace_plugin_sha256"],
            "source": (
                "atomic proof-input import of independently revalidated complete QEMU "
                "artifacts from one published compat/QEMU campaign"
            ),
            "source_campaign": {
                "path": str(validated.root),
                "campaign_json_sha256": validated.measurements[
                    "campaign.json"
                ].sha256,
                "sha256sums_sha256": (
                    validated.expected_campaign_sha256s_sha256
                ),
                "expected_sha256s_sha256": (
                    validated.expected_campaign_sha256s_sha256
                ),
                "input_manifest_sha256": validated.measurements[
                    "inputs/input-manifest.json"
                ].sha256,
                "input_sha256sums_sha256": validated.measurements[
                    "inputs/SHA256SUMS"
                ].sha256,
                "qemu_capture_sha256": validated.measurements[
                    "qemu/capture.json"
                ].sha256,
                "qemu_sha256sums_sha256": validated.measurements[
                    "qemu/SHA256SUMS"
                ].sha256,
                "runtime_manifest_snapshot_sha256": validated.measurements[
                    "runtime-manifests/manifest.json"
                ].sha256,
                "runtime_manifest_sha256sums_sha256": validated.measurements[
                    "runtime-manifests/SHA256SUMS"
                ].sha256,
                "trusted_suite": {
                    "path": str(validated.trusted_suite_root),
                    "files": {
                        name: {
                            "bytes": measurement.bytes,
                            "sha256": measurement.sha256,
                        }
                        for name, measurement in sorted(
                            validated.trusted_suite_measurements.items()
                        )
                    },
                },
            },
            "import_contract": {
                "complete_registry_only": True,
                "same_snapshotted_elf_as_compat_campaign": True,
                "guest_exit_status_zero": True,
                "complete_boundary_required": True,
                "recorded_path_recomputed_from_raw_trace": True,
                "trace_evidence_recomputed_from_raw_trace": True,
                "trusted_provider_source_set_required": True,
                "exact_qemu_revision_required": validated.expected_qemu_revision,
                "shadow_must_be_projected_from_imported_complete_registry": True,
                "independent_shadow_qemu_capture_forbidden": True,
            },
            "results": results,
        }
        write_json_new(staging / "tracer-results.json", summary)
        _validate_imported_output(staging, summary)
        rename_noreplace(staging, target)
    return summary


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--campaign", type=Path, required=True, help="published compat/QEMU campaign"
    )
    parser.add_argument(
        "--suite-root",
        type=Path,
        required=True,
        help="trusted original functional-suite root used as an external byte anchor",
    )
    parser.add_argument(
        "--provider-root",
        type=Path,
        default=DEFAULT_PROVIDER_ROOT,
        help="trusted local provider source root (default: repository provider/)",
    )
    parser.add_argument(
        "--expected-qemu-revision",
        default=EXPECTED_QEMU_REVISION,
        help="exact trusted QEMU commit expected in all campaign bindings",
    )
    parser.add_argument(
        "--expected-campaign-sha256s-sha256",
        required=True,
        help="caller-trusted SHA-256 of the published campaign root SHA256SUMS",
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="new legacy proof-input campaign root"
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    summary = import_campaign(
        args.campaign,
        args.output,
        args.suite_root,
        expected_campaign_sha256s_sha256=(
            args.expected_campaign_sha256s_sha256
        ),
        provider_root=args.provider_root,
        expected_qemu_revision=args.expected_qemu_revision,
    )
    print(
        json.dumps(
            {
                "application_count": summary["application_count"],
                "failed": summary["failed"],
                "output": str(args.output.absolute()),
                "passed": summary["passed"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
