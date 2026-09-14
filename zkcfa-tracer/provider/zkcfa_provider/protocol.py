"""Signed authority/device handoff for raw24 and raw64 Binius64 relations.

* an authority signs the independently provisioned CFG commitment and the complete circuit
  identity, code measurement, endpoint policy, device key, and QEMU scope policy;
* a device faithfully normalizes the QEMU evidence, constructs the exact blinded raw EP
  commitment, and signs it against a fresh one-time registry challenge without deciding
  CFG membership or call/return compliance; and
* a confidential worker secret carries only the two independent openings and statement
  identities.  The worker recomputes both commitments from fixed-name proof inputs; device-local
  QEMU evidence is not part of the proof handoff.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
import threading
import time
from pathlib import Path
from typing import Iterable

from static.normalize import (
    build_trace_evidence,
    load_translator,
    load_typed_cfg,
    normalize,
    parse_plugin_map,
    parse_trace,
    render_recorded_path,
)
from static.shadow_safe_bundle import materialize_shadow_safe_bundle

from .scope import external_call_model
from .common import canonical_json
from .crypto import (
    load_private,
    load_public,
    public_key_b64,
    public_key_from_b64,
    public_key_id,
    sign_domain_envelope,
    verify_domain_envelope,
)
from .statement import (
    RAW_CONFIG_SCHEMA,
    RAW_REGISTRY_SCHEMA,
    RAW24_PROFILE,
    RAW_PROFILES,
    RawBlind,
    RawParams,
    circuit_object,
    load_raw_cfg,
    load_raw_evidence,
    load_raw_statement,
    random_blind,
    raw_config_id,
    raw_registry_id,
)


AUTHORITY_SIGNATURE_DOMAIN = b"ZKCFA/raw/registry/signature\x00"
DEVICE_SIGNATURE_DOMAIN = b"ZKCFA/raw/report/signature\x00"
AUTHORITY_OPENING_SIGNATURE_DOMAIN = b"ZKCFA/raw/enrollment/signature\x00"
SCOPE_POLICY_DOMAIN = b"ZKCFA/raw/scope/digest\x00"

RAW_SCOPE_SCHEMA = "zkcfa.raw.scope"
RAW_OPENING_SCHEMA = "zkcfa.raw.enrollment"
RAW_REPORT_SCHEMA = "zkcfa.raw.report"
RAW_WORKER_SCHEMA = "zkcfa.raw.worker"
RAW_CHALLENGE_SCHEMA = "zkcfa.raw.challenge"
RAW_VERDICT_SCHEMA = "zkcfa.raw.verdict"
HEX_32 = re.compile(r"[0-9a-f]{64}")
HEX_16 = re.compile(r"[0-9a-f]{32}")
APPLICATION = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")


def raw_capture_context(
    raw_registry_id_value: str, device_id: str, challenge_id: str, nonce: str
) -> str:
    """Bind a protected acquisition session to its issued challenge.

    The context is a public identifier, not a MAC. Its integrity depends on the
    same protected capture-to-signing path as the raw trace itself.
    """
    if HEX_32.fullmatch(raw_registry_id_value) is None:
        raise ValueError("invalid capture registry identifier")
    if HEX_16.fullmatch(challenge_id) is None or HEX_32.fullmatch(nonce) is None:
        raise ValueError("invalid capture challenge")
    fields = {
        "raw_registry_id": raw_registry_id_value, "device_id": device_id,
        "challenge_id": challenge_id, "nonce": nonce,
    }
    return hashlib.sha256(
        b"ZKCFA/raw/capture/session\x00" + canonical_json(fields)
    ).hexdigest()


def _require_ascii_tree(value: object, context: str) -> None:
    """Reject signed strings Rust cannot reproduce as byte-identical canonical JSON."""

    if isinstance(value, str):
        if not value.isascii():
            raise ValueError(f"{context} contains a non-ASCII signed string")
    elif isinstance(value, list):
        for item in value:
            _require_ascii_tree(item, context)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise ValueError(f"{context} contains a non-ASCII or non-string key")
            _require_ascii_tree(item, context)


def _require_regular(path: Path, description: str, *, private: bool = False) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"{description} is absent: {path}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{description} must be a regular, non-symlink file: {path}")
    if private and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError(f"{description} must not be accessible by group/other")


def _regular_bytes(path: Path, description: str, *, private: bool = False) -> bytes:
    _require_regular(path, description, private=private)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"cannot open {description} without following links: {path}") from error
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{description} changed to a non-regular file")
        if private and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError(f"{description} must not be accessible by group/other")
        return stream.read()


def _json_object(data: bytes, description: str) -> dict[str, object]:
    try:
        value = json.loads(data)
    except json.JSONDecodeError as error:
        raise ValueError(f"{description} is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{description} must contain a JSON object")
    return value


def _regular_json(path: Path, description: str, *, private: bool = False) -> dict[str, object]:
    return _json_object(_regular_bytes(path, description, private=private), description)


def _sha256_regular(path: Path, description: str) -> str:
    return hashlib.sha256(_regular_bytes(path, description)).hexdigest()


def _refuse_destination(path: Path, description: str) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite an existing {description}: {path}")
    if path.parent.is_symlink():
        raise ValueError(f"{description} parent must not be a symlink")


def _write_json_new(path: Path, value: object, *, private: bool = False) -> None:
    """Atomically publish one new JSON file without an overwrite race."""

    _refuse_destination(path, "JSON output")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ValueError("JSON output parent must not be a symlink")
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            data = json.dumps(value, indent=2, sort_keys=True).encode("ascii") + b"\n"
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600 if private else 0o644)
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise FileExistsError(f"refusing to overwrite JSON output: {path}") from error
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _word(value: int) -> str:
    return f"0x{value:016x}"


def _parse_word(value: object, field: str) -> int:
    if not isinstance(value, str) or re.fullmatch(r"0x[0-9a-f]{16}", value) is None:
        raise ValueError(f"{field} must be canonical 64-bit lowercase hex")
    return int(value, 16)


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or HEX_32.fullmatch(value) is None:
        raise ValueError(f"{field} must be canonical 32-byte lowercase hex")
    return value


def scope_policy_digest(policy: dict[str, object]) -> str:
    if policy.get("schema") != RAW_SCOPE_SCHEMA:
        raise ValueError("unsupported raw scope-policy schema")
    return hashlib.sha256(SCOPE_POLICY_DOMAIN + canonical_json(policy)).hexdigest()


def _static_inputs(
    artifacts: Path,
    binary: Path,
    *,
    policy_artifacts: Path | None = None,
) -> tuple[dict[str, object], dict[str, str], str]:
    policy_root = policy_artifacts or artifacts
    paths = {
        "translator_sha256": artifacts / "translator",
        "typed_cfg_sha256": artifacts / "typed_cfg",
        "plugin_map_sha256": policy_root / "plugin-map.txt",
        "static_manifest_sha256": policy_root / "static-manifest.json",
    }
    for name, path in paths.items():
        _require_regular(path, name)
    _require_regular(binary, "measured executable")
    manifest = _regular_json(paths["static_manifest_sha256"], "static manifest")
    if manifest.get("schema") != "zkcfa.static":
        raise ValueError("unsupported static-provisioning manifest")
    application = manifest.get("application")
    if not isinstance(application, str) or APPLICATION.fullmatch(application) is None:
        raise ValueError("static manifest has no canonical application identifier")
    binary_measurement = _sha256_regular(binary, "measured executable")
    hashes = {name: _sha256_regular(path, name) for name, path in paths.items()}
    expected = {
        "elf_sha256": binary_measurement,
        "translator_sha256": hashes["translator_sha256"],
        "typed_cfg_sha256": hashes["typed_cfg_sha256"],
        "plugin_map_sha256": hashes["plugin_map_sha256"],
    }
    for field, digest in expected.items():
        if manifest.get(field) != digest:
            raise ValueError(f"static manifest disagrees with {field}")
    external_call_model(manifest)
    return manifest, {"elf_sha256": binary_measurement, **hashes}, binary_measurement


def _snapshot_authority_inputs(
    *,
    artifacts: Path,
    policy_artifacts: Path,
    binary: Path,
) -> Path:
    """Capture every mutable authority static input exactly once."""

    snapshot = Path(tempfile.mkdtemp(prefix="zkcfa-raw-authority-inputs-"))
    selected = snapshot / "artifacts"
    policy = snapshot / "policy"
    files = (
        (artifacts / "translator", selected / "translator", "raw translator"),
        (artifacts / "typed_cfg", selected / "typed_cfg", "raw typed CFG"),
        (policy_artifacts / "plugin-map.txt", policy / "plugin-map.txt", "plugin map"),
        (
            policy_artifacts / "static-manifest.json",
            policy / "static-manifest.json",
            "static manifest",
        ),
        (binary, snapshot / "binary", "measured executable"),
    )
    captured: dict[str, bytes] = {}
    try:
        for source, destination, description in files:
            key = os.path.abspath(source)
            if key not in captured:
                captured[key] = _regular_bytes(source, description)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with destination.open("xb") as output:
                output.write(captured[key])
            destination.chmod(0o400)
    except BaseException:
        shutil.rmtree(snapshot)
        raise
    return snapshot


def _snapshot_device_inputs(
    *,
    artifacts: Path,
    policy_artifacts: Path,
    binary: Path,
    trace_path: Path,
    evidence_path: Path,
    path_mode: str,
    complete_source_artifacts: Path | None,
    source_trace_path: Path | None,
) -> Path:
    """Capture every mutable statement/evidence input exactly once.

    Validators intentionally reread files while checking cross-bindings.  They must do so from
    this private snapshot rather than from caller-controlled paths, or one source pathname can
    present different bytes to statement construction and evidence validation.
    """

    snapshot = Path(tempfile.mkdtemp(prefix="zkcfa-raw-device-inputs-"))
    selected = snapshot / "artifacts"
    policy = snapshot / "policy"
    files: list[tuple[Path, Path, str]] = [
        (artifacts / "translator", selected / "translator", "raw translator"),
        (artifacts / "typed_cfg", selected / "typed_cfg", "raw typed CFG"),
        (artifacts / "recorded_path", selected / "recorded_path", "recorded path"),
        (policy_artifacts / "plugin-map.txt", policy / "plugin-map.txt", "plugin map"),
        (
            policy_artifacts / "static-manifest.json",
            policy / "static-manifest.json",
            "static manifest",
        ),
        (binary, snapshot / "binary", "measured executable"),
    ]
    if path_mode == "complete":
        files.extend((
            (trace_path, snapshot / "trace", "raw QEMU trace"),
            (evidence_path, selected / "evidence.json", "QEMU trace evidence"),
        ))
    else:
        if complete_source_artifacts is None or source_trace_path is None:
            shutil.rmtree(snapshot)
            raise ValueError(
                "shadow-safe signing requires the complete source artifacts and raw trace"
            )
        complete = snapshot / "complete-source"
        files.extend((
            (
                artifacts / "source-evidence.json",
                selected / "source-evidence.json",
                "source QEMU evidence",
            ),
            (
                evidence_path,
                selected / "projection.json",
                "shadow-safe compression report",
            ),
            (
                complete_source_artifacts / "translator",
                complete / "translator",
                "complete source translator",
            ),
            (
                complete_source_artifacts / "typed_cfg",
                complete / "typed_cfg",
                "complete source typed CFG",
            ),
            (
                complete_source_artifacts / "recorded_path",
                complete / "recorded_path",
                "complete source recorded path",
            ),
            (
                complete_source_artifacts / "evidence.json",
                complete / "evidence.json",
                "complete source QEMU evidence",
            ),
            (source_trace_path, snapshot / "source-trace", "complete source raw QEMU trace"),
        ))

    captured: dict[str, bytes] = {}
    try:
        for source, destination, description in files:
            key = os.path.abspath(source)
            if key not in captured:
                captured[key] = _regular_bytes(source, description)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with destination.open("xb") as output:
                output.write(captured[key])
            destination.chmod(0o400)
    except BaseException:
        shutil.rmtree(snapshot)
        raise
    return snapshot


def _scope_policy(manifest: dict[str, object], path_mode: str) -> dict[str, object]:
    source = manifest.get("scope_policy")
    if not isinstance(source, dict):
        raise ValueError("static manifest has no scope policy")
    call_model = external_call_model(manifest)
    policy: dict[str, object] = {
        "schema": RAW_SCOPE_SCHEMA,
        "architecture": manifest.get("architecture", "aarch64"),
        "boundary_kind": source.get("boundary_kind"),
        "external_call_model": call_model,
        "root_symbol": source.get("root_symbol"),
        "caller_symbol": source.get("caller_symbol"),
        "scope_call_address": source.get("scope_call_address"),
        "root_address": source.get("root_address"),
        "root_exit_blocks": source.get("root_exit_blocks"),
        "scope_return_address": source.get("scope_return_address"),
        "sentinel": "SCOPE_RETURN",
        "sentinel_address": "0xffff0000",
        "require_complete_entry_exit": True,
        "position_independent": bool(manifest.get("position_independent", False)),
        "canonical_entry": manifest.get("canonical_entry", "0x0"),
        "canonical_start_code": manifest.get("canonical_start_code", "0x0"),
        "canonical_address_model": manifest.get(
            "canonical_address_model", "elf-virtual-address"
        ),
        "proof_path_compression": (
            "none" if path_mode == "complete" else "shadow-safe"
        ),
        "normalization": "qemu-root-scope",
    }
    _validate_scope_policy(policy)
    return policy


def _validate_scope_policy(policy: dict[str, object]) -> None:
    _require_ascii_tree(policy, "raw scope policy")
    expected_fields = {
        "schema", "architecture", "boundary_kind",
        "external_call_model", "root_symbol", "caller_symbol", "scope_call_address",
        "root_address", "root_exit_blocks", "scope_return_address", "sentinel",
        "sentinel_address", "require_complete_entry_exit", "position_independent",
        "canonical_entry", "canonical_start_code", "canonical_address_model",
        "proof_path_compression", "normalization",
    }
    if set(policy) != expected_fields or policy.get("schema") != RAW_SCOPE_SCHEMA:
        raise ValueError("raw scope policy has missing or unknown fields")
    if policy.get("architecture") not in {"aarch64", "x86_64"}:
        raise ValueError("raw scope policy has an unsupported architecture")
    if policy.get("external_call_model") not in {"none", "plt-exact-return"}:
        raise ValueError("raw scope policy has an unsupported external-call model")
    if policy.get("boundary_kind") not in {
        "in-binary-direct-call-and-root-ret",
        "external-root-entry-and-captured-return",
    }:
        raise ValueError("raw scope policy has an unsupported boundary kind")
    if policy.get("sentinel") != "SCOPE_RETURN" or policy.get("sentinel_address") != "0xffff0000":
        raise ValueError("raw scope policy has a non-canonical sentinel")
    if policy.get("require_complete_entry_exit") is not True:
        raise ValueError("raw scope policy does not require a complete interval")
    if type(policy.get("position_independent")) is not bool:
        raise ValueError("raw scope policy has a malformed position-independent flag")
    if policy.get("proof_path_compression") not in {"none", "shadow-safe"}:
        raise ValueError("raw scope policy has an unsupported compression mode")
    if policy.get("normalization") != "qemu-root-scope":
        raise ValueError("raw scope policy has an unsupported normalization")
    if policy.get("canonical_address_model") not in {
        "elf-virtual-address", "pie-load-bias"
    }:
        raise ValueError("raw scope policy has an unsupported canonical address model")
    exits = policy.get("root_exit_blocks")
    if not isinstance(exits, list) or not exits or len(exits) != len(set(exits)):
        raise ValueError("raw scope policy has malformed root exit blocks")
    if any(not isinstance(exit_block, str) or not exit_block for exit_block in exits):
        raise ValueError("raw scope policy has malformed root exit blocks")
    for field in (
        "architecture", "root_symbol", "caller_symbol", "scope_call_address",
        "root_address", "scope_return_address", "canonical_entry",
        "canonical_start_code", "canonical_address_model", "normalization",
        "external_call_model",
    ):
        if not isinstance(policy.get(field), str) or not policy[field]:
            raise ValueError(f"raw scope policy has a malformed {field}")


def provision_raw_authority(
    *,
    artifacts: Path,
    binary: Path,
    authority_private: Path,
    device_public: Path,
    device_id: str,
    registry_output: Path,
    opening_output: Path,
    ep_cap: int,
    edge_cap: int | None = None,
    path_mode: str = "complete",
    log_inv_rate: int = 1,
    cfg_blind: RawBlind | None = None,
    policy_artifacts: Path | None = None,
    profile: str = RAW24_PROFILE,
) -> tuple[dict[str, object], dict[str, object]]:
    """Provision a trace-independent CFG registry with a policy EP capacity."""

    for destination, description in (
        (registry_output, "raw authority registry"),
        (opening_output, "raw authority opening"),
    ):
        _refuse_destination(destination, description)
    for key, description, private in (
        (authority_private, "authority private key", True),
        (device_public, "device public key", False),
    ):
        _require_regular(key, description, private=private)
    if not isinstance(device_id, str) or APPLICATION.fullmatch(device_id) is None:
        raise ValueError("device_id must use the canonical identifier alphabet")
    policy_root = policy_artifacts or artifacts
    snapshot = _snapshot_authority_inputs(
        artifacts=artifacts,
        policy_artifacts=policy_root,
        binary=binary,
    )
    try:
        snapshot_artifacts = snapshot / "artifacts"
        snapshot_policy = snapshot / "policy"
        snapshot_binary = snapshot / "binary"
        manifest, source_hashes, binary_measurement = _static_inputs(
            snapshot_artifacts,
            snapshot_binary,
            policy_artifacts=snapshot_policy,
        )
        cfg_blind = cfg_blind or random_blind()
        cfg = load_raw_cfg(
            snapshot_artifacts,
            cfg_blind=cfg_blind,
            ep_cap=ep_cap,
            edge_cap=edge_cap,
            path_mode=path_mode,
            log_inv_rate=log_inv_rate,
            profile=profile,
        )
        if cfg.params.scope_sentinel not in cfg.nodes:
            raise ValueError("raw translator has no canonical SCOPE_RETURN endpoint")
        circuit = circuit_object(cfg.params)
        config_id = raw_config_id(circuit)
        scope = _scope_policy(manifest, path_mode)
        device_key = load_public(device_public)
        base_payload: dict[str, object] = {
            "schema": RAW_REGISTRY_SCHEMA,
            "application": manifest["application"],
            "binary_measurement": binary_measurement,
            "raw_config_id": config_id,
            "h_cfg_raw24": cfg.h_cfg_raw24,
            "circuit": circuit,
            "allowed_endpoints": [
                {"entry_raw": cfg.params.scope_sentinel, "final_raw": cfg.params.scope_sentinel}
            ],
            "devices": {
                device_id: {
                    "algorithm": "Ed25519",
                    "key_id": public_key_id(device_key),
                    "public_key": public_key_b64(device_key),
                }
            },
            "scope_policy": scope,
        }
        payload = dict(base_payload)
        payload["raw_registry_id"] = raw_registry_id(base_payload)
        validate_raw_registry_payload(payload)
        registry_envelope = sign_domain_envelope(
            payload, load_private(authority_private), domain=AUTHORITY_SIGNATURE_DOMAIN
        )
        opening_payload: dict[str, object] = {
            "schema": RAW_OPENING_SCHEMA,
            "raw_registry_id": payload["raw_registry_id"],
            "cfg_blind_low": _word(cfg_blind.low),
            "cfg_blind_high": _word(cfg_blind.high),
            "static_manifest_sha256": source_hashes["static_manifest_sha256"],
        }
        opening_envelope = sign_domain_envelope(
            opening_payload,
            load_private(authority_private),
            domain=AUTHORITY_OPENING_SIGNATURE_DOMAIN,
        )
    finally:
        shutil.rmtree(snapshot)
    _write_json_new(registry_output, registry_envelope)
    _write_json_new(opening_output, opening_envelope, private=True)
    return registry_envelope, opening_envelope


def _params_from_circuit(circuit: dict[str, object]) -> RawParams:
    try:
        for field in ("edge_cap", "ep_cap", "log_inv_rate"):
            if type(circuit[field]) is not int:
                raise TypeError(f"{field} is not an integer")
        if not isinstance(circuit["path_mode"], str):
            raise TypeError("path_mode is not a string")
        params = RawParams(
            edge_cap=circuit["edge_cap"],
            ep_cap=circuit["ep_cap"],
            path_mode=circuit["path_mode"],
            log_inv_rate=circuit["log_inv_rate"],
            profile=circuit["profile"],
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("raw circuit has malformed capacity fields") from error
    params.validate()
    if circuit != circuit_object(params):
        raise ValueError("raw circuit config has missing, unknown, or downgraded fields")
    return params


def validate_raw_registry_payload(payload: dict[str, object]) -> RawParams:
    _require_ascii_tree(payload, "raw authority registry")
    expected_fields = {
        "schema", "application", "raw_registry_id", "binary_measurement",
        "raw_config_id", "h_cfg_raw24", "circuit", "allowed_endpoints",
        "devices", "scope_policy",
    }
    if set(payload) != expected_fields or payload.get("schema") != RAW_REGISTRY_SCHEMA:
        raise ValueError("raw authority registry has missing or unknown fields")
    application = payload.get("application")
    if not isinstance(application, str) or APPLICATION.fullmatch(application) is None:
        raise ValueError("raw registry application is not canonical")
    for field in ("raw_registry_id", "binary_measurement", "raw_config_id", "h_cfg_raw24"):
        _require_digest(payload.get(field), field)
    circuit = payload.get("circuit")
    if not isinstance(circuit, dict) or circuit.get("schema") != RAW_CONFIG_SCHEMA:
        raise ValueError("raw registry has no canonical circuit config")
    params = _params_from_circuit(circuit)
    if payload["raw_config_id"] != raw_config_id(circuit):
        raise ValueError("raw registry config identifier is not canonical")
    unsigned = dict(payload)
    claimed = unsigned.pop("raw_registry_id")
    if claimed != raw_registry_id(unsigned):
        raise ValueError("raw registry identifier is not canonical")
    endpoints = payload.get("allowed_endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        raise ValueError("raw registry has no allowed endpoint")
    canonical_endpoints: list[tuple[int, int]] = []
    for endpoint in endpoints:
        if not isinstance(endpoint, dict) or set(endpoint) != {"entry_raw", "final_raw"}:
            raise ValueError("raw registry endpoint is malformed")
        entry, final = endpoint["entry_raw"], endpoint["final_raw"]
        if any(type(value) is not int or not 0 < value < params.addr_limit for value in (entry, final)):
            raise ValueError(f"raw registry endpoint is outside raw{params.addr_bits}")
        canonical_endpoints.append((entry, final))
    if canonical_endpoints != sorted(set(canonical_endpoints)):
        raise ValueError("raw registry endpoints are repeated or unordered")
    devices = payload.get("devices")
    if not isinstance(devices, dict) or not devices:
        raise ValueError("raw registry has no authorized device")
    for device_id, device in devices.items():
        if not isinstance(device_id, str) or APPLICATION.fullmatch(device_id) is None:
            raise ValueError("raw registry has a malformed device identifier")
        if not isinstance(device, dict) or set(device) != {"algorithm", "key_id", "public_key"}:
            raise ValueError("raw registry device record is malformed")
        if device.get("algorithm") != "Ed25519":
            raise ValueError("raw registry device is not Ed25519")
        key = public_key_from_b64(str(device.get("public_key", "")))
        if device.get("key_id") != public_key_id(key):
            raise ValueError("raw registry device key identifier is not canonical")
    scope = payload.get("scope_policy")
    if not isinstance(scope, dict):
        raise ValueError("raw registry has no scope policy")
    _validate_scope_policy(scope)
    expected_compression = "none" if params.path_mode == "complete" else "shadow-safe"
    if scope.get("proof_path_compression") != expected_compression:
        raise ValueError("raw registry path mode disagrees with scope policy")
    return params


def _validate_complete_evidence(
    *,
    artifacts: Path,
    policy_artifacts: Path,
    binary: Path,
    trace_path: Path,
    evidence_path: Path,
    registry: dict[str, object],
) -> dict[str, object]:
    for path, description in (
        (trace_path, "raw QEMU trace"),
        (evidence_path, "QEMU trace evidence"),
        (artifacts / "recorded_path", "recorded path"),
    ):
        _require_regular(path, description)
    manifest, source_hashes, binary_measurement = _static_inputs(
        artifacts, binary, policy_artifacts=policy_artifacts
    )
    if binary_measurement != registry.get("binary_measurement"):
        raise ValueError("executed binary differs from the raw authority registry")
    if manifest.get("application") != registry.get("application"):
        raise ValueError("static application differs from the raw authority registry")
    plugin_map_path = policy_artifacts / "plugin-map.txt"
    typed_cfg_path = artifacts / "typed_cfg"
    translator_path = artifacts / "translator"
    recorded_path = artifacts / "recorded_path"
    static_manifest_path = policy_artifacts / "static-manifest.json"
    plugin_map = parse_plugin_map(plugin_map_path)
    trace = parse_trace(trace_path)
    operations = normalize(
        plugin_map,
        trace,
        load_typed_cfg(typed_cfg_path),
        load_translator(translator_path),
    )
    if recorded_path.read_text(encoding="ascii") != render_recorded_path(operations):
        raise ValueError("recorded_path does not match device recomputation from the raw QEMU trace")
    recomputed = build_trace_evidence(
        plugin_map=plugin_map,
        trace=trace,
        recorded_path=recorded_path,
        typed_cfg=typed_cfg_path,
        expected_typed_cfg_sha256=source_hashes["typed_cfg_sha256"],
        translator=translator_path,
        static_manifest=static_manifest_path,
        plugin_map_path=plugin_map_path,
    )
    supplied = _regular_json(evidence_path, "QEMU trace evidence")
    if canonical_json(supplied) != canonical_json(recomputed):
        raise ValueError("supplied QEMU evidence does not match device recomputation")
    if supplied.get("schema") != "zkcfa.raw.evidence":
        raise ValueError("unsupported QEMU boundary-evidence schema")
    if supplied.get("runtime_code_match") is not True:
        raise ValueError("QEMU runtime code did not match the measured ELF")
    boundary = supplied.get("boundary")
    if not isinstance(boundary, dict) or boundary.get("complete") is not True:
        raise ValueError("QEMU evidence does not contain a complete boundary")
    policy = registry["scope_policy"]
    if policy["external_call_model"] != external_call_model(manifest):
        raise ValueError("QEMU evidence differs from the raw external-call model")
    if boundary.get("boundary_kind") != policy["boundary_kind"]:
        raise ValueError("QEMU boundary kind differs from the raw scope policy")
    if boundary.get("scope_call_address") != policy["scope_call_address"]:
        raise ValueError("QEMU scope entry differs from the raw scope policy")
    if boundary.get("root_address") != policy["root_address"]:
        raise ValueError("QEMU root entry differs from the raw scope policy")
    if boundary.get("root_exit_block") not in policy["root_exit_blocks"]:
        raise ValueError("QEMU root exit is not authority authorized")
    if boundary.get("scope_exit_address") != policy["scope_return_address"]:
        raise ValueError("QEMU scope exit differs from the raw scope policy")
    if boundary.get("sentinel") != policy["sentinel"]:
        raise ValueError("QEMU evidence used a non-canonical sentinel")
    if not all(boundary.get(field) is True for field in (
        "root_entry_observed", "root_return_observed", "scope_exit_observed"
    )):
        raise ValueError("QEMU evidence lacks a complete root entry/return/exit interval")
    if policy["boundary_kind"] == "in-binary-direct-call-and-root-ret":
        if boundary.get("scope_call_observed") is not True:
            raise ValueError("QEMU did not observe the configured direct scope call")
    elif (
        boundary.get("scope_call_observed") is not False
        or boundary.get("external_root_entry_observed") is not True
        or boundary.get("captured_return_continuation_matched") is not True
    ):
        raise ValueError("QEMU did not observe the configured external entry/return continuation")
    return supplied


def _validate_shadow_evidence(
    *,
    artifacts: Path,
    policy_artifacts: Path,
    binary: Path,
    complete_source_artifacts: Path,
    source_trace_path: Path,
    registry: dict[str, object],
) -> dict[str, object]:
    report_path = artifacts / "projection.json"
    source_evidence_path = artifacts / "source-evidence.json"
    report = _regular_json(report_path, "shadow-safe compression report")
    source_evidence = _regular_json(source_evidence_path, "source QEMU evidence")
    _validate_complete_evidence(
        artifacts=complete_source_artifacts,
        policy_artifacts=policy_artifacts,
        binary=binary,
        trace_path=source_trace_path,
        evidence_path=complete_source_artifacts / "evidence.json",
        registry=registry,
    )
    if canonical_json(source_evidence) != canonical_json(
        _regular_json(complete_source_artifacts / "evidence.json", "complete source evidence")
    ):
        raise ValueError("projected bundle does not copy the recomputed source evidence exactly")
    temporary_root = Path(tempfile.mkdtemp(prefix="zkcfa-raw-shadow-check-"))
    regenerated = temporary_root / "projected"
    try:
        expected_report = materialize_shadow_safe_bundle(
            complete_source_artifacts, regenerated
        )
        for name in ("translator", "typed_cfg", "recorded_path", "source-evidence.json"):
            if _regular_bytes(artifacts / name, f"selected projected {name}") != _regular_bytes(
                regenerated / name, f"regenerated projected {name}"
            ):
                raise ValueError(f"selected shadow-safe {name} differs from trusted regeneration")
        if canonical_json(report) != canonical_json(expected_report):
            raise ValueError("selected compression report differs from trusted regeneration")
    finally:
        shutil.rmtree(temporary_root)
    return report


def build_raw_device_report(
    *,
    artifacts: Path,
    policy_artifacts: Path,
    binary: Path,
    trace_path: Path,
    evidence_path: Path,
    registry_path: Path,
    opening_path: Path,
    authority_public: Path,
    device_private: Path,
    device_id: str,
    challenge_id: str,
    nonce: str,
    report_output: Path,
    worker_secret_output: Path,
    ep_blind: RawBlind | None = None,
    complete_source_artifacts: Path | None = None,
    source_trace_path: Path | None = None,
    require_capture_context: bool = False,
) -> tuple[dict[str, object], dict[str, object]]:
    for destination, description in (
        (report_output, "raw device report"),
        (worker_secret_output, "raw worker secret"),
    ):
        _refuse_destination(destination, description)
    for path, description, private in (
        (registry_path, "raw authority registry", False),
        (opening_path, "raw authority opening", True),
        (authority_public, "authority public key", False),
        (device_private, "device private key", True),
    ):
        _require_regular(path, description, private=private)
    authority = load_public(authority_public)
    registry = verify_domain_envelope(
        _regular_json(registry_path, "raw authority registry"),
        authority,
        domain=AUTHORITY_SIGNATURE_DOMAIN,
    )
    params = validate_raw_registry_payload(registry)
    opening = verify_domain_envelope(
        _regular_json(opening_path, "raw authority opening", private=True),
        authority,
        domain=AUTHORITY_OPENING_SIGNATURE_DOMAIN,
    )
    opening_fields = {
        "schema", "raw_registry_id", "cfg_blind_low", "cfg_blind_high",
        "static_manifest_sha256",
    }
    if set(opening) != opening_fields or opening.get("schema") != RAW_OPENING_SCHEMA:
        raise ValueError("raw authority opening has missing or unknown fields")
    if opening.get("raw_registry_id") != registry.get("raw_registry_id"):
        raise ValueError("raw authority opening disagrees with registry raw_registry_id")
    _require_digest(opening.get("static_manifest_sha256"), "static_manifest_sha256")
    device = registry["devices"].get(device_id)
    if not isinstance(device, dict):
        raise ValueError("device is not authorized by the raw authority registry")
    device_key = load_private(device_private)
    if public_key_id(device_key.public_key()) != device.get("key_id"):
        raise ValueError("device private key does not match the authorized device")
    if params.path_mode == "complete":
        if os.path.abspath(evidence_path) != os.path.abspath(
            artifacts / "evidence.json"
        ):
            raise ValueError(
                "complete raw signing requires the bundle-local evidence.json"
            )
    else:
        if complete_source_artifacts is None or source_trace_path is None:
            raise ValueError("shadow-safe signing requires the complete source artifacts and raw trace")
        if os.path.abspath(evidence_path) != os.path.abspath(
            artifacts / "projection.json"
        ):
            raise ValueError("shadow evidence must be the selected projection.json")

    snapshot = _snapshot_device_inputs(
        artifacts=artifacts,
        policy_artifacts=policy_artifacts,
        binary=binary,
        trace_path=trace_path,
        evidence_path=evidence_path,
        path_mode=params.path_mode,
        complete_source_artifacts=complete_source_artifacts,
        source_trace_path=source_trace_path,
    )
    try:
        snapshot_artifacts = snapshot / "artifacts"
        snapshot_policy = snapshot / "policy"
        snapshot_binary = snapshot / "binary"
        if require_capture_context:
            capture_trace = snapshot / (
                "trace" if params.path_mode == "complete" else "source-trace"
            )
            expected_context = raw_capture_context(
                str(registry["raw_registry_id"]), device_id, challenge_id, nonce
            )
            if parse_trace(capture_trace).capture_context != expected_context:
                raise ValueError("trace capture context does not match the issued challenge")
        manifest, source_hashes, binary_measurement = _static_inputs(
            snapshot_artifacts,
            snapshot_binary,
            policy_artifacts=snapshot_policy,
        )
        if opening.get("static_manifest_sha256") != source_hashes["static_manifest_sha256"]:
            raise ValueError("raw authority opening disagrees with the local static policy")
        if (
            binary_measurement != registry["binary_measurement"]
            or manifest["application"] != registry["application"]
        ):
            raise ValueError("device source identity differs from the raw authority registry")
        if _scope_policy(manifest, params.path_mode) != registry["scope_policy"]:
            raise ValueError("device static scope policy differs from the raw authority registry")
        cfg_blind = RawBlind(
            _parse_word(opening["cfg_blind_low"], "cfg_blind_low"),
            _parse_word(opening["cfg_blind_high"], "cfg_blind_high"),
        )
        ep_blind = ep_blind or random_blind(excluding=(cfg_blind.value,))
        # Authentication attests what was recorded. CFA policy and concrete
        # multiplicity feasibility are checked by the worker and proof circuit.
        statement = load_raw_evidence(
            snapshot_artifacts,
            cfg_blind=cfg_blind,
            ep_blind=ep_blind,
            edge_cap=params.edge_cap,
            ep_cap=params.ep_cap,
            path_mode=params.path_mode,
            log_inv_rate=params.log_inv_rate,
            profile=params.profile,
        )
        if statement.h_cfg_raw24 != registry["h_cfg_raw24"]:
            raise ValueError("local canonical H_cfg_raw24 differs from the authority signature")
        if raw_config_id(circuit_object(statement.params)) != registry["raw_config_id"]:
            raise ValueError("local raw circuit config differs from the authority signature")
        endpoint = (statement.entry_raw, statement.final_raw)
        allowed = {
            (item["entry_raw"], item["final_raw"])
            for item in registry["allowed_endpoints"]
        }
        if endpoint not in allowed:
            raise ValueError("actual raw endpoint pair is not authority authorized")

        if params.path_mode == "complete":
            _validate_complete_evidence(
                artifacts=snapshot_artifacts,
                policy_artifacts=snapshot_policy,
                binary=snapshot_binary,
                trace_path=snapshot / "trace",
                evidence_path=snapshot_artifacts / "evidence.json",
                registry=registry,
            )
        else:
            _validate_shadow_evidence(
                artifacts=snapshot_artifacts,
                policy_artifacts=snapshot_policy,
                binary=snapshot_binary,
                complete_source_artifacts=snapshot / "complete-source",
                source_trace_path=snapshot / "source-trace",
                registry=registry,
            )

        if not HEX_16.fullmatch(challenge_id):
            raise ValueError("challenge_id must be canonical 16-byte lowercase hex")
        if not HEX_32.fullmatch(nonce):
            raise ValueError("nonce must be canonical 32-byte lowercase hex")
        scope_digest = scope_policy_digest(registry["scope_policy"])
        report_payload: dict[str, object] = {
            "schema": RAW_REPORT_SCHEMA,
            "device_id": device_id,
            "challenge_id": challenge_id,
            "nonce": nonce,
            "raw_registry_id": registry["raw_registry_id"],
            "raw_config_id": registry["raw_config_id"],
            "binary_measurement": binary_measurement,
            "h_cfg_raw24": statement.h_cfg_raw24,
            "h_ep_raw24": statement.h_ep_raw24,
            "entry_raw": statement.entry_raw,
            "final_raw": statement.final_raw,
            "scope_policy_digest": scope_digest,
            "runtime_code_match": True,
            "boundary_policy_satisfied": True,
        }
        validate_raw_report_payload(report_payload, registry)
        report_envelope = sign_domain_envelope(
            report_payload, device_key, domain=DEVICE_SIGNATURE_DOMAIN
        )
        worker_secret: dict[str, object] = {
            "schema": RAW_WORKER_SCHEMA,
            "raw_registry_id": registry["raw_registry_id"],
            "raw_config_id": registry["raw_config_id"],
            "h_cfg_raw24": statement.h_cfg_raw24,
            "h_ep_raw24": statement.h_ep_raw24,
            "ep_blind_low": _word(ep_blind.low),
            "ep_blind_high": _word(ep_blind.high),
            "cfg_blind_low": _word(cfg_blind.low),
            "cfg_blind_high": _word(cfg_blind.high),
        }
    finally:
        shutil.rmtree(snapshot)
    _write_json_new(report_output, report_envelope)
    _write_json_new(worker_secret_output, worker_secret, private=True)
    return report_envelope, worker_secret


def validate_raw_report_payload(
    payload: dict[str, object], registry: dict[str, object]
) -> None:
    _require_ascii_tree(payload, "raw device report")
    expected_fields = {
        "schema", "device_id", "challenge_id", "nonce",
        "raw_registry_id", "raw_config_id", "binary_measurement", "h_cfg_raw24", "h_ep_raw24",
        "entry_raw", "final_raw", "scope_policy_digest", "runtime_code_match",
        "boundary_policy_satisfied",
    }
    if set(payload) != expected_fields or payload.get("schema") != RAW_REPORT_SCHEMA:
        raise ValueError("raw device report has missing or unknown fields")
    for field, pattern in (("challenge_id", HEX_16), ("nonce", HEX_32)):
        value = payload.get(field)
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            raise ValueError(f"raw device report has a non-canonical {field}")
    for field in (
        "raw_registry_id", "raw_config_id", "binary_measurement", "h_cfg_raw24", "h_ep_raw24",
        "scope_policy_digest",
    ):
        _require_digest(payload.get(field), field)
    for field in ("raw_registry_id", "raw_config_id", "binary_measurement", "h_cfg_raw24"):
        if payload.get(field) != registry.get(field):
            raise ValueError(f"raw device report disagrees with registry {field}")
    if payload.get("scope_policy_digest") != scope_policy_digest(registry["scope_policy"]):
        raise ValueError("raw device report is not bound to the authority scope policy")
    if payload.get("runtime_code_match") is not True or payload.get("boundary_policy_satisfied") is not True:
        raise ValueError("raw device report does not attest runtime/boundary success")
    if any(type(payload.get(field)) is not int for field in ("entry_raw", "final_raw")):
        raise ValueError("raw device report has malformed endpoint values")
    endpoint = (payload.get("entry_raw"), payload.get("final_raw"))
    if endpoint not in {
        (item["entry_raw"], item["final_raw"])
        for item in registry["allowed_endpoints"]
    }:
        raise ValueError("raw device report uses an unauthorized endpoint pair")


class RawRegistryService:
    """In-memory reference registry with one-time challenge consumption."""

    def __init__(self, signed_registry: dict[str, object], authority_public: Path) -> None:
        _require_regular(authority_public, "authority public key")
        self.envelope = copy.deepcopy(signed_registry)
        self.registry = verify_domain_envelope(
            self.envelope,
            load_public(authority_public),
            domain=AUTHORITY_SIGNATURE_DOMAIN,
        )
        validate_raw_registry_payload(self.registry)
        self._challenges: dict[str, dict[str, object]] = {}
        self._lock = threading.Lock()

    def issue_challenge(
        self, device_id: str, raw_registry_id_value: str, *, ttl_seconds: int = 300
    ) -> dict[str, object]:
        if raw_registry_id_value != self.registry["raw_registry_id"]:
            raise ValueError("unknown raw registry")
        if device_id not in self.registry["devices"]:
            raise ValueError("device is not authorized by the raw registry")
        if not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 3600:
            raise ValueError("challenge TTL must be in 1..=3600 seconds")
        now = int(time.time())
        with self._lock:
            while True:
                challenge_id = secrets.token_hex(16)
                if challenge_id not in self._challenges:
                    break
            challenge: dict[str, object] = {
                "schema": RAW_CHALLENGE_SCHEMA,
                "challenge_id": challenge_id,
                "nonce": secrets.token_hex(32),
                "device_id": device_id,
                "raw_registry_id": raw_registry_id_value,
                "issued_at": now,
                "expires_at": now + ttl_seconds,
                "used": False,
            }
            self._challenges[challenge_id] = challenge
        return {field: value for field, value in challenge.items() if field != "used"}

    def verify_report(self, envelope: object) -> dict[str, object]:
        """Authenticate a fresh report; acceptance is not a CFA proof verdict."""
        if not isinstance(envelope, dict):
            raise ValueError("raw device report must be a signed envelope")
        unsigned = envelope.get("payload")
        if not isinstance(unsigned, dict):
            raise ValueError("raw device report has no payload")
        device_id = unsigned.get("device_id")
        device = self.registry["devices"].get(device_id)
        if not isinstance(device, dict):
            raise ValueError("device is not authorized by the raw registry")
        payload = verify_domain_envelope(
            envelope,
            public_key_from_b64(device["public_key"]),
            domain=DEVICE_SIGNATURE_DOMAIN,
            expected_key_id=device["key_id"],
        )
        validate_raw_report_payload(payload, self.registry)
        self._consume_challenge(payload)
        return {
            "schema": RAW_VERDICT_SCHEMA,
            "accepted": True,
            "challenge_id": payload["challenge_id"],
            "device_id": device_id,
            "raw_registry_id": self.registry["raw_registry_id"],
        }

    @staticmethod
    def _validate_challenge(payload: dict[str, object], challenge: object) -> None:
        if not isinstance(challenge, dict):
            raise ValueError("unknown raw challenge")
        if challenge["used"]:
            raise ValueError("raw challenge was already consumed")
        if int(challenge["expires_at"]) < int(time.time()):
            raise ValueError("raw challenge expired")
        for field in ("nonce", "device_id", "raw_registry_id"):
            if payload.get(field) != challenge[field]:
                raise ValueError(f"raw report {field} does not match the challenge")

    def _consume_challenge(self, payload: dict[str, object]) -> None:
        challenge_id = payload["challenge_id"]
        with self._lock:
            challenge = self._challenges.get(challenge_id)
            self._validate_challenge(payload, challenge)
            challenge["used"] = True


def materialize_raw_bundle(
    *,
    output: Path,
    artifacts: Path,
    authority_public: Path,
    registry_path: Path,
    report_path: Path,
    worker_secret_path: Path,
) -> dict[str, int]:
    """Worker-side preflight and atomic export of the Binius64 input contract.

    A device may sign noncompliant evidence. The worker rejects it here before
    spending time proving; circuit constraints enforce the same policy even if
    a worker bypasses this host-side preflight.
    """

    _refuse_destination(output, "raw signed provider bundle")
    private_files = ["translator", "typed_cfg", "recorded_path"]
    worker_bytes = _regular_bytes(worker_secret_path, "raw worker secret", private=True)
    secret = _json_object(worker_bytes, "raw worker secret")
    worker_fields = {
        "schema", "raw_registry_id", "raw_config_id", "h_cfg_raw24", "h_ep_raw24",
        "ep_blind_low", "ep_blind_high", "cfg_blind_low", "cfg_blind_high",
    }
    if set(secret) != worker_fields or secret.get("schema") != RAW_WORKER_SCHEMA:
        raise ValueError("raw worker secret has missing or unknown fields")
    _require_ascii_tree(secret, "raw worker secret")
    for field in (
        "raw_registry_id", "raw_config_id", "h_cfg_raw24", "h_ep_raw24",
    ):
        _require_digest(secret.get(field), field)
    for field in ("ep_blind_low", "ep_blind_high", "cfg_blind_low", "cfg_blind_high"):
        _parse_word(secret.get(field), field)
    for path, description, private in (
        (authority_public, "authority public key", False),
        (registry_path, "raw signed registry", False),
        (report_path, "raw signed device report", False),
        (worker_secret_path, "raw worker secret", True),
    ):
        _require_regular(path, description, private=private)
    for name in private_files:
        _require_regular(artifacts / name, f"raw proof input {name}")
    authority = load_public(authority_public)
    registry_bytes = _regular_bytes(registry_path, "raw signed registry")
    registry_envelope = _json_object(registry_bytes, "raw signed registry")
    registry = verify_domain_envelope(
        registry_envelope, authority, domain=AUTHORITY_SIGNATURE_DOMAIN
    )
    validate_raw_registry_payload(registry)
    report_bytes = _regular_bytes(report_path, "raw signed device report")
    report_envelope = _json_object(report_bytes, "raw signed device report")
    unsigned_report = report_envelope.get("payload")
    if not isinstance(unsigned_report, dict):
        raise ValueError("raw signed device report has no payload")
    device = registry["devices"].get(unsigned_report.get("device_id"))
    if not isinstance(device, dict):
        raise ValueError("raw signed device report uses an unauthorized device")
    report = verify_domain_envelope(
        report_envelope,
        public_key_from_b64(device["public_key"]),
        domain=DEVICE_SIGNATURE_DOMAIN,
        expected_key_id=device["key_id"],
    )
    validate_raw_report_payload(report, registry)
    for field in ("raw_registry_id", "raw_config_id", "h_cfg_raw24", "h_ep_raw24"):
        expected = report[field] if field == "h_ep_raw24" else registry[field]
        if secret.get(field) != expected:
            raise ValueError(f"raw worker secret disagrees with signed {field}")
    proof_input_bytes = {
        name: _regular_bytes(artifacts / name, f"raw proof input {name}")
        for name in private_files
    }
    snapshot = Path(tempfile.mkdtemp(prefix="zkcfa-raw-proof-inputs-"))
    try:
        for name, data in proof_input_bytes.items():
            (snapshot / name).write_bytes(data)
        params = _params_from_circuit(registry["circuit"])
        statement = load_raw_statement(
            snapshot,
            cfg_blind=RawBlind(
                _parse_word(secret["cfg_blind_low"], "cfg_blind_low"),
                _parse_word(secret["cfg_blind_high"], "cfg_blind_high"),
            ),
            ep_blind=RawBlind(
                _parse_word(secret["ep_blind_low"], "ep_blind_low"),
                _parse_word(secret["ep_blind_high"], "ep_blind_high"),
            ),
            edge_cap=params.edge_cap,
            ep_cap=params.ep_cap,
            path_mode=params.path_mode,
            log_inv_rate=params.log_inv_rate,
            profile=params.profile,
        )
    finally:
        shutil.rmtree(snapshot)
    for field, actual, expected in (
        ("h_cfg_raw24", statement.h_cfg_raw24, registry["h_cfg_raw24"]),
        ("h_ep_raw24", statement.h_ep_raw24, report["h_ep_raw24"]),
        ("entry_raw", statement.entry_raw, report["entry_raw"]),
        ("final_raw", statement.final_raw, report["final_raw"]),
    ):
        if actual != expected:
            raise ValueError(f"raw proof inputs disagree with signed {field}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.tmp-", dir=output.parent))
    try:
        public = temporary / "public"
        private = temporary / "private"
        public.mkdir(mode=0o755)
        private.mkdir(mode=0o700)
        copies = (
            (registry_bytes, public / "registry.json"),
            (report_bytes, public / "report.json"),
            (worker_bytes, private / "worker.json"),
            *((proof_input_bytes[name], private / name) for name in private_files),
        )
        for data, destination in copies:
            destination.write_bytes(data)
            destination.chmod(0o644 if destination.parent == public else 0o600)
        if output.exists() or output.is_symlink():
            raise FileExistsError(f"raw signed provider bundle appeared during export: {output}")
        os.rename(temporary, output)
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    public_bytes = sum(path.stat().st_size for path in (output / "public").iterdir())
    private_bytes = sum(path.stat().st_size for path in (output / "private").iterdir())
    return {"public_bytes": public_bytes, "private_bytes": private_bytes}


def _cli(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    authority = commands.add_parser("authority", help="provision and sign raw H_cfg")
    authority.add_argument("--artifacts", type=Path, required=True)
    authority.add_argument("--policy-artifacts", type=Path)
    authority.add_argument("--binary", type=Path, required=True)
    authority.add_argument("--authority-private", type=Path, required=True)
    authority.add_argument("--device-public", type=Path, required=True)
    authority.add_argument("--device-id", required=True)
    authority.add_argument("--registry-output", type=Path, required=True)
    authority.add_argument("--opening-output", type=Path, required=True)
    authority.add_argument("--edge-cap", type=int)
    authority.add_argument(
        "--ep-cap", type=int, required=True,
        help="pre-execution power-of-two policy capacity for the eventual path",
    )
    authority.add_argument("--path-mode", choices=("complete", "shadow"), default="complete")
    authority.add_argument("--log-inv-rate", type=int, default=1)
    authority.add_argument("--profile", choices=RAW_PROFILES, default=RAW24_PROFILE)

    device = commands.add_parser("device", help="recompute QEMU evidence and sign raw H_ep")
    device.add_argument("--artifacts", type=Path, required=True)
    device.add_argument("--policy-artifacts", type=Path, required=True)
    device.add_argument("--binary", type=Path, required=True)
    device.add_argument("--trace", type=Path, required=True)
    device.add_argument("--evidence", type=Path, required=True)
    device.add_argument("--registry", type=Path, required=True)
    device.add_argument("--opening", type=Path, required=True)
    device.add_argument("--authority-public", type=Path, required=True)
    device.add_argument("--device-private", type=Path, required=True)
    device.add_argument("--device-id", required=True)
    device.add_argument("--challenge-id", required=True)
    device.add_argument("--nonce", required=True)
    device.add_argument("--report-output", type=Path, required=True)
    device.add_argument("--worker-secret-output", type=Path, required=True)
    device.add_argument("--complete-source-artifacts", type=Path)
    device.add_argument("--source-trace", type=Path)
    device.add_argument("--require-capture-context", action="store_true",
                        help="require a challenge-bound online QEMU capture")

    bundle = commands.add_parser("bundle", help="atomically export a Binius64 proof bundle")
    bundle.add_argument("--output", type=Path, required=True)
    bundle.add_argument("--artifacts", type=Path, required=True)
    bundle.add_argument("--authority-public", type=Path, required=True)
    bundle.add_argument("--registry", type=Path, required=True)
    bundle.add_argument("--report", type=Path, required=True)
    bundle.add_argument("--worker-secret", type=Path, required=True)

    args = parser.parse_args(argv)
    started = time.perf_counter()
    result: dict[str, object]
    if args.command == "authority":
        registry, _ = provision_raw_authority(
            artifacts=args.artifacts,
            policy_artifacts=args.policy_artifacts,
            binary=args.binary,
            authority_private=args.authority_private,
            device_public=args.device_public,
            device_id=args.device_id,
            registry_output=args.registry_output,
            opening_output=args.opening_output,
            edge_cap=args.edge_cap,
            ep_cap=args.ep_cap,
            path_mode=args.path_mode,
            log_inv_rate=args.log_inv_rate,
            profile=args.profile,
        )
        result = {
            "raw_registry_id": registry["payload"]["raw_registry_id"],
            "h_cfg_raw24": registry["payload"]["h_cfg_raw24"],
            "registry_bytes": args.registry_output.stat().st_size,
        }
    elif args.command == "device":
        report, _ = build_raw_device_report(
            artifacts=args.artifacts,
            policy_artifacts=args.policy_artifacts,
            binary=args.binary,
            trace_path=args.trace,
            evidence_path=args.evidence,
            registry_path=args.registry,
            opening_path=args.opening,
            authority_public=args.authority_public,
            device_private=args.device_private,
            device_id=args.device_id,
            challenge_id=args.challenge_id,
            nonce=args.nonce,
            report_output=args.report_output,
            worker_secret_output=args.worker_secret_output,
            complete_source_artifacts=args.complete_source_artifacts,
            source_trace_path=args.source_trace,
            require_capture_context=args.require_capture_context,
        )
        result = {
            "challenge_id": args.challenge_id,
            "nonce": args.nonce,
            "h_ep_raw24": report["payload"]["h_ep_raw24"],
            "report_bytes": args.report_output.stat().st_size,
            "worker_secret_bytes": args.worker_secret_output.stat().st_size,
        }
    else:
        result = materialize_raw_bundle(
            output=args.output,
            artifacts=args.artifacts,
            authority_public=args.authority_public,
            registry_path=args.registry,
            report_path=args.report,
            worker_secret_path=args.worker_secret,
        )
        result["bundle"] = str(args.output)
    result["elapsed_ms"] = (time.perf_counter() - started) * 1000
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
