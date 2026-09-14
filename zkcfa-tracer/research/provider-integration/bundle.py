"""Evaluation harness: run all protocol roles and export one fitted raw proof bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Iterable

from keys import create_keys
from zkcfa_provider.protocol import (
    RawRegistryService,
    _regular_json,
    _write_json_new,
    build_raw_device_report,
    materialize_raw_bundle,
    provision_raw_authority,
)
from zkcfa_provider.statement import RAW24_PROFILE, RAW_PROFILES, fitted_raw_params


def build_signed_raw_bundle(
    *,
    run_dir: Path,
    artifacts: Path,
    policy_artifacts: Path,
    binary: Path,
    trace_path: Path,
    ep_cap: int | None = None,
    edge_cap: int | None = None,
    path_mode: str = "complete",
    log_inv_rate: int = 1,
    device_id: str = "qemu-raw-device",
    complete_source_artifacts: Path | None = None,
    source_trace_path: Path | None = None,
    profile: str = RAW24_PROFILE,
) -> dict[str, object]:
    if run_dir.exists() or run_dir.is_symlink():
        raise FileExistsError(f"refusing to overwrite raw protocol run directory: {run_dir}")
    fitted = fitted_raw_params(
        artifacts, path_mode=path_mode, log_inv_rate=log_inv_rate, profile=profile
    )
    if edge_cap is not None and edge_cap != fitted.edge_cap:
        raise ValueError(f"evaluation edge_cap must equal fitted capacity {fitted.edge_cap}")
    if ep_cap is not None and ep_cap != fitted.ep_cap:
        raise ValueError(f"evaluation ep_cap must equal fitted capacity {fitted.ep_cap}")
    selected_edge_cap = fitted.edge_cap
    selected_ep_cap = fitted.ep_cap
    run_dir.mkdir(parents=True, mode=0o700)
    keys = run_dir / "keys"
    create_keys(keys, device_id)
    registry_path = run_dir / "staging/registry.json"
    opening_path = run_dir / "staging-private/enrollment.json"
    report_path = run_dir / "staging/report.json"
    worker_secret_path = run_dir / "staging-private/worker.json"

    authority_started = time.perf_counter()
    registry_envelope, _ = provision_raw_authority(
        artifacts=artifacts,
        policy_artifacts=policy_artifacts,
        binary=binary,
        authority_private=keys / "private/authority.pem",
        device_public=keys / f"public/{device_id}.pem",
        device_id=device_id,
        registry_output=registry_path,
        opening_output=opening_path,
        edge_cap=selected_edge_cap,
        ep_cap=selected_ep_cap,
        path_mode=path_mode,
        log_inv_rate=log_inv_rate,
        profile=profile,
    )
    authority_ms = (time.perf_counter() - authority_started) * 1000

    service = RawRegistryService(
        _regular_json(registry_path, "raw authority registry"),
        keys / "public/authority.pem",
    )
    challenge = service.issue_challenge(device_id, service.registry["raw_registry_id"])
    evidence_path = artifacts / (
        "evidence.json"
        if path_mode == "complete"
        else "projection.json"
    )
    device_started = time.perf_counter()
    report_envelope, _ = build_raw_device_report(
        artifacts=artifacts,
        policy_artifacts=policy_artifacts,
        binary=binary,
        trace_path=trace_path,
        evidence_path=evidence_path,
        registry_path=registry_path,
        opening_path=opening_path,
        authority_public=keys / "public/authority.pem",
        device_private=keys / f"private/{device_id}.pem",
        device_id=device_id,
        challenge_id=str(challenge["challenge_id"]),
        nonce=str(challenge["nonce"]),
        report_output=report_path,
        worker_secret_output=worker_secret_path,
        complete_source_artifacts=complete_source_artifacts,
        source_trace_path=source_trace_path,
    )
    device_ms = (time.perf_counter() - device_started) * 1000
    verdict = service.verify_report(report_envelope)
    try:
        service.verify_report(report_envelope)
    except ValueError as error:
        replay_rejection = str(error)
    else:
        raise AssertionError("raw registry accepted a replayed challenge")

    bundle = run_dir / "bundle"
    sizes = materialize_raw_bundle(
        output=bundle,
        artifacts=artifacts,
        authority_public=keys / "public/authority.pem",
        registry_path=registry_path,
        report_path=report_path,
        worker_secret_path=worker_secret_path,
    )
    authority_bytes = (keys / "public/authority.pem").read_bytes()
    registry = registry_envelope["payload"]
    report = report_envelope["payload"]
    invocation = [
        sys.executable,
        str(Path(__file__).absolute()),
        "--run-dir",
        str(run_dir.absolute()),
        "--artifacts",
        str(artifacts.absolute()),
        "--policy-artifacts",
        str(policy_artifacts.absolute()),
        "--binary",
        str(binary.absolute()),
        "--trace",
        str(trace_path.absolute()),
        "--path-mode",
        path_mode,
        "--log-inv-rate",
        str(log_inv_rate),
        "--device-id",
        device_id,
        "--profile",
        profile,
    ]
    if ep_cap is not None:
        invocation.extend(("--ep-cap", str(ep_cap)))
    if edge_cap is not None:
        invocation.extend(("--edge-cap", str(edge_cap)))
    if complete_source_artifacts is not None:
        invocation.extend(
            ("--complete-source-artifacts", str(complete_source_artifacts.absolute()))
        )
    if source_trace_path is not None:
        invocation.extend(("--source-trace", str(source_trace_path.absolute())))
    result: dict[str, object] = {
        "schema": "zkcfa.raw.run",
        "python_executable": sys.executable,
        "pythonpath": str(Path(__file__).resolve().parents[2] / "provider"),
        "invocation": invocation,
        "process_argv": [sys.executable, *sys.argv],
        "inputs": {
            "artifacts": str(artifacts.absolute()),
            "policy_artifacts": str(policy_artifacts.absolute()),
            "binary": str(binary.absolute()),
            "trace": str(trace_path.absolute()),
            "complete_source_artifacts": (
                str(complete_source_artifacts.absolute())
                if complete_source_artifacts is not None
                else None
            ),
            "source_trace": (
                str(source_trace_path.absolute())
                if source_trace_path is not None
                else None
            ),
        },
        "bundle": str(bundle.absolute()),
        "path_mode": path_mode,
        "capacity_policy": "fitted-evaluation",
        "authority_sha256": hashlib.sha256(authority_bytes).hexdigest(),
        "challenge": challenge,
        "raw_registry_id": registry["raw_registry_id"],
        "raw_config_id": registry["raw_config_id"],
        "h_cfg_raw24": registry["h_cfg_raw24"],
        "h_ep_raw24": report["h_ep_raw24"],
        "circuit": registry["circuit"],
        "authority_provision_ms": authority_ms,
        "device_sign_ms": device_ms,
        "registry_bytes": registry_path.stat().st_size,
        "report_bytes": report_path.stat().st_size,
        **sizes,
        "online_verdict": verdict,
        "replay_rejection": replay_rejection,
        "freshness_boundary": (
            "the in-memory reference service consumed this challenge once; a deployment must "
            "persist challenge state across process restarts"
        ),
    }
    _write_json_new(run_dir / "protocol-result.json", result)
    return result


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--policy-artifacts", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument(
        "--ep-cap", type=int,
        help="optional assertion; must equal the fitted normalized-path capacity",
    )
    parser.add_argument("--edge-cap", type=int)
    parser.add_argument(
        "--path-mode",
        choices=("complete", "shadow"),
        default="complete",
    )
    parser.add_argument("--log-inv-rate", type=int, default=1)
    parser.add_argument("--profile", choices=RAW_PROFILES, default=RAW24_PROFILE)
    parser.add_argument("--device-id", default="qemu-raw-device")
    parser.add_argument("--complete-source-artifacts", type=Path)
    parser.add_argument("--source-trace", type=Path)
    args = parser.parse_args(argv)
    result = build_signed_raw_bundle(
        run_dir=args.run_dir,
        artifacts=args.artifacts,
        policy_artifacts=args.policy_artifacts,
        binary=args.binary,
        trace_path=args.trace,
        edge_cap=args.edge_cap,
        ep_cap=args.ep_cap,
        path_mode=args.path_mode,
        log_inv_rate=args.log_inv_rate,
        profile=args.profile,
        device_id=args.device_id,
        complete_source_artifacts=args.complete_source_artifacts,
        source_trace_path=args.source_trace,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
