"""Challenge-first capture-to-signing orchestration for the QEMU prototype.

This entry point accepts no pre-existing trace. It starts QEMU with the issued
context in a new private directory, normalizes that run, and signs its evidence.
QEMU, this module, the static policy, and their storage emulate a protected Tracer.
The public context is not an authentication tag for an untrusted trace producer.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from pathlib import Path

from static.normalize import (
    load_translator, load_typed_cfg, normalize, parse_plugin_map, parse_trace,
    render_recorded_path, write_trace_evidence,
)
from static.runtime_dependencies import qemu_environment

from .protocol import build_raw_device_report, raw_capture_context, _write_json_new


def capture_raw_online_report(
    *, run_dir: Path, policy_artifacts: Path, binary: Path, qemu: Path,
    plugin: Path, sysroot: Path, challenge: dict[str, object],
    registry_path: Path, opening_path: Path, authority_public: Path,
    device_private: Path, device_id: str,
) -> dict[str, object]:
    """Acquire and sign one complete path using preprovisioned capacities.

    Production callers must supply the authenticated challenge through their
    protected session channel and protect acquisition buffers from replacement.
    No CFG membership or internal return-target check is performed here.
    """
    if challenge.get("device_id") != device_id:
        raise ValueError("online challenge targets a different device")
    if int(challenge["expires_at"]) < int(time.time()):
        raise ValueError("online challenge expired before capture")
    context = raw_capture_context(
        str(challenge["raw_registry_id"]), device_id,
        str(challenge["challenge_id"]), str(challenge["nonce"]),
    )
    run_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    artifacts = run_dir / "artifacts"
    artifacts.mkdir(mode=0o700)
    # Only static provisioning is reused; no dynamic log or EP is imported.
    for name in ("translator", "typed_cfg", "plugin-map.txt", "static-manifest.json"):
        shutil.copyfile(policy_artifacts / name, artifacts / name)
    trace = run_dir / "trace.log"
    report = run_dir / "report.json"
    secret = run_dir / "worker.json"
    started = time.perf_counter()
    start_ns = time.time_ns()
    command = [
        str(qemu), "-L", str(sysroot), "-plugin",
        f"{plugin},map={artifacts / 'plugin-map.txt'},log={trace},capture-context={context}",
        str(binary),
    ]
    captured = subprocess.run(command, env=qemu_environment(), capture_output=True, check=True)
    capture_ms = (time.perf_counter() - started) * 1000
    end_ns = time.time_ns()
    trace.chmod(0o600)
    (run_dir / "qemu.stdout.log").write_bytes(captured.stdout)
    (run_dir / "qemu.stderr.log").write_bytes(captured.stderr)
    norm_start = time.perf_counter()
    plugin_map = parse_plugin_map(artifacts / "plugin-map.txt")
    parsed = parse_trace(trace)
    if parsed.capture_context != context:
        raise ValueError("QEMU capture did not carry the issued session context")
    operations = normalize(
        plugin_map, parsed, load_typed_cfg(artifacts / "typed_cfg"),
        load_translator(artifacts / "translator"),
    )
    path = artifacts / "recorded_path"
    path.write_text(render_recorded_path(operations), encoding="ascii")
    evidence = artifacts / "evidence.json"
    write_trace_evidence(
        output=evidence, plugin_map_path=artifacts / "plugin-map.txt", trace=parsed,
        plugin_map=plugin_map,
        typed_cfg=artifacts / "typed_cfg", translator=artifacts / "translator",
        expected_typed_cfg_sha256=hashlib.sha256((artifacts / "typed_cfg").read_bytes()).hexdigest(),
        static_manifest=artifacts / "static-manifest.json", recorded_path=path,
    )
    normalize_ms = (time.perf_counter() - norm_start) * 1000
    if int(challenge["expires_at"]) < int(time.time()):
        raise ValueError("online challenge expired during capture")
    sign_start = time.perf_counter()
    signed, _ = build_raw_device_report(
        artifacts=artifacts, policy_artifacts=policy_artifacts, binary=binary,
        trace_path=trace, evidence_path=evidence, registry_path=registry_path,
        opening_path=opening_path, authority_public=authority_public,
        device_private=device_private, device_id=device_id,
        challenge_id=str(challenge["challenge_id"]), nonce=str(challenge["nonce"]),
        report_output=report, worker_secret_output=secret, require_capture_context=True,
    )
    sign_ms = (time.perf_counter() - sign_start) * 1000
    result = {
        "schema": "zkcfa.raw.online-capture.v1", "capture_context": context,
        "challenge": challenge, "capture_started_ns": start_ns,
        "capture_completed_ns": end_ns, "qemu_command": command,
        "qemu_exit_status": captured.returncode, "capture_ms": capture_ms,
        "normalization_ms": normalize_ms, "device_report_ms": sign_ms,
        "trace_sha256": hashlib.sha256(trace.read_bytes()).hexdigest(),
        "trace_bytes": trace.stat().st_size,
        "ep_rows": len(path.read_text().splitlines()), "report": signed,
    }
    _write_json_new(run_dir / "capture-result.json", result, private=True)
    return result
