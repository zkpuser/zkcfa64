"""A fresh authenticated execution report is not a control-flow verdict."""

from __future__ import annotations

import json
import unittest

import test_protocol as fixtures
from static.normalize import (
    load_translator, load_typed_cfg, normalize, parse_plugin_map, parse_trace,
    render_recorded_path, write_trace_evidence,
)
from static.shadow_safe_bundle import materialize_shadow_safe_bundle
from zkcfa_provider.common import sha256_file, write_json
from zkcfa_provider.protocol import (
    RawRegistryService, build_raw_device_report, materialize_raw_bundle,
    provision_raw_authority,
)
from zkcfa_provider.statement import RAW24_PROFILE, RAW64_PROFILE, RawBlind


class CaptureSigningTests(unittest.TestCase):
    def test_authenticated_noncompliant_executions_reach_worker(self) -> None:
        """Exercise real normalization, signing, report verification and handoff.

        These are synthetic trace fixtures, not fabricated proof acceptance:
        noncompliant evidence must be signed but fail worker preflight.
        """
        cases = {
            "valid": (0x400000, 0x400008, 0x400004),
            "missing-cal": (0x400000, 0x400008, 0x400004),
            "missing-crt": (0x400000, 0x400008, 0x400004),
            "wrong-return": (0x400000, 0x400008, 0x400000, 0x400008, 0x400004),
            "underflow": (0x400000, 0x400008, 0x400008, 0x400008, 0x400004),
            "discontinuity": (0x400000, 0x400008, 0x400004),
        }
        for profile in (RAW24_PROFILE, RAW64_PROFILE):
            for mode in ("complete", "shadow"):
                for case, pcs in cases.items():
                    with self.subTest(profile=profile, mode=mode, case=case):
                        fixture = fixtures.RawSignedProtocolTests()
                        fixture.setUp()
                        try:
                            self._check_case(fixture, profile, mode, case, pcs)
                        finally:
                            fixture.tearDown()

    def _check_case(self, f, profile, mode, case, pcs) -> None:
        if case in {"missing-cal", "missing-crt"}:
            edge = ("0x400000 cal 0x400008\n" if case == "missing-cal"
                    else "0x400000 crt 0x400004\n")
            cfg = f.artifacts / "typed_cfg"
            cfg.write_text(cfg.read_text().replace(edge, ""), encoding="ascii")
        if case == "discontinuity":
            plugin_map = f.artifacts / "plugin-map.txt"
            plugin_map.write_text(plugin_map.read_text().replace(
                "0x400008 4 0x400008 ret", "0x400008 4 0x400008 other"
            ), encoding="ascii")

        manifest_path = f.artifacts / "static-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["typed_cfg_sha256"] = sha256_file(f.artifacts / "typed_cfg")
        manifest["plugin_map_sha256"] = sha256_file(f.artifacts / "plugin-map.txt")
        write_json(manifest_path, manifest)
        original = f.trace.read_text().splitlines()
        f.trace.write_text("\n".join([
            *original[:2],
            *(f"insn {i} {pc:#x}" for i, pc in enumerate(pcs)),
            original[-2], f"end count={len(pcs)} complete=1 runtime_code_match=1",
        ]) + "\n", encoding="ascii")
        plugin_map = parse_plugin_map(f.artifacts / "plugin-map.txt")
        trace = parse_trace(f.trace)
        operations = normalize(plugin_map, trace,
                               load_typed_cfg(f.artifacts / "typed_cfg"),
                               load_translator(f.artifacts / "translator"))
        recorded = f.artifacts / "recorded_path"
        recorded.write_text(render_recorded_path(operations), encoding="ascii")
        write_trace_evidence(
            plugin_map=plugin_map, trace=trace, recorded_path=recorded,
            typed_cfg=f.artifacts / "typed_cfg",
            expected_typed_cfg_sha256=sha256_file(f.artifacts / "typed_cfg"),
            translator=f.artifacts / "translator", static_manifest=manifest_path,
            plugin_map_path=f.artifacts / "plugin-map.txt", output=f.evidence,
        )
        selected = f.artifacts
        if mode == "shadow":
            selected = f.root / "projected"
            materialize_shadow_safe_bundle(f.artifacts, selected)
        registry, opening = f.root / "public/new-registry.json", f.root / "private/new-opening.json"
        provision_raw_authority(
            artifacts=selected, policy_artifacts=f.artifacts, binary=f.binary,
            authority_private=f.root / "keys/private/authority.pem",
            device_public=f.root / "keys/public/device-1.pem", device_id="device-1",
            registry_output=registry, opening_output=opening,
            ep_cap=16, cfg_blind=RawBlind(1, 2), profile=profile, path_mode=mode,
        )
        service = RawRegistryService(json.loads(registry.read_text()),
                                     f.root / "keys/public/authority.pem")
        challenge = service.issue_challenge("device-1", service.registry["raw_registry_id"])
        report_path, secret_path = f.root / "new-report.json", f.root / "new-secret.json"
        report, _ = build_raw_device_report(
            artifacts=selected, policy_artifacts=f.artifacts, binary=f.binary,
            trace_path=f.trace, evidence_path=selected / (
                "evidence.json" if mode == "complete" else "projection.json"),
            registry_path=registry, opening_path=opening,
            authority_public=f.root / "keys/public/authority.pem",
            device_private=f.root / "keys/private/device-1.pem", device_id="device-1",
            challenge_id=challenge["challenge_id"], nonce=challenge["nonce"],
            report_output=report_path, worker_secret_output=secret_path,
            ep_blind=RawBlind(3, 4),
            complete_source_artifacts=f.artifacts if mode == "shadow" else None,
            source_trace_path=f.trace if mode == "shadow" else None,
        )
        # Freshness/authentication succeeds even for an invalid execution.
        self.assertTrue(service.verify_report(report)["accepted"])
        if case == "discontinuity":
            self.assertIn("discontinuity 0x400004 0x400008", recorded.read_text())
            self.assertIn("discontinuity", (selected / "recorded_path").read_text())
        destination = f.root / "worker-bundle"
        arguments = dict(
            output=destination, artifacts=selected,
            authority_public=f.root / "keys/public/authority.pem",
            registry_path=registry, report_path=report_path, worker_secret_path=secret_path,
        )
        if case == "valid":
            materialize_raw_bundle(**arguments)
            self.assertTrue((destination / "public/report.json").is_file())
        else:
            reason = {
                "missing-cal": "no typed forward edge",
                "missing-crt": "no typed CRT declaration",
                "wrong-return": "wrong call site",
                "underflow": "wrong call site",
                "discontinuity": "instruction discontinuity",
            }[case]
            with self.assertRaisesRegex(ValueError, reason):
                materialize_raw_bundle(**arguments)
            self.assertFalse(destination.exists())
