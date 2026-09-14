from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import zkcfa_provider.protocol as protocol_module
from static.normalize import (
    load_translator,
    load_typed_cfg,
    normalize,
    parse_plugin_map,
    parse_trace,
    render_recorded_path,
    write_trace_evidence,
)
from zkcfa_provider.common import sha256_file, write_json
from zkcfa_provider.protocol import (
    AUTHORITY_OPENING_SIGNATURE_DOMAIN,
    AUTHORITY_SIGNATURE_DOMAIN,
    DEVICE_SIGNATURE_DOMAIN,
    RawRegistryService,
    _cli as protocol_cli,
    build_raw_device_report,
    materialize_raw_bundle,
    provision_raw_authority,
)
from zkcfa_provider.crypto import (
    generate_keypair,
    load_private,
    load_public,
    sign_domain_envelope,
    verify_domain_envelope,
)
from zkcfa_provider.statement import (
    RAW64_PROFILE,
    RawBlind,
    RawParams,
    RawStep,
    encode_step,
    parse_raw_address,
    circuit_object,
    load_raw_evidence,
    load_raw_statement,
    raw_config_id,
    raw_registry_id,
)
from static.shadow_safe_bundle import materialize_shadow_safe_bundle


def create_keys(root: Path, device_id: str) -> None:
    private = root / "private"
    public = root / "public"
    private.mkdir(parents=True, mode=0o700)
    public.mkdir(parents=True, mode=0o755)
    generate_keypair(private / "authority.pem", public / "authority.pem")
    generate_keypair(private / f"{device_id}.pem", public / f"{device_id}.pem")


class RawSignedProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.binary = self.root / "crc32.elf"
        self.binary.write_bytes(b"raw-provider-test-binary")
        binary_hash = sha256_file(self.binary)
        (self.artifacts / "translator").write_text(
            "SCOPE_RETURN\n0x400000\n0x400004\n0x400008\n",
            encoding="ascii",
        )
        (self.artifacts / "typed_cfg").write_text(
            "SCOPE_RETURN cal 0x400000\n"
            "SCOPE_RETURN crt SCOPE_RETURN\n"
            "0x400000 cal 0x400008\n"
            "0x400000 crt 0x400004\n",
            encoding="ascii",
        )
        (self.artifacts / "plugin-map.txt").write_text(
            "zkcfa.provider.map\n"
            f"elf_sha256 {binary_hash}\n"
            "trace_schema zkcfa.scope.trace\n"
            "sentinel SCOPE_RETURN 0xffff0000\n"
            "scope_call 0x300000\n"
            "root_entry 0x400000\n"
            "scope_return 0x300004\n"
            "root_ret 0x400004\n"
            "insn 0x300000 4 0x300000 call 0x400000 00000000\n"
            "insn 0x400000 4 0x400000 call 0x400008 00000000\n"
            "insn 0x400004 4 0x400004 ret 0x0 00000000\n"
            "insn 0x400008 4 0x400008 ret 0x0 00000000\n",
            encoding="ascii",
        )
        self.trace = self.root / "trace.log"
        self.trace.write_text(
            f"zkcfa.scope.trace elf_sha256={binary_hash}\n"
            "begin scope_call=0x300000 root=0x400000 scope_return=0x300004 "
            "boundary_kind=in-binary-direct-call-and-root-ret\n"
            "insn 0 0x400000\n"
            "insn 1 0x400008\n"
            "insn 2 0x400004\n"
            "scope_exit 0x300004 return_continuation_matched=1\n"
            "end count=3 complete=1 runtime_code_match=1\n",
            encoding="ascii",
        )
        write_json(
            self.artifacts / "static-manifest.json",
            {
                "schema": "zkcfa.static",
                "application": "crc32",
                "runtime_profile": "freestanding-static",
                "runtime_dependencies_sha256": (
                    "4d0763621fc031affff9f1f62fb60e2496b1e29cf7892053c94be2c7d52d1ca3"
                ),
                "elf_sha256": binary_hash,
                "translator_sha256": sha256_file(self.artifacts / "translator"),
                "typed_cfg_sha256": sha256_file(self.artifacts / "typed_cfg"),
                "plugin_map_sha256": sha256_file(self.artifacts / "plugin-map.txt"),
                "trace_schema": "zkcfa.scope.trace",
                "external_call_policy": {
                    "schema": "zkcfa.external-call-policy",
                    "mode": "none",
                    "binding": "none",
                    "loader_scope": "none",
                    "thread_model": "single",
                    "dispatch_integrity": None,
                    "runtime_dependencies": {
                        "schema": "zkcfa.runtime-dependencies",
                        "runtime_profile": "freestanding-static",
                        "binding": "none",
                        "environment": {},
                        "files": [],
                        "loader_scope": "none",
                    },
                    "calls": [],
                },
                "scope_policy": {
                    "root_symbol": "attested_crc32",
                    "caller_symbol": "_start",
                    "scope_call_address": "0x300000",
                    "root_address": "0x400000",
                    "root_exit_blocks": ["0x400004"],
                    "scope_return_address": "0x300004",
                    "boundary_kind": "in-binary-direct-call-and-root-ret",
                    "sentinel": "SCOPE_RETURN",
                },
            },
        )
        plugin_map = parse_plugin_map(self.artifacts / "plugin-map.txt")
        parsed_trace = parse_trace(self.trace)
        operations = normalize(
            plugin_map,
            parsed_trace,
            load_typed_cfg(self.artifacts / "typed_cfg"),
            load_translator(self.artifacts / "translator"),
        )
        (self.artifacts / "recorded_path").write_text(
            render_recorded_path(operations), encoding="ascii"
        )
        self.evidence = self.artifacts / "evidence.json"
        write_trace_evidence(
            plugin_map=plugin_map,
            trace=parsed_trace,
            recorded_path=self.artifacts / "recorded_path",
            typed_cfg=self.artifacts / "typed_cfg",
            expected_typed_cfg_sha256=sha256_file(self.artifacts / "typed_cfg"),
            translator=self.artifacts / "translator",
            static_manifest=self.artifacts / "static-manifest.json",
            plugin_map_path=self.artifacts / "plugin-map.txt",
            output=self.evidence,
        )
        create_keys(self.root / "keys", "device-1")
        self.registry = self.root / "public/registry.json"
        self.opening = self.root / "private/opening.json"
        provision_raw_authority(
            artifacts=self.artifacts,
            binary=self.binary,
            authority_private=self.root / "keys/private/authority.pem",
            device_public=self.root / "keys/public/device-1.pem",
            device_id="device-1",
            registry_output=self.registry,
            opening_output=self.opening,
            ep_cap=16,
            cfg_blind=RawBlind(1, 2),
        )
        self.service = RawRegistryService(
            json.loads(self.registry.read_text()),
            self.root / "keys/public/authority.pem",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _sign(self, *, evidence: Path | None = None) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        challenge = self.service.issue_challenge(
            "device-1", self.service.registry["raw_registry_id"]
        )
        report_path = self.root / f"report-{challenge['challenge_id']}.json"
        secret_path = self.root / f"secret-{challenge['challenge_id']}.json"
        report, secret = build_raw_device_report(
            artifacts=self.artifacts,
            policy_artifacts=self.artifacts,
            binary=self.binary,
            trace_path=self.trace,
            evidence_path=evidence or self.evidence,
            registry_path=self.registry,
            opening_path=self.opening,
            authority_public=self.root / "keys/public/authority.pem",
            device_private=self.root / "keys/private/device-1.pem",
            device_id="device-1",
            challenge_id=str(challenge["challenge_id"]),
            nonce=str(challenge["nonce"]),
            report_output=report_path,
            worker_secret_output=secret_path,
            ep_blind=RawBlind(3, 4),
        )
        self.report_path = report_path
        self.secret_path = secret_path
        return report, secret, challenge

    def test_end_to_end_signature_freshness_and_minimal_worker_boundary(self) -> None:
        report, secret, _challenge = self._sign()
        payload = report["payload"]
        self.assertEqual(payload["h_cfg_raw24"], self.service.registry["h_cfg_raw24"])
        self.assertEqual(secret["h_cfg_raw24"], payload["h_cfg_raw24"])
        self.assertEqual(secret["h_ep_raw24"], payload["h_ep_raw24"])
        public = json.dumps(report, sort_keys=True)
        for forbidden in ("blind", "translator_sha256", "typed_cfg_sha256"):
            self.assertNotIn(forbidden, public)
        self.assertEqual(
            set(secret),
            {
                "schema", "raw_registry_id", "raw_config_id", "h_cfg_raw24",
                "h_ep_raw24", "ep_blind_low", "ep_blind_high",
                "cfg_blind_low", "cfg_blind_high",
            },
        )
        self.assertEqual(stat.S_IMODE(self.secret_path.stat().st_mode), 0o600)
        self.assertTrue(self.service.verify_report(report)["accepted"])
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.service.verify_report(report)

    def test_signed_tampering_and_cross_registry_cfg_are_rejected(self) -> None:
        report, _secret, _challenge = self._sign()
        for field, value in (
            ("h_ep_raw24", "00" * 32),
            ("h_cfg_raw24", "00" * 32),
            ("entry_raw", 1),
            ("nonce", "00" * 32),
        ):
            tampered = copy.deepcopy(report)
            tampered["payload"][field] = value
            with self.assertRaisesRegex(ValueError, "signature"):
                self.service.verify_report(tampered)

        authority_tamper = json.loads(self.registry.read_text())
        authority_tamper["payload"]["h_cfg_raw24"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "signature"):
            RawRegistryService(
                authority_tamper, self.root / "keys/public/authority.pem"
            )

        # A report can have a cryptographically valid device signature and still be invalid
        # protocol data. Re-signing a mismatched H_cfg must be caught by registry cross-binding.
        mismatched_payload = copy.deepcopy(report["payload"])
        mismatched_payload["h_cfg_raw24"] = "00" * 32
        valid_but_mismatched = sign_domain_envelope(
            mismatched_payload,
            load_private(self.root / "keys/private/device-1.pem"),
            domain=DEVICE_SIGNATURE_DOMAIN,
        )
        with self.assertRaisesRegex(ValueError, "h_cfg_raw24"):
            self.service.verify_report(valid_but_mismatched)

    def test_valid_cross_registry_report_splicing_is_rejected(self) -> None:
        second_registry = self.root / "public/registry-second.json"
        second_opening = self.root / "private/opening-second.json"
        provision_raw_authority(
            artifacts=self.artifacts,
            binary=self.binary,
            authority_private=self.root / "keys/private/authority.pem",
            device_public=self.root / "keys/public/device-1.pem",
            device_id="device-1",
            registry_output=second_registry,
            opening_output=second_opening,
            ep_cap=16,
            cfg_blind=RawBlind(5, 6),
        )
        second_service = RawRegistryService(
            json.loads(second_registry.read_text()),
            self.root / "keys/public/authority.pem",
        )
        challenge = second_service.issue_challenge(
            "device-1", second_service.registry["raw_registry_id"]
        )
        second_report, _ = build_raw_device_report(
            artifacts=self.artifacts,
            policy_artifacts=self.artifacts,
            binary=self.binary,
            trace_path=self.trace,
            evidence_path=self.evidence,
            registry_path=second_registry,
            opening_path=second_opening,
            authority_public=self.root / "keys/public/authority.pem",
            device_private=self.root / "keys/private/device-1.pem",
            device_id="device-1",
            challenge_id=str(challenge["challenge_id"]),
            nonce=str(challenge["nonce"]),
            report_output=self.root / "report-second.json",
            worker_secret_output=self.root / "secret-second.json",
            ep_blind=RawBlind(7, 8),
        )
        self.assertTrue(second_service.verify_report(second_report)["accepted"])
        self.assertNotEqual(
            second_report["payload"]["raw_registry_id"],
            self.service.registry["raw_registry_id"],
        )
        with self.assertRaisesRegex(ValueError, "raw_registry_id"):
            self.service.verify_report(second_report)

    def test_non_ascii_signed_public_payload_is_rejected(self) -> None:
        payload = copy.deepcopy(self.service.registry)
        payload["scope_policy"]["root_symbol"] = "røot"
        payload.pop("raw_registry_id")
        payload["raw_registry_id"] = raw_registry_id(payload)
        envelope = sign_domain_envelope(
            payload,
            load_private(self.root / "keys/private/authority.pem"),
            domain=AUTHORITY_SIGNATURE_DOMAIN,
        )
        with self.assertRaisesRegex(ValueError, "non-ASCII"):
            RawRegistryService(
                envelope, self.root / "keys/public/authority.pem"
            )

    def test_cross_language_scope_and_numeric_types_are_rejected(self) -> None:
        authority = load_private(self.root / "keys/private/authority.pem")
        malformed_payloads = []

        bad_architecture = copy.deepcopy(self.service.registry)
        bad_architecture["scope_policy"]["architecture"] = "riscv64"
        malformed_payloads.append((bad_architecture, "architecture"))

        bad_position_flag = copy.deepcopy(self.service.registry)
        bad_position_flag["scope_policy"]["position_independent"] = 1
        malformed_payloads.append((bad_position_flag, "position-independent"))

        bad_capacity_type = copy.deepcopy(self.service.registry)
        bad_capacity_type["circuit"]["ep_cap"] = True
        bad_capacity_type["raw_config_id"] = raw_config_id(
            bad_capacity_type["circuit"]
        )
        malformed_payloads.append((bad_capacity_type, "capacity"))

        extra_circuit_field = copy.deepcopy(self.service.registry)
        extra_circuit_field["circuit"]["unsupported_field"] = 96
        extra_circuit_field["raw_config_id"] = raw_config_id(
            extra_circuit_field["circuit"]
        )
        malformed_payloads.append((extra_circuit_field, "missing, unknown, or downgraded"))

        for payload, error in malformed_payloads:
            payload.pop("raw_registry_id")
            payload["raw_registry_id"] = raw_registry_id(payload)
            envelope = sign_domain_envelope(
                payload, authority, domain=AUTHORITY_SIGNATURE_DOMAIN
            )
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                RawRegistryService(
                    envelope, self.root / "keys/public/authority.pem"
                )

    def test_signature_domains_are_not_interchangeable(self) -> None:
        envelope = json.loads(self.registry.read_text())
        authority = load_public(self.root / "keys/public/authority.pem")
        with self.assertRaisesRegex(ValueError, "signature"):
            verify_domain_envelope(
                envelope, authority, domain=DEVICE_SIGNATURE_DOMAIN
            )

    def test_offline_cli_has_no_replayable_challenge_or_verify_commands(self) -> None:
        for command in ("challenge", "verify"):
            with self.subTest(command=command), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as stopped:
                    protocol_cli([command])
                self.assertEqual(stopped.exception.code, 2)

    def test_wrong_evidence_is_rejected_before_any_output(self) -> None:
        value = json.loads(self.evidence.read_text())
        value["runtime_code_match"] = False
        original = self.evidence.read_bytes()
        write_json(self.evidence, value)
        challenge = self.service.issue_challenge(
            "device-1", self.service.registry["raw_registry_id"]
        )
        report = self.root / "rejected-report.json"
        secret = self.root / "rejected-secret.json"
        try:
            with self.assertRaisesRegex(ValueError, "recomputation"):
                build_raw_device_report(
                    artifacts=self.artifacts,
                    policy_artifacts=self.artifacts,
                    binary=self.binary,
                    trace_path=self.trace,
                    evidence_path=self.evidence,
                    registry_path=self.registry,
                    opening_path=self.opening,
                    authority_public=self.root / "keys/public/authority.pem",
                    device_private=self.root / "keys/private/device-1.pem",
                    device_id="device-1",
                    challenge_id=str(challenge["challenge_id"]),
                    nonce=str(challenge["nonce"]),
                    report_output=report,
                    worker_secret_output=secret,
                )
        finally:
            self.evidence.write_bytes(original)
        self.assertFalse(report.exists())
        self.assertFalse(secret.exists())

    def test_statement_and_evidence_share_one_recorded_path_snapshot(self) -> None:
        recorded_path = self.artifacts / "recorded_path"
        recomputed_path = recorded_path.read_bytes()
        recorded_path.write_text(
            "initial_node=SCOPE_RETURN final_node=SCOPE_RETURN\n"
            "call 0x400000 SCOPE_RETURN\n"
            "ret SCOPE_RETURN\n",
            encoding="ascii",
        )
        challenge = self.service.issue_challenge(
            "device-1", self.service.registry["raw_registry_id"]
        )
        report = self.root / "snapshot-race-report.json"
        secret = self.root / "snapshot-race-secret.json"

        def restore_source_after_statement(bundle: Path, **kwargs: object):
            statement = load_raw_evidence(bundle, **kwargs)
            recorded_path.write_bytes(recomputed_path)
            return statement

        try:
            with patch(
                "zkcfa_provider.protocol.load_raw_evidence",
                side_effect=restore_source_after_statement,
            ):
                with self.assertRaisesRegex(ValueError, "device recomputation"):
                    build_raw_device_report(
                        artifacts=self.artifacts,
                        policy_artifacts=self.artifacts,
                        binary=self.binary,
                        trace_path=self.trace,
                        evidence_path=self.evidence,
                        registry_path=self.registry,
                        opening_path=self.opening,
                        authority_public=self.root / "keys/public/authority.pem",
                        device_private=self.root / "keys/private/device-1.pem",
                        device_id="device-1",
                        challenge_id=str(challenge["challenge_id"]),
                        nonce=str(challenge["nonce"]),
                        report_output=report,
                        worker_secret_output=secret,
                        ep_blind=RawBlind(3, 4),
                    )
        finally:
            recorded_path.write_bytes(recomputed_path)
        self.assertFalse(report.exists())
        self.assertFalse(secret.exists())

    def test_symlink_and_overwrite_fail_closed(self) -> None:
        original = self.evidence.read_bytes()
        target = self.root / "linked-evidence-target.json"
        target.write_bytes(original)
        self.evidence.unlink()
        self.evidence.symlink_to(target)
        challenge = self.service.issue_challenge(
            "device-1", self.service.registry["raw_registry_id"]
        )
        try:
            with self.assertRaisesRegex(ValueError, "symlink"):
                build_raw_device_report(
                    artifacts=self.artifacts,
                    policy_artifacts=self.artifacts,
                    binary=self.binary,
                    trace_path=self.trace,
                    evidence_path=self.evidence,
                    registry_path=self.registry,
                    opening_path=self.opening,
                    authority_public=self.root / "keys/public/authority.pem",
                    device_private=self.root / "keys/private/device-1.pem",
                    device_id="device-1",
                    challenge_id=str(challenge["challenge_id"]),
                    nonce=str(challenge["nonce"]),
                    report_output=self.root / "link-report.json",
                    worker_secret_output=self.root / "link-secret.json",
                )
        finally:
            self.evidence.unlink()
            self.evidence.write_bytes(original)
        report, _secret, _challenge = self._sign()
        with self.assertRaises(FileExistsError):
            build_raw_device_report(
                artifacts=self.artifacts,
                policy_artifacts=self.artifacts,
                binary=self.binary,
                trace_path=self.trace,
                evidence_path=self.evidence,
                registry_path=self.registry,
                opening_path=self.opening,
                authority_public=self.root / "keys/public/authority.pem",
                device_private=self.root / "keys/private/device-1.pem",
                device_id="device-1",
                challenge_id=report["payload"]["challenge_id"],
                nonce=report["payload"]["nonce"],
                report_output=self.report_path,
                worker_secret_output=self.root / "unused-secret.json",
            )

    def test_authority_cfg_commitment_is_trace_independent(self) -> None:
        original = (self.artifacts / "recorded_path").read_text()
        (self.artifacts / "recorded_path").write_text("not a path\n")
        try:
            registry, _ = provision_raw_authority(
                artifacts=self.artifacts,
                binary=self.binary,
                authority_private=self.root / "keys/private/authority.pem",
                device_public=self.root / "keys/public/device-1.pem",
                device_id="device-1",
                registry_output=self.root / "trace-independent-registry.json",
                opening_output=self.root / "private/trace-independent-opening.json",
                ep_cap=16,
                cfg_blind=RawBlind(1, 2),
            )
            self.assertEqual(
                registry["payload"]["h_cfg_raw24"],
                self.service.registry["h_cfg_raw24"],
            )
        finally:
            (self.artifacts / "recorded_path").write_text(original)

    def test_authority_static_inputs_share_one_snapshot(self) -> None:
        manifest_path = self.artifacts / "static-manifest.json"
        source_manifest = manifest_path.read_bytes()
        first_manifest = json.loads(source_manifest)
        first_manifest["scope_policy"]["root_symbol"] = "first-root"
        first_bytes = (
            json.dumps(first_manifest, indent=2, sort_keys=True).encode("ascii") + b"\n"
        )
        source_files = {
            os.path.abspath(self.artifacts / "translator"): "translator",
            os.path.abspath(self.artifacts / "typed_cfg"): "typed_cfg",
            os.path.abspath(self.artifacts / "plugin-map.txt"): "plugin-map.txt",
            os.path.abspath(manifest_path): "static-manifest.json",
            os.path.abspath(self.binary): "binary",
        }
        source_reads = {name: 0 for name in source_files.values()}
        regular_bytes = protocol_module._regular_bytes

        def alternate_source_manifest(
            path: Path, description: str, *, private: bool = False
        ) -> bytes:
            source_name = source_files.get(os.path.abspath(path))
            if source_name is not None:
                source_reads[source_name] += 1
            if source_name == "static-manifest.json":
                return (
                    first_bytes
                    if source_reads["static-manifest.json"] == 1
                    else source_manifest
                )
            return regular_bytes(path, description, private=private)

        with patch(
            "zkcfa_provider.protocol._regular_bytes",
            side_effect=alternate_source_manifest,
        ):
            registry, opening = provision_raw_authority(
                artifacts=self.artifacts,
                binary=self.binary,
                authority_private=self.root / "keys/private/authority.pem",
                device_public=self.root / "keys/public/device-1.pem",
                device_id="device-1",
                registry_output=self.root / "snapshot-registry.json",
                opening_output=self.root / "private/snapshot-opening.json",
                ep_cap=16,
                cfg_blind=RawBlind(1, 2),
            )

        self.assertEqual(source_reads, {name: 1 for name in source_reads})
        self.assertEqual(registry["payload"]["scope_policy"]["root_symbol"], "first-root")
        self.assertEqual(
            opening["payload"]["static_manifest_sha256"],
            hashlib.sha256(first_bytes).hexdigest(),
        )

    def test_device_rejects_complete_scope_policy_mismatch(self) -> None:
        registry_payload = copy.deepcopy(self.service.registry)
        registry_payload["scope_policy"]["root_symbol"] = "mismatched-root"
        registry_payload.pop("raw_registry_id")
        registry_payload["raw_registry_id"] = raw_registry_id(registry_payload)
        authority = load_private(self.root / "keys/private/authority.pem")
        registry_envelope = sign_domain_envelope(
            registry_payload,
            authority,
            domain=AUTHORITY_SIGNATURE_DOMAIN,
        )
        opening_payload = json.loads(self.opening.read_text())["payload"]
        opening_payload["raw_registry_id"] = registry_payload["raw_registry_id"]
        opening_envelope = sign_domain_envelope(
            opening_payload,
            authority,
            domain=AUTHORITY_OPENING_SIGNATURE_DOMAIN,
        )
        registry_path = self.root / "scope-mismatch-registry.json"
        opening_path = self.root / "private/scope-mismatch-opening.json"
        write_json(registry_path, registry_envelope)
        write_json(opening_path, opening_envelope, private=True)
        service = RawRegistryService(
            registry_envelope,
            self.root / "keys/public/authority.pem",
        )
        challenge = service.issue_challenge(
            "device-1", service.registry["raw_registry_id"]
        )
        report_path = self.root / "scope-mismatch-report.json"
        secret_path = self.root / "scope-mismatch-secret.json"

        with self.assertRaisesRegex(ValueError, "static scope policy"):
            build_raw_device_report(
                artifacts=self.artifacts,
                policy_artifacts=self.artifacts,
                binary=self.binary,
                trace_path=self.trace,
                evidence_path=self.evidence,
                registry_path=registry_path,
                opening_path=opening_path,
                authority_public=self.root / "keys/public/authority.pem",
                device_private=self.root / "keys/private/device-1.pem",
                device_id="device-1",
                challenge_id=str(challenge["challenge_id"]),
                nonce=str(challenge["nonce"]),
                report_output=report_path,
                worker_secret_output=secret_path,
            )
        self.assertFalse(report_path.exists())
        self.assertFalse(secret_path.exists())

    def test_bundle_permissions_and_exact_contract(self) -> None:
        _, secret, _ = self._sign()
        enrollment = json.loads(self.opening.read_text())["payload"]
        self.assertEqual(
            set(secret),
            {
                "schema", "raw_registry_id", "raw_config_id", "h_cfg_raw24",
                "h_ep_raw24", "ep_blind_low", "ep_blind_high",
                "cfg_blind_low", "cfg_blind_high",
            },
        )
        self.assertEqual(
            set(enrollment),
            {
                "schema", "raw_registry_id", "cfg_blind_low", "cfg_blind_high",
                "static_manifest_sha256",
            },
        )
        output = self.root / "signed-bundle"
        sizes = materialize_raw_bundle(
            output=output,
            artifacts=self.artifacts,
            authority_public=self.root / "keys/public/authority.pem",
            registry_path=self.registry,
            report_path=self.report_path,
            worker_secret_path=self.secret_path,
        )
        self.assertGreater(sizes["public_bytes"], 0)
        self.assertGreater(sizes["private_bytes"], 0)
        self.assertEqual(stat.S_IMODE((output / "public").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((output / "private").stat().st_mode), 0o700)
        self.assertEqual(
            {path.name for path in (output / "public").iterdir()},
            {"registry.json", "report.json"},
        )
        for path in (output / "public").iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        for path in (output / "private").iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(
            {path.name for path in (output / "private").iterdir()},
            {"worker.json", "translator", "typed_cfg", "recorded_path"},
        )
        unknown_secret = dict(secret)
        unknown_secret["unsupported_field"] = "rejected"
        unknown_path = self.root / "unknown-worker.json"
        write_json(unknown_path, unknown_secret, private=True)
        with self.assertRaisesRegex(ValueError, "missing or unknown fields"):
            materialize_raw_bundle(
                output=self.root / "unknown-worker-bundle",
                artifacts=self.artifacts,
                authority_public=self.root / "keys/public/authority.pem",
                registry_path=self.registry,
                report_path=self.report_path,
                worker_secret_path=unknown_path,
            )

    def test_shadow_safe_is_independently_signed_after_trusted_regeneration(self) -> None:
        projected = self.root / "projected"
        materialize_shadow_safe_bundle(self.artifacts, projected)
        registry = self.root / "public/shadow-registry.json"
        opening = self.root / "private/shadow-opening.json"
        provision_raw_authority(
            artifacts=projected,
            policy_artifacts=self.artifacts,
            binary=self.binary,
            authority_private=self.root / "keys/private/authority.pem",
            device_public=self.root / "keys/public/device-1.pem",
            device_id="device-1",
            registry_output=registry,
            opening_output=opening,
            ep_cap=16,
            path_mode="shadow",
            cfg_blind=RawBlind(9, 10),
        )
        service = RawRegistryService(
            json.loads(registry.read_text()),
            self.root / "keys/public/authority.pem",
        )
        challenge = service.issue_challenge(
            "device-1", service.registry["raw_registry_id"]
        )
        report_path = self.root / "shadow-report.json"
        secret_path = self.root / "shadow-secret.json"
        report, secret = build_raw_device_report(
            artifacts=projected,
            policy_artifacts=self.artifacts,
            binary=self.binary,
            trace_path=self.trace,
            evidence_path=projected / "projection.json",
            registry_path=registry,
            opening_path=opening,
            authority_public=self.root / "keys/public/authority.pem",
            device_private=self.root / "keys/private/device-1.pem",
            device_id="device-1",
            challenge_id=str(challenge["challenge_id"]),
            nonce=str(challenge["nonce"]),
            report_output=report_path,
            worker_secret_output=secret_path,
            ep_blind=RawBlind(11, 12),
            complete_source_artifacts=self.artifacts,
            source_trace_path=self.trace,
        )
        self.assertEqual(
            service.registry["circuit"]["path_mode"], "shadow"
        )
        self.assertNotIn("path_evidence", secret)
        self.assertTrue(service.verify_report(report)["accepted"])
        bundle = self.root / "shadow-bundle"
        materialize_raw_bundle(
            output=bundle,
            artifacts=projected,
            authority_public=self.root / "keys/public/authority.pem",
            registry_path=registry,
            report_path=report_path,
            worker_secret_path=secret_path,
        )
        self.assertEqual(
            {path.name for path in (bundle / "private").iterdir()},
            {"worker.json", "translator", "typed_cfg", "recorded_path"},
        )

        projected_path = projected / "recorded_path"
        regenerated_path = projected_path.read_bytes()
        projected_path.write_text(
            "initial_node=SCOPE_RETURN final_node=SCOPE_RETURN\n"
            "call 0x400000 SCOPE_RETURN\n"
            "ret SCOPE_RETURN\n",
            encoding="ascii",
        )
        snapshot_challenge = service.issue_challenge(
            "device-1", service.registry["raw_registry_id"]
        )
        snapshot_report = self.root / "shadow-snapshot-race-report.json"
        snapshot_secret = self.root / "shadow-snapshot-race-secret.json"

        def restore_projected_after_statement(bundle_path: Path, **kwargs: object):
            statement = load_raw_evidence(bundle_path, **kwargs)
            projected_path.write_bytes(regenerated_path)
            return statement

        try:
            with patch(
                "zkcfa_provider.protocol.load_raw_evidence",
                side_effect=restore_projected_after_statement,
            ):
                with self.assertRaisesRegex(
                    ValueError, "selected shadow-safe recorded_path"
                ):
                    build_raw_device_report(
                        artifacts=projected,
                        policy_artifacts=self.artifacts,
                        binary=self.binary,
                        trace_path=self.trace,
                        evidence_path=projected / "projection.json",
                        registry_path=registry,
                        opening_path=opening,
                        authority_public=self.root / "keys/public/authority.pem",
                        device_private=self.root / "keys/private/device-1.pem",
                        device_id="device-1",
                        challenge_id=str(snapshot_challenge["challenge_id"]),
                        nonce=str(snapshot_challenge["nonce"]),
                        report_output=snapshot_report,
                        worker_secret_output=snapshot_secret,
                        ep_blind=RawBlind(13, 14),
                        complete_source_artifacts=self.artifacts,
                        source_trace_path=self.trace,
                    )
        finally:
            projected_path.write_bytes(regenerated_path)
        self.assertFalse(snapshot_report.exists())
        self.assertFalse(snapshot_secret.exists())

        projection = json.loads((projected / "projection.json").read_text())
        projection["compressor_source_sha256"] = "00" * 32
        write_json(projected / "projection.json", projection)
        second_challenge = service.issue_challenge(
            "device-1", service.registry["raw_registry_id"]
        )
        with self.assertRaisesRegex(ValueError, "trusted regeneration"):
            build_raw_device_report(
                artifacts=projected,
                policy_artifacts=self.artifacts,
                binary=self.binary,
                trace_path=self.trace,
                evidence_path=projected / "projection.json",
                registry_path=registry,
                opening_path=opening,
                authority_public=self.root / "keys/public/authority.pem",
                device_private=self.root / "keys/private/device-1.pem",
                device_id="device-1",
                challenge_id=str(second_challenge["challenge_id"]),
                nonce=str(second_challenge["nonce"]),
                report_output=self.root / "shadow-report-unknown.json",
                worker_secret_output=self.root / "shadow-secret-unknown.json",
                complete_source_artifacts=self.artifacts,
                source_trace_path=self.trace,
            )

    def test_serializer_vector_and_log_rate_boundary(self) -> None:
        statement = load_raw_statement(
            self.artifacts,
            cfg_blind=RawBlind(1, 2),
            ep_blind=RawBlind(3, 4),
            edge_cap=8,
            ep_cap=16,
        )
        self.assertEqual(
            statement.h_cfg_raw24,
            "adbeb0db35f96861fde983404a70d70fd1c8bc55a9242d7bb2da27c77c0c1d72",
        )
        self.assertEqual(
            statement.h_ep_raw24,
            "89a5fdf4dfd3f8c06528525f0e1ae7a026345e19a8ba0a4d71cc091252e7847d",
        )
        self.assertEqual(
            raw_config_id(circuit_object(statement.params)),
            "bdd2a50f0d5716899d7f06ebf01e0a6e84ee3d1873e7d10dce746fc6a2136dbc",
        )
        self.assertEqual(
            circuit_object(statement.params),
            {
                "schema": "zkcfa.raw.circuit",
                "profile": "raw24-full-key",
                "backend": "binius64",
                "edge_cap": 8,
                "ep_cap": 16,
                "path_mode": "complete",
                "log_inv_rate": 1,
            },
        )
        self.assertEqual(
            (RawParams(8, 1 << 14).ep_encoding, RawParams(8, 1 << 14).multiplicity_bits),
            ("inline14", 12),
        )
        self.assertEqual(
            (RawParams(8, 1 << 15).ep_encoding, RawParams(8, 1 << 15).multiplicity_bits),
            ("shared24", 16),
        )
        RawParams(8, 16, log_inv_rate=16).validate()
        with self.assertRaisesRegex(ValueError, "1..=16"):
            RawParams(8, 16, log_inv_rate=17).validate()
        with self.assertRaisesRegex(ValueError, "power of two"):
            RawParams(True, 16).validate()
        with self.assertRaisesRegex(ValueError, "canonical u64"):
            RawBlind(True, 2).validate("test blind")
        oversized = load_raw_statement(
            self.artifacts,
            cfg_blind=RawBlind(1, 2),
            ep_blind=RawBlind(3, 4),
            edge_cap=16,
            ep_cap=32,
        )
        self.assertEqual((oversized.params.edge_cap, oversized.params.ep_cap), (16, 32))

    def test_proof_input_text_grammar_is_canonical(self) -> None:
        files = {
            name: (self.artifacts / name).read_text(encoding="ascii")
            for name in ("translator", "typed_cfg", "recorded_path")
        }
        malformed = (
            ("translator", files["translator"].replace("\n0x400004", "\n\n0x400004")),
            ("translator", files["translator"] + "# comment\n"),
            ("typed_cfg", files["typed_cfg"].replace("\n0x400000 cal", "\n\n0x400000 cal")),
            ("typed_cfg", files["typed_cfg"] + "# comment\n"),
            ("recorded_path", files["recorded_path"].replace("\ncall", "\n\ncall")),
            ("recorded_path", files["recorded_path"].replace("0x400000", "0X400000", 1)),
        )
        for index, (name, contents) in enumerate(malformed):
            with self.subTest(index=index, name=name):
                (self.artifacts / name).write_text(contents, encoding="ascii")
                try:
                    with self.assertRaises(ValueError):
                        load_raw_statement(
                            self.artifacts,
                            cfg_blind=RawBlind(1, 2),
                            ep_blind=RawBlind(3, 4),
                            edge_cap=8,
                            ep_cap=16,
                        )
                finally:
                    (self.artifacts / name).write_text(files[name], encoding="ascii")


    def _select_wide_profile(self, *, relocate: bool = True) -> None:
        """Create fresh signed inputs, including regenerated acquisition evidence."""
        if relocate:
            replacements = {
                "0x400000": "0x555555554000",
                "0x400004": "0x555555554004",
                "0x400008": "0x555555554008",
                "0x300000": "0x555555553000",
                "0x300004": "0x555555553004",
            }
            for path in (
                self.artifacts / "translator", self.artifacts / "typed_cfg",
                self.artifacts / "plugin-map.txt", self.artifacts / "static-manifest.json",
                self.trace,
            ):
                contents = path.read_text(encoding="ascii")
                for old, new in replacements.items():
                    contents = contents.replace(old, new)
                path.write_text(contents, encoding="ascii")
            manifest = json.loads((self.artifacts / "static-manifest.json").read_text())
            for field, filename in (
                ("translator_sha256", "translator"),
                ("typed_cfg_sha256", "typed_cfg"),
                ("plugin_map_sha256", "plugin-map.txt"),
            ):
                manifest[field] = sha256_file(self.artifacts / filename)
            write_json(self.artifacts / "static-manifest.json", manifest)
            plugin_map = parse_plugin_map(self.artifacts / "plugin-map.txt")
            parsed_trace = parse_trace(self.trace)
            operations = normalize(
                plugin_map, parsed_trace,
                load_typed_cfg(self.artifacts / "typed_cfg"),
                load_translator(self.artifacts / "translator"),
            )
            (self.artifacts / "recorded_path").write_text(
                render_recorded_path(operations), encoding="ascii"
            )
            write_trace_evidence(
                plugin_map=plugin_map, trace=parsed_trace,
                recorded_path=self.artifacts / "recorded_path",
                typed_cfg=self.artifacts / "typed_cfg",
                expected_typed_cfg_sha256=sha256_file(self.artifacts / "typed_cfg"),
                translator=self.artifacts / "translator",
                static_manifest=self.artifacts / "static-manifest.json",
                plugin_map_path=self.artifacts / "plugin-map.txt", output=self.evidence,
            )
        self.registry = self.root / "public/registry-wide.json"
        self.opening = self.root / "private/opening-wide.json"
        provision_raw_authority(
            artifacts=self.artifacts, binary=self.binary,
            authority_private=self.root / "keys/private/authority.pem",
            device_public=self.root / "keys/public/device-1.pem", device_id="device-1",
            registry_output=self.registry, opening_output=self.opening,
            ep_cap=16, cfg_blind=RawBlind(1, 2), profile=RAW64_PROFILE,
        )
        self.service = RawRegistryService(
            json.loads(self.registry.read_text()), self.root / "keys/public/authority.pem"
        )

    def test_raw64_full_signed_flow_preserves_high_addresses(self) -> None:
        self._select_wide_profile()
        self.assertEqual(self.service.registry["circuit"]["profile"], RAW64_PROFILE)
        self.assertEqual(self.service.registry["allowed_endpoints"], [
            {"entry_raw": (1 << 64) - 1, "final_raw": (1 << 64) - 1}
        ])
        self.test_end_to_end_signature_freshness_and_minimal_worker_boundary()
        self.test_bundle_permissions_and_exact_contract()
        contents = (self.root / "signed-bundle/private/recorded_path").read_text()
        self.assertIn("0x555555554008", contents)

    def test_raw64_golden_vector_and_domain_separation(self) -> None:
        low = load_raw_statement(
            self.artifacts, cfg_blind=RawBlind(1, 2), ep_blind=RawBlind(3, 4)
        )
        wide_low = load_raw_statement(
            self.artifacts, cfg_blind=RawBlind(1, 2), ep_blind=RawBlind(3, 4),
            profile=RAW64_PROFILE,
        )
        self.assertNotEqual(low.h_cfg_raw24, wide_low.h_cfg_raw24)
        self.assertNotEqual(low.h_ep_raw24, wide_low.h_ep_raw24)
        self.assertNotEqual(raw_config_id(circuit_object(low.params)),
                            raw_config_id(circuit_object(wide_low.params)))
        self._select_wide_profile()
        wide = load_raw_statement(
            self.artifacts, cfg_blind=RawBlind(1, 2), ep_blind=RawBlind(3, 4),
            edge_cap=8, ep_cap=16, profile=RAW64_PROFILE,
        )
        sentinel = (1 << 64) - 1
        root, ret, inner = 0x555555554000, 0x555555554004, 0x555555554008
        cfg = [int.from_bytes(b"CFG-W64V", "big"), 8, 4, 64, 0, 0, 0, 0, 1, 2]
        cfg += [root, 1, inner, root, 3, ret, sentinel, 1, root, sentinel, 3, sentinel]
        cfg += [0, 0, 5, 0, 0, 6, 0, 0, 7, 0, 0, 8]
        ep = [int.from_bytes(b"EP-W64V1", "big"), 16, 5, 64, 3, 4, 24,
              int.from_bytes(b"COMPLETE", "big"), 0, 0]
        ep += [0, sentinel, 0, 1, root, sentinel, 1, inner, ret,
               2, ret, 2, 2, sentinel, 1] + [0] * (3 * 11)
        self.assertEqual(wide.cfg_words(), cfg)
        self.assertEqual(wide.ep_words(), ep)
        self.assertEqual(wide.h_cfg_raw24, hashlib.sha256(b"".join(
            word.to_bytes(8, "big") for word in cfg)).hexdigest())
        self.assertEqual(wide.h_ep_raw24, hashlib.sha256(b"".join(
            word.to_bytes(8, "big") for word in ep)).hexdigest())
        self.assertEqual(wide.h_cfg_raw24,
                         "90f834f0b364ee65a66e72c3c811f262ea5d9c8c7a1a48d44870f2b6eaf2c0c3")
        self.assertEqual(wide.h_ep_raw24,
                         "0f8568daa0d4f4d3fc76a53075626aded6a806f28ef4850b5310778039ea42b8")
        self.assertEqual(raw_config_id(circuit_object(wide.params)),
                         "6b67e38e870e71a350b85b5a0ff900920b9d5788a40ecdf26b508ff26f6611f2")
        self.assertNotEqual(wide.h_cfg_raw24, wide_low.h_cfg_raw24)
        self.assertNotEqual(wide.h_ep_raw24, wide_low.h_ep_raw24)
        with self.assertRaisesRegex(ValueError, "outside raw24"):
            load_raw_statement(self.artifacts, cfg_blind=RawBlind(1, 2), ep_blind=RawBlind(3, 4))

    def test_raw64_profile_downgrade_and_cross_registry_are_rejected(self) -> None:
        narrow_registry = copy.deepcopy(self.service.registry)
        self._select_wide_profile(relocate=False)
        report, _, _ = self._sign()
        with self.assertRaisesRegex(ValueError, "disagrees with registry"):
            protocol_module.validate_raw_report_payload(report["payload"], narrow_registry)
        downgraded = copy.deepcopy(self.service.registry)
        downgraded["circuit"]["profile"] = "raw24-full-key"
        with self.assertRaisesRegex(ValueError, "config identifier"):
            protocol_module.validate_raw_registry_payload(downgraded)
        # Even a newly authenticated config cannot reinterpret wide endpoints as raw24.
        downgraded["raw_config_id"] = raw_config_id(downgraded["circuit"])
        unsigned = dict(downgraded)
        unsigned.pop("raw_registry_id")
        downgraded["raw_registry_id"] = raw_registry_id(unsigned)
        with self.assertRaisesRegex(ValueError, "outside raw24"):
            protocol_module.validate_raw_registry_payload(downgraded)
        unknown = dict(self.service.registry["circuit"], profile="raw64-truncated")
        with self.assertRaisesRegex(ValueError, "unsupported raw circuit profile"):
            protocol_module._params_from_circuit(unknown)

    def test_raw64_address_and_payload_ranges_fail_closed(self) -> None:
        for token in ("0x0", "0xffffffffffff0000", "0xffffffffffffffff",
                      "0x10000000000000000", "-0x1", "0X1"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                parse_raw_address(token, RAW64_PROFILE)
        self.assertEqual(parse_raw_address("0xfffffffffffeffff", RAW64_PROFILE),
                         0xFFFF_FFFF_FFFE_FFFF)
        self.assertEqual(parse_raw_address("0xfffe0000", RAW64_PROFILE),
                         0xFFFF_FFFF_FFFF_0000)
        self.assertEqual(parse_raw_address("0xfffefffe", RAW64_PROFILE),
                         0xFFFF_FFFF_FFFF_FFFE)
        self.assertEqual(parse_raw_address("SCOPE_RETURN", RAW64_PROFILE), (1 << 64) - 1)
        params = RawParams(8, 16, profile=RAW64_PROFILE)
        self.assertEqual((params.ep_encoding, params.multiplicity_bits), ("wide64", 12))
        self.assertEqual(RawParams(8, 1 << 15, profile=RAW64_PROFILE).multiplicity_bits, 16)
        for step in (RawStep(1 << 64, 0), RawStep(1, 1, 1 << 64),
                     RawStep(1, 2, hint=1 << 24), RawStep(1, 1, 0)):
            with self.subTest(step=step), self.assertRaises(ValueError):
                encode_step(step, params)
        with self.assertRaisesRegex(ValueError, "hint domain"):
            RawParams(8, 1 << 25, profile=RAW64_PROFILE).validate()

if __name__ == "__main__":
    unittest.main()
