from __future__ import annotations

import json
import subprocess
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import test_protocol as fixtures
from static.normalize import parse_trace
from zkcfa_provider.online import capture_raw_online_report
from zkcfa_provider.persistent_registry import PersistentRawRegistryService
from zkcfa_provider.protocol import RawRegistryService, build_raw_device_report, raw_capture_context


class OnlineLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixtures.RawSignedProtocolTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.f = self.fixture
        self.registry = json.loads(self.f.registry.read_text())
        self.authority = self.f.root / "keys/public/authority.pem"
        self.database = self.f.root / "state/challenges.sqlite3"

    def persistent(self) -> PersistentRawRegistryService:
        return PersistentRawRegistryService(
            self.registry, self.authority, state_path=self.database
        )

    def sign_for(self, challenge: dict[str, object], *, require: bool = False,
                 name: str = "online") -> dict[str, object]:
        report, _ = build_raw_device_report(
            artifacts=self.f.artifacts, policy_artifacts=self.f.artifacts,
            binary=self.f.binary, trace_path=self.f.trace, evidence_path=self.f.evidence,
            registry_path=self.f.registry, opening_path=self.f.opening,
            authority_public=self.authority,
            device_private=self.f.root / "keys/private/device-1.pem", device_id="device-1",
            challenge_id=str(challenge["challenge_id"]), nonce=str(challenge["nonce"]),
            report_output=self.f.root / f"{name}-report.json",
            worker_secret_output=self.f.root / f"{name}-worker.json",
            require_capture_context=require,
        )
        return report

    def challenge(self, service: RawRegistryService) -> dict[str, object]:
        return service.issue_challenge("device-1", service.registry["raw_registry_id"])

    def test_capture_context_matches_signed_challenge(self) -> None:
        challenge = self.challenge(self.f.service)
        context = raw_capture_context(
            str(challenge["raw_registry_id"]), "device-1",
            str(challenge["challenge_id"]), str(challenge["nonce"]),
        )
        lines = self.f.trace.read_text().splitlines()
        lines[0] += f" capture_context={context}"
        self.f.trace.write_text("\n".join(lines) + "\n")
        self.assertEqual(parse_trace(self.f.trace).capture_context, context)
        self.assertTrue(self.f.service.verify_report(self.sign_for(challenge, require=True))["accepted"])
        other = self.challenge(self.f.service)
        with self.assertRaisesRegex(ValueError, "capture context"):
            self.sign_for(other, require=True, name="stale")
        self.assertFalse((self.f.root / "stale-report.json").exists())

    def test_online_signer_rejects_unbound_offline_trace(self) -> None:
        with self.assertRaisesRegex(ValueError, "capture context"):
            self.sign_for(self.challenge(self.f.service), require=True)

    def test_online_orchestrator_rejects_a_producer_replaying_an_old_trace(self) -> None:
        challenge = self.challenge(self.f.service)
        run = self.f.root / "capture"

        def stale_producer(command, **kwargs):
            (run / "trace.log").write_bytes(self.f.trace.read_bytes())
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with patch("zkcfa_provider.online.subprocess.run", side_effect=stale_producer):
            with self.assertRaisesRegex(ValueError, "issued session context"):
                capture_raw_online_report(
                    run_dir=run, policy_artifacts=self.f.artifacts,
                    binary=self.f.binary, qemu=self.f.root / "qemu", plugin=self.f.root / "plugin",
                    sysroot=self.f.root / "sysroot", challenge=challenge,
                    registry_path=self.f.registry, opening_path=self.f.opening,
                    authority_public=self.authority,
                    device_private=self.f.root / "keys/private/device-1.pem", device_id="device-1",
                )
        self.assertFalse((run / "report.json").exists())

    def test_issued_challenge_survives_a_new_process(self) -> None:
        challenge = self.challenge(self.persistent())
        report = self.sign_for(challenge)
        code = (
            "import json, sys; from pathlib import Path; "
            "from zkcfa_provider.persistent_registry import PersistentRawRegistryService; "
            "r,a,d,p = map(Path,sys.argv[1:]); "
            "s=PersistentRawRegistryService(json.loads(r.read_text()),a,state_path=d); "
            "print(json.dumps(s.verify_report(json.loads(p.read_text()))))"
        )
        checked = subprocess.run(
            [sys.executable, "-c", code, str(self.f.registry), str(self.authority),
             str(self.database), str(self.f.root / "online-report.json")],
            capture_output=True, text=True, check=True,
        )
        self.assertTrue(json.loads(checked.stdout)["accepted"])
        with self.assertRaisesRegex(ValueError, "already consumed"):
            self.persistent().verify_report(report)

    def test_two_service_instances_consume_exactly_once(self) -> None:
        challenge = self.challenge(self.persistent())
        report = self.sign_for(challenge)
        services = [self.persistent(), self.persistent()]

        def consume(service):
            try:
                return service.verify_report(report)["accepted"]
            except ValueError as error:
                return str(error)

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(consume, services))
        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(outcomes.count("raw challenge was already consumed"), 1)

    def test_expiry_survives_service_restart(self) -> None:
        with patch("zkcfa_provider.protocol.time.time", return_value=time.time() - 400):
            challenge = self.challenge(self.persistent())
        with self.assertRaisesRegex(ValueError, "expired"):
            self.persistent().verify_report(self.sign_for(challenge))

    def test_memory_registry_restart_fails_closed_for_old_report(self) -> None:
        challenge = self.challenge(self.f.service)
        report = self.sign_for(challenge)
        restarted = RawRegistryService(self.registry, self.authority)
        with self.assertRaisesRegex(ValueError, "unknown raw challenge"):
            restarted.verify_report(report)


if __name__ == "__main__":
    unittest.main()
