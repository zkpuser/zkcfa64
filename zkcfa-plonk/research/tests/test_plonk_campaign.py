"""Lightweight regression checks; no proof generation or provider keys."""

from __future__ import annotations

import copy
import importlib.util
import json
import csv
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "plonk_campaign", Path(__file__).resolve().parents[1] / "scripts/run_plonk_campaign.py"
)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class CampaignChecks(unittest.TestCase):
    def setUp(self):
        self.row = dict(application="crc32", path_mode="shadow", edge_cap=32,
            ep_cap=32, proof_rows=23, encoding="inline14", plonk_gates=18607,
            padded_domain=32768)
        self.report = dict(schema="zkcfa.raw.proof", backend="plonk",
            profile="raw24-full-key", application="crc32", path_mode="shadow",
            capacity=dict(edge_cap=32, ep_cap=32, ep_encoding="inline14"),
            instance=dict(steps=23), constraints=dict(plonk_gates=18607, padded_domain=32768),
            public_inputs=dict(H_ep="aa", H_cfg="bb", entry="0x400000", final_node="0xffffff"),
            verified=True)
        self.target = dict(bundle="/unused", h_ep_raw24="aa", h_cfg_raw24="bb")

    def check(self, value):
        with patch.object(runner, "load", return_value={"payload": {
                "entry_raw": 0x400000, "final_raw": 0xffffff}}):
            runner.check_report(value, self.row, self.target, proof=True)

    def test_paired_report_accepts_matching_public_and_shape_bindings(self):
        self.check(self.report)

    def test_report_rejects_backend_lane_shape_and_commitment_substitution(self):
        mutations = [
            lambda v: v.update(backend="binius64"),
            lambda v: v.update(path_mode="complete"),
            lambda v: v["capacity"].update(ep_cap=64),
            lambda v: v["constraints"].update(padded_domain=65536),
            lambda v: v["public_inputs"].update(H_cfg="cc"),
            lambda v: v["public_inputs"].update(entry="0x400001"),
            lambda v: v.update(verified=False),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(self.report)
                mutation(report)
                with self.assertRaises(ValueError):
                    self.check(report)

    def test_preflight_cannot_be_used_as_a_proof(self):
        stdout = json.dumps(dict(schema="zkcfa.raw.preflight", backend="plonk", satisfied=True))
        with self.assertRaisesRegex(ValueError, "missing"):
            runner.report_json(stdout, "zkcfa.raw.proof")
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            runner.report_json(json.dumps(self.report) + "\n" + json.dumps(self.report), "zkcfa.raw.proof")

    def test_resource_failure_is_not_relabelled_as_success(self):
        self.assertEqual(runner.process_status({"stop": "resource-terminated-rss", "returncode": 0}),
            "resource-terminated-rss")
        self.assertEqual(runner.process_status({"stop": "", "returncode": -9}), "failed--9")

    def test_cleanup_uses_owned_pid_controller(self):
        process = object()
        with patch.object(runner.process_control, "terminate_owned_group", return_value={"complete": True}) as cleanup:
            self.assertTrue(runner.terminate_group(process)["complete"])
        cleanup.assert_called_once_with(process)

    def test_cleanup_failure_preserves_timeout_rss_wall_and_sidecar(self):
        class RunningWrapper:
            pid, returncode = 123, None
            def poll(self): return None
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(runner.subprocess, "Popen", return_value=RunningWrapper()), \
                patch.object(runner, "sample_group_rss", return_value=4096), \
                patch.object(runner.time, "perf_counter", side_effect=[0, 10, 11]), \
                patch.object(runner, "terminate_group", return_value={"complete": False, "errors": [{"errno": 1}]}):
            result = runner.timed(["diagnostic-only"], env={}, cwd=directory, timeout=1,
                rss_limit=8192, log_stem=Path(directory) / "attempt")
            self.assertEqual(result["stop"], "timeout")
            self.assertEqual(result["peak_rss_bytes"], 4096)
            self.assertEqual(result["wall_ms"], 11000)
            self.assertFalse(result["cleanup_complete"])
            saved = runner.load(Path(directory) / "attempt.controller.json")
            self.assertEqual(saved["cleanup"]["errors"], [{"errno": 1}])

    def test_retry_preserves_and_links_original_failed_row(self):
        identity = dict(binary_sha256={"prove": "same"}, source_manifest_sha256="manifest", threads=8)
        original = dict(self.row, proof_outcome="orchestration-failed", preflight_outcome="satisfied",
            verified="", failure_note="[Errno 1] Operation not permitted")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.csv"
            with path.open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=list(original))
                writer.writeheader(); writer.writerow(original)
            before = path.read_bytes()
            runner.save_json(path.with_name("metadata.json"), dict(results_sha256=runner.sha256(path),run_identity=identity))
            runner.save_json(path.with_name("run-identity.json"), identity)
            rows, link = runner.retry_rows(path, ["crc32"], ["shadow"], identity)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(rows[0]["proof_outcome"], "not-attempted")
            self.assertEqual(rows[0]["source_attempt_outcome"], "orchestration-failed")
            self.assertEqual(link["original_attempts"][0]["row"]["failure_note"], original["failure_note"])
            with self.assertRaisesRegex(ValueError, "different threads"):
                runner.retry_rows(path, ["crc32"], ["shadow"], dict(identity,threads=4))


if __name__ == "__main__":
    unittest.main()
