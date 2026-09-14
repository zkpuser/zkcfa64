"""Small deterministic checks for RSS scope, proof parsing, and resumption."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import run_zekra_rss_apps as runner
import zekra_linux_rss as collector


class RSSChecks(unittest.TestCase):
    def phase(self, rss, kind="measured", verified=True, **extra):
        return {"stage": "app:native", "kind": kind, "verified": verified,
                "peak_rss_bytes": rss, "observed_peak_rss_bytes": rss,
                "rss_complete": True, "returncode": 0, "setup_s": 2., "prove_s": 3.,
                "verify_s": 0.01, "wall_seconds": 6., **extra}

    def test_medians_and_max_exclude_warmup_and_separate_compilation(self):
        result = {"verified": True, "phases": [self.phase(800, kind="compile")],
                  "runs": [self.phase(9999, kind="warmup"), self.phase(100, prove_s=1.),
                           self.phase(300, prove_s=90.), self.phase(200, prove_s=3.)]}
        runner.aggregate(result)
        self.assertEqual(result["rss"]["native_measured_peak_rss_bytes"], 300)
        self.assertEqual(result["rss"]["native_measured_median_peak_rss_bytes"], 200)
        self.assertEqual(result["rss"]["full_pipeline_peak_rss_bytes"], 800)
        self.assertEqual(result["timings"]["prove_s"]["median"], 3)
        self.assertEqual(result["measured_verified_runs"], 3)

    def test_failed_warmup_rss_is_retained_without_formal_measurement(self):
        failed = self.phase(None, kind="warmup", verified=False, observed_peak_rss_bytes=123,
                            rss_complete=False, returncode=137, state={"OOMKilled": True})
        result = {"verified": False, "phases": [self.phase(800, kind="compile")], "runs": [failed]}
        runner.aggregate(result)
        self.assertIsNone(result["rss"]["native_measured_peak_rss_bytes"])
        self.assertIsNone(result["rss"]["native_failed_attempt_peak_rss_bytes"])
        self.assertEqual(result["rss"]["native_failed_attempt_observed_peak_rss_bytes"], 123)
        self.assertIsNone(result["rss"]["full_pipeline_peak_rss_bytes"])

    def test_missing_rss_cannot_claim_full_pipeline_complete(self):
        result = {"verified": True, "phases": [self.phase(None, rss_complete=False)],
                  "runs": [self.phase(100), self.phase(200), self.phase(300)]}
        runner.aggregate(result)
        self.assertFalse(result["rss"]["full_pipeline_exact"])
        self.assertIsNone(result["rss"]["full_pipeline_peak_rss_bytes"])

    def test_native_verification_requires_matching_constraints_and_all_phases(self):
        text = """QAP pre degree: 123
QAP degree: 128
QAP number of variables: 110
Proof size in bits: 1019
(leave) Call to r1cs_gg_ppzksnark_generator [2.123s x]
(leave) Call to r1cs_gg_ppzksnark_prover [1.123s x]
(leave) Call to r1cs_gg_ppzksnark_verifier_strong_IC [0.001s x]
The verification result is: PASS
"""
        self.assertTrue(runner.native_metrics(text, {"returncode": 0}, 123)["verified"])
        self.assertFalse(runner.native_metrics(text, {"returncode": 0}, 124)["verified"])
        self.assertFalse(runner.native_metrics(text, {"returncode": 0, "measurement_error": "missing"}, 123)["verified"])
        self.assertFalse(runner.native_metrics(text.replace("[0.001s", "[nans"), {"returncode": 0}, 123)["verified"])

    def test_partial_rss_null_peak_is_kept_as_sampled_lower_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "rss.json").write_text(json.dumps({"complete": False, "peak_rss_bytes": None,
                                                       "sampled_process_hwm_max_bytes": 4096}))
            campaign = runner.Campaign.__new__(runner.Campaign)
            campaign.base = base
            record = {"returncode": 137}
            campaign.finish_phase(record, base)
            self.assertEqual(record["observed_peak_rss_bytes"], 4096)
            self.assertIsNone(record["peak_rss_bytes"])
            self.assertFalse(record["rss_complete"])

    def test_success_without_rss_is_explicit_measurement_error(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign = runner.Campaign.__new__(runner.Campaign)
            campaign.base = Path(directory)
            record = {"returncode": 0}
            campaign.finish_phase(record, campaign.base)
            self.assertIn("measurement_error", record)

    def test_completed_stage_reused_without_docker_or_log_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            attempt = base / "attempts/native-1/001"
            attempt.mkdir(parents=True)
            log = attempt / "output.log"
            log.write_text("proof output")
            phase = {"stage": "app:native-1/4", "workload_command": ["native"],
                     "interrupted": False, "log": str(log.relative_to(base)), "log_sha256": runner.sha(log)}
            (attempt / "phase.json").write_text(json.dumps(phase))
            campaign = runner.Campaign.__new__(runner.Campaign)
            campaign.base = base
            with patch.object(runner.subprocess, "Popen", side_effect=AssertionError("must not launch")):
                self.assertEqual(campaign.run_container(base, "arm64", ["native"], base / "native-1.log", "app:native-1/4"), phase)
            self.assertEqual(log.read_text(), "proof output")

    def test_collector_refuses_host_macos_units(self):
        with patch.object(collector.sys, "platform", "darwin"):
            with self.assertRaisesRegex(RuntimeError, "Linux"):
                collector.run(Path("unused"), ["true"], 1)


if __name__ == "__main__":
    unittest.main()
