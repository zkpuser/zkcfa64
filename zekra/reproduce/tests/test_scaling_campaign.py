"""Campaign planning, warmup evidence and failure accounting without Docker."""
import argparse
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
REPRODUCE = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, REPRODUCE / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load("zekra_scaling_warmups", "scaling/run_scaling.py")
campaign = load("zekra_scaling_campaign", "scaling/run_campaign.py")
summary = load("zekra_scaling_summary", "scaling/summarize_scaling.py")
wrapper = load("zekra_scaling_events", "scripts/run_zekra_scaling.py")


def native_log(seconds, count=12):
    return (f"QAP pre degree: {count}\nQAP degree: 16\nQAP number of variables: 8\n"
            + "".join(f"(leave) Call to r1cs_gg_ppzksnark_{phase} [{seconds}s]\n"
                      for phase in ("generator", "prover", "verifier_strong_IC"))
            + "The verification result is: PASS\n")


class TemporaryTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)


class CampaignPlanningTests(TemporaryTest):
    def fixtures(self):
        root = self.base / "inputs"
        root.mkdir()
        cases = []
        for family in campaign.FAMILIES:
            for size in campaign.SIZES:
                directory = root / family / str(size) / "complete"
                directory.mkdir(parents=True)
                hashes = {}
                for name in campaign.INPUT_FILES:
                    path = directory / name
                    path.write_text(f"{family}/{size}/{name}\n")
                    hashes[name] = campaign.sha(path)
                cases.append({"family": family, "source_ep_rows": size,
                              "rows_by_mode": {"complete": size},
                              "input_sha256": {"complete": hashes}})
        manifest = {"schema": "zkcfa.synthetic-scaling-inputs.v1", "sizes": list(campaign.SIZES), "cases": cases}
        (root / "manifest.json").write_text(json.dumps(manifest))
        return root, manifest

    def test_seven_points_and_one_excluded_warmup_per_family(self):
        self.assertEqual(campaign.SIZES, (64, 128, 256, 512, 1024, 2048, 4096))
        schedule = campaign.case_schedule(campaign.FAMILIES, 1)
        self.assertEqual(len(schedule), 14)
        self.assertEqual([(family, size) for family, size, count in schedule if count],
                         [("growing-cfg", 64), ("fixed-cfg", 64)])
        self.assertEqual(campaign.case_schedule(("growing-cfg",), 1), schedule[:7])

    def test_invalid_family_selections_are_rejected(self):
        for text in ("", "unknown", "growing-cfg,", "growing-cfg,growing-cfg"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                campaign.select_families(text)
        self.assertEqual(campaign.select_families("fixed-cfg,growing-cfg"), campaign.FAMILIES)

    def test_manifest_missing_2048_duplicate_and_tampered_input_are_rejected(self):
        root, manifest = self.fixtures()
        self.assertEqual(len(campaign.input_inventory(root, ("growing-cfg",))), 29)
        for change in ("missing", "duplicate", "old-grid"):
            bad = copy.deepcopy(manifest)
            if change == "missing":
                bad["cases"] = [case for case in bad["cases"] if case["source_ep_rows"] != 2048]
            elif change == "duplicate":
                bad["cases"].append(bad["cases"][0])
            else:
                bad["sizes"].remove(2048)
            (root / "manifest.json").write_text(json.dumps(bad))
            with self.subTest(change=change), self.assertRaises(ValueError):
                campaign.input_inventory(root, ("growing-cfg",))
        (root / "manifest.json").write_text(json.dumps(manifest))
        (root / "growing-cfg/2048/complete/typed_cfg").write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "differs from frozen"):
            campaign.input_inventory(root, ("growing-cfg",))

    def test_selected_case_cannot_read_a_symlink_outside_input_root(self):
        root, _ = self.fixtures()
        path = root / "growing-cfg/64/complete/translator"
        outside = self.base / "translator"
        path.rename(outside)
        path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "escapes"):
            campaign.input_inventory(root, ("growing-cfg",))

    def test_campaign_forwards_only_selected_grid_and_records_real_failures(self):
        root, _ = self.fixtures()
        output = self.base / "campaign"
        calls = []

        def fake_run(command):
            calls.append(command)
            directory = Path(command[command.index("--output") + 1])
            directory.mkdir()
            size = int(directory.name)
            measured = {"status": "failed" if size == 4096 else "verified", "runs": [],
                        "repetitions": 3, "warmup_repetitions": int(command[command.index("--warmups") + 1])}
            (directory / "measurement.json").write_text(json.dumps(measured))
            return subprocess.CompletedProcess(command, int(size == 4096))

        argv = ["run_campaign.py", "--inputs", str(root), "--output", str(output), "--families", "growing-cfg"]
        with patch.object(sys, "argv", argv), patch.object(campaign.subprocess, "run", side_effect=fake_run), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(campaign.main(), 1)
        result = json.loads((output / "campaign.json").read_text())
        self.assertEqual(result["families"], ["growing-cfg"])
        self.assertEqual(result["sizes"], list(campaign.SIZES))
        self.assertEqual(len(calls), 7)
        self.assertEqual([command[command.index("--warmups") + 1] for command in calls], ["1"] + ["0"] * 6)
        self.assertEqual(result["results"][-1]["status"], "failed")
        self.assertIsNone(result["results"][-1]["medians"])
        self.assertIn("end_utc", result)
        self.assertTrue((output / "input-manifest.json").is_file())
        self.assertTrue((output / "execution-sources/run_scaling.py").is_file())

    def test_dangling_output_symlink_is_rejected_before_execution(self):
        root, _ = self.fixtures()
        output = self.base / "output"
        output.symlink_to(self.base / "missing")
        argv = ["run_campaign.py", "--inputs", str(root), "--output", str(output)]
        with patch.object(sys, "argv", argv), patch.object(campaign.subprocess, "run") as run, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                campaign.main()
        run.assert_not_called()
        self.assertFalse((self.base / "missing").exists())

    def test_event_wrapper_rejects_upstream_output_before_any_writes(self):
        upstream = self.base / "zekra/ZEKRA"
        upstream.mkdir(parents=True)
        output = upstream / "new/campaign"
        argv = ["run_zekra_scaling.py", "--inputs", str(self.base / "inputs"), "--output", str(output)]
        with patch.object(sys, "argv", argv), patch.object(wrapper, "ROOT", self.base), patch.object(wrapper.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(ValueError, "outside the upstream"):
                wrapper.main()
        popen.assert_not_called()
        self.assertFalse((upstream / "new").exists())


class WarmupMeasurementTests(TemporaryTest):
    def report(self):
        return {"status": "compiled", "r1cs_constraints": 12, "repetitions": 3,
                "warmup_repetitions": 1, "runs": [], "warmup_runs": []}

    def fake_run(self, values, overrides=None):
        values = iter(values)

        def run(command, log, timeout):
            value = next(values)
            text = native_log(value)
            if overrides:
                text = overrides(text)
            log.write_text(text)
            return {"command": command, "returncode": 0, "wall_seconds": value + 1,
                    "log": str(log), "log_sha256": runner.sha(log)}
        return run

    def test_warmup_is_recorded_and_excluded_from_medians(self):
        measured = self.report()
        with patch.object(runner, "run", side_effect=self.fake_run([1000, 1, 3, 5])):
            runner.native_measurements(measured, self.base, "native-test", 10)
        self.assertEqual(measured["medians"], {"setup_s": 3, "prove_s": 3, "verify_s": 3, "wall_seconds": 4})
        self.assertEqual([row["kind"] for row in measured["warmup_runs"]], ["warmup"])
        self.assertEqual([row["repetition"] for row in measured["runs"]], [1, 2, 3])
        self.assertTrue((self.base / "04-groth16-warmup1.log").is_file())
        measured["status"] = "verified"
        self.assertEqual(summary.audit_attempts(measured, self.base), measured["medians"])
        measured["medians"]["prove_s"] = 4
        with self.assertRaisesRegex(ValueError, "stored medians"):
            summary.audit_attempts(measured, self.base)

    def test_missing_timing_pass_and_fail_conflict_or_wrong_count_stop_before_formal(self):
        for transform in (lambda text: text.replace("verifier_strong_IC", "unknown"),
                          lambda text: text.replace("The verification result is: PASS", "no result"),
                          lambda text: text + "The verification result is: FAIL\n",
                          lambda text: text.replace("QAP pre degree: 12", "QAP pre degree: 13")):
            measured = self.report()
            with self.subTest(transform=transform), patch.object(runner, "run", side_effect=self.fake_run([1], transform)) as run:
                with self.assertRaisesRegex(ValueError, "warmup repetition 1"):
                    runner.native_measurements(measured, self.base, "native-test", 10)
                self.assertEqual(run.call_count, 1)
            self.assertEqual(measured["runs"], [])
            self.assertFalse(measured["warmup_runs"][0]["verified"])
            measured["status"] = "failed"
            self.assertEqual(summary.audit_attempts(measured, self.base), dict.fromkeys(summary.TIMINGS))
            self.assertNotIn("medians", measured)

    def test_native_launch_failure_is_saved_without_zero_timing(self):
        measured = self.report()
        with patch.object(runner, "run", side_effect=OSError("unavailable")):
            with self.assertRaises(OSError):
                runner.native_measurements(measured, self.base, "native-test", 10)
        frozen = json.loads((self.base / "measurement.json").read_text())
        self.assertEqual(frozen["warmup_runs"][0]["returncode"], "launch-error")
        self.assertNotIn("prove_s", frozen["warmup_runs"][0])
        self.assertEqual(frozen["runs"], [])

    def test_legacy_without_warmups_remains_readable_and_log_tampering_is_rejected(self):
        measured = self.report()
        measured["warmup_repetitions"] = 0
        with patch.object(runner, "run", side_effect=self.fake_run([1, 3, 5])):
            runner.native_measurements(measured, self.base, "native-test", 10)
        measured["status"] = "verified"
        measured.pop("warmup_repetitions")
        measured.pop("warmup_runs")
        for run in measured["runs"]:
            run.pop("kind")
        self.assertEqual(summary.audit_attempts(measured, self.base), measured["medians"])
        (self.base / "04-groth16-r1.log").write_text("modified evidence")
        with self.assertRaisesRegex(ValueError, "frozen hash"):
            summary.audit_attempts(measured, self.base)

    def test_missing_duplicate_and_misclassified_formal_runs_are_rejected(self):
        measured = self.report()
        with patch.object(runner, "run", side_effect=self.fake_run([100, 1, 3, 5])):
            runner.native_measurements(measured, self.base, "native-test", 10)
        measured["status"] = "verified"
        for change in ("missing", "duplicate", "kind", "warmup-failed"):
            bad = copy.deepcopy(measured)
            if change == "missing":
                bad["runs"].pop()
            elif change == "duplicate":
                bad["runs"][1]["repetition"] = 1
            elif change == "kind":
                bad["runs"][1]["kind"] = "warmup"
            else:
                bad["warmup_runs"][0]["verified"] = False
            with self.subTest(change=change), self.assertRaises(ValueError):
                summary.audit_attempts(bad, self.base)


class SummaryCoverageTests(TemporaryTest):
    def failed_campaign(self, legacy=False):
        sizes = summary.LEGACY_SIZES if legacy else summary.SIZES
        families = summary.FAMILIES if legacy else ("growing-cfg",)
        manifest = {"schema": "zkcfa.zekra.scaling-campaign.v1", "repetitions": 3,
                    "end_utc": "finished", "results": []}
        if not legacy:
            manifest.update(sizes=list(sizes), families=list(families), warmup_repetitions=1,
                            warmup_source_ep_rows=64, warmup_scope="per-family")
        for family in families:
            for size in sizes:
                measured = {"status": "failed", "repetitions": 3, "runs": [], "error": "compile failed"}
                if not legacy:
                    measured.update(warmup_repetitions=int(size == 64), warmup_runs=[])
                directory = self.base / family / str(size)
                directory.mkdir(parents=True)
                path = directory / "measurement.json"
                path.write_text(json.dumps(measured))
                manifest["results"].append({"family": family, "source_ep_rows": size, "status": "failed",
                                            "returncode": 1, "measurement_sha256": summary.digest(path)})
        (self.base / "campaign.json").write_text(json.dumps(manifest))
        return manifest

    def test_early_compile_failures_export_null_timings_and_actual_zero_attempt_count(self):
        self.failed_campaign()
        rows, attempts, jar = summary.summarize(self.base)
        self.assertEqual(len(rows), 7)
        self.assertEqual(attempts, [])
        self.assertIsNone(jar)
        self.assertTrue(all(row["prove_s"] is None and row["attempted_repetitions"] == 0 for row in rows))
        self.assertEqual(sum(row["planned_warmups"] for row in rows), 1)
        self.assertTrue(all(row["error"] == "compile failed" for row in rows))

    def test_legacy_six_point_grid_is_readable(self):
        self.failed_campaign(legacy=True)
        rows, _, _ = summary.summarize(self.base)
        self.assertEqual(len(rows), 12)
        self.assertEqual(sum(row["planned_warmups"] for row in rows), 0)

    def test_missing_duplicate_and_extra_cases_are_rejected(self):
        manifest = self.failed_campaign()
        for change in ("missing", "duplicate", "extra"):
            bad = copy.deepcopy(manifest)
            if change == "missing":
                bad["results"].pop()
            elif change == "duplicate":
                bad["results"].append(bad["results"][0])
            else:
                bad["results"].append(dict(bad["results"][0], source_ep_rows=8192))
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "cases"):
                summary.validate_cases(bad)

    def test_measurement_hash_tampering_is_rejected(self):
        self.failed_campaign()
        (self.base / "growing-cfg/2048/measurement.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "frozen manifest"):
            summary.summarize(self.base)


class EventAccountingTests(unittest.TestCase):
    def test_wrapper_forwards_family_warmup_and_formal_counts(self):
        args = argparse.Namespace(inputs=Path("/tmp/inputs"), repetitions=3, warmups=1, families="growing-cfg")
        command = wrapper.campaign_command(args, Path("/tmp/output"))
        self.assertEqual(command[command.index("--families") + 1], "growing-cfg")
        self.assertEqual(command[command.index("--warmups") + 1], "1")
        self.assertEqual(command[command.index("--repetitions") + 1], "3")

    def test_warmup_oom_is_not_counted_as_formal_and_unmatched_events_do_not_prove_oom(self):
        run = {"command": ["docker", "run", "--name", "warmup-test"], "verified": False, "returncode": 137}
        counts = dict(actual_attempts=0, verified_attempts=0, oom_attempts=0, other_failed_attempts=0)
        formal, warmups = counts.copy(), counts.copy()
        events = [{"Action": action, "Actor": {"Attributes": {"name": "warmup-test", "exitCode": "137"}}}
                  for action in ("oom", "die")]
        _, matched, oom = wrapper.account_attempt(warmups, run, events)
        self.assertTrue(oom)
        self.assertEqual(len(matched), 2)
        self.assertEqual(warmups["oom_attempts"], 1)
        self.assertEqual(formal, counts)
        self.assertFalse(wrapper.attempt_events(run, events[:1])[2])
        unrelated = copy.deepcopy(events)
        unrelated[0]["Actor"]["Attributes"]["name"] = "other-container"
        self.assertFalse(wrapper.attempt_events(run, unrelated)[2])
        self.assertFalse(wrapper.attempt_events(dict(run, returncode="timeout"), events)[2])


class PartialCampaignAccountingTests(TemporaryTest):
    def plan(self, families=("growing-cfg",)):
        return dict(families=list(families), sizes=list(campaign.SIZES), repetitions=3,
                    warmup_repetitions=1, warmup_source_ep_rows=64, warmup_scope="per-family", results=[])

    def measurement(self, plan, size, formal=3, indexed=True, status="verified", failed=False):
        directory = self.base / "growing-cfg" / str(size)
        directory.mkdir(parents=True)

        def attempt(kind, repetition):
            good = not (failed and kind == "measured" and repetition == formal)
            return dict(kind=kind, repetition=repetition, verified=good, returncode=0 if good else 137,
                        command=["docker", "run", "--name", f"case-{size}-{kind}-{repetition}"])

        measured = dict(status=status, repetitions=3, warmup_repetitions=int(size == 64), phases=[],
                        warmup_runs=[attempt("warmup", 1)] if size == 64 else [],
                        runs=[attempt("measured", rep) for rep in range(1, formal + 1)])
        path = directory / "measurement.json"
        path.write_text(json.dumps(measured))
        if indexed:
            plan["results"].append(dict(family="growing-cfg", source_ep_rows=size,
                                       status=status, measurement_sha256=wrapper.sha(path)))
        return measured

    def test_aborted_after_two_cases_retains_full_formal_plan(self):
        plan = self.plan()
        for size in (64, 128):
            self.measurement(plan, size)
        result, events = wrapper.collect_accounting(plan, self.base, [])
        self.assertEqual(result["accounting"], dict(planned_attempts=21, actual_attempts=6,
            verified_attempts=6, oom_attempts=0, other_failed_attempts=0, unexecuted_attempts=15))
        self.assertEqual(result["warmup_accounting"]["actual_attempts"], 1)
        self.assertEqual([case["source_ep_rows"] for case in result["incomplete_cases"]], [256, 512, 1024, 2048, 4096])
        self.assertTrue(all(case["status"] == "not-started" for case in result["incomplete_cases"]))
        self.assertTrue(result["attempt_accounting_complete"])
        self.assertEqual(len(events), 2)

    def test_unreached_family_keeps_its_planned_warmup(self):
        plan = self.plan(campaign.FAMILIES)
        self.measurement(plan, 64)
        result, _ = wrapper.collect_accounting(plan, self.base, [])
        self.assertEqual(result["accounting"]["planned_attempts"], 42)
        self.assertEqual(result["warmup_accounting"]["planned_attempts"], 2)
        self.assertEqual(result["warmup_accounting"]["unexecuted_attempts"], 1)

    def test_unindexed_failure_keeps_observed_attempt_and_oom_evidence(self):
        plan = self.plan()
        for size in (64, 128):
            self.measurement(plan, size)
        measured = self.measurement(plan, 256, formal=1, indexed=False, status="failed", failed=True)
        name = measured["runs"][0]["command"][-1]
        observations = [dict(Action=action, Actor=dict(Attributes=dict(name=name, exitCode="137")))
                        for action in ("oom", "die")]
        result, events = wrapper.collect_accounting(plan, self.base, observations)
        self.assertEqual(result["accounting"]["actual_attempts"], 7)
        self.assertEqual(result["accounting"]["unexecuted_attempts"], 14)
        self.assertEqual(result["accounting"]["oom_attempts"], 1)
        self.assertEqual(result["incomplete_cases"][0]["status"], "unindexed-measurement")
        self.assertEqual(len(events[self.base / "growing-cfg/256"]), 2)
        self.assertTrue(result["failed_attempts"][0]["documented_docker_oom"])

    def test_existing_case_without_readable_record_does_not_invent_unexecuted_total(self):
        for invalid in (False, True):
            with self.subTest(invalid=invalid):
                plan = self.plan()
                directory = self.base / "growing-cfg/64"
                directory.mkdir(parents=True, exist_ok=True)
                if invalid:
                    (directory / "measurement.json").write_text("incomplete JSON")
                result, _ = wrapper.collect_accounting(plan, self.base, [])
                self.assertFalse(result["attempt_accounting_complete"])
                self.assertEqual(result["accounting"]["planned_attempts"], 21)
                self.assertIsNone(result["accounting"]["unexecuted_attempts"])
                self.assertIsNone(result["warmup_accounting"]["unexecuted_attempts"])

    def test_full_grid_failure_totals_stay_unchanged(self):
        plan = self.plan()
        for size in campaign.SIZES:
            self.measurement(plan, size, formal=1 if size == 4096 else 3,
                             status="failed" if size == 4096 else "verified", failed=size == 4096)
        result, _ = wrapper.collect_accounting(plan, self.base, [])
        self.assertEqual(result["accounting"], dict(planned_attempts=21, actual_attempts=19,
            verified_attempts=18, oom_attempts=0, other_failed_attempts=1, unexecuted_attempts=2))
        self.assertEqual(result["incomplete_cases"], [])
        self.assertTrue(result["attempt_accounting_complete"])

    def test_indexed_measurement_hash_cannot_be_replaced(self):
        plan = self.plan()
        self.measurement(plan, 64)
        (self.base / "growing-cfg/64/measurement.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "frozen campaign hash"):
            wrapper.collect_accounting(plan, self.base, [])


if __name__ == "__main__":
    unittest.main()
