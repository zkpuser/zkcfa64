"""No proof execution: check input identity, timing scope, failure and resume rules."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_matched_compressed as runner


def app(name="crc32"):
    return {"application": name, "rows": 26, "edges": 23, "nodes": 21,
            "common_dir": name + "/common", "zekra_dir": name + "/zekra",
            "common_hashes": {n: "a" * 64 for n in runner.COMMON_FILES},
            "zekra_hashes": {n: "b" * 64 for n in runner.ZEKRA_FILES},
            "binius": {"edge_cap": 32, "ep_cap": 32, "path_mode": "shadow"},
            "zekra": {"adjlist_len": 32, "path_len": 32, "levels": 2,
                      "stack_depth": 15, "label_bw": 6, "bucket_bw": 3, "addr_bw": 24}}


def report(a):
    return {"schema": "zkcfa.research.scaling.v1", "verified": True,
            "input_sha256": a["common_hashes"], "rows": a["rows"], "edges": a["edges"], "nodes": a["nodes"],
            "edge_capacity": 32, "ep_capacity": 32, "path_mode": "shadow",
            "rayon_num_threads": 8, "log_inv_rate": 1, "addr_bits": 24,
            "proof_bytes": 512000, **{k: 100. for k in runner.BINIUS_TIMINGS}}


class MatchedRunnerTests(unittest.TestCase):
    def test_new_campaign_requires_all_explicit_artifact_paths(self):
        base = ["--inputs", "prepared", "--output", "campaign"]
        artifacts = {"--binius-binary": "evaluated/scaling",
                     "--binius-build-metadata": "evaluated/build.json",
                     "--repaired-jar": "repair/backend.jar"}
        for missing in artifacts:
            argv = base + [token for flag, value in artifacts.items() if flag != missing
                           for token in (flag, value)]
            with self.subTest(missing=missing), patch.object(sys, "stderr", io.StringIO()) as error:
                with self.assertRaises(SystemExit) as stopped:
                    runner.parse_args(argv)
                self.assertEqual(stopped.exception.code, 2)
                self.assertIn(missing, error.getvalue())
        args = runner.parse_args(base + [token for item in artifacts.items() for token in item])
        self.assertEqual(args.binius_binary, Path(artifacts["--binius-binary"]))
        self.assertEqual(args.binius_build_metadata, Path(artifacts["--binius-build-metadata"]))
        self.assertEqual(args.repaired_jar, Path(artifacts["--repaired-jar"]))

    def test_resume_needs_no_original_artifact_paths(self):
        args = runner.parse_args(["--inputs", "prepared", "--output", "campaign", "--resume"])
        self.assertTrue(args.resume)
        self.assertIsNone(args.binius_binary)
        self.assertIsNone(args.binius_build_metadata)
        self.assertIsNone(args.repaired_jar)

    def test_preparation_freezes_explicit_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            upstream = root / "zekra/ZEKRA"
            for name in ("scripts/compiler.py", "zekra_java/main.java", "xjsnark_backend.jar"):
                source = upstream / name
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(name)
            for name in ("PatchNativeMemory.java", "CheckNativeMemory.java"):
                source = root / "zekra/reproduce/scaling" / name
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(name)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            binary, build, repaired = (artifacts / name for name in ("scaling", "build.json", "backend.jar"))
            binary.write_bytes(b"evaluated executable")
            build.write_text(json.dumps({"binary": {"sha256": runner.sha(binary)}, "compiler": "evaluated"}))
            repaired.write_bytes(b"repaired jar")
            prepared = root / "prepared"
            prepared.mkdir()
            (prepared / "manifest.json").write_text("{}")
            c = runner.Campaign.__new__(runner.Campaign)
            c.base = root / "campaign"
            c.base.mkdir()
            c.docker = "docker"
            c.args = SimpleNamespace(resume=False, applications=None, inputs=prepared,
                                     binius_binary=binary, binius_build_metadata=build, repaired_jar=repaired,
                                     expected_binius_sha256=runner.sha(binary))
            docker = {"Architecture": "aarch64", "NCPU": 8, "MemTotal": 20 * 2**30,
                      "ServerVersion": "test", "KernelVersion": "test"}
            images = [{"Architecture": "amd64", "Id": "compiler"}, {"Architecture": "arm64", "Id": "native"}]
            with patch.object(runner, "ROOT", root), patch.object(runner.sys, "platform", "darwin"), \
                    patch.object(runner, "validate_manifest", return_value=({"scope": "test"}, [])), \
                    patch.object(runner, "validate_jar_pair", return_value=sorted(runner.CHANGED_CLASSES)) as jars, \
                    patch.object(runner.rss, "capture", side_effect=[json.dumps(docker), json.dumps(images), "", "test host", "test revision"]):
                c.prepare()
            jars.assert_called_once_with(upstream / "xjsnark_backend.jar", repaired.resolve())
            for source, frozen in ((binary, "scaling"), (build, "binius-build.json"), (repaired, "xjsnark_backend.jar")):
                self.assertEqual((c.base / "frozen" / frozen).read_bytes(), source.read_bytes())
                self.assertEqual(c.plan["frozen_sha256"]["frozen/" + frozen], runner.sha(source))
            for source in (binary, build, repaired):
                source.unlink()
            c.check_plan()
            c.args.resume = True
            c.args.expected_binius_sha256 = None
            with patch.object(runner.rss, "capture", return_value=json.dumps(images)):
                c.prepare()
            self.assertEqual(c.plan["binius_binary_sha256"], runner.sha(c.base / "frozen/scaling"))
            c.args.expected_binius_sha256 = "0" * 64
            with self.assertRaisesRegex(RuntimeError, "resume Binius binary pin changed"):
                c.prepare()
            c.plan["binius_binary_sha256"] = "0" * 64
            with self.assertRaisesRegex(RuntimeError, "binary pin differs"):
                c.check_plan()

    def test_new_binary_pin_must_match_build_metadata_and_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            binary, metadata = Path(directory) / "scaling", Path(directory) / "build.json"
            binary.write_bytes(b"fresh executable")
            expected = runner.sha(binary)
            for record in ({"binary": {"sha256": expected}}, {"binaries": {"scaling": {"sha256": expected}}}):
                metadata.write_text(json.dumps(record))
                runner.validate_binius_build(binary, metadata, expected)
            metadata.write_text(json.dumps({"binary": {"sha256": "0" * 64}}))
            with self.assertRaisesRegex(RuntimeError, "build metadata does not bind"):
                runner.validate_binius_build(binary, metadata, expected)
            with self.assertRaisesRegex(RuntimeError, "binary differs from expected pin"):
                runner.validate_binius_build(binary, metadata, "0" * 64)

    def test_explicit_pin_requires_full_lowercase_sha256(self):
        base = ["--inputs", "prepared", "--output", "campaign", "--resume", "--expected-binius-sha256"]
        self.assertEqual(runner.parse_args(base + ["a" * 64]).expected_binius_sha256, "a" * 64)
        for wrong in ("short", "A" * 64, "x" * 64):
            with self.subTest(value=wrong), patch.object(sys, "stderr", io.StringIO()):
                with self.assertRaises(SystemExit):
                    runner.parse_args(base + [wrong])

    def test_instrumentation_sources_cover_relocated_helpers(self):
        self.assertEqual(set(runner.INSTRUMENTATION_SOURCES), set(runner.INSTRUMENTATION))
        for name, source in runner.INSTRUMENTATION_SOURCES.items():
            self.assertEqual(source.name, name)
            self.assertTrue(source.is_file())
        self.assertEqual(runner.INSTRUMENTATION_SOURCES["run_zekra_rss_apps.py"].parent,
                         Path(runner.rss.__file__).resolve().parent)

    def test_saved_flat_instrumentation_loads_its_own_helpers(self):
        with tempfile.TemporaryDirectory() as directory:
            frozen = Path(directory)
            for name, source in runner.INSTRUMENTATION_SOURCES.items():
                shutil.copy2(source, frozen / name)
            code = ("import json; import run_matched_compressed as runner; "
                    "print(json.dumps({name: str(path.parent) for name, path "
                    "in runner.INSTRUMENTATION_SOURCES.items()}))")
            output = subprocess.check_output([sys.executable, "-c", code], cwd=frozen,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": ""}, text=True)
            self.assertEqual(json.loads(output), {name: str(frozen.resolve()) for name in runner.INSTRUMENTATION})

    def test_binius_strict_identity_and_real_rss(self):
        a = app()
        r = report(a)
        runner.validate_binius(r, a, 123)
        for field, wrong in [("verified", False), ("rows", 25), ("edges", 22), ("ep_capacity", 64),
                             ("path_mode", "complete"), ("input_sha256", {}), ("crypto_prove_ms", float("nan"))]:
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                runner.validate_binius(dict(r, **{field: wrong}), a, 123)
        with self.assertRaises(RuntimeError):
            runner.validate_binius(r, a, None)

    def test_binius_excludes_warmup_and_keeps_crypto_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            c = runner.Campaign.__new__(runner.Campaign)
            c.base = Path(directory)
            (c.base / "cases/crc32").mkdir(parents=True)
            records = []
            for i, value in enumerate([9999, 11, 7, 9]):
                r = report(app())
                r.update(crypto_prove_ms=value, prove_total_ms=value + 1000)
                records.append({"kind": "warmup" if i == 0 else "measured", "verified": True,
                                "status": "verified", "peak_rss_bytes": value * 100, "report": r})
            with patch.object(c, "binius_attempt", side_effect=records):
                result = c.binius_case(app())
            self.assertEqual(result["timings_ms"]["crypto_prove_ms"]["median"], 9)
            self.assertEqual(result["timings_ms"]["prove_total_ms"]["median"], 1009)
            self.assertEqual(result["peak_rss_bytes"], 1100)
            self.assertEqual(result["measured_verified_runs"], 3)

    def test_binius_failed_warmup_stops_lane_without_statistics(self):
        with tempfile.TemporaryDirectory() as directory:
            c = runner.Campaign.__new__(runner.Campaign)
            c.base = Path(directory)
            (c.base / "cases/crc32").mkdir(parents=True)
            failure = {"kind": "warmup", "verified": False, "status": "rss-guard", "peak_rss_bytes": 100}
            with patch.object(c, "binius_attempt", return_value=failure) as invoke:
                result = c.binius_case(app())
            self.assertEqual(invoke.call_count, 1)
            self.assertFalse(result["verified"])
            self.assertNotIn("timings_ms", result)

    def test_completed_binius_attempt_reuses_only_pinned_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            c = runner.Campaign.__new__(runner.Campaign)
            c.base = Path(directory)
            a = app()
            common = c.base / "cases/crc32/common"
            attempt = c.base / "cases/crc32/binius/attempts/run-1/001"
            attempt.mkdir(parents=True)
            log = attempt / "stdout.log"
            log.write_text(json.dumps(report(a)))
            command = [str(c.base / "frozen/scaling"), "--typed-dir", str(common), "--path-mode", "shadow",
                       "--edge-cap", "32", "--ep-cap", "32", "--log-inv-rate", "1"]
            phase = {"workload_command": command, "verified": True, "peak_rss_bytes": 123,
                     "log_sha256": {str(log.relative_to(c.base)): runner.sha(log)}, "report": report(a)}
            (attempt / "phase.json").write_text(json.dumps(phase))
            with patch.object(runner.subprocess, "Popen", side_effect=AssertionError("must not rerun")):
                self.assertTrue(c.binius_attempt(a, 0)["verified"])
            log.write_text("changed")
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                c.binius_attempt(a, 0)

    def test_intermediate_identity_cannot_be_silently_refreshed(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / "witness").write_text("original")
            runner.remember_identity(p, ["witness"], "identity.json")
            runner.remember_identity(p, ["witness"], "identity.json")
            (p / "witness").write_text("changed")
            with self.assertRaisesRegex(RuntimeError, "intermediate artifacts changed"):
                runner.remember_identity(p, ["witness"], "identity.json")

    def test_all_planned_lanes_appear_and_failures_have_no_success_timings(self):
        with tempfile.TemporaryDirectory() as directory:
            c = runner.Campaign.__new__(runner.Campaign)
            c.base = Path(directory)
            c.plan = {"applications": [app(), app("wikisort")], "scope": "test"}
            runner.save(c.base / "plan.json", c.plan)
            path = c.base / "cases/crc32/binius/result.json"
            path.parent.mkdir(parents=True)
            runner.save(path, {"status": "failed", "verified": False, "measured_verified_runs": 1,
                              "runs": [{"verified": False, "peak_rss_bytes": 500}]})
            c.summarize("running")
            summary = json.loads((c.base / "summary.json").read_text())
            self.assertEqual(len(summary["results"]), 4)
            self.assertEqual(summary["results"][0]["failed_attempt_peak_rss_bytes"], 500)
            self.assertIsNone(summary["results"][0]["crypto_prove_s"])
            self.assertTrue(all(r["status"] == "not-run" for r in summary["results"][1:]))

    def test_failed_compile_rss_is_preserved_as_lower_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            c = runner.Campaign.__new__(runner.Campaign)
            c.base = Path(directory)
            c.plan = {"applications": [app()], "scope": "test"}
            runner.save(c.base / "plan.json", c.plan)
            path = c.base / "cases/crc32/zekra/result.json"
            path.parent.mkdir(parents=True)
            runner.save(path, {"status": "oom", "verified": False, "runs": [],
                              "phases": [{"stage": "crc32:compile", "returncode": 0, "failure_reason": "compile-failed",
                                          "peak_rss_bytes": None, "observed_peak_rss_bytes": 1234}]})
            c.summarize("running")
            row = json.loads((c.base / "summary.json").read_text())["results"][1]
            self.assertEqual(row["failed_attempt_peak_rss_bytes"], 1234)
            self.assertTrue(row["failed_attempt_rss_is_lower_bound"])
            self.assertEqual(row["failed_attempt_stage"], "crc32:compile")

    def test_backend_failure_does_not_skip_peer_or_next_application(self):
        c = runner.Campaign.__new__(runner.Campaign)
        c.args = SimpleNamespace(prepare_only=False)
        c.plan = {"applications": [app(), app("wikisort")]}
        order = []
        with patch.object(c, "prepare"), patch.object(c, "summarize"), patch.object(c, "check_plan"), patch.object(c, "native_environment"), \
             patch.object(c, "binius_case", side_effect=lambda a: order.append("b:" + a["application"])), \
             patch.object(c, "zekra_case", side_effect=lambda a: order.append("z:" + a["application"])):
            self.assertEqual(c.execute(), 0)
        self.assertEqual(order, ["b:crc32", "z:crc32", "b:wikisort", "z:wikisort"])

    def test_jar_verification_checks_exact_class_delta(self):
        with tempfile.TemporaryDirectory() as directory:
            original, repaired = Path(directory) / "a.jar", Path(directory) / "b.jar"
            entries = sorted(runner.CHANGED_CLASSES | {"unchanged"})
            with zipfile.ZipFile(original, "w") as z:
                for n in entries:
                    z.writestr(n, "a")
            with zipfile.ZipFile(repaired, "w") as z:
                for n in entries:
                    z.writestr(n, "b" if n in runner.CHANGED_CLASSES else "a")
            with patch.object(runner, "ORIGINAL_JAR_SHA", runner.sha(original)), patch.object(runner, "REPAIRED_JAR_SHA", runner.sha(repaired)):
                self.assertEqual(set(runner.validate_jar_pair(original, repaired)), runner.CHANGED_CLASSES)

    def test_manifest_prevents_path_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "escapes"):
                runner.inside(Path(directory), "../elsewhere")

    def test_manifest_requires_preparer_audit_and_suite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for candidate in ({"applications": [app()]},
                              {"schema": "zkcfa.matched-compressed.inputs.v1", "all_audits_passed": True,
                               "application_count": 1, "applications": [app()]}):
                (root / "manifest.json").write_text(json.dumps(candidate))
                with self.assertRaises(RuntimeError):
                    runner.validate_manifest(root)

    def test_configured_java_hash_matches_upstream_configuration_writer(self):
        root = Path(__file__).resolve().parents[3]
        upstream = root / "zekra/ZEKRA"
        script = upstream / "scripts/compile_circuit.py"
        source = upstream / "zekra_java/zekra/zekra.java"
        original_hash = runner.sha(source)
        for params in (app()["zekra"], dict(app()["zekra"], adjlist_len=512, path_len=1024, levels=4, label_bw=10, bucket_bw=7)):
            with self.subTest(params=params), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / "zekra.java"
                shutil.copy2(source, target)
                namespace = {"__name__": "configuration_writer_test"}
                exec(compile(script.read_text(), str(script), "exec"), namespace)
                namespace.update(ZEKRA_DIR=directory, SHADOWSTACK_DEPTH=params["stack_depth"],
                                 LABEL_BITWIDTH=params["label_bw"], BUCKET_BITWIDTH=params["bucket_bw"],
                                 ADDR_BITWIDTH=params["addr_bw"], ADJLIST_SIZE=params["adjlist_len"],
                                 ADJLIST_LEVELS=params["levels"], EXECUTION_PATH_SIZE=params["path_len"])
                namespace["configure_main_component"]("/work/inputs", "/work/inputs")
                self.assertEqual(runner.configured_java_hash(upstream, params), runner.sha(target))
                self.assertNotEqual(runner.sha(target), original_hash)
        self.assertEqual(runner.sha(source), original_hash)

    def test_linux_lifecycle_is_reused(self):
        self.assertIs(runner.Campaign.run_container, runner.rss.Campaign.run_container)
        self.assertIs(runner.Campaign.finish_phase, runner.rss.Campaign.finish_phase)


if __name__ == "__main__":
    unittest.main()
