"""CRC32 snapshot and result checks; no Docker or upstream writes."""

from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "crc32_runner", Path(__file__).resolve().parents[1] / "run_crc32.py"
)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class OutputPathTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "upstream"
        self.source.mkdir()

    def test_rejects_upstream_and_normalized_descendants(self):
        for output in (
            self.source,
            self.source / "generated",
            self.root / "other" / ".." / "upstream" / "generated",
        ):
            with self.subTest(output=output):
                with self.assertRaisesRegex(ValueError, "outside the upstream"):
                    runner.validate_output(output, self.source)
        self.assertEqual(list(self.source.iterdir()), [])

    def test_rejects_output_through_symlink_into_upstream(self):
        alias = self.root / "innocent-output-parent"
        alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "outside the upstream"):
            runner.validate_output(alias / "generated", self.source)
        self.assertFalse((self.source / "generated").exists())

    def test_rejects_dangling_output_symlink_without_creating_target(self):
        target = self.root / "missing-output"
        output = self.root / "output-link"
        output.symlink_to(target, target_is_directory=True)
        self.assertTrue(output.is_symlink())
        self.assertFalse(output.exists())
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            runner.validate_output(output, self.source)
        self.assertTrue(output.is_symlink())
        self.assertEqual(output.readlink(), target)
        self.assertFalse(target.exists())

    def test_rejects_existing_file_and_directory_without_changing_them(self):
        existing_file = self.root / "output-file"
        existing_file.write_text("preserve file")
        existing_directory = self.root / "output-directory"
        existing_directory.mkdir()
        sentinel = existing_directory / "sentinel"
        sentinel.write_text("preserve directory")
        for output in (existing_file, existing_directory):
            with self.subTest(output=output):
                with self.assertRaisesRegex(ValueError, "already exists"):
                    runner.validate_output(output, self.source)
        self.assertEqual(existing_file.read_text(), "preserve file")
        self.assertEqual(sentinel.read_text(), "preserve directory")

    def test_accepts_new_sibling_without_creating_it(self):
        output = self.root / "results" / "new-run"
        self.assertEqual(runner.validate_output(output, self.source), output)
        self.assertFalse(output.exists())


class SourceInventoryTests(unittest.TestCase):
    def test_includes_ignored_files_and_records_links_without_following_them(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / ".gitignore").write_text("ignored.log\n")
            ignored = source / "ignored.log"
            ignored.write_text("local ignored evidence")
            executable = source / "program"
            executable.write_text("fixture executable")
            executable.chmod(0o700)
            metadata = source / ".git"
            metadata.mkdir()
            (metadata / "config").write_text("excluded metadata")
            external = root / "external"
            external.mkdir()
            target = external / "outside.txt"
            target.write_text("outside the source inventory")
            (source / "directory-link").symlink_to(external, target_is_directory=True)
            (source / "file-link").symlink_to(target)
            (source / "dangling-link").symlink_to("missing-target")

            before = runner.source_inventory(source)
            self.assertEqual(
                set(before),
                {".gitignore", "ignored.log", "program", "directory-link",
                 "file-link", "dangling-link"},
            )
            self.assertEqual(before["ignored.log"]["sha256"], runner.sha256(ignored))
            self.assertEqual(before["program"]["mode"], 0o700)
            self.assertEqual(before["directory-link"], {"symlink": str(external)})
            self.assertEqual(before["file-link"], {"symlink": str(target)})
            self.assertEqual(before["dangling-link"], {"symlink": "missing-target"})

            target.write_text("changed outside source")
            (metadata / "config").write_text("changed excluded metadata")
            self.assertEqual(runner.source_inventory(source), before)
            ignored.write_text("changed ignored evidence")
            self.assertNotEqual(runner.source_inventory(source), before)

    def test_excludes_submodule_git_pointer_file(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / ".git").write_text("gitdir: /unrelated/metadata\n")
            (source / "kept").write_text("source")
            self.assertEqual(set(runner.source_inventory(source)), {"kept"})


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.output = self.root / "output"
        self.output.mkdir()
        self.git("init", "--quiet")

    def git(self, *arguments):
        return subprocess.check_output(
            ["git", "-C", str(self.source),
             "-c", "user.name=CRC32 Test", "-c", "user.email=crc32@example.invalid",
             "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
             *arguments],
            text=True,
        ).strip()

    def test_archive_uses_only_committed_bytes_and_isolates_working_writes(self):
        (self.source / ".gitignore").write_text("ignored.log\n")
        tracked = self.source / "committed.txt"
        tracked.write_text("committed source\n")
        (self.source / "deleted.txt").write_text("committed but locally removed\n")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "fixture")
        pin = self.git("rev-parse", "HEAD")

        tracked.write_text("uncommitted modification\n")
        (self.source / "deleted.txt").unlink()
        (self.source / "staged.txt").write_text("staged but uncommitted\n")
        self.git("add", "staged.txt")
        (self.source / "untracked.txt").write_text("untracked\n")
        (self.source / "ignored.log").write_text("ignored\n")
        before = runner.source_state(self.source)

        work = runner.snapshot(self.source, self.output, pin)
        self.assertEqual((work / "committed.txt").read_text(), "committed source\n")
        self.assertEqual(
            (work / "deleted.txt").read_text(), "committed but locally removed\n"
        )
        self.assertEqual(
            {path.name for path in work.iterdir()},
            {".gitignore", "committed.txt", "deleted.txt"},
        )
        (work / "committed.txt").write_text("container would overwrite its copy\n")
        (work / "proof-output").write_text("generated in disposable work tree\n")
        self.assertEqual(runner.source_state(self.source), before)
        self.assertEqual(tracked.read_text(), "uncommitted modification\n")
        self.assertFalse((self.source / "proof-output").exists())

    def test_rejects_committed_symlink_without_touching_its_target(self):
        outside = self.root / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_text("preserve")
        (self.source / "link").symlink_to(outside, target_is_directory=True)
        self.git("add", "link")
        self.git("commit", "--quiet", "-m", "symlink fixture")
        before = runner.source_state(self.source)
        with self.assertRaisesRegex(ValueError, "Unexpected link"):
            runner.snapshot(self.source, self.output, self.git("rev-parse", "HEAD"))
        self.assertEqual(sentinel.read_text(), "preserve")
        self.assertEqual(runner.source_state(self.source), before)


class StageCleanupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name).resolve()
        self.work = self.output / "work"
        self.work.mkdir()
        self.run = runner.Run(self.output, self.work, threads=2, timeout=5)

    def invoke_stage(self, *, inspection=None, cleanup=None, stage_error=None):
        """Mock every subprocess boundary so these cases cannot launch Docker."""
        def execute(arguments, **kwargs):
            operation = arguments[1]
            if operation == "run":
                kwargs["stdout"].write("partial stage output\n")
                if stage_error is not None:
                    raise stage_error
                return subprocess.CompletedProcess(arguments, 0)
            if operation == "inspect":
                if isinstance(inspection, BaseException):
                    raise inspection
                if inspection is not None:
                    return inspection
                return subprocess.CompletedProcess(
                    arguments, 0, stdout='{"Running": false, "ExitCode": 0}', stderr=""
                )
            if operation == "rm":
                if isinstance(cleanup, BaseException):
                    raise cleanup
                if cleanup is not None:
                    return cleanup
                return subprocess.CompletedProcess(arguments, 0, stdout="", stderr="")
            self.fail(f"Unexpected subprocess: {arguments}")

        with patch.object(runner.subprocess, "run", side_effect=execute) as mocked:
            self.subprocess = mocked
            with redirect_stdout(io.StringIO()):
                return self.run.stage("02-extractor", "fixture-image", ["fixture-command"])

    def assert_cleanup_and_log_recorded(self):
        calls = self.subprocess.call_args_list
        self.assertEqual([call.args[0][1] for call in calls], ["run", "inspect", "rm"])
        run_arguments = calls[0].args[0]
        container = run_arguments[run_arguments.index("--name") + 1]
        self.assertEqual(calls[1].args[0][-1], container)
        self.assertEqual(calls[2].args[0], ["docker", "rm", "--force", container])
        record = self.run.stages[-1]
        self.assertGreaterEqual(record["wall_s"], 0)
        self.assertEqual(record["log_sha256"], runner.sha256(self.output / record["log"]))
        self.assertEqual((self.output / record["log"]).read_text(), "partial stage output\n")
        return record

    def assert_inspection_failure_is_cleaned_up(self, inspection):
        with self.assertRaisesRegex(RuntimeError, "inspection or cleanup failed"):
            self.invoke_stage(inspection=inspection)
        record = self.assert_cleanup_and_log_recorded()
        self.assertEqual(record["exit_code"], 0)
        self.assertEqual(record["cleanup_exit_code"], 0)
        self.assertTrue(record["inspection_error"])
        self.assertNotIn("container_state", record)

    def test_cleans_up_when_inspect_cannot_start(self):
        self.assert_inspection_failure_is_cleaned_up(OSError("inspect unavailable"))

    def test_cleans_up_when_inspect_times_out(self):
        self.assert_inspection_failure_is_cleaned_up(
            subprocess.TimeoutExpired(["docker", "inspect"], 30)
        )

    def test_cleans_up_when_inspect_returns_invalid_json(self):
        self.assert_inspection_failure_is_cleaned_up(
            subprocess.CompletedProcess(["docker", "inspect"], 0, stdout="invalid json", stderr="")
        )

    def test_cleans_up_without_losing_original_stage_timeout(self):
        timeout = subprocess.TimeoutExpired(["docker", "run"], 5)
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            self.invoke_stage(
                stage_error=timeout,
                inspection=subprocess.TimeoutExpired(["docker", "inspect"], 30),
            )
        self.assertIs(raised.exception, timeout)
        record = self.assert_cleanup_and_log_recorded()
        self.assertNotIn("exit_code", record)
        self.assertEqual(record["cleanup_exit_code"], 0)
        self.assertTrue(record["inspection_error"])

    def test_rejects_inspect_nonzero_even_without_error_text(self):
        self.assert_inspection_failure_is_cleaned_up(
            subprocess.CompletedProcess(["docker", "inspect"], 9, stdout="", stderr="")
        )

    def test_rejects_cleanup_nonzero_even_without_error_text(self):
        with self.assertRaisesRegex(RuntimeError, "inspection or cleanup failed"):
            self.invoke_stage(
                cleanup=subprocess.CompletedProcess(["docker", "rm"], 9, stdout="", stderr="")
            )
        record = self.assert_cleanup_and_log_recorded()
        self.assertEqual(record["exit_code"], 0)
        self.assertEqual(record["container_state"]["ExitCode"], 0)
        self.assertEqual(record["cleanup_exit_code"], 9)
        self.assertTrue(record["cleanup_error"])

    def test_records_cleanup_exception_as_failure_and_keeps_log(self):
        for cleanup_error in (
            OSError("cleanup unavailable"),
            subprocess.TimeoutExpired(["docker", "rm"], 30),
        ):
            with self.subTest(error=type(cleanup_error).__name__):
                with self.assertRaisesRegex(RuntimeError, "inspection or cleanup failed"):
                    self.invoke_stage(cleanup=cleanup_error)
                record = self.assert_cleanup_and_log_recorded()
                self.assertEqual(record["exit_code"], 0)
                self.assertNotIn("cleanup_exit_code", record)
                self.assertEqual(record["cleanup_error"], str(cleanup_error))

    def test_cleanup_exception_does_not_mask_original_stage_timeout(self):
        timeout = subprocess.TimeoutExpired(["docker", "run"], 5)
        cleanup_error = subprocess.TimeoutExpired(["docker", "rm"], 30)
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            self.invoke_stage(stage_error=timeout, cleanup=cleanup_error)
        self.assertIs(raised.exception, timeout)
        record = self.assert_cleanup_and_log_recorded()
        self.assertNotIn("exit_code", record)
        self.assertNotIn("cleanup_exit_code", record)
        self.assertEqual(record["cleanup_error"], str(cleanup_error))


class ProofMetricsTests(unittest.TestCase):
    TIMINGS = (
        "(leave) Call to r1cs_gg_ppzksnark_generator [1.25s]\n",
        "(leave) Call to r1cs_gg_ppzksnark_prover [0.75s]\n",
        "(leave) Call to r1cs_gg_ppzksnark_verifier_strong_IC [0.03s]\n",
    )
    PASS = "The verification result is: PASS\n"

    def test_extracts_verified_phase_times_and_optional_size_metrics(self):
        text = self.PASS + "".join(self.TIMINGS) + (
            "QAP pre degree: 123\nQAP degree: 256\n"
            "QAP number of variables: 110\nProof size in bits: 1024\n"
        )
        self.assertEqual(
            runner.proof_metrics(text),
            {"verified": True, "setup_s": 1.25, "prove_s": 0.75, "verify_s": 0.03,
             "qap_pre_degree": 123, "qap_degree": 256,
             "qap_variables": 110, "proof_bits": 1024},
        )

    def test_requires_explicit_pass_even_when_timings_are_present(self):
        for verdict in ("", "The verification result is: FAIL\n"):
            with self.subTest(verdict=verdict):
                with self.assertRaises(RuntimeError):
                    runner.proof_metrics(verdict + "".join(self.TIMINGS))

    def test_rejects_mixed_pass_and_fail(self):
        with self.assertRaisesRegex(RuntimeError, "failed verification"):
            runner.proof_metrics(
                self.PASS + "".join(self.TIMINGS) + "The verification result is: FAIL\n"
            )

    def test_requires_every_native_phase_timing(self):
        for omitted in range(len(self.TIMINGS)):
            with self.subTest(omitted=omitted):
                text = self.PASS + "".join(
                    timing for index, timing in enumerate(self.TIMINGS) if index != omitted
                )
                with self.assertRaisesRegex(RuntimeError, "Missing native phase timing"):
                    runner.proof_metrics(text)


if __name__ == "__main__":
    unittest.main()
