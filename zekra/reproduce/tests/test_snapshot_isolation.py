"""Check source isolation without invoking Docker, Java, or a prover."""
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
REPRODUCE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scaling = load("zekra_isolation_scaling", REPRODUCE / "scaling/run_scaling.py")
stack = load("zekra_isolation_stack", REPRODUCE / "stack_constraints/run_stack_constraints.py")


class SuiteSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.snapshot = self.base / "snapshot/zekra"
        self.source = self.snapshot / "ZEKRA"
        self.runner = self.snapshot / "reproduce/run-embench-suite.sh"
        self.runner.parent.mkdir(parents=True)
        shutil.copy2(REPRODUCE / "run-embench-suite.sh", self.runner)
        self.marker = self.snapshot / ".zekra-campaign-snapshot"
        self.marker.write_text("isolated ZEKRA source archive\n")
        java = self.source / "zekra_java/zekra/zekra.java"
        java.parent.mkdir(parents=True)
        java.write_text("original parameter source\n")
        inputs = self.source / "embench-iot-applications/fixture"
        inputs.mkdir(parents=True)
        for name, text in {
            "translator": "0x1\n0x2\n",
            "adjlist": "0x1 0x2\n0x2\n",
            "recorded_path": "initial_node=0x1 final_node=0x2\njump 0x2\n",
            "numified_adjlist": "0 1\n1\n",
            "numified_path": "initial_node=0 final_node=1\njump 1\n",
        }.items():
            (inputs / name).write_text(text)
        fake_bin = self.base / "fake-bin"
        fake_bin.mkdir()
        docker = fake_bin / "docker"
        docker.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$TEST_DOCKER_LOG"\nexit 3\n')
        docker.chmod(0o755)
        self.docker_log = self.base / "docker-calls"
        self.env = dict(os.environ, PATH=str(fake_bin) + os.pathsep + os.environ["PATH"],
                        TEST_DOCKER_LOG=str(self.docker_log), CONTROL="0", APPS="fixture")
        self.env.pop("OUT", None)

    def run_suite(self):
        return subprocess.run(["bash", str(self.runner)], env=self.env,
                              text=True, capture_output=True, timeout=20)

    def assert_refused(self, text):
        result = self.run_suite()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(text, result.stderr)
        self.assertIn("zekra/reproduce/scripts/run_zekra_campaign.py", result.stderr)
        self.assertIn("--prepare-only", result.stderr)
        self.assertFalse((self.runner.parent / "results").exists())
        self.assertFalse(self.docker_log.exists())
        self.assertEqual((self.source / "zekra_java/zekra/zekra.java").read_text(),
                         "original parameter source\n")

    def test_git_files_directories_and_dangling_links_are_rejected_before_writes(self):
        entry = self.source / ".git"
        for kind in ("file", "directory", "dangling-link"):
            with self.subTest(kind=kind):
                if kind == "file":
                    entry.write_text("gitdir: ../../upstream.git\n")
                elif kind == "directory":
                    entry.mkdir()
                else:
                    entry.symlink_to(self.base / "missing-git-dir")
                self.assert_refused("Git checkout")
                if entry.is_dir():
                    entry.rmdir()
                else:
                    entry.unlink()

    def test_source_symlink_to_checkout_is_rejected(self):
        upstream = self.base / "upstream"
        self.source.rename(upstream)
        (upstream / ".git").write_text("gitdir: somewhere\n")
        self.source.symlink_to(upstream, target_is_directory=True)
        self.assert_refused("Git checkout")

    def test_source_symlink_outside_snapshot_is_rejected(self):
        outside = self.base / "outside-archive"
        self.source.rename(outside)
        self.source.symlink_to(outside, target_is_directory=True)
        self.assert_refused("inside the campaign snapshot")

    def test_unmarked_source_is_rejected(self):
        self.marker.unlink()
        self.assert_refused("snapshot marker")

    def test_marker_symlink_is_rejected(self):
        outside = self.base / "marker"
        self.marker.rename(outside)
        self.marker.symlink_to(outside)
        self.assert_refused("snapshot marker")

    def test_marked_archive_reaches_only_the_fake_docker(self):
        result = self.run_suite()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("scripts/circuit_input_formatter.py", self.docker_log.read_text())
        self.assertTrue((self.runner.parent / "results/embench-suite/summary.csv").is_file())
        self.assertEqual((self.source / "zekra_java/zekra/zekra.java").read_text(),
                         "original parameter source\n")


class ScalingArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.upstream = self.base / "upstream"
        self.upstream.mkdir()
        self.git("init", "-q")
        (self.upstream / "scripts").mkdir()
        (self.upstream / "scripts/compiler.py").write_text("# committed compiler\n")
        (self.upstream / "zekra_java/zekra").mkdir(parents=True)
        (self.upstream / "zekra_java/zekra/zekra.java").write_text("committed Java\n")
        (self.upstream / "xjsnark_backend.jar").write_bytes(b"committed jar fixture")
        (self.upstream / ".gitignore").write_text("__pycache__/\nbin/\n")
        self.git("add", ".")
        self.git("-c", "user.name=Isolation test", "-c", "user.email=isolation@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
        self.revision = self.git("rev-parse", "HEAD").strip()
        self.jar_hash = hashlib.sha256(b"committed jar fixture").hexdigest()
        override = patch.multiple(scaling, UPSTREAM=self.upstream,
                                  PINNED_UPSTREAM=self.revision, PINNED_JAR=self.jar_hash)
        override.start()
        self.addCleanup(override.stop)

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.upstream), *args], text=True,
                                       stderr=subprocess.STDOUT)

    def test_archive_excludes_ignored_caches_and_preserves_upstream(self):
        for name in ("scripts/__pycache__/compiler.pyc", "zekra_java/bin/compiled.class"):
            path = self.upstream / name
            path.parent.mkdir(parents=True)
            path.write_bytes(b"ignored generated cache")
        before = self.git("status", "--porcelain")
        self.assertEqual(before, "")
        destination = self.base / "source"
        report = scaling.snapshot_upstream(destination)
        self.assertEqual(sorted(str(path.relative_to(destination)) for path in destination.rglob("*")
                                if path.is_file()),
                         ["original.jar", "scripts/compiler.py", "zekra_java/zekra/zekra.java"])
        self.assertEqual((destination / "scripts/compiler.py").read_text(), "# committed compiler\n")
        self.assertEqual(report["upstream_revision"], self.revision)
        self.assertEqual(report["jar_before_sha256"], self.jar_hash)
        self.assertEqual(len(report["upstream_archive_sha256"]), 64)
        self.assertEqual(self.git("status", "--porcelain"), before)
        self.assertTrue((self.upstream / "scripts/__pycache__/compiler.pyc").is_file())

    def test_dirty_checkout_is_rejected_before_snapshot_creation(self):
        (self.upstream / "scripts/compiler.py").write_text("local edit\n")
        destination = self.base / "source"
        with self.assertRaisesRegex(ValueError, "must be clean"):
            scaling.snapshot_upstream(destination)
        self.assertFalse(destination.exists())
        self.assertEqual((self.upstream / "scripts/compiler.py").read_text(), "local edit\n")

    def test_unpinned_checkout_is_rejected_before_snapshot_creation(self):
        destination = self.base / "source"
        with patch.object(scaling, "PINNED_UPSTREAM", "0" * 40):
            with self.assertRaisesRegex(ValueError, "pinned revision"):
                scaling.snapshot_upstream(destination)
        self.assertFalse(destination.exists())

    def test_output_inside_upstream_is_rejected_before_any_creation(self):
        destination = self.upstream / "generated"
        with self.assertRaisesRegex(ValueError, "outside the upstream"):
            scaling.snapshot_upstream(destination)
        with patch.object(sys, "argv", ["run_scaling.py", "--input", str(self.base),
                                         "--output", str(destination), "--prepare-only"]):
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    scaling.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertFalse(destination.exists())


class StackFrozenSourceTests(unittest.TestCase):
    def test_output_inside_upstream_or_symlink_is_rejected_before_creation(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            component = directory / "component"
            upstream = component / "ZEKRA"
            upstream.mkdir(parents=True)
            alias = directory / "upstream-alias"
            alias.symlink_to(upstream, target_is_directory=True)
            for output in (upstream / "generated", alias / "generated"):
                with self.subTest(output=output), patch.object(stack, "ZEKRA", component):
                    argv = ["run_stack_constraints.py", "--inputs", str(directory), "--output", str(output)]
                    with patch.object(sys, "argv", argv), contextlib.redirect_stderr(io.StringIO()):
                        with patch.object(stack.subprocess, "check_output", side_effect=AssertionError("no Docker")):
                            with self.assertRaises(SystemExit) as raised:
                                stack.main()
                    self.assertEqual(raised.exception.code, 2)
                    self.assertFalse(output.exists())
                    self.assertEqual(list(upstream.iterdir()), [])

    def test_parameterization_keeps_using_frozen_source_after_upstream_changes(self):
        original = stack.SOURCE.read_text()
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            released = directory / "released_zekra_c6.java"
            released.write_text(original)
            upstream = directory / "upstream.java"
            upstream.write_text(original)
            with patch.object(stack, "SOURCE", upstream):
                expected = stack.parameterize(16, 4, released_source=released)
                upstream.write_text("changed after the source snapshot\n")
                self.assertEqual(stack.parameterize(16, 4, released_source=released), expected)
            self.assertEqual(released.read_text(), original)
            self.assertIn("private static int EXECUTION_PATH_SIZE = 16;", expected)
            self.assertIn("private static int SHADOWSTACK_DEPTH = 4;", expected)


if __name__ == "__main__":
    unittest.main()
