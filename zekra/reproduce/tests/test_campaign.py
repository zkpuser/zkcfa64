"""Campaign selection and coverage checks without Docker or proving."""

from contextlib import redirect_stderr
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "zekra_campaign",
    Path(__file__).resolve().parents[1] / "scripts/run_zekra_campaign.py",
)
campaign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(campaign)


class ApplicationSelectionTests(unittest.TestCase):
    def setUp(self):
        self.available = ["st", "crc32", "aha-mont64"]

    def test_default_selects_all_applications_in_stable_order(self):
        self.assertEqual(
            campaign.select_applications(None, self.available),
            ["aha-mont64", "crc32", "st"],
        )
        self.assertEqual(self.available, ["st", "crc32", "aha-mont64"])

    def test_explicit_subset_is_sorted_without_adding_unrequested_applications(self):
        self.assertEqual(
            campaign.select_applications("st,crc32", self.available),
            ["crc32", "st"],
        )
        self.assertEqual(self.available, ["st", "crc32", "aha-mont64"])

    def test_single_application_remains_a_single_application(self):
        self.assertEqual(campaign.select_applications("crc32", self.available), ["crc32"])

    def test_trims_whitespace_around_comma_separated_names(self):
        self.assertEqual(
            campaign.select_applications(" st , crc32 ", self.available), ["crc32", "st"]
        )

    def test_rejects_empty_list_and_empty_entries(self):
        for requested in ("", " ", ",", ",crc32", "crc32,", "st,,crc32", "st, ,crc32"):
            with self.subTest(requested=requested):
                with self.assertRaises(ValueError):
                    campaign.select_applications(requested, self.available)

    def test_rejects_unknown_names_even_when_other_names_are_valid(self):
        for requested in ("unknown", "crc32,unknown", "CRC32", "../crc32", "crc32 st"):
            with self.subTest(requested=requested):
                with self.assertRaises(ValueError):
                    campaign.select_applications(requested, self.available)

    def test_rejects_duplicate_names_instead_of_silently_deduplicating(self):
        for requested in ("crc32,crc32", "st,crc32,st", "crc32, crc32"):
            with self.subTest(requested=requested):
                with self.assertRaises(ValueError):
                    campaign.select_applications(requested, self.available)


class ApplicationCoverageTests(unittest.TestCase):
    def assert_coverage_issue(self, names, expected):
        result = campaign.coverage_issue([{"app": name} for name in names], expected)
        self.assertIsInstance(result, str)
        self.assertTrue(result.strip())

    def test_accepts_exact_coverage_regardless_of_row_order(self):
        rows = [{"app": "st"}, {"app": "crc32"}]
        self.assertIsNone(campaign.coverage_issue(rows, ["crc32", "st"]))
        self.assertEqual(rows, [{"app": "st"}, {"app": "crc32"}])

    def test_accepts_selected_subset_without_requiring_other_available_applications(self):
        self.assertIsNone(campaign.coverage_issue([{"app": "crc32"}], ["crc32"]))

    def test_coverage_is_separate_from_proof_outcome_validation(self):
        self.assertIsNone(campaign.coverage_issue(
            [{"app": "crc32", "outcome": "unsatisfiable"}], ["crc32"]
        ))

    def test_rejects_missing_application(self):
        self.assert_coverage_issue(["crc32"], ["crc32", "st"])

    def test_rejects_completely_missing_results(self):
        self.assert_coverage_issue([], ["crc32", "st"])

    def test_rejects_unselected_extra_application(self):
        self.assert_coverage_issue(["crc32", "st", "aha-mont64"], ["crc32", "st"])

    def test_rejects_duplicate_row_even_when_all_selected_names_are_present(self):
        self.assert_coverage_issue(["crc32", "st", "crc32"], ["crc32", "st"])

    def test_rejects_duplicate_masking_missing_application_at_same_row_count(self):
        self.assert_coverage_issue(["crc32", "crc32"], ["crc32", "st"])

    def test_rejects_wrong_application_at_same_row_count(self):
        self.assert_coverage_issue(["crc32", "aha-mont64"], ["crc32", "st"])


class ExecutionSelectionTests(unittest.TestCase):
    def assert_execution_rejects(self, *options):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "unprepared-output"
            argv = ["run_zekra_campaign.py", "--output", str(output), *options]
            errors = io.StringIO()
            with patch.object(campaign.sys, "argv", argv), \
                 patch.object(campaign.subprocess, "check_output") as captured, \
                 patch.object(campaign.subprocess, "run") as run, \
                 patch.object(campaign.subprocess, "Popen") as popen, \
                 redirect_stderr(errors):
                with self.assertRaises(SystemExit) as raised:
                    campaign.main()
            self.assertEqual(raised.exception.code, 2)
            self.assertIn("must be frozen with --prepare-only", errors.getvalue())
            captured.assert_not_called()
            run.assert_not_called()
            popen.assert_not_called()
            self.assertFalse(output.exists())

    def test_execution_cannot_change_or_expand_frozen_application_selection(self):
        self.assert_execution_rejects("--applications", "crc32,st")

    def test_execution_cannot_change_frozen_artifact_retention(self):
        self.assert_execution_rejects("--keep-artifacts")

    def test_execution_environment_uses_frozen_selection_and_retention(self):
        checksum = "a" * 64
        prep = {
            "applications": ["aha-mont64", "st"],
            "keep_artifacts": False,
            "frozen_sources_sha256": {"snapshot/frozen-source": checksum},
            "real_docker": "fixture-docker",
            "paper22_image": "compiler-id",
            "native_image": "native-id",
            "wrapper_revision": "wrapper-revision",
            "zekra_revision": "zekra-revision",
        }
        inspected = json.dumps([
            {"Id": "compiler-id", "Architecture": "amd64"},
            {"Id": "native-id", "Architecture": "arm64"},
        ])
        information = json.dumps({"NCPU": 8, "Architecture": "aarch64"})
        with tempfile.TemporaryDirectory() as directory:
            argv = ["run_zekra_campaign.py", "--output", directory]
            with patch.object(campaign.sys, "argv", argv), \
                 patch.object(campaign, "read_json", return_value=prep), \
                 patch.object(campaign, "digest", return_value=checksum), \
                 patch.object(campaign.os, "umask"), \
                 patch.object(campaign.signal, "signal"), \
                 patch.dict(campaign.os.environ, {
                     "APPS": "crc32 unknown st", "CONTROL": "0",
                     "OUT": "/unrelated/result.csv", "KEEP_ARTIFACTS": "1",
                 }), \
                 patch.object(campaign.subprocess, "check_output", side_effect=[
                     inspected, information, checksum + "  /fixture-native-runner\n",
                 ]), \
                 patch.object(campaign.subprocess, "run") as run, \
                 patch.object(campaign.subprocess, "Popen", side_effect=RuntimeError(
                     "mock suite boundary"
                 )) as popen:
                with self.assertRaisesRegex(RuntimeError, "mock suite boundary"):
                    campaign.main()
                run.assert_not_called()
                popen.assert_called_once()
                environment = popen.call_args.kwargs["env"]
                self.assertEqual(environment["APPS"], "aha-mont64 st")
                self.assertEqual(environment["CONTROL"], "1")
                self.assertEqual(environment["KEEP_ARTIFACTS"], "0")
                self.assertNotIn("OUT", environment)


if __name__ == "__main__":
    unittest.main()
