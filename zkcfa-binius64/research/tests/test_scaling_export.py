"""Audit scaling inputs without requiring equal backend-specific projections."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
EXPERIMENTS = ROOT / "zkcfa-binius64/research/scripts"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


export = load_module("scaling_export_audit", EXPERIMENTS / "summarize_scaling.py")
inputs = load_module("scaling_input_audit", EXPERIMENTS / "scaling_inputs.py")


class ScalingExportChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "inputs"
        with patch("sys.argv", ["scaling_inputs.py", "--output", str(self.directory)]), \
                redirect_stdout(io.StringIO()):
            inputs.main()
        self.manifest = json.loads((self.directory / "manifest.json").read_text())

    def save_case(self, case):
        base = self.directory / case["family"] / str(case["source_ep_rows"])
        (base / "case.json").write_text(json.dumps(case))
        (self.directory / "manifest.json").write_text(json.dumps(self.manifest))

    def growing_case(self, size=1024):
        return next(case for case in self.manifest["cases"]
                    if case["family"] == "growing-cfg" and case["source_ep_rows"] == size)

    def test_corrected_projections_keep_separate_rows_and_capacities(self):
        _, cases = export.load_inputs(self.directory, export.Evidence())
        case = cases["growing-cfg", 1024]
        self.assertEqual(case["rows_by_mode"], {"complete": 1024, "shadow": 764, "zekra": 512})
        self.assertEqual(case["binius_ep_cap"], {"complete": 1024, "shadow": 1024, "zekra": 512})
        self.assertFalse(case["shadow_and_zekra_paths_equal"])
        self.assertEqual(cases["fixed-cfg", 64]["rows_by_mode"],
                         {"complete": 64, "shadow": 12, "zekra": 8})

    def test_seven_scale_grid_includes_2048_for_both_families(self):
        manifest, cases = export.load_inputs(self.directory, export.Evidence())
        self.assertEqual(manifest["sizes"], [64, 128, 256, 512, 1024, 2048, 4096])
        self.assertEqual(len(cases), 14)
        self.assertEqual(len(cases) * 2 * len(export.REPETITIONS), 84)
        growing = cases["growing-cfg", 2048]
        self.assertEqual((growing["nodes"], growing["typed_edges"]), (895, 1023))
        self.assertEqual(growing["rows_by_mode"]["zekra"], 1024)
        self.assertEqual(cases["fixed-cfg", 2048]["rows_by_mode"]["shadow"], 12)

    def test_missing_scale_case_is_rejected(self):
        self.manifest["cases"] = [case for case in self.manifest["cases"]
                                  if (case["family"], case["source_ep_rows"]) != ("growing-cfg", 2048)]
        (self.directory / "manifest.json").write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, "every declared scale"):
            export.load_inputs(self.directory, export.Evidence())

    def test_projected_file_tampering_is_rejected(self):
        path = self.directory / "growing-cfg/1024/shadow/recorded_path"
        path.write_text(path.read_text().replace("0x400310", "0x400311"))
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            export.load_inputs(self.directory, export.Evidence())

    def test_wrong_equality_flag_and_nonboolean_flag_are_rejected(self):
        case = self.growing_case()
        for flag in (True, 0):
            with self.subTest(flag=flag):
                case["shadow_and_zekra_paths_equal"] = flag
                self.save_case(case)
                with self.assertRaisesRegex(ValueError, "equality flag differs"):
                    export.load_inputs(self.directory, export.Evidence())

    def test_different_cfg_cannot_be_accepted_by_rehashing_it(self):
        case = self.growing_case()
        path = self.directory / "growing-cfg/1024/shadow/typed_cfg"
        lines = path.read_text().splitlines()
        # A different ordering is enough to violate byte-identical canonical
        # CFG inputs, even when line counts and every declared digest agree.
        path.write_text("\n".join(reversed(lines)) + "\n")
        case["input_sha256"]["shadow"]["typed_cfg"] = export.digest(path)
        self.save_case(case)
        with self.assertRaisesRegex(ValueError, "Shared CFG input mismatch"):
            export.load_inputs(self.directory, export.Evidence())

    def test_wrong_per_mode_capacity_is_rejected(self):
        case = self.growing_case()
        case["binius_ep_cap"]["shadow"] = case["binius_ep_cap"]["zekra"]
        self.save_case(case)
        with self.assertRaisesRegex(ValueError, "Wrong EP capacity"):
            export.load_inputs(self.directory, export.Evidence())

    def test_changed_projector_source_identity_is_rejected(self):
        name = "zkcfa-tracer/provider/static/projection.py"
        self.manifest["source_sha256"][name] = "0" * 64
        (self.directory / "manifest.json").write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            export.load_inputs(self.directory, export.Evidence())

    def test_equal_paths_are_allowed_only_when_flag_matches(self):
        # Support independently verified fixtures that happen to project
        # identically; equality is an observation, never a prerequisite.
        for case in self.manifest["cases"]:
            base = self.directory / case["family"] / str(case["source_ep_rows"])
            path = base / "shadow/recorded_path"
            path.write_bytes((base / "zekra/recorded_path").read_bytes())
            case["input_sha256"]["shadow"]["recorded_path"] = export.digest(path)
            case["rows_by_mode"]["shadow"] = case["rows_by_mode"]["zekra"]
            case["binius_ep_cap"]["shadow"] = case["binius_ep_cap"]["zekra"]
            case["shadow_and_zekra_paths_equal"] = True
            self.save_case(case)
        _, cases = export.load_inputs(self.directory, export.Evidence())
        self.assertTrue(all(case["shadow_and_zekra_paths_equal"] for case in cases.values()))


if __name__ == "__main__":
    unittest.main()
