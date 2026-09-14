"""Keep archive provenance separate from any enclosing repository."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "released_input_audit",
    Path(__file__).resolve().parents[1] / "scripts/audit_zekra_released_inputs.py",
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class InputRevisionTests(unittest.TestCase):
    def test_archive_does_not_inherit_an_enclosing_checkout_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            source = root / "output/snapshot/zekra/ZEKRA/embench-iot-applications"
            source.mkdir(parents=True)
            with patch.object(audit, "revision", return_value="outer-head") as revision:
                self.assertIsNone(audit.input_revision(source))
            revision.assert_not_called()

    def test_direct_upstream_repository_or_submodule_supplies_revision(self):
        for marker_type in ("directory", "file"):
            with self.subTest(marker_type=marker_type), tempfile.TemporaryDirectory() as directory:
                upstream = Path(directory)
                source = upstream / "embench-iot-applications"
                source.mkdir()
                marker = upstream / ".git"
                if marker_type == "directory":
                    marker.mkdir()
                else:
                    marker.write_text("gitdir: /unused/submodule-metadata\n")
                with patch.object(audit, "revision", return_value="upstream-head") as revision:
                    self.assertEqual(audit.input_revision(source), "upstream-head")
                revision.assert_called_once_with(upstream.resolve())


if __name__ == "__main__":
    unittest.main()
