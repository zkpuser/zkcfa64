from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from static.materialize_recovery import materialize_recovery


VENDOR = Path(__file__).parents[1] / "vendor/zekra-embench21"
OVERLAY = VENDOR / "recovery/overlay.json"
EXPECTED_OVERLAY_SHA256 = "f5ec96bde01835a212d34a1c1c6d4fdb6350cdcafa21975efd70bbc74fced044"
EXPECTED_MATERIALIZED_MANIFEST_SHA256 = (
    "bb4216e5e87eefb10716c5bfec1b63f0308ec63df148abeec2a4777b070c0221"
)
RECOVERED = {
    "picojpeg": {
        "source": "picojpeg_test.c",
        "source_sha256": "dd7d4f86ddc716c88cc09b9649f962465949973cb0ca18c6225a518415f1ceb8",
        "elf_sha256": "14d9fb046c074bd4a3fd22ce4daa117e76fb4b97a856c4e81edcf84ab42810b7",
        "policy_sha256": "95dc5e54af13f50c534aa33193f9a81cf681085e7c8ac5b248c5ddff8f79d4df",
    },
    "sglib-combined": {
        "source": "combined.c",
        "source_sha256": "8b219b35bff52f6cad7af62cf920f1d5e4e2032c17f6a933265b5138cd00c3be",
        "elf_sha256": "64984e2551069ef2e849e05c83419bdc075b0af93b25d35ad5d2db571674bdeb",
        "policy_sha256": "bdba189495c7f0f66354427fd35e266c7c2628e5a5f5d4fe56c5c24c43ec1904",
    },
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RecoveryOverlayTests(unittest.TestCase):
    def test_checked_in_overlay_materializes_exact_composite_identity(self) -> None:
        self.assertEqual(sha256(OVERLAY), EXPECTED_OVERLAY_SHA256)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "recovered"
            provenance = materialize_recovery(VENDOR, OVERLAY, output)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            manifest_apps = {item["name"]: item for item in manifest["applications"]}
            self.assertEqual(
                sha256(output / "manifest.json"), EXPECTED_MATERIALIZED_MANIFEST_SHA256
            )
            self.assertEqual(provenance["overlay_sha256"], EXPECTED_OVERLAY_SHA256)
            self.assertEqual(
                provenance["identity"],
                "base ZEKRA source revision plus audited recovery overlay",
            )
            self.assertEqual(
                manifest["source_revision"],
                "01a0152bfd9812a0569dce19965e7e92df30015d",
            )
            self.assertFalse((output / "bin").exists())
            for name, expected in RECOVERED.items():
                source = (
                    output
                    / "source/embench-iot-applications"
                    / name
                    / expected["source"]
                )
                self.assertEqual(sha256(source), expected["source_sha256"])
                self.assertEqual(manifest_apps[name]["elf_sha256"], expected["elf_sha256"])
                self.assertEqual(
                    sha256(output / f"policies/{name}.json"),
                    expected["policy_sha256"],
                )
            on_disk = json.loads(
                (output / "recovery-provenance.json").read_text(encoding="utf-8")
            )
            self.assertEqual(on_disk, provenance)

    def test_changed_base_source_fails_before_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor = root / "vendor"
            shutil.copytree(VENDOR, vendor)
            source = (
                vendor
                / "source/embench-iot-applications/picojpeg/picojpeg_test.c"
            )
            source.write_bytes(source.read_bytes() + b"\n")
            output = root / "recovered"
            with self.assertRaisesRegex(ValueError, "base source SHA-256"):
                materialize_recovery(vendor, vendor / "recovery/overlay.json", output)
            self.assertFalse(output.exists())

    def test_changed_patch_fails_closed_and_leaves_no_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor = root / "vendor"
            shutil.copytree(VENDOR, vendor)
            patch = vendor / "recovery/patches/sglib-combined.patch"
            patch.write_bytes(patch.read_bytes() + b"\n")
            output = root / "recovered"
            with self.assertRaisesRegex(ValueError, "patch SHA-256"):
                materialize_recovery(vendor, vendor / "recovery/overlay.json", output)
            self.assertFalse(output.exists())

    def test_symlinked_overlay_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor = root / "vendor"
            shutil.copytree(VENDOR, vendor)
            patch = vendor / "recovery/patches/picojpeg.patch"
            patch_bytes = patch.read_bytes()
            external = root / "external.patch"
            external.write_bytes(patch_bytes)
            patch.unlink()
            patch.symlink_to(external)
            with self.assertRaisesRegex(ValueError, "contains a symlink"):
                materialize_recovery(
                    vendor, vendor / "recovery/overlay.json", root / "recovered"
                )

    def test_symlinked_vendor_root_is_rejected_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vendor = root / "vendor"
            shutil.copytree(VENDOR, vendor)
            linked = root / "linked-vendor"
            linked.symlink_to(vendor, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "vendor root must not be a symlink"):
                materialize_recovery(
                    linked, linked / "recovery/overlay.json", root / "recovered"
                )

    def test_existing_output_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "recovered"
            output.mkdir()
            sentinel = output / "sentinel"
            sentinel.write_text("preserve", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                materialize_recovery(VENDOR, OVERLAY, output)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")


if __name__ == "__main__":
    unittest.main()
