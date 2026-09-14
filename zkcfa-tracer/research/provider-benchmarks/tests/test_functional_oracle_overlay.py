from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import static.materialize_functional_oracle as functional_oracle_module
from static.build_embench21 import load_manifest_document
from static.materialize_functional_oracle import (
    BOOTSTRAP_ELF,
    FUNCTIONAL_APPLICATIONS,
    materialize_functional_oracle,
)
from static.materialize_recovery import materialize_recovery


ROOT = Path(__file__).parents[1]
VENDOR = ROOT / "vendor/zekra-embench21"
RECOVERY_OVERLAY = VENDOR / "recovery/overlay.json"
FUNCTIONAL_OVERLAY_ROOT = ROOT / "functional-oracle"
FUNCTIONAL_OVERLAY = FUNCTIONAL_OVERLAY_ROOT / "overlay.json"
EXPECTED_OVERLAY_SHA256 = (
    "c14478918fdb536709384154c3bcc26932a6cf75ec5467036e16b55516ce9903"
)
EXPECTED_SOURCES = {
    "matmult-int": (
        "matmult-int.c",
        "1e4295657970bb257e6e9a48c55fc36d6e940b8fa20b86e585b3fff8473825fe",
    ),
    "nbody": (
        "nbody.c",
        "fd732d51b52d59ab4092cb0e6654bdda901db410fac3adc2390fbaf4f7d4ecc1",
    ),
    "primecount": (
        "primecount.c",
        "ed6472699008a223ed1e749a3554aec9b8f9adad5e4cebc514bf1795006a8810",
    ),
    "slre": (
        "libslre.c",
        "1e6e6d373a4c25837ef07fce7171f51e32a3d3bee1f73221170caecd9fcd6bd8",
    ),
}
EXPECTED_ELFS = {
    "matmult-int": (
        "551a02c0ddb778645777c50176a3bc7063b60487113b8f31d2c0b0549a77960c"
    ),
    "nbody": (
        "0d35c90e58c9057e15f074ef11efbfb29bf41ea13e4407badbd9c923e3ae5765"
    ),
    "primecount": (
        "75e38d50790364b2ee54e5c0eb1ac70a8d3de55d7ea3a468f5a6da914f2ceca6"
    ),
    "slre": (
        "18675b07c2da113870fa4149d11ec663bd15a205e3e9fe6dc52fa885d7fe02c1"
    ),
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def materialize_first_layer(root: Path) -> Path:
    recovered = root / "recovered"
    materialize_recovery(VENDOR, RECOVERY_OVERLAY, recovered)
    return recovered


class FunctionalOracleOverlayTests(unittest.TestCase):
    def test_checked_in_pinned_overlay_materializes_valid_manifest(self) -> None:
        self.assertEqual(sha256(FUNCTIONAL_OVERLAY), EXPECTED_OVERLAY_SHA256)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recovered = materialize_first_layer(root)
            original_manifest = (recovered / "manifest.json").read_bytes()
            output = root / "functional"
            provenance = materialize_functional_oracle(
                recovered, FUNCTIONAL_OVERLAY, output
            )
            self.assertEqual(provenance["mode"], "pinned")
            self.assertEqual(provenance["unresolved_elf_applications"], [])
            self.assertEqual(
                provenance["overlay_sha256"], EXPECTED_OVERLAY_SHA256
            )
            manifest = load_manifest_document(output)
            manifest_apps = {
                item["name"]: item for item in manifest["applications"]
            }
            for name, (source_name, expected_hash) in EXPECTED_SOURCES.items():
                source = (
                    output
                    / "source/embench-iot-applications"
                    / name
                    / source_name
                )
                self.assertEqual(sha256(source), expected_hash)
                self.assertEqual(
                    manifest_apps[name]["elf_sha256"], EXPECTED_ELFS[name]
                )
            self.assertEqual(
                (recovered / "manifest.json").read_bytes(), original_manifest
            )
            self.assertEqual(
                (output / "functional-oracle/overlay.json").read_bytes(),
                FUNCTIONAL_OVERLAY.read_bytes(),
            )
            on_disk = json.loads(
                (output / "functional-oracle-provenance.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(on_disk, provenance)

    def test_explicit_bootstrap_is_source_only_and_self_describing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recovered = materialize_first_layer(root)
            original_manifest = (recovered / "manifest.json").read_bytes()
            overlay_root = root / "functional-overlay"
            shutil.copytree(FUNCTIONAL_OVERLAY_ROOT, overlay_root)
            overlay_path = overlay_root / "overlay.json"
            overlay = json.loads(overlay_path.read_text(encoding="utf-8"))
            for item in overlay["applications"]:
                item["functional_elf_sha256"] = BOOTSTRAP_ELF
            overlay_path.write_text(
                json.dumps(overlay, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            output = root / "functional"
            with self.assertRaisesRegex(ValueError, "ELF hashes are unpinned"):
                materialize_functional_oracle(recovered, overlay_path, output)
            self.assertFalse(output.exists())
            provenance = materialize_functional_oracle(
                recovered,
                overlay_path,
                output,
                bootstrap_source_only=True,
            )
            self.assertEqual(provenance["mode"], "source-bootstrap")
            self.assertEqual(
                provenance["unresolved_elf_applications"],
                list(FUNCTIONAL_APPLICATIONS),
            )
            self.assertEqual(
                provenance["overlay_sha256"], sha256(overlay_path)
            )
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            manifest_apps = {item["name"]: item for item in manifest["applications"]}
            for name, (source_name, expected_hash) in EXPECTED_SOURCES.items():
                source = (
                    output
                    / "source/embench-iot-applications"
                    / name
                    / source_name
                )
                self.assertEqual(sha256(source), expected_hash)
                self.assertEqual(manifest_apps[name]["elf_sha256"], BOOTSTRAP_ELF)
            self.assertEqual(
                (recovered / "manifest.json").read_bytes(), original_manifest
            )
            self.assertEqual(
                (output / "functional-oracle/overlay.json").read_bytes(),
                overlay_path.read_bytes(),
            )
            on_disk = json.loads(
                (output / "functional-oracle-provenance.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(on_disk, provenance)
            with self.assertRaisesRegex(ValueError, "invalid application"):
                load_manifest_document(output)

    def test_bootstrap_is_forbidden_for_checked_in_pinned_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recovered = materialize_first_layer(root)
            rejected = root / "rejected-bootstrap"
            with self.assertRaisesRegex(ValueError, "bootstrap mode is forbidden"):
                materialize_functional_oracle(
                    recovered,
                    FUNCTIONAL_OVERLAY,
                    rejected,
                    bootstrap_source_only=True,
                )
            self.assertFalse(rejected.exists())

    def test_one_byte_base_source_change_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recovered = materialize_first_layer(root)
            source = recovered / (
                "source/embench-iot-applications/primecount/primecount.c"
            )
            source.write_bytes(source.read_bytes() + b"\n")
            output = root / "functional"
            with self.assertRaisesRegex(ValueError, "base source SHA-256"):
                materialize_functional_oracle(
                    recovered,
                    FUNCTIONAL_OVERLAY,
                    output,
                )
            self.assertFalse(output.exists())

    def test_one_byte_patch_change_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recovered = materialize_first_layer(root)
            overlay_root = root / "functional-overlay"
            shutil.copytree(FUNCTIONAL_OVERLAY_ROOT, overlay_root)
            patch = overlay_root / "patches/slre.patch"
            patch.write_bytes(patch.read_bytes() + b"\n")
            output = root / "functional"
            with self.assertRaisesRegex(ValueError, "patch SHA-256"):
                materialize_functional_oracle(
                    recovered,
                    overlay_root / "overlay.json",
                    output,
                )
            self.assertFalse(output.exists())

    def test_changed_first_layer_provenance_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recovered = materialize_first_layer(root)
            provenance = recovered / "recovery-provenance.json"
            provenance.write_bytes(provenance.read_bytes() + b"\n")
            output = root / "functional"
            with self.assertRaisesRegex(ValueError, "provenance SHA-256"):
                materialize_functional_oracle(
                    recovered,
                    FUNCTIONAL_OVERLAY,
                    output,
                )
            self.assertFalse(output.exists())

    def test_mixed_pending_and_pinned_hashes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recovered = materialize_first_layer(root)
            overlay_root = root / "functional-overlay"
            shutil.copytree(FUNCTIONAL_OVERLAY_ROOT, overlay_root)
            overlay_path = overlay_root / "overlay.json"
            overlay = json.loads(overlay_path.read_text(encoding="utf-8"))
            overlay["applications"][0]["functional_elf_sha256"] = BOOTSTRAP_ELF
            overlay_path.write_text(json.dumps(overlay), encoding="utf-8")
            output = root / "functional"
            with self.assertRaisesRegex(ValueError, "all pinned or all pending"):
                materialize_functional_oracle(
                    recovered,
                    overlay_path,
                    output,
                )
            self.assertFalse(output.exists())

    def test_stale_binary_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recovered = materialize_first_layer(root)
            (recovered / "bin").mkdir()
            (recovered / "bin/nbody").write_bytes(b"stale")
            with self.assertRaisesRegex(ValueError, "stale built ELFs"):
                materialize_functional_oracle(
                    recovered,
                    FUNCTIONAL_OVERLAY,
                    root / "functional",
                )

    def test_existing_output_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recovered = materialize_first_layer(root)
            output = root / "functional"
            output.mkdir()
            sentinel = output / "sentinel"
            sentinel.write_text("preserve", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                materialize_functional_oracle(
                    recovered,
                    FUNCTIONAL_OVERLAY,
                    output,
                )
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")

    def test_concurrent_publisher_wins_without_being_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            recovered = materialize_first_layer(root)
            output = root / "functional"
            atomic_rename = functional_oracle_module.rename_noreplace

            def publish_competitor(source: Path, destination: Path) -> None:
                destination.mkdir()
                (destination / "sentinel").write_text(
                    "competitor", encoding="utf-8"
                )
                atomic_rename(source, destination)

            with mock.patch.object(
                functional_oracle_module,
                "rename_noreplace",
                side_effect=publish_competitor,
            ):
                with self.assertRaisesRegex(
                    ValueError, "output appeared during materialization"
                ):
                    materialize_functional_oracle(
                        recovered,
                        FUNCTIONAL_OVERLAY,
                        output,
                    )
            self.assertEqual(
                (output / "sentinel").read_text(encoding="utf-8"),
                "competitor",
            )
            self.assertEqual(
                [path for path in root.iterdir() if ".materializing-" in path.name],
                [],
            )


if __name__ == "__main__":
    unittest.main()
