from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import capture_recovered as capture


class RecoveryHandoffTests(unittest.TestCase):
    def make_capture(
        self, root: Path, *, boundary_complete: bool = True
    ) -> tuple[str, dict[str, object]]:
        application = "picojpeg"
        app = root / application
        artifacts = app / "artifacts"
        artifacts.mkdir(parents=True)
        binary = app / application
        binary.write_bytes(b"deterministic recovery ELF fixture\n")
        binary.chmod(0o500)
        elf_hash = capture.sha256(binary)
        (app / "indirect-policy.json").write_text("{}\n", encoding="ascii")
        for name in ("translator", "typed_cfg"):
            (artifacts / name).write_text(f"{name}\n", encoding="ascii")
        (artifacts / "plugin-map.txt").write_text(
            "zkcfa.provider.map\n"
            "trace_schema zkcfa.scope.trace\n"
            f"elf_sha256 {elf_hash}\n",
            encoding="ascii",
        )
        (artifacts / "recorded_path").write_text(
            "initial_node=SCOPE_RETURN final_node=SCOPE_RETURN\n"
            "call 0x401000 SCOPE_RETURN\n"
            "ret SCOPE_RETURN\n",
            encoding="ascii",
        )
        (artifacts / "static-manifest.json").write_text(
            json.dumps(
                {
                    "application": application,
                    "elf_sha256": elf_hash,
                    "plugin_map_sha256": capture.sha256(
                        artifacts / "plugin-map.txt"
                    ),
                    "runtime_dependencies_sha256": "55" * 32,
                    "translator_sha256": capture.sha256(artifacts / "translator"),
                    "typed_cfg_sha256": capture.sha256(artifacts / "typed_cfg"),
                    "indirect_target_policy": {
                        "policy_sha256": capture.sha256(
                            app / "indirect-policy.json"
                        )
                    },
                }
            ),
            encoding="ascii",
        )
        boundary = {
            "captured_return_continuation_matched": boundary_complete,
            "complete": boundary_complete,
            "external_root_entry_observed": True,
            "root_entry_observed": True,
            "root_return_observed": boundary_complete,
            "scope_exit_observed": boundary_complete,
        }
        (app / "trace.log").write_text(
            f"zkcfa.scope.trace elf_sha256={elf_hash} runtime_bias=0x0\n"
            "begin scope_call=0xffff0000 root=0x401000 "
            "scope_return=0xffff0000 "
            "boundary_kind=external-root-entry-and-captured-return\n"
            "insn 0 0x401000\n"
            "scope_exit 0xffff0000 return_continuation_matched=1\n"
            "end count=1 complete=1 runtime_code_match=1\n",
            encoding="ascii",
        )
        (artifacts / "evidence.json").write_text(
            json.dumps(
                {
                    "boundary": boundary,
                    "event_count": 1,
                    "external_call_count": 0,
                    "recorded_path_sha256": capture.sha256(
                        artifacts / "recorded_path"
                    ),
                    "runtime_code_match": True,
                    "schema": "zkcfa.raw.evidence",
                    "typed_cfg_sha256": capture.sha256(artifacts / "typed_cfg"),
                }
            ),
            encoding="ascii",
        )
        source_variant = {
            "name": application,
            "recovered_elf_sha256": elf_hash,
            "recovered_source_sha256": "11" * 32,
        }
        (app / "recovery-provenance.json").write_text(
            json.dumps(
                {
                    "applications": [source_variant],
                    "identity": "base ZEKRA source revision plus audited recovery overlay",
                }
            ),
            encoding="ascii",
        )
        return elf_hash, source_variant

    def test_create_handoff_binds_exact_elf_path_and_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf_hash, source_variant = self.make_capture(root)
            with patch.dict(capture.APPLICATIONS, {"picojpeg": elf_hash}, clear=True):
                result = capture.create_handoff(
                    root,
                    "picojpeg",
                    elf_hash,
                    capture_identity={
                        "plugin_sha256": "22" * 32,
                        "qemu_revision": "33" * 20,
                        "recovery_provenance_sha256": capture.sha256(
                            root / "picojpeg/recovery-provenance.json"
                        ),
                        "runtime_dependencies_sha256": "55" * 32,
                    },
                    source_variant=source_variant,
                )
                bundle = root / result["bundle"]
                manifest = capture.verify_handoff(bundle)
                self.assertTrue(result["verified"])
                self.assertEqual(manifest["elf_sha256"], elf_hash)
                self.assertEqual(manifest["zekra_input"]["path"], "main")
                self.assertFalse(manifest["zekra_input"]["recompile"])
                self.assertEqual(
                    manifest["ours_recorded_path"]["rows_including_header"], 3
                )
                self.assertEqual(capture.sha256(bundle / "main"), elf_hash)

                translator = bundle / "ours/translator"
                translator.chmod(0o644)
                translator.write_bytes(translator.read_bytes() + b"tamper")
                with self.assertRaisesRegex(ValueError, "measurement differs"):
                    capture.verify_handoff(bundle)

    def test_incomplete_boundary_cannot_publish_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf_hash, source_variant = self.make_capture(root, boundary_complete=False)
            with patch.dict(capture.APPLICATIONS, {"picojpeg": elf_hash}, clear=True):
                with self.assertRaisesRegex(ValueError, "complete measured main boundary"):
                    capture.create_handoff(
                        root,
                        "picojpeg",
                        elf_hash,
                        capture_identity={},
                        source_variant=source_variant,
                    )
            self.assertFalse((root / "same-elf-zekra-handoff").exists())

    def test_evidence_cannot_rebind_a_different_recorded_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf_hash, source_variant = self.make_capture(root)
            evidence_path = root / "picojpeg/artifacts/evidence.json"
            evidence = json.loads(evidence_path.read_text())
            evidence["recorded_path_sha256"] = "99" * 32
            evidence_path.write_text(json.dumps(evidence), encoding="ascii")
            with patch.dict(capture.APPLICATIONS, {"picojpeg": elf_hash}, clear=True):
                with self.assertRaisesRegex(ValueError, "bindings differ"):
                    capture.create_handoff(
                        root,
                        "picojpeg",
                        elf_hash,
                        capture_identity={
                            "plugin_sha256": "22" * 32,
                            "qemu_revision": "33" * 20,
                            "recovery_provenance_sha256": capture.sha256(
                                root / "picojpeg/recovery-provenance.json"
                            ),
                            "runtime_dependencies_sha256": "55" * 32,
                        },
                        source_variant=source_variant,
                    )


if __name__ == "__main__":
    unittest.main()
