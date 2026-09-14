"""Semantic regression tests for the frozen compressed-input converter."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import prepare_matched_compressed as converter


TRANSLATOR = "0x100\n0x104\n0x108\n0x200\n0x300\n0x304\nSCOPE_RETURN\n"
TYPED = """SCOPE_RETURN cal 0x100
SCOPE_RETURN crt SCOPE_RETURN
0x100 cal 0x200
0x100 crt 0x104
0x104 jmp 0x100
0x104 jmp 0x108
0x104 jmp 0x300
0x300 crt 0x304
"""
PLUGIN_MAP = """zkcfa.provider.map
elf_sha256 {elf}
root_entry 0x100
insn 0x100 4 0x100 call 0x200 e8000000
insn 0x104 4 0x104 cond 0x100 75000000
insn 0x108 1 0x108 ret 0x0 c3
insn 0x200 1 0x200 ret 0x0 c3
insn 0x300 4 0x300 indirect_call 0x0 ffd50000
insn 0x304 1 0x304 ret 0x0 c3
""".format(elf="ab" * 32)
LOOP = "call 0x200 0x104\nret 0x104\njump 0x100\n"
PATH = ("initial_node=SCOPE_RETURN final_node=SCOPE_RETURN\ncall 0x100 SCOPE_RETURN\n"
        + LOOP * 4 + "call 0x200 0x104\nret 0x104\njump 0x108\nret SCOPE_RETURN\n")


def fixture_campaign(base: Path) -> Path:
    campaign = base / "source"
    private = campaign / "signed/fixture/shadow/bundle/private"
    public = private.parent / "public"
    static = campaign / "inputs/fixture/artifacts"
    for directory in (private, public, static):
        directory.mkdir(parents=True)
    common = {"translator": TRANSLATOR, "typed_cfg": TYPED, "recorded_path": PATH}
    for name, text in common.items():
        # CRLF is intentional: common files must preserve bytes, not be re-rendered.
        data = text.replace("\n", "\r\n").encode()
        (private / name).write_bytes(data)
        (static / name).write_bytes(data)
    (static / "plugin-map.txt").write_text(PLUGIN_MAP)
    code = "ab" * 32
    evidence = {"recorded_path_sha256": converter.sha(static / "recorded_path"),
                "typed_cfg_sha256": converter.sha(static / "typed_cfg"), "runtime_code_match": True,
                "boundary": {"complete": True, "root_entry_observed": True, "root_return_observed": True}}
    (static / "evidence.json").write_bytes(converter.json_bytes(evidence))
    manifest = {"application": "fixture", "elf_sha256": code,
                "plugin_map_sha256": converter.sha(static / "plugin-map.txt"),
                "translator_sha256": converter.sha(private / "translator"),
                "typed_cfg_sha256": converter.sha(private / "typed_cfg")}
    (static / "static-manifest.json").write_bytes(converter.json_bytes(manifest))
    circuit = {"backend": "binius64", "path_mode": "shadow", "edge_cap": 8, "ep_cap": 32}
    registry = {"payload": {"application": "fixture", "binary_measurement": code, "circuit": circuit}}
    report = {"payload": {"binary_measurement": code, "entry_raw": converter.SCOPE, "final_raw": converter.SCOPE}}
    (public / "registry.json").write_bytes(converter.json_bytes(registry))
    (public / "report.json").write_bytes(converter.json_bytes(report))
    projection = {"algorithm": "shadow-safe", "shadow_stack_preserved": True,
                  "compressed_rows": len(PATH.splitlines()),
                  "compressed_recorded_path_sha256": converter.sha(private / "recorded_path"),
                  "full_recorded_path_sha256": converter.sha(static / "recorded_path"),
                  "source_evidence_sha256": converter.sha(static / "evidence.json"),
                  "translator_sha256": converter.sha(private / "translator"),
                  "typed_cfg_sha256": converter.sha(private / "typed_cfg")}
    suite = {"applications": [{"application": "fixture", "projection": projection,
                                "shadow": {"edge_cap": 8, "ep_cap": 32}}]}
    (campaign / "signed/bundles.json").write_bytes(converter.json_bytes(suite))
    return campaign


class MatchedCompressedChecks(unittest.TestCase):
    def test_cli_requires_explicit_source_campaign(self):
        with patch.object(sys, "argv", ["prepare_matched_compressed.py", "--output", "prepared"]), \
                patch.object(sys, "stderr", io.StringIO()) as error, \
                patch.object(converter, "prepare_campaign") as prepare:
            with self.assertRaises(SystemExit) as stopped:
                converter.main()
        self.assertEqual(stopped.exception.code, 2)
        self.assertIn("--source-campaign", error.getvalue())
        prepare.assert_not_called()

    def convert(self, path=PATH, typed=TYPED, plugin_map=PLUGIN_MAP):
        return converter.convert_artifacts(TRANSLATOR, typed, path, plugin_map)

    def test_repeated_calls_and_jumps_are_not_compressed_or_retagged(self):
        buffers, audit = self.convert()
        source = converter.parse_path(PATH)
        output = converter.parse_path(buffers["recorded_path"].decode(), converter.parse_raw_address)
        self.assertEqual(source, output)
        self.assertEqual(buffers["recorded_path"].decode().count(LOOP), 4)
        self.assertEqual(audit["source_relation"]["operation_counts"], {"call": 6, "ret": 6, "jump": 5})
        self.assertFalse(audit["compression_invoked"])
        self.assertEqual(audit["inserted_returns"], 0)

    def test_changed_call_target_and_continuation_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "typed CAL"):
            self.convert(path=PATH.replace("call 0x200 0x104", "call 0x108 0x104", 1))
        with self.assertRaisesRegex(ValueError, "static CRT"):
            self.convert(path=PATH.replace("call 0x200 0x104", "call 0x200 0x108", 1))

    def test_wrong_return_is_rejected_even_when_destination_is_in_cfg(self):
        with self.assertRaisesRegex(ValueError, "incorrect exact return"):
            self.convert(path=PATH.replace("ret 0x104", "ret 0x100", 1))

    def test_partial_path_cannot_be_completed_by_converter(self):
        with self.assertRaisesRegex(ValueError, "root wrapper"):
            self.convert(path=PATH.removesuffix("ret SCOPE_RETURN\n"))

    def test_static_terminal_with_only_crt_is_not_a_return(self):
        buffers, audit = self.convert()
        self.assertNotIn(0x300, {edge[0] for edge in audit["static_returns"]})
        self.assertNotIn(0x304, {edge[0] for edge in audit["static_returns"]})
        fake_return = PATH.replace("jump 0x108\nret SCOPE_RETURN", "jump 0x300\nret SCOPE_RETURN")
        with self.assertRaisesRegex(ValueError, "static provenance"):
            self.convert(path=fake_return)
        _, adjacency = converter.parse_adjacency(buffers["adjlist"].decode(), converter.parse_raw_address)
        self.assertNotIn((0x300, 0x304), adjacency)
        self.assertNotIn((0x100, 0x104), adjacency)
        self.assertIn([0x300, 0x304], audit["crt_declarations"])

    def test_removing_real_return_evidence_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "no statically evidenced reachable return"):
            self.convert(plugin_map=PLUGIN_MAP.replace("0x200 ret", "0x200 other"))

    def test_static_label_order_is_independent_of_path_repetitions(self):
        original, first_audit = self.convert()
        shorter, second_audit = self.convert(path=PATH.replace(LOOP * 4, LOOP))
        for name in ("translator", "adjlist", "numified_adjlist"):
            self.assertEqual(original[name], shorter[name])
        self.assertEqual(first_audit["static_returns"], second_audit["static_returns"])
        self.assertEqual(first_audit["parameters"]["levels"], second_audit["parameters"]["levels"])

    def test_symbolic_scope_and_external_gateway_mapping_are_injective(self):
        self.assertEqual(converter.parse_provider_address("SCOPE_RETURN"), 0xFFFFFF)
        self.assertEqual(converter.parse_provider_address("0xfffe0000"), 0xFF0000)
        self.assertEqual(converter.parse_provider_address("0xfffefffe"), 0xFFFFFE)
        self.assertEqual(converter.parse_provider_address("0x401060"), 0x401060)
        for token in ("0x0", "0xffffff", "0xff0000", "0xfffeffff", "0xffff0000", "0xFFFE0000"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                converter.parse_provider_address(token)

    def test_frozen_common_files_keep_bytes_and_manifest_parameters(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(converter, "APPLICATIONS", ("fixture",)):
            base = Path(temporary)
            source = fixture_campaign(base)
            output = base / "prepared"
            before = {str(path.relative_to(source)): converter.sha(path) for path in source.rglob("*") if path.is_file()}
            manifest = converter.prepare_campaign(source, output)
            self.assertTrue(manifest["all_audits_passed"])
            row = manifest["applications"][0]
            self.assertEqual(row["binius"], {"edge_cap": 8, "ep_cap": 32, "path_mode": "shadow"})
            self.assertEqual(row["zekra"]["path_len"], 32)
            for name in converter.COMMON_FILES:
                self.assertEqual((source / "signed/fixture/shadow/bundle/private" / name).read_bytes(),
                                 (output / "common/fixture" / name).read_bytes())
            self.assertEqual(set(path.name for path in (output / "zekra/fixture").iterdir()), set(converter.ZEKRA_FILES))
            self.assertEqual(before, {str(path.relative_to(source)): converter.sha(path)
                                      for path in source.rglob("*") if path.is_file()})
            with self.assertRaisesRegex(ValueError, "already exists"):
                converter.prepare_campaign(source, output)

    def test_changed_source_path_hash_is_rejected_before_writing_output(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(converter, "APPLICATIONS", ("fixture",)):
            base = Path(temporary)
            source = fixture_campaign(base)
            path = source / "signed/fixture/shadow/bundle/private/recorded_path"
            path.write_text(PATH.replace(LOOP * 4, LOOP))
            with self.assertRaisesRegex(ValueError, "compressed path hash mismatch"):
                converter.prepare_campaign(source, base / "prepared")
            self.assertFalse((base / "prepared").exists())

    def test_changed_static_map_hash_is_rejected_before_writing_output(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(converter, "APPLICATIONS", ("fixture",)):
            base = Path(temporary)
            source = fixture_campaign(base)
            (source / "inputs/fixture/artifacts/plugin-map.txt").write_text(PLUGIN_MAP.replace("0x200 ret", "0x200 other"))
            with self.assertRaisesRegex(ValueError, "static map hash mismatch"):
                converter.prepare_campaign(source, base / "prepared")
            self.assertFalse((base / "prepared").exists())


if __name__ == "__main__":
    unittest.main()
