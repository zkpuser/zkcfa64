from __future__ import annotations

import hashlib
import json
import random
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from static.normalize import EVIDENCE_SCHEMA, TRACE_MAGIC
from static.projection import shadow_safe_compress
from static.provision import (
    SCHEMA,
    Function,
    Instruction,
    Program,
    ScopePolicy,
    _classify_x86_64,
    provision_program,
)
from static.shadow_safe_bundle import materialize_shadow_safe_bundle
from zkcfa_provider.scope import external_call_model


class StaticPipelineTests(unittest.TestCase):
    def test_stable_schema_names(self) -> None:
        self.assertEqual(SCHEMA, "zkcfa.static")
        self.assertEqual(TRACE_MAGIC, "zkcfa.scope.trace")
        self.assertEqual(EVIDENCE_SCHEMA, "zkcfa.raw.evidence")

    @staticmethod
    def classify_x86(mnemonic: str, target: int | None = None) -> tuple[str, int | None]:
        operand = types.SimpleNamespace(type=1, imm=target)
        instruction = types.SimpleNamespace(
            mnemonic=mnemonic,
            operands=[] if target is None else [operand],
        )
        capstone = types.SimpleNamespace(CS_OP_IMM=1)
        with patch.dict(sys.modules, {"capstone": capstone}):
            return _classify_x86_64(instruction)

    def test_x86_rep_string_instructions_have_a_dedicated_kind(self) -> None:
        for mnemonic in ("rep movsb", "repe cmpsq", "repne scasb", "rep stosd"):
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(self.classify_x86(mnemonic), ("repeat", None))
        for mnemonic in ("movsb", "rep nop", "repne ret", "endbr64"):
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(self.classify_x86(mnemonic), ("other", None))

    def test_x86_rep_prefixed_ret_is_a_return_across_capstone_spellings(self) -> None:
        try:
            import capstone as cs  # type: ignore
        except ModuleNotFoundError:
            self.skipTest("Capstone is required for the real decoder spelling check")

        decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        decoder.detail = True
        decoded = list(decoder.disasm(bytes.fromhex("f3c3"), 0x2000))
        self.assertEqual(len(decoded), 1)
        self.assertIn(decoded[0].mnemonic, {"ret", "rep ret", "repz ret"})
        self.assertEqual(_classify_x86_64(decoded[0]), ("ret", None))
        for mnemonic in ("rep ret", "repz ret"):
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(self.classify_x86(mnemonic), ("ret", None))

    def test_rep_prefixed_ret_is_admitted_as_a_root_return(self) -> None:
        return_kind, _ = self.classify_x86("repz ret")
        program = Program(
            "a" * 64,
            {
                0x1000: Instruction(0x1000, 5, "call", 0x2000),
                0x1005: Instruction(0x1005, 1, "stop"),
                0x2000: Instruction(0x2000, 2, return_kind),
            },
            {
                "_start": Function("_start", 0x1000, 0x1006),
                "crc32_scope": Function("crc32_scope", 0x2000, 0x2002),
            },
            architecture="x86_64",
        )
        provisioned = provision_program(program, ScopePolicy())
        self.assertEqual(provisioned.root_returns, (0x2000,))

    def test_x86_loop_family_is_conditional(self) -> None:
        for mnemonic in ("loop", "loope", "loopne", "loopz", "loopnz"):
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(self.classify_x86(mnemonic, 0x2000), ("cond", 0x2000))

    def test_loop_conditional_builds_target_and_fallthrough_cfg_edges(self) -> None:
        program = Program(
            "a" * 64,
            {
                0x1000: Instruction(0x1000, 5, "call", 0x2000),
                0x1005: Instruction(0x1005, 1, "stop"),
                0x2000: Instruction(0x2000, 1),
                0x2001: Instruction(0x2001, 2, "cond", 0x2000),
                0x2003: Instruction(0x2003, 1),
                0x2004: Instruction(0x2004, 1, "ret"),
            },
            {
                "_start": Function("_start", 0x1000, 0x1006),
                "crc32_scope": Function("crc32_scope", 0x2000, 0x2005),
            },
            architecture="x86_64",
        )
        provisioned = provision_program(program, ScopePolicy())
        self.assertEqual(provisioned.instruction_blocks[0x2001], 0x2000)
        self.assertEqual(provisioned.instruction_blocks[0x2003], 0x2003)
        self.assertIn((0x2000, "jmp", 0x2000), provisioned.edges)
        self.assertIn((0x2000, "jmp", 0x2003), provisioned.edges)

    def test_dynamic_runtime_is_bound_without_opaque_external_calls(self) -> None:
        runtime = {
            "schema": "zkcfa.runtime-dependencies",
            "runtime_profile": "ubuntu22",
            "binding": "eager",
            "environment": {"LD_BIND_NOW": "1"},
            "files": [
                {"path": path, "sha256": "00" * 32}
                for path in (
                    "lib64/ld-linux-x86-64.so.2",
                    "lib/x86_64-linux-gnu/libc.so.6",
                    "lib/x86_64-linux-gnu/libm.so.6",
                )
            ],
            "loader_scope": "trusted-out-of-scope",
        }
        encoded = (json.dumps(runtime, indent=2, sort_keys=True) + "\n").encode()
        manifest = {
            "trace_schema": "zkcfa.scope.trace",
            "architecture": "x86_64",
            "runtime_profile": "ubuntu22",
            "runtime_dependencies_sha256": hashlib.sha256(encoded).hexdigest(),
            "external_call_policy": {
                "schema": "zkcfa.external-call-policy",
                "mode": "none",
                "binding": "eager",
                "loader_scope": "trusted-out-of-scope",
                "thread_model": "single",
                "dispatch_integrity": {
                    "schema": "zkcfa.external-dispatch-policy",
                    "bind_now": True,
                    "no_rpath_or_runpath": True,
                    "needed": ["libc.so.6"],
                    "allowed_needed": ["libc.so.6", "libm.so.6"],
                    "relro_ranges": [{"start": "0x1000", "end": "0x2000"}],
                    "jump_slots": ["0x1800"],
                },
                "runtime_dependencies": runtime,
                "calls": [],
            },
        }
        self.assertEqual(external_call_model(manifest), "none")

    def test_shadow_projection_collapses_stack_neutral_repetition(self) -> None:
        operations = [
            ("call", 0x1000, 0x2000),
            *(("jump", 0x1000, None),) * 4,
            ("ret", 0x2000, None),
        ]
        projected, decisions = shadow_safe_compress(operations)
        self.assertLess(len(projected), len(operations))
        self.assertTrue(any(item["occurrences_collapsed"] for item in decisions))

    def test_shadow_projection_preserves_stack_changing_repetition(self) -> None:
        operations = [
            ("call", 0x1000, 0x2000),
            ("call", 0x1000, 0x2000),
            ("ret", 0x2000, None),
            ("ret", 0x2000, None),
        ]
        projected, decisions = shadow_safe_compress(operations)
        self.assertEqual(projected, operations)
        self.assertTrue(any(item["occurrences_preserved"] for item in decisions))

    def test_shadow_projection_preserves_underflow_and_unmatched_calls(self) -> None:
        for operations in (
            [("ret", 0x2000, None)] * 3,
            [("call", 0x1000, 0x2000)] * 3,
        ):
            with self.subTest(operations=operations):
                projected, _ = shadow_safe_compress(operations)
                self.assertEqual(projected, operations)

    def test_shadow_projection_keeps_wrong_return_in_retained_copy(self) -> None:
        unit = [("call", 0x2000, 0x1000), ("ret", 0x1001, None)]
        operations = [("jump", 0x1001, None), *(unit * 3)]
        projected, _ = shadow_safe_compress(operations)
        self.assertEqual(projected, [("jump", 0x1001, None), *unit])
        self.assertNotEqual(projected[-1][1], projected[-2][2])

    def test_shadow_projection_preserves_changed_stack_at_first_boundary(self) -> None:
        # The first RET consumes the outer frame; later copies consume frames
        # from the previous copy. Deleting copies would erase a distinct check.
        operations = [
            ("call", 0x1000, 0x1000),
            *(("ret", 0x1000, None), ("call", 0x1000, 0x2000)) * 3,
        ]
        projected, _ = shadow_safe_compress(operations)
        self.assertEqual(projected, operations[:5])

    def test_shadow_projection_preserves_first_distinct_source_edge(self) -> None:
        operations = [("jump", 0x2000, None), *(("jump", 0x1000, None),) * 3]
        projected, _ = shadow_safe_compress(operations)
        # B->A cannot stand in for A->A: the latter might be the sole violation.
        self.assertEqual(projected, operations[:3])

    def test_shadow_projection_never_removes_discontinuity(self) -> None:
        unit = [("discontinuity", 0x1000, 0x1001)]
        operations = [("jump", 0x1000, None), *(unit * 3)]
        projected, _ = shadow_safe_compress(operations)
        self.assertEqual(projected, operations)

    def test_projection_preserves_queries_and_return_failures(self) -> None:
        def semantics(operations):
            source = None
            queries, return_failures, discontinuities = set(), set(), []
            stack = []
            for kind, destination, auxiliary in operations:
                if kind == "call":
                    queries.add((source, "cal", destination))
                    queries.add((source, "crt", auxiliary))
                    stack.append(auxiliary)
                elif kind == "jump":
                    queries.add((source, "jmp", destination))
                elif kind == "ret":
                    expected = stack.pop() if stack else None
                    if expected != destination:
                        return_failures.add((expected, destination))
                else:
                    discontinuities.append((destination, auxiliary))
                source = destination
            return queries, return_failures, stack, discontinuities, source

        generator = random.Random(0xCFA64)
        alphabet = [
            ("jump", 0, None), ("jump", 1, None),
            ("call", 0, 0), ("call", 1, 1),
            ("ret", 0, None), ("ret", 1, None),
            ("discontinuity", 0, 1),
        ]
        for case in range(500):
            prefix = generator.choices(alphabet, k=generator.randrange(3))
            unit = generator.choices(alphabet, k=generator.randrange(1, 5))
            suffix = generator.choices(alphabet, k=generator.randrange(3))
            operations = prefix + unit * generator.randrange(2, 6) + suffix
            with self.subTest(case=case):
                projected, _ = shadow_safe_compress(operations)
                self.assertEqual(semantics(projected), semantics(operations))

    def test_shadow_bundle_has_minimal_stable_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "translator").write_text(
                "SCOPE_RETURN\n0x1000\n", encoding="ascii"
            )
            (source / "typed_cfg").write_text(
                "SCOPE_RETURN cal 0x1000\n"
                "SCOPE_RETURN crt SCOPE_RETURN\n"
                "0x1000 jmp 0x1000\n",
                encoding="ascii",
            )
            (source / "recorded_path").write_text(
                "initial_node=SCOPE_RETURN final_node=SCOPE_RETURN\n"
                "call 0x1000 SCOPE_RETURN\n"
                "jump 0x1000\n"
                "jump 0x1000\n"
                "jump 0x1000\n"
                "jump 0x1000\n"
                "ret SCOPE_RETURN\n",
                encoding="ascii",
            )
            digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            evidence = {
                "schema": EVIDENCE_SCHEMA,
                "runtime_code_match": True,
                "recorded_path_sha256": digest(source / "recorded_path"),
                "typed_cfg_sha256": digest(source / "typed_cfg"),
                "event_count": 6,
                "external_call_count": 0,
                "boundary": {
                    "complete": True,
                    "boundary_kind": "in-binary-direct-call-and-root-ret",
                    "scope_call_address": "0x1000",
                    "scope_call_observed": True,
                    "external_root_entry_observed": False,
                    "captured_return_continuation_matched": False,
                    "root_address": "0x1000",
                    "root_entry_observed": True,
                    "root_exit_block": "0x1000",
                    "root_return_observed": True,
                    "scope_exit_address": "0x1000",
                    "scope_exit_observed": True,
                    "sentinel": "SCOPE_RETURN",
                },
            }
            (source / "evidence.json").write_text(
                json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                encoding="ascii",
            )
            output = root / "shadow"
            report = materialize_shadow_safe_bundle(source, output)
            self.assertEqual(report["schema"], "zkcfa.raw.projection")
            self.assertEqual(report["algorithm"], "shadow-safe")
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "translator", "typed_cfg", "recorded_path",
                    "source-evidence.json", "projection.json",
                },
            )
            self.assertEqual(
                set(report),
                {
                    "schema", "algorithm", "lossy", "shadow_stack_preserved",
                    "loop_multiplicity_preserved", "full_rows", "compressed_rows",
                    "full_recorded_path_sha256", "compressed_recorded_path_sha256",
                    "typed_cfg_sha256", "translator_sha256",
                    "source_evidence_sha256",
                },
            )
            # A signed-evidence projection must remain available even when
            # the execution cannot satisfy the worker's CFA relation.
            invalid_paths = {
                "off-cfg": "call 0x1000 SCOPE_RETURN\njump 0x3000\nret SCOPE_RETURN\n",
                "wrong-return": (
                    "call 0x1000 SCOPE_RETURN\ncall 0x3000 0x1000\n"
                    "ret 0x4000\nret SCOPE_RETURN\n"
                ),
                "underflow": "ret SCOPE_RETURN\nret SCOPE_RETURN\n",
                "unmatched-call": (
                    "call 0x1000 SCOPE_RETURN\ncall 0x3000 SCOPE_RETURN\n"
                    "ret SCOPE_RETURN\n"
                ),
                "discontinuity": (
                    "call 0x1000 SCOPE_RETURN\n"
                    "discontinuity 0x1000 0x1001\n"
                    "discontinuity 0x1000 0x1001\nret SCOPE_RETURN\n"
                ),
            }
            for name, body in invalid_paths.items():
                with self.subTest(name=name):
                    recorded = "initial_node=SCOPE_RETURN final_node=SCOPE_RETURN\n" + body
                    (source / "recorded_path").write_text(recorded, encoding="ascii")
                    evidence["recorded_path_sha256"] = digest(source / "recorded_path")
                    evidence["event_count"] = len(body.splitlines())
                    (source / "evidence.json").write_text(
                        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
                        encoding="ascii",
                    )
                    destination = root / name
                    materialize_shadow_safe_bundle(source, destination)
                    self.assertEqual((destination / "recorded_path").read_text(), recorded)


if __name__ == "__main__":
    unittest.main()
