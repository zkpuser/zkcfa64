from __future__ import annotations

import unittest

from static.normalize import (
    DIRECT_BOUNDARY,
    TRACE_MAGIC,
    ExternalCallPolicy,
    ExternalExcursion,
    PluginMap,
    Trace,
    normalize,
    render_recorded_path,
)
from static.provision import SCOPE_ADDRESS, Instruction


class InstructionGranularNormalizationTests(unittest.TestCase):
    def setUp(self) -> None:
        instructions = {
            0x1000: Instruction(0x1000, 1, "indirect_call"),
            0x1001: Instruction(0x1001, 1),
            0x1002: Instruction(0x1002, 1),
            0x1003: Instruction(0x1003, 1, "ret"),
            0x2000: Instruction(0x2000, 1),
            0x2001: Instruction(0x2001, 1),
            0x2002: Instruction(0x2002, 1, "ret"),
        }
        self.plugin_map = PluginMap(
            elf_sha256="a" * 64,
            trace_schema=TRACE_MAGIC,
            scope_call=0x3000,
            root_entry=0x1000,
            scope_return=0x3001,
            root_returns=frozenset({0x1003}),
            instructions=instructions,
            blocks={
                0x1000: 0x1000,
                0x1001: 0x1001,
                0x1002: 0x1001,
                0x1003: 0x1001,
                0x2000: 0x2000,
                0x2001: 0x2000,
                0x2002: 0x2000,
            },
            external_calls={},
            indirect_calls={0x1000: (0x2000,)},
            indirect_jumps={},
            executable_ranges=(),
        )
        self.typed_edges = {
            (SCOPE_ADDRESS, "cal", 0x1000),
            (SCOPE_ADDRESS, "crt", SCOPE_ADDRESS),
            (0x1000, "cal", 0x2000),
            (0x1000, "crt", 0x1001),
        }
        self.nodes = {SCOPE_ADDRESS, 0x1000, 0x1001, 0x2000}

    def trace(self, *pcs: int) -> Trace:
        return Trace(
            elf_sha256="a" * 64,
            trace_schema=TRACE_MAGIC,
            scope_call=0x3000,
            root_entry=0x1000,
            scope_return=0x3001,
            pcs=pcs,
            complete=True,
            runtime_code_match=True,
            boundary_kind=DIRECT_BOUNDARY,
            return_continuation_matched=True,
        )

    def normalize(self, *pcs: int) -> list[tuple[str, int, int | None]]:
        return normalize(
            self.plugin_map,
            self.trace(*pcs),
            self.typed_edges,
            self.nodes,
        )

    def test_exact_instruction_sequence_is_accepted(self) -> None:
        self.assertEqual(
            self.normalize(0x1000, 0x2000, 0x2001, 0x2002, 0x1001, 0x1002, 0x1003),
            [
                ("call", 0x1000, SCOPE_ADDRESS),
                ("call", 0x2000, 0x1001),
                ("ret", 0x1001, None),
                ("ret", SCOPE_ADDRESS, None),
            ],
        )

    def test_mid_block_call_target_is_preserved_without_rounding(self) -> None:
        operations = self.normalize(0x1000, 0x2001, 0x2002, 0x1001, 0x1002, 0x1003)
        self.assertEqual(operations[1], ("call", 0x2001, 0x1001))
        self.assertNotIn(0x2001, self.nodes)

    def test_wrong_return_target_is_preserved_without_rounding(self) -> None:
        operations = self.normalize(0x1000, 0x2000, 0x2001, 0x2002, 0x1002, 0x1003)
        self.assertEqual(operations[2], ("ret", 0x1002, None))

    def test_skipped_instruction_is_an_explicit_discontinuity(self) -> None:
        operations = self.normalize(0x1000, 0x2000, 0x2002, 0x1001, 0x1002, 0x1003)
        self.assertIn(("discontinuity", 0x2002, 0x2000), operations)
        self.assertIn("discontinuity 0x2002 0x2000", render_recorded_path(operations))

    def test_within_block_back_edge_is_an_explicit_discontinuity(self) -> None:
        operations = self.normalize(
            0x1000, 0x2000, 0x2001, 0x2000, 0x2001, 0x2002,
            0x1001, 0x1002, 0x1003,
        )
        self.assertIn(("discontinuity", 0x2000, 0x2001), operations)

    def test_cfg_membership_and_crt_do_not_gate_normalization(self) -> None:
        trace = self.trace(0x1000, 0x2000, 0x2001, 0x2002, 0x1001, 0x1002, 0x1003)
        expected = normalize(self.plugin_map, trace, self.typed_edges, self.nodes)
        self.assertEqual(normalize(self.plugin_map, trace, set(), set()), expected)


class ExactControlTransferTests(unittest.TestCase):
    def plugin_map(
        self,
        instructions: dict[int, Instruction],
        *,
        root_entry: int,
        root_return: int,
        blocks: dict[int, int] | None = None,
        external_calls: dict[int, ExternalCallPolicy] | None = None,
        indirect_calls: dict[int, tuple[int, ...]] | None = None,
        indirect_jumps: dict[int, tuple[int, ...]] | None = None,
    ) -> PluginMap:
        return PluginMap(
            elf_sha256="b" * 64,
            trace_schema=TRACE_MAGIC,
            scope_call=0x3000,
            root_entry=root_entry,
            scope_return=0x3001,
            root_returns=frozenset({root_return}),
            instructions=instructions,
            blocks=blocks or {pc: pc for pc in instructions},
            external_calls=external_calls or {},
            indirect_calls=indirect_calls or {},
            indirect_jumps=indirect_jumps or {},
            executable_ranges=(),
        )

    def normalize(
        self,
        plugin_map: PluginMap,
        pcs: tuple[int, ...],
        edges: set[tuple[int, str, int]],
        *,
        external_calls: tuple[ExternalExcursion, ...] = (),
    ) -> list[tuple[str, int, int | None]]:
        trace = Trace(
            elf_sha256=plugin_map.elf_sha256,
            trace_schema=plugin_map.trace_schema,
            scope_call=plugin_map.scope_call,
            root_entry=plugin_map.root_entry,
            scope_return=plugin_map.scope_return,
            pcs=pcs,
            complete=True,
            runtime_code_match=True,
            boundary_kind=DIRECT_BOUNDARY,
            return_continuation_matched=True,
            external_calls=external_calls,
        )
        envelope = {
            (SCOPE_ADDRESS, "cal", plugin_map.root_entry),
            (SCOPE_ADDRESS, "crt", SCOPE_ADDRESS),
        }
        nodes = {SCOPE_ADDRESS, *plugin_map.blocks.values()}
        return normalize(plugin_map, trace, envelope | edges, nodes)

    def test_direct_call_records_actual_target(self) -> None:
        plugin_map = self.plugin_map(
            {
                0x1000: Instruction(0x1000, 1, "call", 0x2000),
                0x1001: Instruction(0x1001, 1, "ret"),
                0x2000: Instruction(0x2000, 1),
                0x2001: Instruction(0x2001, 1, "ret"),
            },
            root_entry=0x1000,
            root_return=0x1001,
            blocks={0x1000: 0x1000, 0x1001: 0x1001, 0x2000: 0x2000, 0x2001: 0x2000},
        )
        edges = {(0x1000, "cal", 0x2000), (0x1000, "crt", 0x1001)}
        self.normalize(plugin_map, (0x1000, 0x2000, 0x2001, 0x1001), edges)
        actual = self.normalize(plugin_map, (0x1000, 0x2001, 0x1001), edges)
        self.assertEqual(actual[1], ("call", 0x2001, 0x1001))

    def test_direct_jump_records_actual_target(self) -> None:
        plugin_map = self.plugin_map(
            {
                0x1000: Instruction(0x1000, 1, "jump", 0x1002),
                0x1002: Instruction(0x1002, 1),
                0x1003: Instruction(0x1003, 1, "ret"),
            },
            root_entry=0x1000,
            root_return=0x1003,
            blocks={0x1000: 0x1000, 0x1002: 0x1002, 0x1003: 0x1002},
        )
        edges = {(0x1000, "jmp", 0x1002)}
        self.normalize(plugin_map, (0x1000, 0x1002, 0x1003), edges)
        actual = self.normalize(plugin_map, (0x1000, 0x1003), edges)
        self.assertEqual(actual[1], ("jump", 0x1003, None))

    def test_conditional_branch_records_actual_successor(self) -> None:
        plugin_map = self.plugin_map(
            {
                0x1000: Instruction(0x1000, 1, "cond", 0x1010),
                0x1001: Instruction(0x1001, 1),
                0x1002: Instruction(0x1002, 1, "jump", 0x1020),
                0x1010: Instruction(0x1010, 1, "jump", 0x1020),
                0x1020: Instruction(0x1020, 1, "ret"),
            },
            root_entry=0x1000,
            root_return=0x1020,
            blocks={
                0x1000: 0x1000,
                0x1001: 0x1001,
                0x1002: 0x1001,
                0x1010: 0x1010,
                0x1020: 0x1020,
            },
        )
        edges = {
            (0x1000, "jmp", 0x1001),
            (0x1000, "jmp", 0x1010),
            (0x1001, "jmp", 0x1020),
            (0x1010, "jmp", 0x1020),
        }
        self.normalize(plugin_map, (0x1000, 0x1001, 0x1002, 0x1020), edges)
        self.normalize(plugin_map, (0x1000, 0x1010, 0x1020), edges)
        actual = self.normalize(plugin_map, (0x1000, 0x1002, 0x1020), edges)
        self.assertEqual(actual[1], ("jump", 0x1002, None))

    def test_repeat_string_model_accepts_same_pc_then_exact_fallthrough(self) -> None:
        """Model QEMU callbacks here; the pinned-QEMU test supplies live coverage."""
        plugin_map = self.plugin_map(
            {
                0x1000: Instruction(0x1000, 2, "repeat"),
                0x1002: Instruction(0x1002, 1),
                0x1003: Instruction(0x1003, 1, "ret"),
                0x1010: Instruction(0x1010, 1),
            },
            root_entry=0x1000,
            root_return=0x1003,
            blocks={
                0x1000: 0x1000,
                0x1002: 0x1000,
                0x1003: 0x1000,
                0x1010: 0x1010,
            },
        )
        self.normalize(
            plugin_map,
            (0x1000, 0x1000, 0x1000, 0x1002, 0x1003),
            set(),
        )
        actual = self.normalize(plugin_map, (0x1000, 0x1010, 0x1003), set())
        self.assertIn(("discontinuity", 0x1010, 0x1000), actual)

    def test_ordinary_instruction_same_pc_is_discontinuity(self) -> None:
        plugin_map = self.plugin_map(
            {
                0x1000: Instruction(0x1000, 1, "other"),
                0x1001: Instruction(0x1001, 1, "ret"),
            },
            root_entry=0x1000,
            root_return=0x1001,
            blocks={0x1000: 0x1000, 0x1001: 0x1000},
        )
        actual = self.normalize(plugin_map, (0x1000, 0x1000, 0x1001), set())
        self.assertIn(("discontinuity", 0x1000, 0x1000), actual)

    def test_indirect_jump_records_unlisted_raw_target(self) -> None:
        plugin_map = self.plugin_map(
            {
                0x1000: Instruction(0x1000, 1, "indirect_jump"),
                0x2000: Instruction(0x2000, 1),
                0x2001: Instruction(0x2001, 1, "ret"),
            },
            root_entry=0x1000,
            root_return=0x2001,
            blocks={0x1000: 0x1000, 0x2000: 0x2000, 0x2001: 0x2000},
            indirect_jumps={0x1000: (0x2000,)},
        )
        edges = {(0x1000, "jmp", 0x2000)}
        self.normalize(plugin_map, (0x1000, 0x2000, 0x2001), edges)
        actual = self.normalize(plugin_map, (0x1000, 0x2001), edges)
        self.assertEqual(actual[1], ("jump", 0x2001, None))

    def test_nested_wrong_return_and_unmatched_call_are_recorded(self) -> None:
        plugin_map = self.plugin_map(
            {
                0x1000: Instruction(0x1000, 1, "call", 0x2000),
                0x1001: Instruction(0x1001, 1, "ret"),
                0x2000: Instruction(0x2000, 1, "call", 0x3000),
                0x2001: Instruction(0x2001, 1, "ret"),
                0x3000: Instruction(0x3000, 1, "ret"),
            },
            root_entry=0x1000,
            root_return=0x1001,
        )
        edges = {
            (0x1000, "cal", 0x2000),
            (0x1000, "crt", 0x1001),
            (0x2000, "cal", 0x3000),
            (0x2000, "crt", 0x2001),
        }
        self.normalize(plugin_map, (0x1000, 0x2000, 0x3000, 0x2001, 0x1001), edges)
        actual = self.normalize(plugin_map, (0x1000, 0x2000, 0x3000, 0x1001), edges)
        self.assertEqual(actual[-2:], [("ret", 0x1001, None), ("ret", SCOPE_ADDRESS, None)])

    def test_external_excursion_is_an_exact_atomic_call_and_return(self) -> None:
        policy = ExternalCallPolicy(0x1000, 0x4000, 0x9000, 0x1001, "puts", 0x4002)
        plugin_map = self.plugin_map(
            {
                0x1000: Instruction(0x1000, 1, "call", 0x4000),
                0x1001: Instruction(0x1001, 1, "ret"),
                0x1002: Instruction(0x1002, 1),
                0x4000: Instruction(0x4000, 1),
                0x4001: Instruction(0x4001, 1, "indirect_jump"),
            },
            root_entry=0x1000,
            root_return=0x1001,
            blocks={
                0x1000: 0x1000,
                0x1001: 0x1001,
                0x1002: 0x1001,
                0x4000: 0x9000,
                0x4001: 0x9000,
            },
            external_calls={0x1000: policy},
        )
        edges = {(0x1000, "cal", 0x9000), (0x1000, "crt", 0x1001)}
        excursion = ExternalExcursion(1, 0x1000, 0x4000, 0x9000, 0x1001)
        self.normalize(
            plugin_map,
            (0x1000, 0x1001),
            edges,
            external_calls=(excursion,),
        )

        with self.subTest("wrong bracket"):
            with self.assertRaisesRegex(ValueError, "not bracketed"):
                self.normalize(
                    plugin_map,
                    (0x1000, 0x1002, 0x1001),
                    edges,
                    external_calls=(excursion,),
                )
        with self.subTest("wrong policy"):
            wrong = ExternalExcursion(1, 0x1000, 0x4000, 0x9001, 0x1001)
            with self.assertRaisesRegex(ValueError, "differs from the static PLT policy"):
                self.normalize(
                    plugin_map,
                    (0x1000, 0x1001),
                    edges,
                    external_calls=(wrong,),
                )

    def test_stop_instruction_successor_is_discontinuity(self) -> None:
        plugin_map = self.plugin_map(
            {
                0x1000: Instruction(0x1000, 1, "stop"),
                0x1001: Instruction(0x1001, 1, "ret"),
            },
            root_entry=0x1000,
            root_return=0x1001,
        )
        actual = self.normalize(plugin_map, (0x1000, 0x1001), set())
        self.assertIn(("discontinuity", 0x1001, 0x1000), actual)


if __name__ == "__main__":
    unittest.main()
