from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from zkcfa_provider.protocol import _params_from_circuit
from zkcfa_provider.statement import (
    RAW24_PROFILE,
    RAW64_PROFILE,
    RAW_PROFILES,
    RawBlind,
    RawParams,
    circuit_object,
    load_raw_cfg,
    load_raw_evidence,
    load_raw_statement,
    validate_raw_statement,
)


def raw_circuit(*, edge_cap: int, ep_cap: int) -> dict[str, object]:
    return {
        "schema": "zkcfa.raw.circuit",
        "profile": "raw24-full-key",
        "backend": "binius64",
        "log_inv_rate": 1,
        "path_mode": "complete",
        "edge_cap": edge_cap,
        "ep_cap": ep_cap,
    }


class CapacityFeasibilityTests(unittest.TestCase):
    def test_inline14_rejects_aggregate_multiplicity_overflow(self) -> None:
        params = RawParams(edge_cap=8, ep_cap=1 << 14)
        query_count = 2 * (params.ep_cap - 1)
        aggregate_capacity = params.edge_cap * ((1 << params.multiplicity_bits) - 1)

        self.assertEqual(query_count, 32_766)
        self.assertEqual(aggregate_capacity, 32_760)
        with self.assertRaisesRegex(
            ValueError, r"inline14 capacity pair is infeasible: 32766 .* exceed .* 32760"
        ):
            params.validate()

    def test_inline14_feasible_neighboring_capacities_remain_valid(self) -> None:
        for params in (
            RawParams(edge_cap=8, ep_cap=1 << 13),
            RawParams(edge_cap=16, ep_cap=1 << 14),
        ):
            with self.subTest(edge_cap=params.edge_cap, ep_cap=params.ep_cap):
                params.validate()
                self.assertEqual(params.ep_encoding, "inline14")
                self.assertEqual(params.multiplicity_bits, 12)

    def test_shared24_keeps_ep_derived_multiplicity_width(self) -> None:
        params = RawParams(edge_cap=8, ep_cap=1 << 15)

        params.validate()
        self.assertEqual(params.ep_encoding, "shared24")
        self.assertEqual(params.multiplicity_bits, 16)
        self.assertLess(
            2 * (params.ep_cap - 1),
            1 << params.multiplicity_bits,
        )

    def test_authority_cfg_load_rejects_impossible_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / "translator").write_text("0x1\n0x2\n", encoding="ascii")
            (bundle / "typed_cfg").write_text("0x1 jmp 0x2\n", encoding="ascii")

            with self.assertRaisesRegex(ValueError, "inline14 capacity pair is infeasible"):
                load_raw_cfg(
                    bundle,
                    cfg_blind=RawBlind(1, 2),
                    edge_cap=8,
                    ep_cap=1 << 14,
                )

    def test_signing_and_registry_load_paths_reject_impossible_capacity(self) -> None:
        params = RawParams(edge_cap=8, ep_cap=1 << 14)
        with self.assertRaisesRegex(ValueError, "inline14 capacity pair is infeasible"):
            circuit_object(params)
        with self.assertRaisesRegex(ValueError, "inline14 capacity pair is infeasible"):
            _params_from_circuit(raw_circuit(edge_cap=8, ep_cap=1 << 14))

    def test_concrete_inline14_overflow_is_worker_preflight_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / "translator").write_text("0x1\n0x2\n", encoding="ascii")
            (bundle / "typed_cfg").write_text(
                "0x1 jmp 0x2\n0x2 jmp 0x2\n", encoding="ascii"
            )

            def write_path(repetitions: int) -> None:
                (bundle / "recorded_path").write_text(
                    "initial_node=0x2 final_node=0x2\n"
                    + "jump 0x2\n" * repetitions,
                    encoding="ascii",
                )

            write_path(2047)
            load_raw_statement(
                bundle,
                cfg_blind=RawBlind(1, 2),
                ep_blind=RawBlind(3, 4),
                edge_cap=8,
                ep_cap=1 << 13,
            )

            write_path(2048)
            evidence = load_raw_evidence(
                bundle,
                cfg_blind=RawBlind(1, 2),
                ep_blind=RawBlind(3, 4),
                edge_cap=8,
                ep_cap=1 << 13,
            )
            self.assertEqual(len(evidence.steps), 2049)
            self.assertEqual(len(evidence.h_ep_raw24), 64)
            with self.assertRaisesRegex(
                ValueError,
                r"raw CFG entry 1 is reused 4096 times, exceeding .* 4095",
            ):
                load_raw_statement(
                    bundle,
                    cfg_blind=RawBlind(1, 2),
                    ep_blind=RawBlind(3, 4),
                    edge_cap=8,
                    ep_cap=1 << 13,
                )


class EvidenceComplianceSeparationTests(unittest.TestCase):
    """A faithfully encoded violating trace remains authenticatable evidence."""

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.bundle = Path(self.directory.name)
        (self.bundle / "translator").write_text(
            "0x10\n0x20\n0x30\n0x40\n", encoding="ascii"
        )
        (self.bundle / "typed_cfg").write_text(
            "0x10 cal 0x20\n0x10 crt 0x30\n0x20 jmp 0x40\n", encoding="ascii"
        )

    def write_path(self, transfers: str, final: str) -> None:
        (self.bundle / "recorded_path").write_text(
            f"initial_node=0x10 final_node={final}\n{transfers}", encoding="ascii"
        )

    def load(self, loader=load_raw_evidence, *, profile=RAW24_PROFILE, **kwargs):
        return loader(
            self.bundle, cfg_blind=RawBlind(1, 2), ep_blind=RawBlind(3, 4),
            profile=profile, **kwargs,
        )

    def test_compliant_commitments_keep_existing_bytes_for_both_profiles(self) -> None:
        self.write_path("call 0x20 0x30\njump 0x40\nret 0x30\n", "0x30")
        # Values obtained from the original strict serializer before the split.
        expected = {
            RAW24_PROFILE: (
                "670555fa5bb5d3ee7ea8ed74aa5027966d9191fcd4069a740635a99d44226ee8",
                "4842bc0eee493310be5b2ad7b8459e1b0fb2a066c8d9f77795461c91ca81936d",
            ),
            RAW64_PROFILE: (
                "62d82c2a7e0f6f61f5acab4026af0aa1550bbb993e720e12662715d9795118e9",
                "329b13af5875b4d4ca1374b7da526a3c3f45f17360973f1e28a5fb3989652737",
            ),
        }
        for profile in RAW_PROFILES:
            with self.subTest(profile=profile):
                evidence = self.load(profile=profile)
                statement = self.load(load_raw_statement, profile=profile)
                self.assertEqual(
                    (evidence.h_cfg_raw24, evidence.h_ep_raw24), expected[profile]
                )
                self.assertEqual(evidence.ep_words(), statement.ep_words())
                self.assertEqual(evidence.steps[-1].hint, 1)

    def test_cfa_violations_are_preserved_and_rejected_only_by_worker(self) -> None:
        cases = (
            ("jump 0x20\n", "0x20", "no typed forward edge", 0x20, 0),
            ("jump 0x99\n", "0x99", "no typed forward edge", 0x99, 0),
            ("call 0x20 0x40\nret 0x40\n", "0x40", "no typed CRT", 0x40, 1),
            ("call 0x20 0x99\nret 0x99\n", "0x99", "no typed CRT", 0x99, 1),
            ("call 0x20 0x30\nret 0x40\n", "0x40", "wrong call site", 0x40, 1),
            ("call 0x20 0x30\nret 0x99\n", "0x99", "wrong call site", 0x99, 1),
            ("ret 0x30\n", "0x30", "empty stack", 0x30, 0),
            ("call 0x20 0x30\n", "0x20", "unmatched calls", 0x20, 0),
        )
        for profile in RAW_PROFILES:
            for mode in ("complete", "shadow"):
                for transfers, final, error, actual_destination, hint in cases:
                    with self.subTest(profile=profile, mode=mode, transfers=transfers):
                        self.write_path(transfers, final)
                        evidence = self.load(profile=profile, path_mode=mode)
                        self.assertEqual(evidence.steps[-1].dst, actual_destination)
                        self.assertEqual(evidence.steps[-1].hint, hint)
                        self.assertEqual(len(evidence.h_ep_raw24), 64)
                        with self.assertRaisesRegex(ValueError, error):
                            validate_raw_statement(evidence)
                        with self.assertRaisesRegex(ValueError, error):
                            self.load(load_raw_statement, profile=profile, path_mode=mode)

    def test_raw64_unknown_high_address_is_committed_without_truncation(self) -> None:
        destination = 0x7FFF12345678
        self.write_path(f"jump {destination:#x}\n", f"{destination:#x}")
        evidence = self.load(profile=RAW64_PROFILE)
        self.assertEqual(evidence.steps[-1].dst, destination)
        self.assertEqual(evidence.ep_words()[14], destination)
        with self.assertRaisesRegex(ValueError, "no typed forward edge"):
            validate_raw_statement(evidence)
        with self.assertRaisesRegex(ValueError, "outside raw24"):
            self.load(profile=RAW24_PROFILE)

    def test_stack_hints_follow_events_without_repairing_wrong_returns(self) -> None:
        self.write_path(
            "ret 0x40\ncall 0x20 0x30\ncall 0x20 0x40\n"
            "ret 0x30\nret 0x99\nret 0x40\n", "0x40"
        )
        for profile in RAW_PROFILES:
            with self.subTest(profile=profile):
                evidence = self.load(profile=profile)
                returns = [step for step in evidence.steps if step.tag == 2]
                self.assertEqual([step.hint for step in returns], [0, 3, 2, 0])
                self.assertEqual([step.dst for step in returns], [0x40, 0x30, 0x99, 0x40])

    def test_discontinuity_marker_binds_actual_source_and_destination(self) -> None:
        for profile, ep_cap, source, destination in (
            (RAW24_PROFILE, 16, 0x21, 0x29),
            (RAW24_PROFILE, 1 << 15, 0x21, 0x29),
            (RAW64_PROFILE, 16, 0x7FFF12345621, 0x7FFF12345629),
        ):
            with self.subTest(profile=profile, ep_cap=ep_cap):
                self.write_path(
                    f"discontinuity {destination:#x} {source:#x}\n", f"{destination:#x}"
                )
                evidence = self.load(profile=profile, ep_cap=ep_cap)
                self.assertEqual(evidence.steps[-1].tag, 3)
                self.assertEqual(evidence.steps[-1].dst, destination)
                self.assertEqual(evidence.steps[-1].auxiliary, source)
                digest = evidence.h_ep_raw24
                with self.assertRaisesRegex(ValueError, "instruction discontinuity"):
                    validate_raw_statement(evidence)
                self.write_path(
                    f"discontinuity {destination:#x} {source + 1:#x}\n", f"{destination:#x}"
                )
                self.assertNotEqual(self.load(profile=profile, ep_cap=ep_cap).h_ep_raw24, digest)
                self.write_path(
                    f"jump {destination:#x}\n", f"{destination:#x}"
                )
                self.assertNotEqual(self.load(profile=profile, ep_cap=ep_cap).h_ep_raw24, digest)

    def test_worker_rejects_forged_return_hint(self) -> None:
        self.write_path("call 0x20 0x30\nret 0x30\n", "0x30")
        for profile in RAW_PROFILES:
            with self.subTest(profile=profile):
                evidence = self.load(profile=profile)
                evidence.steps[-1].hint = 0
                with self.assertRaisesRegex(ValueError, "wrong matching-CAL hint"):
                    validate_raw_statement(evidence)

    def test_evidence_still_rejects_malformed_or_inconsistent_records(self) -> None:
        cases = (
            ("jump 0x00\n", "0x40", "zero is reserved"),
            ("call 0x20\n", "0x20", "malformed"),
            ("jump 0x20\n", "0x40", "disagrees with final_node"),
        )
        for profile in RAW_PROFILES:
            for transfers, final, error in cases:
                with self.subTest(profile=profile, transfers=transfers):
                    self.write_path(transfers, final)
                    with self.assertRaisesRegex(ValueError, error):
                        self.load(profile=profile)


if __name__ == "__main__":
    unittest.main()
