from __future__ import annotations

import re
import time
import unittest

from zekra_projection import zekra_compress


class ZekraCompressionTests(unittest.TestCase):
    def test_zekra_projection_compression_matches_legacy_regex(self) -> None:
        def legacy(operations):
            serialize = lambda item: f"{item[0]}-{item[1]}-{item[2]}"
            merged = "".join(f"{serialize(item)} " for item in operations)
            matches = re.findall(r"((\b.+?\b)(?:\s\2)+)", merged)
            report = []
            for full, repeated in matches:
                repetitions = int((len(full) + 1) / (len(repeated) + 1))
                merged = merged.replace(
                    f"{repeated} " * repetitions,
                    f"{repeated} ",
                )
                report.append({
                    "sequence_length": len(repeated.split()),
                    "repetitions": repetitions,
                })
            lookup = {serialize(item): item for item in operations}
            return [lookup[value] for value in merged.strip().split()], report

        # Hyphens from negative values and punctuation in kind names exercise
        # the word boundaries used by the legacy string regex.
        alphabet = [
            ("call.v1", -17, -2),
            ("jump+tail", 0, None),
            ("ret/path", -1, None),
            ("call:v2", 23, -99),
        ]
        cases = [
            [],
            [alphabet[0]],
            [alphabet[0]] * 5,
            alphabet[:3] * 4 + alphabet[3:],
            alphabet[:2] * 2 + alphabet[2:] * 3 + alphabet[:2] * 2,
        ]
        # Deterministic exhaustive small words cover overlapping and nested
        # immediate repetitions without importing a randomized oracle.
        for size in range(1, 8):
            for encoded in range(3 ** size):
                word = []
                value = encoded
                for _ in range(size):
                    word.append(alphabet[value % 3])
                    value //= 3
                cases.append(word)

        for operations in cases:
            self.assertEqual(zekra_compress(operations), legacy(operations))

    def test_zekra_projection_compression_scales_to_137k_rows(self) -> None:
        # A long, low-repetition prefix is the pathological case for the old
        # backtracking regex and mirrors the size of the recovered picojpeg EP.
        operations = [("jump", index, None) for index in range(137_168)]
        started = time.monotonic()
        compressed, report = zekra_compress(operations)
        elapsed = time.monotonic() - started
        self.assertEqual(compressed, operations)
        self.assertEqual(report, [])
        self.assertLess(elapsed, 10.0, f"137k-row compression took {elapsed:.3f}s")


if __name__ == "__main__":
    unittest.main()
