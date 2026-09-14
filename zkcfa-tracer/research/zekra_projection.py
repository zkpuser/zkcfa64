"""ZEKRA consecutive-sequence compression used by the scaling comparison.

This lossy baseline is separate from the maintained provider's stack-safe
projection. Its three compression functions retain the measured implementation.
"""

from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict


Operation = tuple[str, int, int | None]


def _serialize(operation: Operation) -> str:
    kind, destination, auxiliary = operation
    return f"{kind}-{destination}-{auxiliary}"


def _repetition_matches(operations: list[Operation]) -> list[tuple[int, int, int]]:
    r"""Find the matches selected by ZEKRA's leftmost/lazy repeat regex.

    A serialized operation contains no whitespace, begins and ends with a word
    character, and operations are separated by one space.  Consequently the
    legacy ``((\b.+?\b)(?:\s\2)+)`` regex selects whole-operation sequences:
    at the leftmost possible operation it chooses the shortest immediately
    repeated period, consumes all copies, and resumes after that match.

    Searching every possible substring in the merged string scales poorly on
    long paths.  Here candidate periods are restricted to later occurrences
    of the first operation.  A deterministic rolling hash rejects unequal
    candidates in constant time; every hash match is then compared directly,
    so hash collisions cannot change the result.
    """
    operation_ids: dict[Operation, int] = {}
    sequence: list[int] = []
    for operation in operations:
        if operation not in operation_ids:
            operation_ids[operation] = len(operation_ids) + 1
        sequence.append(operation_ids[operation])

    length = len(sequence)
    if length < 2:
        return []

    # Arithmetic modulo 2**64 is deterministic and considerably cheaper than
    # materializing every candidate slice.  Direct comparison below supplies
    # collision safety.
    mask = (1 << 64) - 1
    base = 11400714819323198485
    prefix = [0] * (length + 1)
    powers = [1] * (length + 1)
    for index, value in enumerate(sequence):
        prefix[index + 1] = (prefix[index] * base + value) & mask
        powers[index + 1] = (powers[index] * base) & mask

    positions: dict[int, list[int]] = defaultdict(list)
    for index, value in enumerate(sequence):
        positions[value].append(index)

    def equal(left: int, right: int, size: int) -> bool:
        left_hash = (
            prefix[left + size] - prefix[left] * powers[size]
        ) & mask
        right_hash = (
            prefix[right + size] - prefix[right] * powers[size]
        ) & mask
        return (
            left_hash == right_hash
            and sequence[left:left + size] == sequence[right:right + size]
        )

    matches: list[tuple[int, int, int]] = []
    cursor = 0
    while cursor < length - 1:
        match: tuple[int, int] | None = None
        for start in range(cursor, length - 1):
            occurrences = positions[sequence[start]]
            candidate = bisect_right(occurrences, start)
            maximum_period = (length - start) // 2
            while candidate < len(occurrences):
                period = occurrences[candidate] - start
                if period > maximum_period:
                    break
                if equal(start, start + period, period):
                    match = (start, period)
                    break
                candidate += 1
            if match is not None:
                break

        if match is None:
            break
        start, period = match
        repetitions = 2
        while (
            start + (repetitions + 1) * period <= length
            and equal(start, start + repetitions * period, period)
        ):
            repetitions += 1
        matches.append((start, period, repetitions))
        cursor = start + repetitions * period

    return matches


def zekra_compress(operations: list[Operation]) -> tuple[list[Operation], list[dict[str, int]]]:
    """Reproduce ZEKRA extractor.py's consecutive-sequence compression."""
    merged = "".join(f"{_serialize(operation)} " for operation in operations)
    report: list[dict[str, int]] = []
    for start, period, repetitions in _repetition_matches(operations):
        repeated = "".join(
            f"{_serialize(operation)} "
            for operation in operations[start:start + period]
        )
        merged = merged.replace(repeated * repetitions, repeated)
        report.append({
            "sequence_length": period,
            "repetitions": repetitions,
        })

    by_serialized = {_serialize(operation): operation for operation in operations}
    compressed: list[Operation] = []
    for encoded in merged.strip().split():
        try:
            compressed.append(by_serialized[encoded])
        except KeyError as error:
            raise ValueError(f"compression produced an unknown transfer: {encoded}") from error
    return compressed, report
