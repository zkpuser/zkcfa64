"""Shadow-stack-safe projection for the optional compact proof path."""

from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict
from typing import Optional


Operation = tuple[str, int, Optional[int]]


def _operation_id(operation: Operation) -> str:
    kind, destination, auxiliary = operation
    return f"{kind}-{destination}-{auxiliary}"


def _repetition_candidates(
    operations: list[Operation],
) -> list[tuple[int, int, int]]:
    """Find consecutive repeated subsequences in deterministic leftmost order."""

    operation_ids: dict[Operation, int] = {}
    sequence: list[int] = []
    for operation in operations:
        operation_ids.setdefault(operation, len(operation_ids) + 1)
        sequence.append(operation_ids[operation])
    length = len(sequence)
    if length < 2:
        return []

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
        left_hash = (prefix[left + size] - prefix[left] * powers[size]) & mask
        right_hash = (prefix[right + size] - prefix[right] * powers[size]) & mask
        return (
            left_hash == right_hash
            and sequence[left:left + size] == sequence[right:right + size]
        )

    candidates: list[tuple[int, int, int]] = []
    cursor = 0
    while cursor < length - 1:
        selected: tuple[int, int] | None = None
        for start in range(cursor, length - 1):
            occurrences = positions[sequence[start]]
            candidate = bisect_right(occurrences, start)
            maximum_period = (length - start) // 2
            while candidate < len(occurrences):
                period = occurrences[candidate] - start
                if period > maximum_period:
                    break
                if equal(start, start + period, period):
                    selected = (start, period)
                    break
                candidate += 1
            if selected is not None:
                break
        if selected is None:
            break
        start, period = selected
        repetitions = 2
        while (
            start + (repetitions + 1) * period <= length
            and equal(start, start + repetitions * period, period)
        ):
            repetitions += 1
        candidates.append((start, period, repetitions))
        cursor = start + repetitions * period
    return candidates


def _shadow_stack_states(operations: list[Operation]) -> list[int]:
    """Record stack states without checking observed return destinations.

    A return pops the recorded call stack regardless of its destination. Each
    underflow starts a distinct root state, preventing projection from deleting
    that event through an accidental repeated empty-stack state. Unmatched calls
    at the end remain evidence for the proof to reject, rather than an error at
    the acquisition/signing boundary.
    """

    parents = [-1]
    interned: dict[tuple[int, int], int] = {}
    state = 0
    states = [state]
    for row, (kind, _destination, auxiliary) in enumerate(operations):
        if kind == "call":
            if auxiliary is None:
                raise ValueError(f"shadow-stack call has no return site at row {row}")
            key = (state, auxiliary)
            child = interned.get(key)
            if child is None:
                child = len(parents)
                interned[key] = child
                parents.append(state)
            state = child
        elif kind == "ret":
            if parents[state] < 0:
                state = len(parents)
                parents.append(-1)
            else:
                state = parents[state]
        elif kind not in {"jump", "discontinuity"}:
            raise ValueError(f"unsupported operation {kind!r} at row {row}")
        states.append(state)
    return states


def _framed_operations(
    operations: list[Operation],
) -> tuple[str, dict[int, int]]:
    serialized = [_operation_id(operation) for operation in operations]
    offsets: dict[int, int] = {}
    chunks: list[str] = []
    offset = 0
    for index, value in enumerate(serialized):
        offsets[offset] = index
        chunk = f"\0{value}\1"
        chunks.append(chunk)
        offset += len(chunk)
    return "".join(chunks), offsets


def _non_overlapping_occurrences(
    operations: list[Operation],
    pattern: list[Operation],
    framed: str,
    offsets: dict[int, int],
) -> list[int]:
    if not pattern:
        return []
    needle = "".join(f"\0{_operation_id(operation)}\1" for operation in pattern)
    occurrences: list[int] = []
    cursor = 0
    while True:
        found = framed.find(needle, cursor)
        if found < 0:
            break
        start = offsets.get(found)
        if start is not None and operations[start:start + len(pattern)] == pattern:
            occurrences.append(start)
            cursor = found + len(needle)
        else:
            cursor = found + 1
    return occurrences


def shadow_safe_compress(
    operations: list[Operation],
) -> tuple[list[Operation], list[dict[str, int | str]]]:
    """Collapse repeated units with identical stack and path boundary states.

    This is deterministic evidence reduction, not a compliance check. Keeping
    one copy from the same starting stack and source address preserves every
    distinct forward-edge query and return mismatch of the repeated copies.
    A first copy reached from a different source/stack is retained separately;
    only the subsequent repeated copies may collapse. No initial source is
    supplied by this API, so that boundary is treated as distinct.
    """

    _shadow_stack_states(operations)
    current = list(operations)
    framed, offsets = _framed_operations(current)
    decisions: list[dict[str, int | str]] = []
    for candidate_index, (start, period, repetitions) in enumerate(
        _repetition_candidates(operations)
    ):
        unit = operations[start:start + period]
        pattern = unit * repetitions
        occurrences = _non_overlapping_occurrences(
            current, pattern, framed, offsets
        )
        collapsed: list[int] = []
        preserved: list[int] = []
        retained_copies: dict[int, int] = {}
        if occurrences:
            states = _shadow_stack_states(current)
            pattern_length = len(pattern)
            for occurrence in occurrences:
                boundaries = list(range(
                    occurrence, occurrence + pattern_length + 1, period
                ))
                boundary_states = [
                    (
                        states[boundary],
                        current[boundary - 1][1] if boundary > 0 else None,
                    )
                    for boundary in boundaries
                ]
                copies = repetitions
                if all(kind != "discontinuity" for kind, _dst, _aux in unit):
                    if all(value == boundary_states[0] for value in boundary_states):
                        copies = 1
                    elif (
                        repetitions > 2
                        and all(value == boundary_states[1] for value in boundary_states[1:])
                    ):
                        # Keep the entry copy and one steady-state copy. The
                        # second copy can contain the only disallowed loop
                        # edge or a return using a different initial frame.
                        copies = 2
                if copies < repetitions:
                    collapsed.append(occurrence)
                    retained_copies[occurrence] = copies
                else:
                    preserved.append(occurrence)
            if collapsed:
                collapsed_set = set(collapsed)
                rewritten: list[Operation] = []
                cursor = 0
                for occurrence in occurrences:
                    rewritten.extend(current[cursor:occurrence])
                    if occurrence in collapsed_set:
                        rewritten.extend(unit * retained_copies[occurrence])
                    else:
                        rewritten.extend(
                            current[occurrence:occurrence + pattern_length]
                        )
                    cursor = occurrence + pattern_length
                rewritten.extend(current[cursor:])
                current = rewritten
                framed, offsets = _framed_operations(current)

        if not occurrences:
            decision = "not-present"
        elif not preserved:
            decision = "collapsed"
        elif not collapsed:
            decision = "preserved"
        else:
            decision = "partially-collapsed"
        decisions.append(
            {
                "candidate_index": candidate_index,
                "sequence_length": period,
                "repetitions": repetitions,
                "occurrences_considered": len(occurrences),
                "occurrences_collapsed": len(collapsed),
                "occurrences_preserved": len(preserved),
                "rows_removed": sum(
                    period * (repetitions - retained_copies[occurrence])
                    for occurrence in collapsed
                ),
                "decision": decision,
            }
        )
    _shadow_stack_states(current)
    return current, decisions
