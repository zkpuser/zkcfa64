#!/usr/bin/env python3
"""Normalize a complete QEMU instruction trace to a sentinel-enveloped EP."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .provision import MAP_MAGIC, SCOPE_ADDRESS, SCOPE_TOKEN, Instruction


TRACE_MAGIC = "zkcfa.scope.trace"
TRACE_MAGICS = frozenset({TRACE_MAGIC})
EVIDENCE_SCHEMA = "zkcfa.raw.evidence"
EVIDENCE_FIELDS = frozenset({
    "schema", "recorded_path_sha256", "typed_cfg_sha256", "event_count",
    "external_call_count", "runtime_code_match", "boundary",
})
EVIDENCE_BOUNDARY_FIELDS = frozenset({
    "complete", "boundary_kind", "scope_call_address", "scope_call_observed",
    "external_root_entry_observed", "captured_return_continuation_matched",
    "root_address", "root_entry_observed", "root_exit_block",
    "root_return_observed", "scope_exit_address", "scope_exit_observed", "sentinel",
})
DIRECT_BOUNDARY = "in-binary-direct-call-and-root-ret"
EXTERNAL_BOUNDARY = "external-root-entry-and-captured-return"
BOUNDARY_KINDS = frozenset({DIRECT_BOUNDARY, EXTERNAL_BOUNDARY})


@dataclass(frozen=True)
class PluginMap:
    elf_sha256: str
    trace_schema: str
    scope_call: int
    root_entry: int
    scope_return: int
    root_returns: frozenset[int]
    instructions: dict[int, Instruction]
    blocks: dict[int, int]
    external_calls: dict[int, "ExternalCallPolicy"]
    indirect_calls: dict[int, tuple[int, ...]]
    indirect_jumps: dict[int, tuple[int, ...]]
    executable_ranges: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class ExternalCallPolicy:
    call_site: int
    target: int
    synthetic: int
    return_site: int
    symbol: str
    gateway_end: int


@dataclass(frozen=True)
class ExternalExcursion:
    after_count: int
    call_site: int
    target: int
    synthetic: int
    return_site: int


@dataclass(frozen=True)
class Trace:
    elf_sha256: str
    trace_schema: str
    scope_call: int
    root_entry: int
    scope_return: int
    pcs: tuple[int, ...]
    complete: bool
    runtime_code_match: bool
    boundary_kind: str
    return_continuation_matched: bool
    runtime_bias: int = 0
    external_calls: tuple[ExternalExcursion, ...] = ()
    capture_context: str | None = None


def address(text: str) -> int:
    if text == SCOPE_TOKEN:
        return SCOPE_ADDRESS
    return int(text, 0)


def token(value: int) -> str:
    return SCOPE_TOKEN if value == SCOPE_ADDRESS else f"0x{value:x}"


def parse_plugin_map(path: Path) -> PluginMap:
    lines = path.read_text().splitlines()
    if not lines or lines[0] != MAP_MAGIC:
        raise ValueError("bad provider plugin map header")
    elf_sha256 = ""
    trace_schema = ""
    scope_call = root_entry = scope_return = None
    root_returns: set[int] = set()
    instructions: dict[int, Instruction] = {}
    blocks: dict[int, int] = {}
    external_calls: dict[int, ExternalCallPolicy] = {}
    indirect_calls: dict[int, tuple[int, ...]] = {}
    indirect_jumps: dict[int, tuple[int, ...]] = {}
    executable_ranges: list[tuple[int, int]] = []
    for line in lines[1:]:
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "elf_sha256" and len(fields) == 2:
            elf_sha256 = fields[1]
        elif fields[0] == "trace_schema" and len(fields) == 2:
            trace_schema = fields[1]
        elif fields[0] == "scope_call" and len(fields) == 2:
            scope_call = int(fields[1], 0)
        elif fields[0] == "root_entry" and len(fields) == 2:
            root_entry = int(fields[1], 0)
        elif fields[0] == "scope_return" and len(fields) == 2:
            scope_return = int(fields[1], 0)
        elif fields[0] == "root_ret" and len(fields) == 2:
            root_returns.add(int(fields[1], 0))
        elif fields[0] == "insn":
            if len(fields) != 7:
                raise ValueError("malformed instruction in plugin map")
            pc, size, block = int(fields[1], 0), int(fields[2]), int(fields[3], 0)
            target = int(fields[5], 0)
            try:
                encoding = bytes.fromhex(fields[6])
            except ValueError as error:
                raise ValueError(f"invalid instruction encoding for {pc:#x}") from error
            if len(encoding) != size or encoding.hex() != fields[6].lower():
                raise ValueError(f"instruction encoding length mismatch for {pc:#x}")
            if pc in instructions:
                raise ValueError(f"duplicate instruction in plugin map: {pc:#x}")
            instructions[pc] = Instruction(
                pc, size, fields[4], target if target else None, fields[6].lower()
            )
            blocks[pc] = block
        elif fields[0] == "external_call":
            if len(fields) != 7:
                raise ValueError("malformed external-call policy in plugin map")
            call_site, target, synthetic, return_site = (
                int(value, 0) for value in fields[1:5]
            )
            gateway_end = int(fields[5], 0)
            symbol = fields[6]
            if call_site in external_calls:
                raise ValueError(f"duplicate external-call policy: {call_site:#x}")
            if not re.fullmatch(r"[A-Za-z0-9_.$@+-]+", symbol):
                raise ValueError("external-call policy has an invalid symbol")
            external_calls[call_site] = ExternalCallPolicy(
                call_site, target, synthetic, return_site, symbol, gateway_end
            )
        elif fields[0] == "exec_range":
            if len(fields) != 3:
                raise ValueError("malformed primary-ELF executable range")
            start, end = int(fields[1], 0), int(fields[2], 0)
            if start >= end:
                raise ValueError("empty primary-ELF executable range")
            executable_ranges.append((start, end))
        elif fields[0] in {"indirect_call", "indirect_jump"}:
            if len(fields) < 2:
                raise ValueError("malformed indirect-target policy in plugin map")
            site = int(fields[1], 0)
            targets = tuple(int(value, 0) for value in fields[2:])
            table = indirect_calls if fields[0] == "indirect_call" else indirect_jumps
            if site in table or len(targets) != len(set(targets)):
                raise ValueError("duplicate indirect-target policy in plugin map")
            table[site] = targets
    if (not re.fullmatch(r"[0-9a-f]{64}", elf_sha256)
            or trace_schema not in TRACE_MAGICS
            or scope_call is None or root_entry is None or scope_return is None
            or not root_returns or not instructions):
        raise ValueError("incomplete provider plugin map")
    if executable_ranges != sorted(set(executable_ranges)) or any(
        left_end > right_start
        for (_, left_end), (right_start, _) in zip(
            executable_ranges, executable_ranges[1:]
        )
    ):
        raise ValueError("primary-ELF executable ranges overlap or are non-canonical")
    for call_site, policy in external_calls.items():
        instruction = instructions.get(call_site)
        if (
            instruction is None
            or instruction.kind != "call"
            or instruction.target != policy.target
            or instruction.fallthrough != policy.return_site
            or policy.synthetic in instructions
            or policy.gateway_end <= policy.target
            or not all(
                any(start <= address < end for start, end in executable_ranges)
                for address in (
                    call_site,
                    policy.target,
                    policy.gateway_end - 1,
                    policy.return_site,
                )
            )
        ):
            raise ValueError(f"external-call policy disagrees with instruction {call_site:#x}")
        gateway = sorted(
            pc for pc in instructions if policy.target <= pc < policy.gateway_end
        )
        if (
            not gateway
            or gateway[0] != policy.target
            or instructions[gateway[-1]].fallthrough != policy.gateway_end
            or instructions[gateway[-1]].kind != "indirect_jump"
            or any(
                instructions[pc].fallthrough != next_pc
                for pc, next_pc in zip(gateway, gateway[1:])
            )
        ):
            raise ValueError(
                f"external-call gateway is not fully byte-bound: {policy.target:#x}"
            )
    for kind, table in (
        ("indirect_call", indirect_calls),
        ("indirect_jump", indirect_jumps),
    ):
        for site in table:
            instruction = instructions.get(site)
            if instruction is None or instruction.kind != kind:
                raise ValueError(f"{kind} policy disagrees with instruction {site:#x}")
    return PluginMap(
        elf_sha256,
        trace_schema,
        scope_call,
        root_entry,
        scope_return,
        frozenset(root_returns),
        instructions,
        blocks,
        external_calls,
        indirect_calls,
        indirect_jumps,
        tuple(executable_ranges),
    )


def parse_trace(path: Path) -> Trace:
    lines = path.read_text().splitlines()
    if len(lines) < 2:
        raise ValueError("empty QEMU scope trace")
    header = re.fullmatch(
        rf"({re.escape(TRACE_MAGIC)}) elf_sha256=([0-9a-f]{{64}})"
        r"(?: runtime_bias=(0x[0-9a-f]+))?"
        r"(?: capture_context=([0-9a-f]{64}))?",
        lines[0],
    )
    if not header:
        raise ValueError("bad QEMU scope trace header")
    begin = re.fullmatch(
        r"begin scope_call=(0x[0-9a-f]+) root=(0x[0-9a-f]+) "
        r"scope_return=(0x[0-9a-f]+) boundary_kind=([a-z0-9-]+)",
        lines[1],
    )
    if not begin:
        raise ValueError("trace does not start with an authenticated scope boundary")
    boundary_kind = begin.group(4)
    if boundary_kind not in BOUNDARY_KINDS:
        raise ValueError("unsupported QEMU scope boundary kind")
    pcs: list[int] = []
    saw_exit = False
    saw_end = False
    complete = False
    runtime_code_match = False
    return_continuation_matched = False
    declared_count = None
    external_calls: list[ExternalExcursion] = []
    pending_external: ExternalExcursion | None = None
    for line_number, line in enumerate(lines[2:], 3):
        if saw_end:
            raise ValueError(f"trace record appears after final end on line {line_number}")
        if line.startswith("boundary_error "):
            raise ValueError(f"QEMU reported a boundary error on line {line_number}")
        match = re.fullmatch(
            r"external_call after_count=(\d+) call_site=(0x[0-9a-f]+) "
            r"target=(0x[0-9a-f]+) synthetic=(0x[0-9a-f]+) "
            r"return=(0x[0-9a-f]+)",
            line,
        )
        if match:
            if saw_exit or pending_external is not None:
                raise ValueError("nested or out-of-boundary external-call record")
            after_count = int(match.group(1))
            if after_count != len(pcs) or not pcs:
                raise ValueError("external-call record has the wrong instruction position")
            pending_external = ExternalExcursion(
                after_count=after_count,
                call_site=int(match.group(2), 0),
                target=int(match.group(3), 0),
                synthetic=int(match.group(4), 0),
                return_site=int(match.group(5), 0),
            )
            continue
        match = re.fullmatch(
            r"external_return after_count=(\d+) synthetic=(0x[0-9a-f]+) "
            r"return=(0x[0-9a-f]+)",
            line,
        )
        if match:
            if pending_external is None:
                raise ValueError("external-return record has no pending call")
            if (
                int(match.group(1)) != pending_external.after_count
                or int(match.group(2), 0) != pending_external.synthetic
                or int(match.group(3), 0) != pending_external.return_site
            ):
                raise ValueError("external-return record differs from its pending call")
            external_calls.append(pending_external)
            pending_external = None
            continue
        match = re.fullmatch(r"insn (\d+) (0x[0-9a-f]+)", line)
        if match:
            if saw_exit:
                raise ValueError("instruction record appears after scope_exit")
            if pending_external is not None:
                raise ValueError("instruction record appears inside an opaque external call")
            sequence = int(match.group(1))
            if sequence != len(pcs):
                raise ValueError("instruction trace sequence gap or duplicate")
            pcs.append(int(match.group(2), 0))
            continue
        match = re.fullmatch(
            r"scope_exit (0x[0-9a-f]+) return_continuation_matched=([01])",
            line,
        )
        if match:
            if saw_exit:
                raise ValueError("duplicate scope_exit record")
            if int(match.group(1), 0) != int(begin.group(3), 0):
                raise ValueError("scope exit target differs from the declared return site")
            return_continuation_matched = match.group(2) == "1"
            if not return_continuation_matched:
                raise ValueError("scope exit did not match the captured return continuation")
            saw_exit = True
            continue
        match = re.fullmatch(
            r"end count=(\d+) complete=([01]) runtime_code_match=([01])", line
        )
        if match:
            declared_count = int(match.group(1))
            complete = match.group(2) == "1"
            runtime_code_match = match.group(3) == "1"
            saw_end = True
            continue
        raise ValueError(f"unknown trace record: {line}")
    if not saw_end:
        raise ValueError("QEMU scope trace has no final end record")
    if pending_external is not None:
        raise ValueError("QEMU trace ends inside an opaque external call")
    if declared_count != len(pcs):
        raise ValueError("trace count does not match instruction records")
    if complete != saw_exit:
        raise ValueError("scope completion and scope-exit records disagree")
    if complete != return_continuation_matched:
        raise ValueError("scope completion and return-continuation evidence disagree")
    if complete and not runtime_code_match:
        raise ValueError("complete trace reports a runtime code mismatch")
    return Trace(
        header.group(2), header.group(1), int(begin.group(1), 0), int(begin.group(2), 0),
        int(begin.group(3), 0),
        tuple(pcs), complete, runtime_code_match,
        boundary_kind, return_continuation_matched,
        int(header.group(3), 0) if header.group(3) else 0,
        tuple(external_calls),
        header.group(4),
    )


def validate_runtime_instruction(plugin_map: PluginMap, pc: int, encoding: bytes) -> None:
    """Mirror the plugin's fail-closed PC/size/bytes check for test vectors."""
    expected = plugin_map.instructions.get(pc)
    if expected is None:
        raise ValueError(f"runtime PC outside static scope: {pc:#x}")
    if encoding.hex() != expected.encoding:
        raise ValueError(f"runtime instruction bytes differ from static ELF at {pc:#x}")


def load_typed_cfg(path: Path) -> set[tuple[int, str, int]]:
    edges: set[tuple[int, str, int]] = set()
    for line_number, raw in enumerate(path.read_text().splitlines(), 1):
        fields = raw.split("#", 1)[0].split()
        if not fields:
            continue
        if len(fields) != 3 or fields[1] not in {"jmp", "cal", "ret", "crt"}:
            raise ValueError(f"typed_cfg line {line_number} is malformed")
        edge = (address(fields[0]), fields[1], address(fields[2]))
        if edge in edges:
            raise ValueError(f"duplicate typed_cfg edge on line {line_number}")
        edges.add(edge)
    return edges


def load_translator(path: Path) -> set[int]:
    values = [address(line.strip()) for line in path.read_text().splitlines() if line.strip()]
    if len(values) != len(set(values)):
        raise ValueError("translator contains duplicate addresses")
    return set(values)


def normalize(plugin_map: PluginMap, trace: Trace,
              typed_edges: set[tuple[int, str, int]], nodes: set[int]) -> list[tuple[str, int, int | None]]:
    """Faithfully encode supported trace events without deciding CFA compliance.

    The CFG arguments remain for callers of the previous interface, but neither
    membership nor return discipline gates acquisition. Transfer destinations are
    actual instruction addresses: rounding a mid-block entry down to a leader
    would conceal that event. Unexpected straight-line, REP or stop successors
    are preserved as explicit discontinuity records carrying both source and
    destination; they cannot alias a permitted block edge. The authenticated
    code and root-boundary requirements below still apply.
    """
    if not trace.complete:
        raise ValueError("QEMU trace did not cross the complete root entry/return boundary")
    if not trace.runtime_code_match:
        raise ValueError("QEMU trace did not match the statically provisioned code bytes")
    expected_boundary_kind = (
        EXTERNAL_BOUNDARY
        if plugin_map.scope_call == SCOPE_ADDRESS
        else DIRECT_BOUNDARY
    )
    if trace.boundary_kind != expected_boundary_kind:
        raise ValueError("QEMU trace boundary kind differs from the static scope policy")
    if not trace.return_continuation_matched:
        raise ValueError("QEMU trace did not match its authenticated return continuation")
    if trace.elf_sha256 != plugin_map.elf_sha256:
        raise ValueError("trace and statically provisioned ELF measurements differ")
    if trace.trace_schema != plugin_map.trace_schema:
        raise ValueError("trace schema differs from the statically provisioned plugin map")
    if (trace.scope_call != plugin_map.scope_call
            or trace.root_entry != plugin_map.root_entry
            or trace.scope_return != plugin_map.scope_return):
        raise ValueError("trace scope differs from the provisioned root policy")
    if not trace.pcs or trace.pcs[0] != plugin_map.root_entry:
        raise ValueError("first measured instruction is not the provisioned root entry")
    if trace.pcs[-1] not in plugin_map.root_returns:
        raise ValueError("last measured instruction is not a provisioned root return")
    if any(pc not in plugin_map.instructions for pc in trace.pcs):
        missing = next(pc for pc in trace.pcs if pc not in plugin_map.instructions)
        raise ValueError(f"trace contains instruction outside static scope: {missing:#x}")

    excursions = {call.after_count: call for call in trace.external_calls}
    if len(excursions) != len(trace.external_calls):
        raise ValueError("trace has duplicate external-call positions")
    for call in trace.external_calls:
        policy = plugin_map.external_calls.get(call.call_site)
        if policy is None or (
            call.target,
            call.synthetic,
            call.return_site,
        ) != (policy.target, policy.synthetic, policy.return_site):
            raise ValueError("trace external call differs from the static PLT policy")
        if (
            call.after_count <= 0
            or call.after_count >= len(trace.pcs)
            or trace.pcs[call.after_count - 1] != call.call_site
            or trace.pcs[call.after_count] != call.return_site
        ):
            raise ValueError("trace external call is not bracketed by call and return sites")

    operations: list[tuple[str, int, int | None]] = [
        ("call", plugin_map.root_entry, SCOPE_ADDRESS)
    ]
    previous_pc = trace.pcs[0]
    previous_block = plugin_map.blocks[previous_pc]
    consumed_excursions: set[int] = set()
    for current_index, current_pc in enumerate(trace.pcs[1:], 1):
        previous = plugin_map.instructions[previous_pc]
        current_block = plugin_map.blocks[current_pc]
        excursion = excursions.get(current_index)
        if excursion is not None:
            operations.append(("call", excursion.synthetic, excursion.return_site))
            operations.append(("ret", excursion.return_site, None))
            consumed_excursions.add(current_index)
            previous_pc, previous_block = current_pc, current_block
            continue

        if previous.kind == "other":
            if current_pc != previous.fallthrough:
                operations.append(("discontinuity", current_pc, previous_pc))
            elif current_block != previous_block:
                operations.append(("jump", current_pc, None))
        elif previous.kind == "repeat":
            allowed = (previous.address, previous.fallthrough)
            if current_pc not in allowed:
                operations.append(("discontinuity", current_pc, previous_pc))
            elif current_block != previous_block:
                operations.append(("jump", current_pc, None))
        elif previous.kind in {"call", "indirect_call"}:
            operations.append(("call", current_pc, previous.fallthrough))
        elif previous.kind == "ret":
            operations.append(("ret", current_pc, None))
        elif previous.kind in {"jump", "cond", "indirect_jump"}:
            operations.append(("jump", current_pc, None))
        elif previous.kind == "stop":
            operations.append(("discontinuity", current_pc, previous_pc))
        else:
            raise ValueError(
                f"unsupported instruction kind {previous.kind!r} at {previous_pc:#x}"
            )
        previous_pc, previous_block = current_pc, current_block
    if consumed_excursions != set(excursions):
        raise ValueError("trace contains an unconsumed external-call record")
    operations.append(("ret", SCOPE_ADDRESS, None))
    return operations


def render_recorded_path(operations: list[tuple[str, int, int | None]]) -> str:
    lines = [f"initial_node={SCOPE_TOKEN} final_node={SCOPE_TOKEN}"]
    for kind, destination, auxiliary in operations:
        if kind in {"call", "discontinuity"}:
            assert auxiliary is not None
            lines.append(f"{kind} {token(destination)} {token(auxiliary)}")
        else:
            lines.append(f"{kind} {token(destination)}")
    return "\n".join(lines) + "\n"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_trace_evidence(
    *,
    plugin_map: PluginMap,
    trace: Trace,
    recorded_path: Path,
    typed_cfg: Path,
    expected_typed_cfg_sha256: str,
    translator: Path,
    static_manifest: Path,
    plugin_map_path: Path,
) -> dict[str, object]:
    """Recompute evidence from raw trace and immutable static artifacts."""
    typed_cfg_sha256 = sha256_file(typed_cfg)
    if typed_cfg_sha256 != expected_typed_cfg_sha256:
        raise ValueError("typed CFG changed during trace normalization")

    manifest = json.loads(static_manifest.read_text())
    if not isinstance(manifest, dict):
        raise ValueError("static manifest must contain a JSON object")
    policy = manifest.get("scope_policy")
    if not isinstance(policy, dict):
        raise ValueError("static manifest has no scope_policy object")
    root_exit_block = plugin_map.blocks[trace.pcs[-1]]
    expected_exit_blocks = policy.get("root_exit_blocks")
    expected_boundary_kind = (
        EXTERNAL_BOUNDARY
        if plugin_map.scope_call == SCOPE_ADDRESS
        else DIRECT_BOUNDARY
    )
    manifest_external_policy = manifest.get("external_call_policy")
    manifest_external_calls = (
        manifest_external_policy.get("calls")
        if isinstance(manifest_external_policy, dict)
        else None
    )
    expected_external_calls = [
        {
            "call_site": token(call.call_site),
            "plt_target": token(call.target),
            "symbol": call.symbol,
            "synthetic_node": token(call.synthetic),
            "return_site": token(call.return_site),
            "gateway_end": token(call.gateway_end),
        }
        for call in sorted(
            plugin_map.external_calls.values(), key=lambda item: item.call_site
        )
    ]
    manifest_indirect_policy = manifest.get("indirect_target_policy")
    expected_indirect_calls = {
        token(site): [token(target) for target in targets]
        for site, targets in sorted(plugin_map.indirect_calls.items())
    }
    expected_indirect_jumps = {
        token(site): [token(target) for target in targets]
        for site, targets in sorted(plugin_map.indirect_jumps.items())
    }
    expected_executable_ranges = [
        {"start": token(start), "end": token(end)}
        for start, end in plugin_map.executable_ranges
    ]
    if isinstance(manifest_indirect_policy, dict):
        manifest_indirect_calls = manifest_indirect_policy.get("calls")
        manifest_indirect_jumps = manifest_indirect_policy.get("jumps")
    else:
        manifest_indirect_calls = manifest_indirect_jumps = None
    application = manifest.get("application")
    checks = {
        "application": (
            isinstance(application, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", application) is not None
        ),
        "ELF measurement": manifest.get("elf_sha256") == plugin_map.elf_sha256,
        "typed CFG digest": manifest.get("typed_cfg_sha256") == expected_typed_cfg_sha256,
        "translator digest": manifest.get("translator_sha256") == sha256_file(translator),
        "plugin map digest": manifest.get("plugin_map_sha256") == sha256_file(plugin_map_path),
        "trace schema": (
            manifest.get("trace_schema")
            == trace.trace_schema
            == plugin_map.trace_schema
        ),
        "boundary kind": (
            policy.get("boundary_kind")
            == trace.boundary_kind
            == expected_boundary_kind
        ),
        "scope-call address": policy.get("scope_call_address") == token(plugin_map.scope_call),
        "root address": policy.get("root_address") == token(plugin_map.root_entry),
        "root exit block": (
            isinstance(expected_exit_blocks, list)
            and token(root_exit_block) in expected_exit_blocks
        ),
        "scope-return address": (
            policy.get("scope_return_address") == token(plugin_map.scope_return)
        ),
        "sentinel": policy.get("sentinel") == SCOPE_TOKEN,
        "external-call policy": (
            manifest_external_calls == expected_external_calls
            or (not expected_external_calls and manifest_external_calls is None)
        ),
        "indirect-target policy": (
            (
                manifest_indirect_calls == expected_indirect_calls
                and manifest_indirect_jumps == expected_indirect_jumps
            )
            or (
                not expected_indirect_calls
                and not expected_indirect_jumps
                and manifest_indirect_calls is None
                and manifest_indirect_jumps is None
            )
        ),
        "primary ELF executable ranges": (
            manifest.get("primary_elf_executable_ranges")
            == expected_executable_ranges
            or (
                not expected_executable_ranges
                and "primary_elf_executable_ranges" not in manifest
            )
        ),
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise ValueError("static manifest mismatch: " + ", ".join(failed))

    evidence: dict[str, object] = {
        "schema": EVIDENCE_SCHEMA,
        "recorded_path_sha256": sha256_file(recorded_path),
        "typed_cfg_sha256": typed_cfg_sha256,
        "event_count": len(trace.pcs),
        "external_call_count": len(trace.external_calls),
        "runtime_code_match": True,
        "boundary": {
            "complete": True,
            "boundary_kind": trace.boundary_kind,
            "scope_call_address": token(plugin_map.scope_call),
            "scope_call_observed": plugin_map.scope_call != SCOPE_ADDRESS,
            "external_root_entry_observed": plugin_map.scope_call == SCOPE_ADDRESS,
            "captured_return_continuation_matched": (
                trace.return_continuation_matched
                if trace.boundary_kind == EXTERNAL_BOUNDARY
                else False
            ),
            "root_address": token(plugin_map.root_entry),
            "root_entry_observed": True,
            "root_exit_block": token(root_exit_block),
            "root_return_observed": True,
            "scope_exit_address": token(trace.scope_return),
            "scope_exit_observed": True,
            "sentinel": SCOPE_TOKEN,
        },
    }
    return evidence


def write_trace_evidence(*, output: Path, **inputs: object) -> dict[str, object]:
    evidence = build_trace_evidence(**inputs)  # type: ignore[arg-type]
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    return evidence


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--typed-cfg", type=Path, required=True)
    parser.add_argument("--translator", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--static-manifest", type=Path, required=True)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args(argv)
    expected_typed_cfg_sha256 = sha256_file(args.typed_cfg)
    plugin_map = parse_plugin_map(args.map)
    trace = parse_trace(args.trace)
    operations = normalize(
        plugin_map,
        trace,
        load_typed_cfg(args.typed_cfg),
        load_translator(args.translator),
    )
    args.output.write_text(render_recorded_path(operations))
    evidence_path = args.evidence or args.output.with_name("evidence.json")
    write_trace_evidence(
        plugin_map=plugin_map,
        trace=trace,
        recorded_path=args.output,
        typed_cfg=args.typed_cfg,
        expected_typed_cfg_sha256=expected_typed_cfg_sha256,
        translator=args.translator,
        static_manifest=args.static_manifest,
        plugin_map_path=args.map,
        output=evidence_path,
    )
    print(f"normalized complete scope: {len(operations) + 1} EP rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
