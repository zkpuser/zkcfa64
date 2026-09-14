#!/usr/bin/env python3
"""Provision a typed CFG and translator from an ELF.

This module is deliberately a *static* stage.  Its public API accepts an ELF
model and a pre-provisioned root-scope policy; it has no trace/path argument
and never augments the graph with observed execution.  The dynamic stage lives
in ``normalize.py`` and may only consume the artifacts emitted here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable


SCOPE_TOKEN = "SCOPE_RETURN"
SCOPE_ADDRESS = 0xFFFF0000
EXTERNAL_BASE = 0xFFFE0000
SCHEMA = "zkcfa.static"
TRACE_SCHEMA = "zkcfa.scope.trace"
MAP_MAGIC = "zkcfa.provider.map"

CONTROL_KINDS = {
    "call",
    "jump",
    "cond",
    "ret",
    "indirect_call",
    "indirect_jump",
    "stop",
}

X86_REPEAT_PREFIXES = frozenset({"rep", "repe", "repz", "repne", "repnz"})
X86_STRING_MNEMONICS = frozenset({
    "cmpsb", "cmpsd", "cmpsq", "cmpsw",
    "insb", "insd", "insw",
    "lodsb", "lodsd", "lodsq", "lodsw",
    "movsb", "movsd", "movsq", "movsw",
    "outsb", "outsd", "outsw",
    "scasb", "scasd", "scasq", "scasw",
    "stosb", "stosd", "stosq", "stosw",
})
X86_LOOP_MNEMONICS = frozenset({"loop", "loope", "loopne", "loopz", "loopnz"})


@dataclass(frozen=True)
class Instruction:
    address: int
    size: int
    kind: str = "other"
    target: int | None = None
    encoding: str = ""

    @property
    def fallthrough(self) -> int:
        return self.address + self.size


@dataclass(frozen=True)
class Function:
    name: str
    start: int
    end: int

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end


@dataclass(frozen=True)
class ExternalTarget:
    """A statically resolved PLT target represented by an opaque scope node."""

    address: int
    symbol: str
    synthetic: int
    gateway_end: int


@dataclass(frozen=True)
class ExternalCall:
    call_site: int
    source: int
    target: int
    symbol: str
    synthetic: int
    return_site: int
    gateway_end: int


@dataclass(frozen=True)
class Program:
    elf_sha256: str
    instructions: dict[int, Instruction]
    functions: dict[str, Function]
    architecture: str = "aarch64"
    canonical_entry: int = 0
    canonical_start_code: int = 0
    executable_ranges: tuple[tuple[int, int], ...] = ()
    position_independent: bool = False
    external_targets: dict[int, ExternalTarget] = field(default_factory=dict)
    indirect_call_targets: dict[int, tuple[int, ...]] = field(default_factory=dict)
    indirect_jump_targets: dict[int, tuple[int, ...]] = field(default_factory=dict)
    indirect_policy_sha256: str | None = None
    runtime_dependencies: dict[str, object] | None = None
    runtime_dependencies_sha256: str | None = None
    external_dispatch_policy: dict[str, object] | None = None

    def function_at_entry(self, address: int) -> Function | None:
        return next((fn for fn in self.functions.values() if fn.start == address), None)

    def instructions_in(self, fn: Function) -> list[Instruction]:
        return [
            self.instructions[address]
            for address in sorted(self.instructions)
            if fn.contains(address)
        ]


@dataclass(frozen=True)
class ScopePolicy:
    root_symbol: str = "crc32_scope"
    caller_symbol: str = "_start"
    sentinel: int = SCOPE_ADDRESS
    max_out_degree: int = 4
    external_entry: bool = False


@dataclass(frozen=True)
class Provisioned:
    root_symbol: str
    caller_symbol: str
    scope_call: int
    root_entry: int
    scope_return: int
    root_returns: tuple[int, ...]
    leaders: tuple[int, ...]
    edges: tuple[tuple[int, str, int], ...]
    instruction_blocks: dict[int, int]
    included_functions: tuple[str, ...]
    external_calls: tuple[ExternalCall, ...] = ()


def _hex(address: int) -> str:
    return SCOPE_TOKEN if address == SCOPE_ADDRESS else f"0x{address:x}"


def _owner(program: Program, address: int) -> Function | None:
    candidates = [fn for fn in program.functions.values() if fn.contains(address)]
    if not candidates:
        return None
    return min(candidates, key=lambda fn: fn.end - fn.start)


def _reachable_functions(program: Program, root: Function) -> dict[str, Function]:
    """Direct-call closure rooted at ``root`` with static PLT summaries."""
    included = {root.name: root}
    pending = [root]
    while pending:
        function = pending.pop()
        for insn in program.instructions_in(function):
            if insn.kind == "indirect_jump":
                if insn.address not in program.indirect_jump_targets:
                    raise ValueError(
                        f"{function.name}: unsupported indirect_jump at {insn.address:#x}; "
                        "provision an independent target policy before admitting it"
                    )
                continue
            if insn.kind == "indirect_call":
                targets = program.indirect_call_targets.get(insn.address)
                if targets is None:
                    raise ValueError(
                        f"{function.name}: unsupported indirect_call at {insn.address:#x}; "
                        "provision an independent target policy before admitting it"
                    )
                for target in targets:
                    callee = program.function_at_entry(target)
                    if callee is None:
                        raise ValueError(
                            f"indirect call policy {insn.address:#x}->{target:#x} "
                            "does not target a defined function entry"
                        )
                    if callee.name not in included:
                        included[callee.name] = callee
                        pending.append(callee)
                continue
            if insn.kind != "call":
                continue
            if insn.target is None:
                raise ValueError(f"direct call at {insn.address:#x} has no target")
            callee = program.function_at_entry(insn.target)
            if callee is None:
                if insn.target in program.external_targets:
                    continue
                raise ValueError(
                    f"{function.name}: call {insn.address:#x}->{insn.target:#x} "
                    "does not target a defined function entry"
                )
            if callee.name not in included:
                included[callee.name] = callee
                pending.append(callee)
    return included


def _leaders_for_function(program: Program, fn: Function) -> set[int]:
    leaders = {fn.start}
    for insn in program.instructions_in(fn):
        if insn.kind in CONTROL_KINDS and fn.contains(insn.fallthrough):
            leaders.add(insn.fallthrough)
        # A call target begins a different function; adding it here would
        # create an empty basic block in the caller.  Intra-function branch
        # targets, by contrast, are basic-block leaders in this function.
        if (insn.kind in {"jump", "cond"} and insn.target is not None
                and fn.contains(insn.target)):
            leaders.add(insn.target)
        if insn.kind == "indirect_jump":
            leaders.update(
                target
                for target in program.indirect_jump_targets.get(insn.address, ())
                if fn.contains(target)
            )
    return leaders


def provision_program(program: Program, policy: ScopePolicy = ScopePolicy()) -> Provisioned:
    """Construct the registry graph solely from ``program`` and ``policy``."""
    root = program.functions.get(policy.root_symbol)
    if root is None:
        raise ValueError("root symbol must be defined")
    if policy.external_entry:
        # A dynamic loader may call the application entry from outside the
        # measured ELF (as glibc does for ``main``).  The authenticated scope
        # policy then represents both sides of that boundary by the reserved
        # sentinel.  No edge is inferred from a runtime trace.
        scope_call = policy.sentinel
        scope_return = policy.sentinel
    else:
        caller = program.functions.get(policy.caller_symbol)
        if caller is None:
            raise ValueError("scope-caller symbol must be defined")
        scope_calls = [
            insn for insn in program.instructions_in(caller)
            if insn.kind == "call" and insn.target == root.start
        ]
        if len(scope_calls) != 1:
            raise ValueError(
                f"scope caller must contain exactly one direct call to {policy.root_symbol}; "
                f"found {len(scope_calls)}"
            )
        scope_call = scope_calls[0].address
        scope_return = scope_calls[0].fallthrough

    included = _reachable_functions(program, root)
    included_entries = {fn.start for fn in included.values()}
    if policy.sentinel in {
        insn.address
        for fn in included.values()
        for insn in program.instructions_in(fn)
    }:
        raise ValueError("scope sentinel collides with an executable instruction address")
    leaders_by_function: dict[str, list[int]] = {}
    for name, fn in included.items():
        leaders_by_function[name] = sorted(
            _leaders_for_function(program, fn)
        )

    edges: set[tuple[int, str, int]] = {
        (policy.sentinel, "cal", root.start),
        (policy.sentinel, "crt", policy.sentinel),
    }
    instruction_blocks: dict[int, int] = {}
    root_returns: list[int] = []
    external_calls: list[ExternalCall] = []

    for name, fn in included.items():
        leaders = leaders_by_function[name]
        fn_insns = program.instructions_in(fn)
        for index, leader in enumerate(leaders):
            limit = leaders[index + 1] if index + 1 < len(leaders) else fn.end
            block_insns = [insn for insn in fn_insns if leader <= insn.address < limit]
            if not block_insns:
                raise ValueError(f"empty block {leader:#x} in {name}")
            for insn in block_insns:
                instruction_blocks[insn.address] = leader
            term = next((insn for insn in block_insns if insn.kind in CONTROL_KINDS), None)
            if term is None:
                if index + 1 < len(leaders):
                    edges.add((leader, "jmp", leaders[index + 1]))
                continue
            if term.kind == "call":
                if not fn.contains(term.fallthrough):
                    raise ValueError(f"call at {term.address:#x} has no in-function return site")
                if term.target in program.external_targets:
                    external = program.external_targets[int(term.target)]
                    external_calls.append(
                        ExternalCall(
                            call_site=term.address,
                            source=leader,
                            target=external.address,
                            symbol=external.symbol,
                            synthetic=external.synthetic,
                            return_site=term.fallthrough,
                            gateway_end=external.gateway_end,
                        )
                    )
                    edges.add((leader, "cal", external.synthetic))
                else:
                    if term.target not in included_entries:
                        raise ValueError(
                            f"call target outside provisioned closure at {term.address:#x}"
                        )
                    edges.add((leader, "cal", int(term.target)))
                edges.add((leader, "crt", term.fallthrough))
            elif term.kind == "jump":
                if term.target not in instruction_blocks and term.target not in set(leaders):
                    target_owner = _owner(program, int(term.target or 0))
                    if target_owner is None or target_owner.name not in included:
                        raise ValueError(f"jump target outside provisioned closure at {term.address:#x}")
                edges.add((leader, "jmp", int(term.target)))
            elif term.kind == "cond":
                if term.target is None:
                    raise ValueError(f"conditional branch at {term.address:#x} has no target")
                edges.add((leader, "jmp", term.target))
                if not fn.contains(term.fallthrough):
                    raise ValueError(f"conditional branch at {term.address:#x} falls out of function")
                edges.add((leader, "jmp", term.fallthrough))
            elif term.kind == "ret":
                if name == root.name:
                    root_returns.append(term.address)
            elif term.kind == "indirect_call":
                targets = program.indirect_call_targets.get(term.address)
                if targets is None:
                    raise ValueError(f"unresolved indirect transfer at {term.address:#x}")
                if not fn.contains(term.fallthrough):
                    raise ValueError(
                        f"indirect call at {term.address:#x} has no in-function return site"
                    )
                for target in targets:
                    if target not in included_entries:
                        raise ValueError(
                            f"indirect call target outside provisioned closure at {term.address:#x}"
                        )
                    edges.add((leader, "cal", target))
                edges.add((leader, "crt", term.fallthrough))
            elif term.kind == "indirect_jump":
                targets = program.indirect_jump_targets.get(term.address)
                if targets is None:
                    raise ValueError(f"unresolved indirect transfer at {term.address:#x}")
                if not targets:
                    raise ValueError(
                        f"indirect jump policy at {term.address:#x} has no legal target"
                    )
                for target in targets:
                    target_owner = _owner(program, target)
                    if target_owner is None or target_owner.name not in included:
                        raise ValueError(
                            f"indirect jump target outside provisioned closure at {term.address:#x}"
                        )
                    edges.add((leader, "jmp", target))
            elif term.kind == "stop" and name == root.name:
                raise ValueError("root scope stops without returning to its authenticated caller")

    if not root_returns:
        raise ValueError("root scope has no statically decoded return instruction")

    synthetic_nodes = {call.synthetic for call in external_calls}
    real_addresses = set(program.instructions)
    if (
        policy.sentinel in synthetic_nodes
        or synthetic_nodes & real_addresses
        or any(not EXTERNAL_BASE <= node < SCOPE_ADDRESS for node in synthetic_nodes)
    ):
        raise ValueError("external-call synthetic node collides with the executable scope")

    leaders = sorted({
        policy.sentinel,
        *(x for values in leaders_by_function.values() for x in values),
        *(call.synthetic for call in external_calls),
    })
    leader_set = set(leaders)
    for source, _, destination in edges:
        if source not in leader_set or destination not in leader_set:
            raise ValueError(
                f"typed edge {_hex(source)}->{_hex(destination)} references a non-node"
            )
    aliases: dict[tuple[int, int], str] = {}
    degrees: dict[int, int] = {}
    for source, edge_type, destination in edges:
        key = (source, destination)
        if key in aliases and aliases[key] != edge_type:
            raise ValueError(
                f"type-aliased edge {_hex(source)}->{_hex(destination)}: "
                f"{aliases[key]} and {edge_type}"
            )
        aliases[key] = edge_type
        degrees[source] = degrees.get(source, 0) + 1
    overfull = [(source, degree) for source, degree in degrees.items()
                if degree > policy.max_out_degree]
    if overfull:
        raise ValueError(f"typed CFG exceeds max out-degree: {overfull}")

    type_order = {"jmp": 0, "cal": 1, "ret": 2, "crt": 3}
    ordered_edges = tuple(sorted(
        edges,
        key=lambda edge: (leaders.index(edge[0]), type_order[edge[1]], leaders.index(edge[2])),
    ))
    return Provisioned(
        root_symbol=policy.root_symbol,
        caller_symbol=policy.caller_symbol,
        scope_call=scope_call,
        root_entry=root.start,
        scope_return=scope_return,
        root_returns=tuple(sorted(root_returns)),
        leaders=tuple(leaders),
        edges=ordered_edges,
        instruction_blocks=instruction_blocks,
        included_functions=tuple(sorted(included)),
        external_calls=tuple(sorted(external_calls, key=lambda call: call.call_site)),
    )


def _classify_aarch64(insn: object) -> tuple[str, int | None]:
    # Imported lazily so unit tests for the security-critical graph logic do not
    # depend on host Capstone/pyelftools packages.
    import capstone as cs  # type: ignore

    mnemonic = insn.mnemonic.lower()
    immediates = [op.imm for op in insn.operands if op.type == cs.CS_OP_IMM]
    if mnemonic in {"ret", "retaa", "retab"}:
        return "ret", None
    if mnemonic == "bl":
        return ("call", immediates[-1]) if immediates else ("indirect_call", None)
    if mnemonic == "blr":
        return "indirect_call", None
    if mnemonic == "b":
        return ("jump", immediates[-1]) if immediates else ("indirect_jump", None)
    if mnemonic == "br":
        return "indirect_jump", None
    if mnemonic.startswith("b.") or mnemonic in {"cbz", "cbnz", "tbz", "tbnz"}:
        return ("cond", immediates[-1]) if immediates else ("indirect_jump", None)
    if mnemonic in {"brk", "hlt", "svc"}:
        return "stop", None
    return "other", None


def load_aarch64_elf(path: Path) -> Program:
    """Decode allocated executable sections and sized function symbols."""
    import capstone as cs  # type: ignore
    from elftools.elf.constants import SH_FLAGS  # type: ignore
    from elftools.elf.elffile import ELFFile  # type: ignore

    data = path.read_bytes()
    instructions: dict[int, Instruction] = {}
    functions: dict[str, Function] = {}
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.get_machine_arch() != "AArch64":
            raise ValueError(f"expected AArch64 ELF, got {elf.get_machine_arch()}")
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            raise ValueError("ELF has no symbol table")
        for symbol in symtab.iter_symbols():
            if (symbol["st_info"]["type"] == "STT_FUNC"
                    and symbol["st_shndx"] != "SHN_UNDEF"
                    and symbol["st_value"] and symbol["st_size"]):
                functions[symbol.name] = Function(
                    symbol.name,
                    int(symbol["st_value"]),
                    int(symbol["st_value"] + symbol["st_size"]),
                )
        decoder = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN)
        decoder.detail = True
        for section in elf.iter_sections():
            if not (section["sh_flags"] & SH_FLAGS.SHF_EXECINSTR and section["sh_size"]):
                continue
            raw = section.data()
            base = int(section["sh_addr"])
            decoded = list(decoder.disasm(raw, base))
            if sum(insn.size for insn in decoded) != len(raw):
                raise ValueError(f"failed to decode complete executable section {section.name}")
            for insn in decoded:
                kind, target = _classify_aarch64(insn)
                instructions[insn.address] = Instruction(
                    insn.address,
                    insn.size,
                    kind,
                    target,
                    bytes(insn.bytes).hex(),
                )
    return Program(
        hashlib.sha256(data).hexdigest(),
        instructions,
        functions,
        architecture="aarch64",
        canonical_entry=0,
        position_independent=False,
    )


def _classify_x86_64(insn: object) -> tuple[str, int | None]:
    """Classify direct x86-64 transfers admitted by the static analysis."""
    import capstone as cs  # type: ignore

    mnemonic = insn.mnemonic.lower()
    mnemonic_parts = mnemonic.split()
    immediates = [op.imm for op in insn.operands if op.type == cs.CS_OP_IMM]
    if tuple(mnemonic_parts) in {("rep", "ret"), ("repz", "ret")}:
        # Capstone versions disagree on whether F3 C3 is rendered as ``ret``
        # or with its REP/REPZ prefix.  It is still a return, not a repeatable
        # string instruction.  Keep the accepted aliases exact so unrelated
        # prefixed mnemonics continue to fail closed.
        return "ret", None
    if (
        len(mnemonic_parts) == 2
        and mnemonic_parts[0] in X86_REPEAT_PREFIXES
        and mnemonic_parts[1] in X86_STRING_MNEMONICS
    ):
        # QEMU may end a translation block and re-enter a long REP string
        # instruction at the same guest PC.  Keep this successor exception
        # explicit instead of weakening the ordinary straight-line kind.
        return "repeat", None
    if mnemonic.startswith("ret"):
        return "ret", None
    if mnemonic == "call":
        return ("call", immediates[-1]) if immediates else ("indirect_call", None)
    if mnemonic == "jmp" or mnemonic.endswith(" jmp"):
        return ("jump", immediates[-1]) if immediates else ("indirect_jump", None)
    if mnemonic.startswith("j") and mnemonic not in {"jmp", "jmpl"}:
        return ("cond", immediates[-1]) if immediates else ("indirect_jump", None)
    if mnemonic in X86_LOOP_MNEMONICS:
        # LOOP-family instructions have the same two statically known
        # successors as other conditional branches.  A missing immediate is
        # retained as an invalid conditional target so provisioning fails
        # closed rather than requesting an indirect-target policy.
        return "cond", immediates[-1] if immediates else None
    if mnemonic in {"hlt", "ud2", "syscall", "sysenter"}:
        return "stop", None
    return "other", None


def _x86_64_plt_targets(elf: object, canonical_bias: int) -> dict[int, ExternalTarget]:
    """Resolve direct PLT entry addresses without consulting a runtime trace.

    Ubuntu's CET-enabled linker emits both legacy resolver slots in ``.plt``
    and direct call slots in ``.plt.sec``.  Both are derived solely from the
    ordered ``.rela.plt`` relocations and map to the same synthetic node for a
    given imported symbol.  The synthetic node is a relation-level summary;
    loader/libc instructions remain explicitly outside the attested scope.
    """
    relocation = elf.get_section_by_name(".rela.plt")
    if relocation is None:
        return {}
    symbols = elf.get_section(relocation["sh_link"])
    if symbols is None:
        raise ValueError(".rela.plt has no linked dynamic symbol table")
    rows: list[tuple[int, str]] = []
    for index, item in enumerate(relocation.iter_relocations()):
        symbol_index = int(item["r_info_sym"])
        if symbol_index <= 0:
            raise ValueError("PLT relocation has no imported symbol")
        name = symbols.get_symbol(symbol_index).name
        if not name or not re.fullmatch(r"[A-Za-z0-9_.$@+-]+", name):
            raise ValueError(f"unsupported imported symbol name: {name!r}")
        rows.append((index, name))

    unique_symbols = sorted({name for _, name in rows})
    if len(unique_symbols) >= SCOPE_ADDRESS - EXTERNAL_BASE:
        raise ValueError("PLT symbol set exhausts the reserved external-node range")
    synthetic_by_symbol = {
        name: EXTERNAL_BASE + index for index, name in enumerate(unique_symbols)
    }
    result: dict[int, ExternalTarget] = {}
    direct = elf.get_section_by_name(".plt.sec")
    if rows and (direct is None or not int(direct["sh_entsize"])):
        raise ValueError("external-call policy requires fixed-size .plt.sec gateways")
    for index, name in rows:
        assert direct is not None
        entry_size = int(direct["sh_entsize"])
        address = canonical_bias + int(direct["sh_addr"]) + index * entry_size
        result[address] = ExternalTarget(
            address=address,
            symbol=name,
            synthetic=synthetic_by_symbol[name],
            gateway_end=address + entry_size,
        )
    return result


def _x86_64_external_dispatch_policy(
    elf: object,
    canonical_bias: int,
    external_targets: dict[int, ExternalTarget],
) -> dict[str, object] | None:
    """Require eager, read-only PLT dispatch into the measured runtime TCB."""
    if not external_targets:
        return None
    dynamic = elf.get_section_by_name(".dynamic")
    relocation = elf.get_section_by_name(".rela.plt")
    if dynamic is None or relocation is None:
        raise ValueError("external PLT targets require dynamic relocation metadata")
    needed: list[str] = []
    flags = flags_1 = 0
    for tag in dynamic.iter_tags():
        name = tag.entry.d_tag
        if name == "DT_NEEDED":
            needed.append(tag.needed)
        elif name in {"DT_RPATH", "DT_RUNPATH"}:
            raise ValueError("external-call ELF must not contain RPATH or RUNPATH")
        elif name == "DT_FLAGS":
            flags |= int(tag.entry.d_val)
        elif name == "DT_FLAGS_1":
            flags_1 |= int(tag.entry.d_val)
    if flags & 0x8 == 0 or flags_1 & 0x1 == 0:
        raise ValueError("external-call ELF must set both DF_BIND_NOW and DF_1_NOW")
    allowed_needed = {"libc.so.6", "libm.so.6"}
    if not needed or len(needed) != len(set(needed)) or not set(needed) <= allowed_needed:
        raise ValueError("external-call ELF has an unmeasured DT_NEEDED dependency")

    relro = tuple(
        (int(segment["p_vaddr"]), int(segment["p_vaddr"]) + int(segment["p_memsz"]))
        for segment in elf.iter_segments()
        if segment["p_type"] == "PT_GNU_RELRO"
    )
    offsets = tuple(int(item["r_offset"]) for item in relocation.iter_relocations())
    if (
        not relro
        or not offsets
        or len(offsets) != len(set(offsets))
        or any(not any(start <= offset < end for start, end in relro) for offset in offsets)
    ):
        raise ValueError("external PLT relocation slot is not covered by PT_GNU_RELRO")
    return {
        "schema": "zkcfa.external-dispatch-policy",
        "bind_now": True,
        "no_rpath_or_runpath": True,
        "needed": sorted(needed),
        "allowed_needed": sorted(allowed_needed),
        "jump_slots": [f"{canonical_bias + offset:#x}" for offset in sorted(offsets)],
        "relro_ranges": [
            {
                "start": f"{canonical_bias + start:#x}",
                "end": f"{canonical_bias + end:#x}",
            }
            for start, end in sorted(relro)
        ],
    }


def load_x86_64_elf(path: Path, *, canonical_bias: int = 0x400000) -> Program:
    """Decode an x86-64 PIE in a stable 0x400000 canonical namespace.

    Applying a fixed object bias keeps static CFG addresses independent of
    QEMU's runtime PIE load address.
    """
    import capstone as cs  # type: ignore
    from elftools.elf.constants import SH_FLAGS  # type: ignore
    from elftools.elf.elffile import ELFFile  # type: ignore

    data = path.read_bytes()
    instructions: dict[int, Instruction] = {}
    functions: dict[str, Function] = {}
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.get_machine_arch() != "x64":
            raise ValueError(f"expected x86-64 ELF, got {elf.get_machine_arch()}")
        canonical_entry = canonical_bias + int(elf.header["e_entry"])
        position_independent = elf.header["e_type"] == "ET_DYN"
        executable_ranges = tuple(
            (
                canonical_bias + int(segment["p_vaddr"]),
                canonical_bias + int(segment["p_vaddr"]) + int(segment["p_memsz"]),
            )
            for segment in elf.iter_segments()
            if segment["p_type"] == "PT_LOAD" and int(segment["p_flags"]) & 1
        )
        if not executable_ranges:
            raise ValueError("x86-64 ELF has no executable PT_LOAD segment")
        canonical_start_code = min(start for start, _ in executable_ranges)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            raise ValueError("ELF has no symbol table")
        for symbol in symtab.iter_symbols():
            if (symbol["st_info"]["type"] == "STT_FUNC"
                    and symbol["st_shndx"] != "SHN_UNDEF"
                    and symbol["st_value"] and symbol["st_size"]):
                name = symbol.name
                start = canonical_bias + int(symbol["st_value"])
                if name in functions and functions[name].start != start:
                    name = f"{name}@{start:x}"
                functions[name] = Function(
                    name,
                    start,
                    start + int(symbol["st_size"]),
                )
        decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        decoder.detail = True
        for section in elf.iter_sections():
            if not (section["sh_flags"] & SH_FLAGS.SHF_EXECINSTR and section["sh_size"]):
                continue
            raw = section.data()
            base = canonical_bias + int(section["sh_addr"])
            decoded = list(decoder.disasm(raw, base))
            if sum(insn.size for insn in decoded) != len(raw):
                raise ValueError(f"failed to decode complete executable section {section.name}")
            for insn in decoded:
                kind, target = _classify_x86_64(insn)
                instructions[insn.address] = Instruction(
                    insn.address,
                    insn.size,
                    kind,
                    target,
                    bytes(insn.bytes).hex(),
                )
        external_targets = _x86_64_plt_targets(elf, canonical_bias)
        external_dispatch_policy = _x86_64_external_dispatch_policy(
            elf, canonical_bias, external_targets
        )
        resolved_external_targets: dict[int, ExternalTarget] = {}
        for address, target in external_targets.items():
            gateway = sorted(
                (
                    instruction
                    for instruction in instructions.values()
                    if address <= instruction.address < target.gateway_end
                ),
                key=lambda instruction: instruction.address,
            )
            terminals = [
                instruction for instruction in gateway if instruction.kind == "indirect_jump"
            ]
            if len(terminals) != 1:
                raise ValueError(
                    f"PLT gateway {address:#x} does not have one indirect-jump terminal"
                )
            terminal = terminals[0]
            prefix = [instruction for instruction in gateway if instruction.address <= terminal.address]
            if (
                not prefix
                or prefix[0].address != address
                or any(
                    left.fallthrough != right.address
                    for left, right in zip(prefix, prefix[1:])
                )
            ):
                raise ValueError(f"PLT gateway {address:#x} is not a linear instruction prefix")
            resolved_external_targets[address] = replace(
                target, gateway_end=terminal.fallthrough
            )
        external_targets = resolved_external_targets
    return Program(
        hashlib.sha256(data).hexdigest(),
        instructions,
        functions,
        architecture="x86_64",
        canonical_entry=canonical_entry,
        canonical_start_code=canonical_start_code,
        executable_ranges=executable_ranges,
        position_independent=position_independent,
        external_targets=external_targets,
        external_dispatch_policy=external_dispatch_policy,
    )


def apply_indirect_policy(program: Program, path: Path, application: str) -> Program:
    """Bind an independently authored indirect-target policy to one exact ELF."""
    raw = path.read_bytes()
    payload = json.loads(raw)
    if (
        not isinstance(payload, dict)
        or set(payload) != {
            "schema", "application", "elf_sha256", "indirect_calls", "indirect_jumps"
        }
        or payload.get("schema") != "zkcfa.indirect-target-policy"
    ):
        raise ValueError("unsupported indirect-target policy")
    if payload.get("application") != application:
        raise ValueError("indirect-target policy is for a different application")
    if payload.get("elf_sha256") != program.elf_sha256:
        raise ValueError("indirect-target policy is for a different ELF")

    def parse_table(field: str, kind: str) -> dict[int, tuple[int, ...]]:
        table = payload.get(field)
        if not isinstance(table, dict):
            raise ValueError(f"indirect-target policy has no {field} object")
        result: dict[int, tuple[int, ...]] = {}
        for site_text, raw_targets in table.items():
            if not isinstance(site_text, str) or not isinstance(raw_targets, list):
                raise ValueError(f"malformed {field} entry")
            site = int(site_text, 0)
            instruction = program.instructions.get(site)
            if instruction is None or instruction.kind != kind:
                raise ValueError(f"{field} site {site:#x} is not an ELF {kind}")
            targets = tuple(int(target, 0) for target in raw_targets)
            if len(targets) != len(set(targets)):
                raise ValueError(f"{field} site {site:#x} has duplicate targets")
            result[site] = targets
        return result

    calls = parse_table("indirect_calls", "indirect_call")
    jumps = parse_table("indirect_jumps", "indirect_jump")
    return replace(
        program,
        indirect_call_targets=calls,
        indirect_jump_targets=jumps,
        indirect_policy_sha256=hashlib.sha256(raw).hexdigest(),
    )


def apply_runtime_dependencies(
    program: Program, path: Path, expected_profile: str
) -> Program:
    """Verify and bind the eager-binding sysroot used outside the CFA scope."""
    from .runtime_dependencies import FILES

    if not path.is_file() or path.is_symlink():
        raise ValueError("runtime-dependency manifest is absent or symlinked")
    raw = path.read_bytes()
    payload = json.loads(raw)
    if expected_profile == "freestanding-static":
        expected = {
            "schema": "zkcfa.runtime-dependencies",
            "runtime_profile": "freestanding-static",
            "binding": "none",
            "environment": {},
            "files": [],
            "loader_scope": "none",
        }
        if payload != expected or program.architecture != "aarch64":
            raise ValueError("unsupported freestanding runtime-dependency manifest")
        return replace(
            program,
            runtime_dependencies=payload,
            runtime_dependencies_sha256=hashlib.sha256(raw).hexdigest(),
        )
    if (
        not isinstance(payload, dict)
        or set(payload) != {
            "schema",
            "runtime_profile",
            "binding",
            "environment",
            "files",
            "loader_scope",
        }
        or payload.get("schema") != "zkcfa.runtime-dependencies"
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", expected_profile) is None
        or payload.get("runtime_profile") != expected_profile
        or payload.get("binding") != "eager"
        or payload.get("environment") != {"LD_BIND_NOW": "1"}
        or payload.get("loader_scope") != "trusted-out-of-scope"
        or not isinstance(payload.get("files"), list)
        or [
            item.get("path") if isinstance(item, dict) else None
            for item in payload.get("files", [])
        ]
        != list(FILES)
    ):
        raise ValueError("unsupported runtime-dependency manifest")
    for item in payload["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise ValueError("malformed runtime-dependency entry")
        relative, expected = item["path"], item["sha256"]
        if (
            not isinstance(relative, str)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or not isinstance(expected, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected)
        ):
            raise ValueError("unsafe runtime-dependency entry")
        dependency = path.parent / relative
        if not dependency.is_file() or dependency.is_symlink():
            raise ValueError(f"runtime dependency is absent or symlinked: {relative}")
        if hashlib.sha256(dependency.read_bytes()).hexdigest() != expected:
            raise ValueError(f"runtime dependency measurement mismatch: {relative}")
    return replace(
        program,
        runtime_dependencies=payload,
        runtime_dependencies_sha256=hashlib.sha256(raw).hexdigest(),
    )


def render_artifacts(
    program: Program,
    result: Provisioned,
    out_dir: Path,
    *,
    application: str = "crc32",
) -> None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", application):
        raise ValueError("application must be a lowercase stable identifier")
    if result.external_calls and program.runtime_dependencies is None:
        raise ValueError("external-call policy requires measured eager-binding runtime dependencies")
    if result.external_calls and program.external_dispatch_policy is None:
        raise ValueError("external-call policy requires NOW/RELRO dispatch validation")
    out_dir.mkdir(parents=True, exist_ok=True)
    translator = "".join(f"{_hex(address)}\n" for address in result.leaders)
    typed_cfg = "".join(
        f"{_hex(source)} {edge_type} {_hex(destination)}\n"
        for source, edge_type, destination in result.edges
    )
    (out_dir / "translator").write_text(translator)
    (out_dir / "typed_cfg").write_text(typed_cfg)
    trace_schema = TRACE_SCHEMA

    lines = [
        MAP_MAGIC,
        f"trace_schema {trace_schema}",
        f"elf_sha256 {program.elf_sha256}",
        f"architecture {program.architecture}",
        f"canonical_entry {program.canonical_entry:#x}",
        f"canonical_start_code {program.canonical_start_code:#x}",
        f"position_independent {int(program.position_independent)}",
        f"boundary_mode {'external_entry' if result.scope_call == SCOPE_ADDRESS else 'direct_call'}",
        f"sentinel {_hex(SCOPE_ADDRESS)} {SCOPE_ADDRESS:#x}",
        f"scope_call {result.scope_call:#x}",
        f"root_entry {result.root_entry:#x}",
        f"scope_return {result.scope_return:#x}",
    ]
    lines.extend(f"exec_range {start:#x} {end:#x}" for start, end in program.executable_ranges)
    lines.extend(f"root_ret {address:#x}" for address in result.root_returns)
    lines.extend(
        "external_call "
        f"{call.call_site:#x} {call.target:#x} {call.synthetic:#x} "
        f"{call.return_site:#x} {call.gateway_end:#x} {call.symbol}"
        for call in result.external_calls
    )
    lines.extend(
        "indirect_call " + f"{site:#x} " + " ".join(f"{target:#x}" for target in targets)
        for site, targets in sorted(program.indirect_call_targets.items())
    )
    lines.extend(
        "indirect_jump " + f"{site:#x} " + " ".join(f"{target:#x}" for target in targets)
        for site, targets in sorted(program.indirect_jump_targets.items())
    )
    gateway_blocks = {
        address: call.synthetic
        for call in result.external_calls
        for address in program.instructions
        if call.target <= address < call.gateway_end
    }
    for call in result.external_calls:
        if call.target not in gateway_blocks:
            raise ValueError(f"external gateway {call.target:#x} has no decoded instruction")
        gateway_instructions = sorted(
            address for address in gateway_blocks if call.target <= address < call.gateway_end
        )
        if not gateway_instructions or (
            program.instructions[gateway_instructions[-1]].fallthrough != call.gateway_end
        ) or program.instructions[gateway_instructions[-1]].kind != "indirect_jump":
            raise ValueError(f"external gateway {call.target:#x} is not completely decoded")
    mapped_addresses = sorted({*result.instruction_blocks, *gateway_blocks})
    if result.scope_call != SCOPE_ADDRESS:
        mapped_addresses.append(result.scope_call)
        mapped_addresses.sort()
    for address in mapped_addresses:
        insn = program.instructions[address]
        try:
            encoding = bytes.fromhex(insn.encoding)
        except ValueError as error:
            raise ValueError(f"invalid instruction encoding at {address:#x}") from error
        if len(encoding) != insn.size or encoding.hex() != insn.encoding.lower():
            raise ValueError(
                f"instruction encoding is not canonical or differs from size at {address:#x}"
            )
        target = insn.target or 0
        block = result.instruction_blocks.get(address, gateway_blocks.get(address, address))
        lines.append(
            f"insn {address:#x} {insn.size} {block:#x} "
            f"{insn.kind} {target:#x} {insn.encoding.lower()}"
        )
    plugin_map = "\n".join(lines) + "\n"
    (out_dir / "plugin-map.txt").write_text(plugin_map)

    root_exit_blocks = sorted({
        result.instruction_blocks[address] for address in result.root_returns
    })
    dynamic_runtime = (
        isinstance(program.runtime_dependencies, dict)
        and program.runtime_dependencies.get("runtime_profile") != "freestanding-static"
    )
    manifest = {
        "schema": SCHEMA,
        "application": application,
        "elf_sha256": program.elf_sha256,
        "architecture": program.architecture,
        "canonical_entry": f"{program.canonical_entry:#x}",
        "canonical_start_code": f"{program.canonical_start_code:#x}",
        "primary_elf_executable_ranges": [
            {"start": f"{start:#x}", "end": f"{end:#x}"}
            for start, end in program.executable_ranges
        ],
        "position_independent": program.position_independent,
        "canonical_address_model": (
            "pie-load-bias" if program.position_independent else "elf-virtual-address"
        ),
        "proof_path_compression": "none",
        "runtime_profile": (
            program.runtime_dependencies.get("runtime_profile")
            if program.runtime_dependencies is not None
            else None
        ),
        "runtime_dependencies_sha256": program.runtime_dependencies_sha256,
        "external_call_policy": {
            "schema": "zkcfa.external-call-policy",
            "mode": "plt-exact-return" if result.external_calls else "none",
            "binding": "eager" if dynamic_runtime else "none",
            "loader_scope": "trusted-out-of-scope" if dynamic_runtime else "none",
            "thread_model": "single",
            "dispatch_integrity": program.external_dispatch_policy,
            "runtime_dependencies": program.runtime_dependencies,
            "calls": [
                {
                    "call_site": f"{call.call_site:#x}",
                    "plt_target": f"{call.target:#x}",
                    "symbol": call.symbol,
                    "synthetic_node": f"{call.synthetic:#x}",
                    "return_site": f"{call.return_site:#x}",
                    "gateway_end": f"{call.gateway_end:#x}",
                }
                for call in result.external_calls
            ],
        },
        "indirect_target_policy": {
            "schema": "zkcfa.indirect-target-policy",
            "policy_sha256": program.indirect_policy_sha256,
            "calls": {
                f"{site:#x}": [f"{target:#x}" for target in targets]
                for site, targets in sorted(program.indirect_call_targets.items())
            },
            "jumps": {
                f"{site:#x}": [f"{target:#x}" for target in targets]
                for site, targets in sorted(program.indirect_jump_targets.items())
            },
        },
        "trace_schema": trace_schema,
        "root_entry": f"{result.root_entry:#x}",
        "scope_return": f"{result.scope_return:#x}",
        "sentinel": SCOPE_TOKEN,
        "root_returns": [f"{address:#x}" for address in result.root_returns],
        "scope_policy": {
            "schema": "zkcfa.static.scope",
            "root_symbol": result.root_symbol,
            "caller_symbol": result.caller_symbol,
            "scope_call_address": _hex(result.scope_call),
            "root_address": f"{result.root_entry:#x}",
            "root_exit_blocks": [f"{address:#x}" for address in root_exit_blocks],
            "scope_return_address": _hex(result.scope_return),
            "sentinel": SCOPE_TOKEN,
            "sentinel_address": f"{SCOPE_ADDRESS:#x}",
            "require_complete_entry_exit": True,
            "external_entry": result.scope_call == SCOPE_ADDRESS,
            "boundary_kind": (
                "external-root-entry-and-captured-return"
                if result.scope_call == SCOPE_ADDRESS
                else "in-binary-direct-call-and-root-ret"
            ),
        },
        "included_functions": list(result.included_functions),
        "nodes": len(result.leaders),
        "typed_edges": len(result.edges),
        "translator_sha256": hashlib.sha256(translator.encode()).hexdigest(),
        "typed_cfg_sha256": hashlib.sha256(typed_cfg.encode()).hexdigest(),
        "plugin_map_sha256": hashlib.sha256(plugin_map.encode()).hexdigest(),
    }
    (out_dir / "static-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--root-symbol", default="crc32_scope")
    parser.add_argument("--caller-symbol", default="_start")
    parser.add_argument("--architecture", choices=("aarch64", "x86_64"), default="aarch64")
    parser.add_argument("--external-entry", action="store_true")
    parser.add_argument("--canonical-bias", type=lambda value: int(value, 0), default=0x400000)
    parser.add_argument("--application", default="crc32")
    parser.add_argument("--indirect-policy", type=Path)
    parser.add_argument("--max-out-degree", type=int, default=4)
    parser.add_argument("--runtime-dependencies", type=Path)
    parser.add_argument("--runtime-profile")
    args = parser.parse_args(argv)
    if (args.runtime_dependencies is None) != (args.runtime_profile is None):
        raise ValueError(
            "--runtime-dependencies and --runtime-profile must be supplied together"
        )
    if args.architecture == "aarch64":
        program = load_aarch64_elf(args.elf)
    else:
        program = load_x86_64_elf(args.elf, canonical_bias=args.canonical_bias)
    if args.indirect_policy is not None:
        program = apply_indirect_policy(program, args.indirect_policy, args.application)
    if args.runtime_dependencies is not None:
        assert args.runtime_profile is not None
        program = apply_runtime_dependencies(
            program, args.runtime_dependencies, args.runtime_profile
        )
    result = provision_program(
        program,
        ScopePolicy(
            root_symbol=args.root_symbol,
            caller_symbol=args.caller_symbol,
            external_entry=args.external_entry,
            max_out_degree=args.max_out_degree,
        ),
    )
    render_artifacts(program, result, args.out_dir, application=args.application)
    print(
        f"static provider: nodes={len(result.leaders)} edges={len(result.edges)} "
        f"root={result.root_entry:#x} scope_return={result.scope_return:#x}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
