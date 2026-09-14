"""Canonical raw24 / raw64 Binius64 statement serializers.

raw24 retains the original packed-word encoding. raw64-typed-channels uses
three u64 words per CFG edge and EP row, without truncating addresses. Distinct
commitment domains and signed circuit profiles prevent cross-profile reuse.
All SHA-256 preimages are arrays of big-endian u64 words.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .common import canonical_json


RAW24_PROFILE = "raw24-full-key"
RAW64_PROFILE = "raw64-typed-channels"
RAW_PROFILES = (RAW24_PROFILE, RAW64_PROFILE)
RAW_ADDR_BITS = 24
RAW_ADDR_LIMIT = 1 << RAW_ADDR_BITS
RAW_NUMERIC_LIMIT = RAW_ADDR_LIMIT - 0x1_0000  # 0xff0000
RAW_GATEWAY_BASE = RAW_NUMERIC_LIMIT
RAW_SCOPE_SENTINEL = RAW_ADDR_LIMIT - 1
PROVIDER_GATEWAY_BASE = 0xFFFE_0000
PROVIDER_GATEWAY_LIMIT = PROVIDER_GATEWAY_BASE + 0xFFFF

MAGIC_WIDE_CFG = int.from_bytes(b"CFG-W64V", "big")
MAGIC_WIDE_EP = int.from_bytes(b"EP-W64V1", "big")

MAGIC_RAW_CFG = 0x4346_472D_464C_4154  # CFG-FLAT
MAGIC_RAW_EP_INLINE = 0x4550_494E_4C49_4E45  # EPINLINE
MAGIC_RAW_EP_SHARED = 0x4550_5348_4152_4544  # EPSHARED
PATH_MODE_WORDS = {
    "complete": 0x434F_4D50_4C45_5445,  # COMPLETE
    "shadow": 0x5348_4144_4F57_4544,  # SHADOWED
}
PAD_KEY = 1 << 63

EDGE_TYPES = {"jmp": 0, "cal": 1, "ret": 2, "crt": 3}
# Tag 3 records an unexpected instruction-sequence discontinuity. It is a
# capture-only marker: valid proof rows use only JUMP, CALL, and RET.
STEP_TAGS = {"jump": 0, "call": 1, "ret": 2, "discontinuity": 3}
HEX_ADDRESS = re.compile(r"0x[0-9a-f]+")

RAW_CONFIG_SCHEMA = "zkcfa.raw.circuit"
RAW_CONFIG_DOMAIN = b"ZKCFA/raw/circuit/id\x00"
RAW_REGISTRY_SCHEMA = "zkcfa.raw.registry"
RAW_REGISTRY_ID_DOMAIN = b"ZKCFA/raw/registry/id\x00"
INLINE_EP_CAP = 1 << 14
INLINE_MULTIPLICITY_BITS = 12


@dataclass(frozen=True)
class RawParams:
    edge_cap: int
    ep_cap: int
    path_mode: str = "complete"
    log_inv_rate: int = 1
    profile: str = RAW24_PROFILE

    @property
    def is_wide(self) -> bool:
        return self.profile == RAW64_PROFILE

    @property
    def addr_bits(self) -> int:
        return 64 if self.is_wide else RAW_ADDR_BITS

    @property
    def addr_limit(self) -> int:
        return 1 << self.addr_bits

    @property
    def scope_sentinel(self) -> int:
        return self.addr_limit - 1

    @property
    def uses_shared_ep(self) -> bool:
        return self.ep_cap > INLINE_EP_CAP

    @property
    def ep_encoding(self) -> str:
        if self.is_wide:
            return "wide64"
        return "shared24" if self.uses_shared_ep else "inline14"

    @property
    def ep_magic(self) -> int:
        if self.is_wide:
            return MAGIC_WIDE_EP
        return MAGIC_RAW_EP_SHARED if self.uses_shared_ep else MAGIC_RAW_EP_INLINE

    @property
    def multiplicity_bits(self) -> int:
        return (
            (2 * (self.ep_cap - 1)).bit_length()
            if self.uses_shared_ep
            else INLINE_MULTIPLICITY_BITS
        )

    def validate(self) -> None:
        if self.profile not in RAW_PROFILES:
            raise ValueError("unsupported raw circuit profile")
        for field, value, minimum in (
            ("edge_cap", self.edge_cap, 8),
            ("ep_cap", self.ep_cap, 16),
        ):
            if type(value) is not int or value < minimum or value & (value - 1):
                raise ValueError(f"{field} must be a power of two >= {minimum}")
        if self.ep_cap > 1 << 24:
            raise ValueError("ep_cap exceeds the 24-bit long-trace hint domain")
        if not self.uses_shared_ep:
            # Binius64 emits two membership queries for every EP transition,
            # including padded transitions. Each of the ``edge_cap`` table
            # entries has one unsigned fixed-width multiplicity. If their
            # aggregate range cannot hold all queries, every possible witness
            # over this capacity pair must overflow at least one entry.
            query_count = 2 * (self.ep_cap - 1)
            max_count_per_entry = (1 << INLINE_MULTIPLICITY_BITS) - 1
            aggregate_capacity = self.edge_cap * max_count_per_entry
            if query_count > aggregate_capacity:
                raise ValueError(
                    "inline14 capacity pair is infeasible: "
                    f"{query_count} BinMult queries exceed the "
                    f"{aggregate_capacity} counts representable by "
                    f"edge_cap={self.edge_cap} with "
                    f"{INLINE_MULTIPLICITY_BITS}-bit multiplicities"
                )
        if self.path_mode not in PATH_MODE_WORDS:
            raise ValueError("signed raw path_mode must be complete or shadow")
        if type(self.log_inv_rate) is not int or not 1 <= self.log_inv_rate <= 16:
            raise ValueError("log_inv_rate must be an integer in 1..=16")


@dataclass(frozen=True)
class RawBlind:
    low: int
    high: int

    @property
    def value(self) -> int:
        return self.low | (self.high << 64)

    def validate(self, name: str) -> None:
        if any(type(word) is not int or word < 0 or word >= 1 << 64 for word in (self.low, self.high)):
            raise ValueError(f"{name} words must be canonical u64 values")
        if self.value == 0:
            raise ValueError(f"{name} must be nonzero")


def random_blind(*, excluding: Iterable[int] = ()) -> RawBlind:
    excluded = set(excluding)
    while True:
        raw = secrets.token_bytes(16)
        candidate = RawBlind(
            int.from_bytes(raw[:8], "big"),
            int.from_bytes(raw[8:], "big"),
        )
        if candidate.value and candidate.value not in excluded:
            return candidate


@dataclass(frozen=True, order=True)
class RawEdge:
    key: int
    src: int
    kind: str
    dst: int


@dataclass
class RawStep:
    dst: int
    tag: int
    auxiliary: int = 0
    hint: int = 0


@dataclass
class RawStatement:
    nodes: set[int]
    edges: list[RawEdge]
    steps: list[RawStep]
    params: RawParams
    cfg_blind: RawBlind
    ep_blind: RawBlind

    @property
    def entry_raw(self) -> int:
        return self.steps[0].dst

    @property
    def final_raw(self) -> int:
        return self.steps[-1].dst

    @property
    def h_cfg_raw24(self) -> str:
        return digest_words(self.cfg_words())

    @property
    def h_ep_raw24(self) -> str:
        return digest_words(self.ep_words())

    def cfg_words(self) -> list[int]:
        if len(self.edges) > self.params.edge_cap:
            raise ValueError("typed CFG exceeds edge_cap")
        return _cfg_words(self.edges, self.params, self.cfg_blind)

    def ep_words(self) -> list[int]:
        if len(self.steps) > self.params.ep_cap:
            raise ValueError("recorded path exceeds ep_cap")
        stride = 3 if self.params.is_wide else 1
        words = [0] * (10 + stride * self.params.ep_cap)
        words[0] = self.params.ep_magic
        words[1] = self.params.ep_cap
        words[2] = len(self.steps)
        words[3] = self.params.addr_bits
        words[4] = self.ep_blind.low
        words[5] = self.ep_blind.high
        words[6] = 24 if self.params.is_wide or self.params.uses_shared_ep else 0
        words[7] = PATH_MODE_WORDS[self.params.path_mode]
        for row, step in enumerate(self.steps):
            encoded = encode_step(step, self.params)
            if self.params.is_wide:
                words[10 + 3 * row:13 + 3 * row] = encoded
            else:
                words[10 + row] = encoded
        return words


@dataclass
class RawCfgStatement:
    """Trace-independent raw CFG commitment selected by the authority."""

    nodes: set[int]
    edges: list[RawEdge]
    params: RawParams
    cfg_blind: RawBlind

    @property
    def h_cfg_raw24(self) -> str:
        return digest_words(_cfg_words(self.edges, self.params, self.cfg_blind))


def _cfg_words(edges: list[RawEdge], params: RawParams, blind: RawBlind) -> list[int]:
    if len(edges) > params.edge_cap:
        raise ValueError("typed CFG exceeds edge_cap")
    words = [0] * 10
    words[0] = MAGIC_WIDE_CFG if params.is_wide else MAGIC_RAW_CFG
    words[1] = params.edge_cap
    words[2] = len(edges)
    words[3] = params.addr_bits
    words[8] = blind.low
    words[9] = blind.high
    if params.is_wide:
        for edge in edges:
            words.extend((edge.src, EDGE_TYPES[edge.kind], edge.dst))
        for slot in range(len(edges), params.edge_cap):
            words.extend((0, 0, slot + 1))
    else:
        words.extend(edge.key for edge in edges)
        words.extend(PAD_KEY | slot for slot in range(len(edges), params.edge_cap))
    return words


def fitted_capacity(value: int, minimum: int) -> int:
    if value <= 0:
        return minimum
    return max(minimum, 1 << (value - 1).bit_length())


def parse_raw_address(token: str, profile: str = RAW24_PROFILE) -> int:
    if profile not in RAW_PROFILES:
        raise ValueError("unsupported raw address profile")
    addr_limit = 1 << (64 if profile == RAW64_PROFILE else RAW_ADDR_BITS)
    numeric_limit = addr_limit - 0x1_0000
    token = token.strip()
    if token == "SCOPE_RETURN":
        return addr_limit - 1
    if not HEX_ADDRESS.fullmatch(token):
        raise ValueError(f"raw address is not canonical lowercase hexadecimal: {token!r}")
    value = int(token, 16)
    if PROVIDER_GATEWAY_BASE <= value < PROVIDER_GATEWAY_LIMIT:
        return numeric_limit + value - PROVIDER_GATEWAY_BASE
    if value == 0:
        raise ValueError("raw address zero is reserved for inactive rows")
    if value >= numeric_limit:
        width = 64 if profile == RAW64_PROFILE else RAW_ADDR_BITS
        raise ValueError(f"numeric address is outside raw{width} or collides with reserved tokens")
    return value


def raw_edge_key(src: int, kind: str, dst: int, profile: str = RAW24_PROFILE) -> int:
    if kind not in EDGE_TYPES:
        raise ValueError(f"unknown typed edge {kind!r}")
    if profile not in RAW_PROFILES:
        raise ValueError("unsupported raw edge profile")
    width = 64 if profile == RAW64_PROFILE else RAW_ADDR_BITS
    if not (0 < src < 1 << width and 0 < dst < 1 << width):
        raise ValueError("raw edge endpoint is outside the canonical namespace")
    # A lossless host-side key for sorting/counting, never serialized as one u64.
    return (src << (width + 2)) | (EDGE_TYPES[kind] << width) | dst


def encode_step(step: RawStep, params: RawParams) -> int | tuple[int, int, int]:
    if not (0 < step.dst < params.addr_limit):
        raise ValueError("raw step destination is outside the canonical namespace")
    if step.tag not in STEP_TAGS.values():
        raise ValueError("raw active step has an invalid tag")
    carries_address = step.tag in (STEP_TAGS["call"], STEP_TAGS["discontinuity"])
    if not carries_address and step.auxiliary != 0:
        raise ValueError("only CAL or a discontinuity may carry a raw auxiliary address")
    if step.tag != STEP_TAGS["ret"] and step.hint != 0:
        raise ValueError("only RET may carry a matching-CAL hint")
    if params.is_wide:
        if not 0 <= step.hint < 1 << 24:
            raise ValueError("wide EP hint exceeds 24 bits")
        if not 0 <= step.auxiliary < params.addr_limit:
            raise ValueError("wide EP auxiliary address exceeds 64 bits")
        if carries_address and step.auxiliary == 0:
            raise ValueError("wide EP auxiliary address must be nonzero")
        payload = step.auxiliary if carries_address else step.hint if step.tag == STEP_TAGS["ret"] else 0
        return step.tag, step.dst, payload
    if params.uses_shared_ep:
        payload = step.auxiliary if carries_address else step.hint if step.tag == STEP_TAGS["ret"] else 0
        if not 0 <= payload < 1 << 24:
            raise ValueError("shared EP payload exceeds 24 bits")
        return step.tag | (step.dst << 2) | (payload << 26)
    if not 0 <= step.hint < 1 << 14:
        raise ValueError("inline EP hint exceeds 14 bits")
    if not 0 <= step.auxiliary < RAW_ADDR_LIMIT:
        raise ValueError("inline EP auxiliary address exceeds 24 bits")
    return step.tag | (step.dst << 2) | (step.auxiliary << 26) | (step.hint << 50)


def _load_nodes(path: Path, profile: str = RAW24_PROFILE) -> set[int]:
    nodes: set[int] = set()
    for line_number, raw in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        fields = raw.split()
        if not fields:
            raise ValueError(f"translator line {line_number} must not be empty")
        if len(fields) != 1:
            raise ValueError(f"translator line {line_number} must contain one node")
        node = parse_raw_address(fields[0], profile)
        if node in nodes:
            raise ValueError(f"translator line {line_number} repeats a node")
        nodes.add(node)
    if not nodes:
        raise ValueError("translator is empty")
    return nodes


def _load_edges(path: Path, nodes: set[int], profile: str = RAW24_PROFILE) -> list[RawEdge]:
    edges: list[RawEdge] = []
    seen_keys: set[int] = set()
    seen_pairs: set[tuple[int, int]] = set()
    for line_number, raw in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        fields = raw.split()
        if len(fields) != 3 or fields[1] not in EDGE_TYPES:
            raise ValueError(f"typed_cfg line {line_number} must be src <jmp|cal|ret|crt> dst")
        if fields[1] == "ret":
            raise ValueError(
                f"typed_cfg line {line_number} contains RET; the flat CFG uses CRT plus the shadow stack"
            )
        src, dst = parse_raw_address(fields[0], profile), parse_raw_address(fields[2], profile)
        if src not in nodes or dst not in nodes:
            raise ValueError(f"typed_cfg line {line_number} references a node outside translator")
        if (src, dst) in seen_pairs:
            raise ValueError(f"typed_cfg line {line_number} aliases an existing endpoint pair")
        seen_pairs.add((src, dst))
        key = raw_edge_key(src, fields[1], dst, profile)
        if key in seen_keys:
            raise ValueError(f"typed_cfg line {line_number} repeats a full edge key")
        seen_keys.add(key)
        edges.append(RawEdge(key, src, fields[1], dst))
    if not edges:
        raise ValueError("typed_cfg is empty")
    edges.sort()
    return edges


def _load_steps(path: Path, profile: str = RAW24_PROFILE) -> list[RawStep]:
    """Parse recorded transfers and annotate observed stack events without judging them.

    A return consumes the latest observed call, even when its actual destination
    differs from that call's continuation. Underflow uses row zero as a canonical
    hint; row zero is the initial JUMP record, so it cannot certify a valid return.
    These hints describe the event sequence, not a device-side compliance result.
    """
    lines = path.read_text(encoding="ascii").splitlines()
    if not lines:
        raise ValueError("recorded_path is empty")
    header = lines[0].split()
    if len(header) != 2:
        raise ValueError("recorded_path header must contain exactly two fields")
    values: dict[str, int] = {}
    for field in header:
        name, separator, value = field.partition("=")
        if not separator or name not in {"initial_node", "final_node"} or name in values:
            raise ValueError("recorded_path has a malformed or duplicate header field")
        values[name] = parse_raw_address(value, profile)
    if set(values) != {"initial_node", "final_node"}:
        raise ValueError("recorded_path header is incomplete")
    steps = [RawStep(values["initial_node"], STEP_TAGS["jump"])]
    for line_number, raw in enumerate(lines[1:], 2):
        fields = raw.split()
        if len(fields) == 3 and fields[0] in {"call", "discontinuity"}:
            step = RawStep(
                parse_raw_address(fields[1], profile),
                STEP_TAGS[fields[0]],
                parse_raw_address(fields[2], profile),
            )
        elif len(fields) == 2 and fields[0] in {"jump", "ret"}:
            step = RawStep(parse_raw_address(fields[1], profile), STEP_TAGS[fields[0]])
        else:
            raise ValueError(f"recorded_path line {line_number} is malformed")
        steps.append(step)
    if steps[-1].dst != values["final_node"]:
        raise ValueError("recorded_path final row disagrees with final_node")
    stack: list[int] = []
    for row, step in enumerate(steps):
        if step.tag == STEP_TAGS["call"]:
            stack.append(row)
        elif step.tag == STEP_TAGS["ret"]:
            step.hint = stack.pop() if stack else 0
    return steps


def _validate_multiplicity_preflight(
    edges: list[RawEdge], steps: list[RawStep], params: RawParams
) -> None:
    """Mirror the Binius64 BinMult host preflight on the worker.

    Every configured EP transition contributes two membership queries, including
    inactive padding rows.  ``RawParams.validate`` can reject a capacity pair
    whose aggregate range is necessarily too small, but only the concrete path
    determines whether one fixed-width table entry overflows.
    """

    if params.uses_shared_ep:
        # The shared24 width is derived from the total query count, so no single
        # entry can exceed it.
        return

    table = [edge.key for edge in edges]
    table.extend(
        slot + 1 if params.is_wide else PAD_KEY | slot
        for slot in range(len(edges), params.edge_cap)
    )
    first = {key: index for index, key in enumerate(table)}
    counts = [0] * len(table)
    limit = 1 << params.multiplicity_bits

    def add_query(key: int) -> None:
        try:
            index = first[key]
        except KeyError as error:
            raise ValueError(
                f"raw membership query {key:#x} is absent from the typed CFG table"
            ) from error
        counts[index] += 1
        if counts[index] >= limit:
            raise ValueError(
                f"raw CFG entry {index} is reused {counts[index]} times, "
                f"exceeding inline14 multiplicity limit {limit - 1}"
            )

    for row in range(1, params.ep_cap):
        neutral0 = table[(2 * (row - 1)) % len(table)]
        neutral1 = table[(2 * (row - 1) + 1) % len(table)]
        if row < len(steps):
            previous, step = steps[row - 1], steps[row]
            add_query(
                neutral0
                if step.tag == STEP_TAGS["ret"]
                else raw_edge_key(
                    previous.dst,
                    "cal" if step.tag == STEP_TAGS["call"] else "jmp",
                    step.dst,
                    params.profile,
                )
            )
            add_query(
                raw_edge_key(previous.dst, "crt", step.auxiliary, params.profile)
                if step.tag == STEP_TAGS["call"]
                else neutral1
            )
        else:
            add_query(neutral0)
            add_query(neutral1)


def load_raw_evidence(
    bundle: Path,
    *,
    cfg_blind: RawBlind,
    ep_blind: RawBlind,
    edge_cap: int | None = None,
    ep_cap: int | None = None,
    path_mode: str = "complete",
    log_inv_rate: int = 1,
    profile: str = RAW24_PROFILE,
) -> RawStatement:
    """Load commitment evidence without checking execution compliance.

    The device authenticates the actual typed transfers, including off-CFG
    destinations and unmatched returns. Only the artifact format, raw-address
    encoding, configured capacity, and commitment blinding are checked here.
    Worker preflight and the proof relation determine control-flow validity.
    """
    cfg_blind.validate("r_cfg")
    ep_blind.validate("r_ep")
    if cfg_blind.value == ep_blind.value:
        raise ValueError("r_cfg and r_ep must be independently sampled")
    nodes = _load_nodes(bundle / "translator", profile)
    edges = _load_edges(bundle / "typed_cfg", nodes, profile)
    steps = _load_steps(bundle / "recorded_path", profile)
    params = RawParams(
        edge_cap=edge_cap if edge_cap is not None else fitted_capacity(len(edges), 8),
        ep_cap=ep_cap if ep_cap is not None else fitted_capacity(len(steps), 16),
        path_mode=path_mode,
        log_inv_rate=log_inv_rate,
        profile=profile,
    )
    params.validate()
    if len(edges) > params.edge_cap or len(steps) > params.ep_cap:
        raise ValueError("raw statement exceeds its configured capacity")
    for step in steps:
        encode_step(step, params)
    return RawStatement(nodes, edges, steps, params, cfg_blind, ep_blind)


def validate_raw_statement(statement: RawStatement) -> None:
    """Perform optional worker-side compliance and witness-feasibility preflight.

    This check must never gate device evidence signing. It gives honest workers
    useful errors; the proof circuit independently enforces the same relation.
    """

    edges, steps, params = statement.edges, statement.steps, statement.params
    available = {edge.key for edge in edges}
    stack: list[int] = []
    for row in range(1, len(steps)):
        previous, step = steps[row - 1], steps[row]
        if step.tag == STEP_TAGS["discontinuity"]:
            raise ValueError(f"recorded_path row {row} records an instruction discontinuity")
        if step.tag != STEP_TAGS["ret"]:
            kind = "cal" if step.tag == STEP_TAGS["call"] else "jmp"
            if raw_edge_key(previous.dst, kind, step.dst, params.profile) not in available:
                raise ValueError(f"recorded_path row {row} has no typed forward edge")
        if step.tag == STEP_TAGS["call"] and raw_edge_key(previous.dst, "crt", step.auxiliary, params.profile) not in available:
            raise ValueError(f"recorded_path row {row} has no typed CRT declaration")
        if step.tag == STEP_TAGS["call"]:
            stack.append(row)
        elif step.tag == STEP_TAGS["ret"]:
            if not stack:
                raise ValueError(f"recorded_path row {row} returns on an empty stack")
            call_row = stack.pop()
            if steps[call_row].auxiliary != step.dst:
                raise ValueError(f"recorded_path row {row} returns to the wrong call site")
            if step.hint != call_row:
                raise ValueError(f"recorded_path row {row} has the wrong matching-CAL hint")
    if stack:
        raise ValueError(f"recorded_path leaves {len(stack)} unmatched calls")
    _validate_multiplicity_preflight(edges, steps, params)


def load_raw_statement(
    bundle: Path,
    *,
    cfg_blind: RawBlind,
    ep_blind: RawBlind,
    edge_cap: int | None = None,
    ep_cap: int | None = None,
    path_mode: str = "complete",
    log_inv_rate: int = 1,
    profile: str = RAW24_PROFILE,
) -> RawStatement:
    """Load evidence and run strict worker-side proof preflight."""

    statement = load_raw_evidence(
        bundle,
        cfg_blind=cfg_blind,
        ep_blind=ep_blind,
        edge_cap=edge_cap,
        ep_cap=ep_cap,
        path_mode=path_mode,
        log_inv_rate=log_inv_rate,
        profile=profile,
    )
    validate_raw_statement(statement)
    return statement


def load_raw_cfg(
    bundle: Path,
    *,
    cfg_blind: RawBlind,
    ep_cap: int,
    edge_cap: int | None = None,
    path_mode: str = "complete",
    log_inv_rate: int = 1,
    profile: str = RAW24_PROFILE,
) -> RawCfgStatement:
    """Load only the pre-execution translator namespace and typed CFG.

    ``ep_cap`` is an authority policy capacity. This function never reads
    ``recorded_path``; the device later rejects an execution that exceeds it.
    """

    cfg_blind.validate("r_cfg")
    nodes = _load_nodes(bundle / "translator", profile)
    edges = _load_edges(bundle / "typed_cfg", nodes, profile)
    params = RawParams(
        edge_cap=edge_cap if edge_cap is not None else fitted_capacity(len(edges), 8),
        ep_cap=ep_cap,
        path_mode=path_mode,
        log_inv_rate=log_inv_rate,
        profile=profile,
    )
    params.validate()
    if len(edges) > params.edge_cap:
        raise ValueError("typed CFG exceeds edge_cap")
    return RawCfgStatement(nodes, edges, params, cfg_blind)


def fitted_raw_params(
    bundle: Path, *, path_mode: str = "complete", log_inv_rate: int = 1,
    profile: str = RAW24_PROFILE,
) -> RawParams:
    """Return the deterministic capacity policy used only by evaluation runners."""

    nodes = _load_nodes(bundle / "translator", profile)
    edges = _load_edges(bundle / "typed_cfg", nodes, profile)
    steps = _load_steps(bundle / "recorded_path", profile)
    params = RawParams(
        edge_cap=fitted_capacity(len(edges), 8),
        ep_cap=fitted_capacity(len(steps), 16),
        path_mode=path_mode,
        log_inv_rate=log_inv_rate,
        profile=profile,
    )
    params.validate()
    return params


def digest_words(words: Iterable[int]) -> str:
    digest = hashlib.sha256()
    for word in words:
        if not isinstance(word, int) or word < 0 or word >= 1 << 64:
            raise ValueError("commitment word is outside u64")
        digest.update(word.to_bytes(8, "big"))
    return digest.hexdigest()


def circuit_object(params: RawParams) -> dict[str, object]:
    params.validate()
    return {
        "schema": RAW_CONFIG_SCHEMA,
        "profile": params.profile,
        "backend": "binius64",
        "log_inv_rate": params.log_inv_rate,
        "path_mode": params.path_mode,
        "edge_cap": params.edge_cap,
        "ep_cap": params.ep_cap,
    }


def raw_config_id(circuit: dict[str, object]) -> str:
    if circuit.get("schema") != RAW_CONFIG_SCHEMA:
        raise ValueError("unsupported raw circuit config schema")
    return hashlib.sha256(RAW_CONFIG_DOMAIN + canonical_json(circuit)).hexdigest()


def raw_registry_id(payload_without_id: dict[str, object]) -> str:
    if payload_without_id.get("schema") != RAW_REGISTRY_SCHEMA:
        raise ValueError("unsupported raw authority registry schema")
    return hashlib.sha256(
        RAW_REGISTRY_ID_DOMAIN + canonical_json(payload_without_id)
    ).hexdigest()
