#!/usr/bin/env python3
"""Freeze existing stack-safe inputs and convert their representation for ZEKRA.

This tool never compresses, retags, completes, or captures an execution path. The
three common files retain their source bytes. ZEKRA receives the same operations
and continuation metadata in its native, untyped representation. Its executable
adjacency is JMP/CAL plus returns derived from the static instruction map and CFG;
CRT declarations are not executable edges. This matches inputs, not the acceptance
sets of the two native proof relations. No compiler or prover is invoked.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Callable

APPLICATIONS = (
    "aha-mont64", "crc32", "cubic", "edn", "huffbench", "matmult-int", "md5sum",
    "minver", "nbody", "nettle-aes", "nettle-sha256", "nsichneu", "picojpeg",
    "primecount", "sglib-combined", "slre", "st", "statemate", "tarfind", "ud", "wikisort",
)
COMMON_FILES = ("translator", "typed_cfg", "recorded_path")
ZEKRA_FILES = ("translator", "adjlist", "numified_adjlist", "recorded_path", "numified_path")
SCOPE = 0xFFFFFF
GATEWAY_BASE = 0xFF0000
PROVIDER_GATEWAY_BASE = 0xFFFE0000
PROVIDER_GATEWAY_LIMIT = 0xFFFEFFFF
Operation = tuple[str, int, int | None]
Edge = tuple[int, str, int]


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def p2(value: int, minimum: int) -> int:
    return max(minimum, 1 << max(0, value - 1).bit_length())


def parse_provider_address(token: str) -> int:
    """Match raw.rs parse_raw_addr_token, including its injective reserved suffix."""
    if token == "SCOPE_RETURN":
        return SCOPE
    require(re.fullmatch(r"0x[0-9a-f]+", token) is not None,
            f"noncanonical provider address: {token}")
    value = int(token, 16)
    if PROVIDER_GATEWAY_BASE <= value < PROVIDER_GATEWAY_LIMIT:
        return GATEWAY_BASE + value - PROVIDER_GATEWAY_BASE
    require(0 < value < GATEWAY_BASE, f"provider address overlaps reserved namespace: {token}")
    return value


def parse_raw_address(token: str) -> int:
    require(re.fullmatch(r"0x[0-9a-f]+", token) is not None, f"invalid raw address: {token}")
    value = int(token, 16)
    require(0 < value <= SCOPE, f"raw address outside nonzero raw24: {token}")
    return value


def parse_path(text: str, address: Callable[[str], int] = parse_provider_address
               ) -> tuple[int, int, list[Operation]]:
    lines = [line.split() for line in text.splitlines() if line.strip()]
    require(bool(lines) and len(lines[0]) == 2, "missing two-field path header")
    first, last = lines[0]
    require(first.startswith("initial_node=") and last.startswith("final_node="),
            "invalid path endpoints")
    initial, final = address(first.split("=", 1)[1]), address(last.split("=", 1)[1])
    operations = []
    for index, fields in enumerate(lines[1:], 1):
        require(fields[0] in {"jump", "call", "ret"}, f"invalid path tag at row {index}")
        require(len(fields) == (3 if fields[0] == "call" else 2),
                f"invalid call/return metadata at row {index}")
        operations.append((fields[0], address(fields[1]),
                           address(fields[2]) if len(fields) == 3 else None))
    return initial, final, operations


def parse_typed_cfg(text: str, nodes: set[int]) -> set[Edge]:
    edges: set[Edge] = set()
    pairs: set[tuple[int, int]] = set()
    for index, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if not fields:
            continue
        require(len(fields) == 3 and fields[1] in {"jmp", "cal", "crt"},
                f"invalid typed CFG row {index}; static RET is not a source record")
        source, kind, destination = parse_provider_address(fields[0]), fields[1], parse_provider_address(fields[2])
        require(source in nodes and destination in nodes, f"unmapped typed CFG row {index}")
        require((source, destination) not in pairs, f"duplicate or type-aliased CFG row {index}")
        edges.add((source, kind, destination))
        pairs.add((source, destination))
    require(bool(edges), "empty typed CFG")
    return edges


def static_map_returns(text: str) -> dict:
    lines = [line.split() for line in text.splitlines() if line.strip()]
    require(bool(lines) and lines[0] == ["zkcfa.provider.map"], "invalid static plugin-map header")
    returns, external = set(), set()
    root, elf_hash = None, None
    for fields in lines[1:]:
        if fields[0] == "insn":
            require(len(fields) == 7, "malformed static instruction map record")
            if fields[4] == "ret":
                returns.add(parse_provider_address(fields[3]))
        elif fields[0] == "external_call":
            require(len(fields) == 7, "malformed external-call map record")
            token = fields[3]
            require(re.fullmatch(r"0x[0-9a-f]+", token) is not None,
                    "invalid external synthetic address")
            require(PROVIDER_GATEWAY_BASE <= int(token, 16) < PROVIDER_GATEWAY_LIMIT,
                    "external synthetic address outside provider gateway namespace")
            external.add(parse_provider_address(token))
        elif fields[0] == "root_entry":
            require(len(fields) == 2 and root is None, "duplicate/malformed static root entry")
            root = parse_provider_address(fields[1])
        elif fields[0] == "elf_sha256":
            require(len(fields) == 2 and elf_hash is None
                    and re.fullmatch(r"[0-9a-f]{64}", fields[1]) is not None,
                    "duplicate/malformed static ELF hash")
            elf_hash = fields[1]
    require(root is not None and elf_hash is not None, "static map lacks root or ELF measurement")
    return {"return_blocks": returns, "external_gateways": external,
            "root_entry": root, "elf_sha256": elf_hash}


def static_return_edges(nodes: set[int], typed: set[Edge], return_sources: set[int]
                        ) -> set[tuple[int, int]]:
    """Derive RET adjacency from static callee JMP/CRT reachability, never from EP."""
    jumps, calls, crts = defaultdict(set), defaultdict(set), defaultdict(set)
    for source, kind, destination in typed:
        {"jmp": jumps, "cal": calls, "crt": crts}[kind][source].add(destination)
    result = set()
    for source in return_sources & nodes:
        require(not jumps.get(source) and not calls.get(source),
                f"static RET source {source:#x} also has executable outgoing edges")
    for site, targets in list(calls.items()):
        require(len(crts[site]) == 1, f"call site {site:#x} needs exactly one static CRT")
        continuation = next(iter(crts[site]))
        for entry in sorted(targets):
            pending, visited, exits = [entry], set(), set()
            while pending:
                node = pending.pop()
                if node in visited:
                    continue
                visited.add(node)
                if node in return_sources:
                    exits.add(node)
                pending.extend(jumps[node])
                if calls[node]:
                    require(len(crts[node]) == 1, f"ambiguous nested CRT at {node:#x}")
                    pending.extend(crts[node])
                # A terminal node or orphan CRT is not evidence of a RET instruction.
            require(bool(exits), f"callee {entry:#x} has no statically evidenced reachable return")
            result.update((exit_node, continuation) for exit_node in exits)
    return result


def audit_typed_path(initial: int, final: int, operations: list[Operation], nodes: set[int],
                     typed: set[Edge], returns: set[tuple[int, int]], root: int) -> dict:
    require(initial == final == SCOPE, "source must retain complete SCOPE_RETURN endpoints")
    require(bool(operations) and operations[0] == ("call", root, SCOPE)
            and operations[-1] == ("ret", SCOPE, None), "source root wrapper is missing or changed")
    state, stack, maximum_depth = initial, [], 0
    counts: Counter[str] = Counter()
    for index, (kind, destination, continuation) in enumerate(operations, 1):
        require(state in nodes and destination in nodes, f"unmapped path row {index}")
        if kind == "call":
            require((state, "cal", destination) in typed, f"invalid typed CAL at row {index}")
            require((state, "crt", continuation) in typed, f"invalid static CRT at row {index}")
            stack.append((index, continuation))
            maximum_depth = max(maximum_depth, len(stack))
        elif kind == "jump":
            require((state, "jmp", destination) in typed, f"invalid typed JMP at row {index}")
        elif kind == "ret":
            require(bool(stack), f"return underflow at row {index}")
            call_index, expected = stack.pop()
            require(call_index < index and destination == expected, f"incorrect exact return at row {index}")
            require((state, destination) in returns, f"return lacks static provenance at row {index}")
        else:
            raise ValueError(f"unsupported path operation at row {index}")
        state = destination
        counts[kind] += 1
    require(state == final and not stack, "path has wrong endpoint or pending calls")
    require(maximum_depth < 15, "path reaches the fixed ZEKRA stack bound of 15")
    return {"typed_cfg_and_crt_checks_passed": True, "exact_returns_passed": True,
            "empty_final_stack": True, "scope_wrapper_preserved": True,
            "max_stack_depth": maximum_depth, "operation_counts": dict(counts),
            "rows_with_initial": len(operations) + 1, "transitions": len(operations),
            "canonical_path_sha256": sha_bytes(json_bytes([initial, final, operations]))}


def static_label_order(nodes: set[int], adjacency: set[tuple[int, int]]) -> list[int]:
    """Group large static successor sets first; neither paths nor visit counts are inputs."""
    successors: dict[int, set[int]] = {node: set() for node in nodes}
    for source, destination in adjacency:
        successors[source].add(destination)
    seen, ordered = set(), []
    for source in sorted(nodes, key=lambda node: (-len(successors[node]), node)):
        for destination in sorted(successors[source]):
            if destination not in seen:
                ordered.append(destination)
                seen.add(destination)
    ordered.extend(sorted(nodes - seen))
    return ordered


def parse_adjacency(text: str, address: Callable[[str], int]) -> tuple[set[int], set[tuple[int, int]]]:
    nodes, edges = set(), set()
    for line in text.splitlines():
        values = [address(token) for token in line.split()]
        require(bool(values) and values[0] not in nodes, "duplicate/malformed adjacency source")
        require(len(values[1:]) == len(set(values[1:])), "duplicate adjacency destination")
        nodes.add(values[0])
        edges.update((values[0], destination) for destination in values[1:])
    return nodes, edges


def convert_artifacts(translator: str, typed_cfg: str, recorded_path: str, plugin_map: str
                      ) -> tuple[dict[str, bytes], dict]:
    """Pure conversion API. Raises ValueError before emitting an invalid matched case."""
    tokens = translator.split()
    ordered_source = [parse_provider_address(token) for token in tokens]
    nodes = set(ordered_source)
    require(bool(nodes) and len(nodes) == len(tokens), "translator must be nonempty and injective")
    typed = parse_typed_cfg(typed_cfg, nodes)
    initial, final, operations = parse_path(recorded_path)
    static = static_map_returns(plugin_map)
    returns = static_return_edges(nodes, typed, static["return_blocks"] | static["external_gateways"])
    source_audit = audit_typed_path(initial, final, operations, nodes, typed, returns, static["root_entry"])
    adjacency = {(source, destination) for source, kind, destination in typed if kind != "crt"} | returns
    ordered = static_label_order(nodes, adjacency)
    labels = {node: index for index, node in enumerate(ordered)}
    successors = {node: sorted(destination for source, destination in adjacency if source == node)
                  for node in ordered}
    levels = max(1, max(len({labels[destination] // 8 for destination in destinations})
                        for destinations in successors.values()))
    node_cap = p2(len(nodes), 8)
    label_bits, bucket_bits = node_cap.bit_length(), (node_cap // 8).bit_length()
    field_budget = levels * (bucket_bits + 8)
    require(field_budget < 254, "ZEKRA adjacency encoding reaches the native field width")
    parameters = {"adjlist_len": node_cap, "path_len": p2(len(operations), 16), "levels": levels,
                  "stack_depth": 15, "label_bw": label_bits, "bucket_bw": bucket_bits, "addr_bw": 24}
    buffers = {"translator": ("\n".join(f"0x{node:x}" for node in ordered) + "\n").encode()}
    for numeric, adjacency_name, path_name in ((False, "adjlist", "recorded_path"),
                                               (True, "numified_adjlist", "numified_path")):
        token = (lambda value: str(labels[value])) if numeric else (lambda value: f"0x{value:x}")
        buffers[adjacency_name] = ("\n".join(" ".join(token(value) for value in [node, *successors[node]])
                                               for node in ordered) + "\n").encode()
        rows = [f"initial_node={token(initial)} final_node={token(final)}"]
        rows.extend(f"{kind} {token(destination)}" + (f" {token(auxiliary)}" if kind == "call" else "")
                    for kind, destination, auxiliary in operations)
        buffers[path_name] = ("\n".join(rows) + "\n").encode()

    def unlabel(token: str) -> int:
        require(re.fullmatch(r"[0-9]+", token) is not None, "invalid numeric label")
        index = int(token)
        require(index < len(ordered), "numeric label outside translator")
        return ordered[index]

    for path_name, adjacency_name, address in (("recorded_path", "adjlist", parse_raw_address),
                                               ("numified_path", "numified_adjlist", unlabel)):
        decoded = parse_path(buffers[path_name].decode(), address)
        require(decoded == (initial, final, operations), f"path semantics changed in {path_name}")
        decoded_nodes, decoded_edges = parse_adjacency(buffers[adjacency_name].decode(), address)
        require(decoded_nodes == nodes and decoded_edges == adjacency, "executable adjacency roundtrip failed")
        audit_typed_path(*decoded, nodes, typed, returns, static["root_entry"])

    encoded_widths = []
    for source, destinations in successors.items():
        groups: dict[int, int] = {}
        for destination in destinations:
            bucket, remainder = divmod(labels[destination], 8)
            groups[bucket] = groups.get(bucket, 0) | (1 << remainder)
        encoded = 0
        for bucket, mask in groups.items():
            require(bucket < 1 << bucket_bits, "adjacency bucket overflow")
            encoded = (encoded << (bucket_bits + 8)) | (mask << bucket_bits) | bucket
        reconstructed = set()
        remaining = encoded
        for _ in range(levels):
            bucket, mask = remaining & ((1 << bucket_bits) - 1), (remaining >> bucket_bits) & 255
            reconstructed.update(bucket * 8 + bit for bit in range(8) if mask & (1 << bit))
            remaining >>= bucket_bits + 8
        require(not remaining and reconstructed == {labels[d] for d in destinations},
                f"packed adjacency roundtrip failed at {source:#x}")
        encoded_widths.append(encoded.bit_length())

    audit = {"source_relation": source_audit, "parameters": parameters,
             "path_semantics_equal": True, "raw_numeric_paths_equal": True,
             "executable_adjacency_roundtrip": True, "packed_adjacency_roundtrip": True,
             "compression_invoked": False, "inserted_returns": 0, "retagged_operations": 0,
             "nodes": len(nodes), "typed_edges": len(typed), "executable_edges": len(adjacency),
             "static_returns": [[source, destination] for source, destination in sorted(returns)],
             "typed_cfg": [[source, kind, destination] for source, kind, destination in sorted(typed)],
             "crt_declarations": [[source, destination] for source, kind, destination in sorted(typed) if kind == "crt"],
             "map_return_blocks": sorted(static["return_blocks"]),
             "map_external_gateways": sorted(static["external_gateways"]),
             "static_return_method": "static instruction RET blocks/external gateways, matched by callee JMP/CRT reachability; no EP-derived edges",
             "label_order_rule": "static successor sets by (-outdegree, source_address), each destination ascending, then remaining nodes ascending",
             "address_mapping": [{"source_token": token, "canonical_raw24": node, "zekra_label": labels[node]}
                                 for token, node in zip(tokens, ordered_source)],
             "adjacency_field_budget_bits": field_budget,
             "maximum_encoded_adjacency_bits": max(encoded_widths),
             "maximum_outdegree": max(map(len, successors.values())),
             "static_elf_sha256": static["elf_sha256"],
             "scope": "Same compressed path and continuation metadata; backend-native relation acceptance sets are not asserted identical."}
    return buffers, audit


def prepare_campaign(source: Path, output: Path) -> dict:
    source, output = source.resolve(), output.resolve()
    require(not output.exists(), "output already exists; choose a new directory")
    require(output != source and source not in output.parents, "output must be outside the source campaign")
    frozen: dict[Path, str] = {}

    def read(path: Path) -> bytes:
        require(path.is_file() and not path.is_symlink(), f"source is not a regular non-symlink file: {path}")
        data = path.read_bytes()
        frozen[path] = sha_bytes(data)
        return data

    suite_bytes = read(source / "signed/bundles.json")
    suite = json.loads(suite_bytes)
    entries = suite["applications"]
    require(len(entries) == len(APPLICATIONS) and {row["application"] for row in entries} == set(APPLICATIONS),
            "source campaign must contain exactly the 21 registered applications")
    by_app = {row["application"]: row for row in entries}
    prepared = []
    for app in APPLICATIONS:
        try:
            private = source / "signed" / app / "shadow/bundle/private"
            static_dir = source / "inputs" / app / "artifacts"
            common = {name: read(private / name) for name in COMMON_FILES}
            evidence = {name: read(static_dir / name) for name in ("plugin-map.txt", "static-manifest.json", "evidence.json")}
            evidence.update({name: read(private.parent / "public" / name) for name in ("registry.json", "report.json")})
            static_manifest = json.loads(evidence["static-manifest.json"])
            captured = json.loads(evidence["evidence.json"])
            registry, report = (json.loads(evidence[name])["payload"] for name in ("registry.json", "report.json"))
            projection = by_app[app]["projection"]
            require(static_manifest["application"] == registry["application"] == app, "application identity mismatch")
            require(static_manifest["plugin_map_sha256"] == sha_bytes(evidence["plugin-map.txt"]), "static map hash mismatch")
            for name in ("translator", "typed_cfg"):
                require(static_manifest[name + "_sha256"] == projection[name + "_sha256"] == sha_bytes(common[name]),
                        f"static/projection {name} hash mismatch")
            require(projection["compressed_recorded_path_sha256"] == sha_bytes(common["recorded_path"]),
                    "frozen compressed path hash mismatch")
            full_path = read(static_dir / "recorded_path")
            require(projection["full_recorded_path_sha256"] == captured["recorded_path_sha256"] == sha_bytes(full_path),
                    "source capture path hash mismatch")
            require(projection["source_evidence_sha256"] == sha_bytes(evidence["evidence.json"]), "projection evidence hash mismatch")
            require(captured["typed_cfg_sha256"] == sha_bytes(common["typed_cfg"]), "capture CFG hash mismatch")
            require(captured["runtime_code_match"] is True and all(captured["boundary"].get(key) is True
                    for key in ("complete", "root_entry_observed", "root_return_observed")), "incomplete source capture")
            require(projection["algorithm"] == "shadow-safe" and projection["shadow_stack_preserved"] is True,
                    "source projection is not the registered stack-safe mode")
            buffers, audit = convert_artifacts(*(common[name].decode() for name in COMMON_FILES), evidence["plugin-map.txt"].decode())
            require(audit["static_elf_sha256"] == static_manifest["elf_sha256"] == registry["binary_measurement"] == report["binary_measurement"],
                    "static map/registered code measurement mismatch")
            require(report["entry_raw"] == report["final_raw"] == SCOPE, "registered endpoints mismatch")
            circuit = registry["circuit"]
            require(circuit["backend"] == "binius64" and circuit["path_mode"] == "shadow", "unexpected source backend or mode")
            binius = {key: circuit[key] for key in ("edge_cap", "ep_cap", "path_mode")}
            for field, length in (("edge_cap", audit["typed_edges"]), ("ep_cap", audit["source_relation"]["rows_with_initial"])):
                require(type(binius[field]) is int and binius[field] >= length
                        and binius[field] & (binius[field] - 1) == 0, f"invalid registered {field}")
                require(by_app[app]["shadow"][field] == binius[field], f"suite/registry {field} mismatch")
            require(projection["compressed_rows"] == audit["source_relation"]["rows_with_initial"], "projection row count mismatch")
            audit["source_hashes"] = {str(path.relative_to(source)): value for path, value in frozen.items()
                                      if app in path.relative_to(source).parts}
            audit["source_signed_records_frozen"] = True
            audit["new_authentication_performed"] = False
            prepared.append((app, common, buffers, evidence, audit, binius))
        except (KeyError, TypeError, UnicodeError, ValueError) as error:
            raise ValueError(f"{app}: {error}") from error

    # All cases pass before creating any output, including code/map/projection provenance checks.
    require(all(sha(path) == value for path, value in frozen.items()), "source changed during preparation")
    output.mkdir(parents=True)
    (output / "source-bundles.json").write_bytes(suite_bytes)
    applications = []
    for app, common, buffers, evidence, audit, binius in prepared:
        for category, files in (("common", common), ("zekra", buffers), ("evidence", evidence)):
            destination = output / category / app
            destination.mkdir(parents=True)
            for name, content in files.items():
                (destination / name).write_bytes(content)
        common_hashes = {name: sha(output / "common" / app / name) for name in COMMON_FILES}
        zekra_hashes = {name: sha(output / "zekra" / app / name) for name in ZEKRA_FILES}
        require(common_hashes == {name: sha_bytes(content) for name, content in common.items()}, "common file bytes changed")
        audit.update({"common_bytes_preserved": True, "common_hashes": common_hashes, "zekra_hashes": zekra_hashes,
                      "evidence_hashes": {name: sha_bytes(content) for name, content in evidence.items()}})
        audit_file = Path("audits") / f"{app}.json"
        (output / audit_file).parent.mkdir(exist_ok=True)
        (output / audit_file).write_bytes(json_bytes(audit))
        applications.append({"application": app, "common_dir": f"common/{app}", "zekra_dir": f"zekra/{app}",
                             "common_hashes": common_hashes, "zekra_hashes": zekra_hashes,
                             "rows": audit["source_relation"]["rows_with_initial"], "edges": audit["typed_edges"], "nodes": audit["nodes"],
                             "binius": binius, "zekra": audit["parameters"], "audit_file": str(audit_file),
                             "audit_sha256": sha(output / audit_file), "source_hashes": audit["source_hashes"]})
    require(all(sha(path) == value for path, value in frozen.items()), "source changed while freezing output")
    manifest = {"schema": "zkcfa.matched-compressed.inputs.v1", "created_utc": datetime.now(timezone.utc).isoformat(),
                "source_campaign": str(source), "preparer_sha256": sha(Path(__file__)),
                "source_hashes": {str(path.relative_to(source)): value for path, value in frozen.items()},
                "source_bundles_sha256": sha_bytes(suite_bytes), "application_count": len(applications),
                "all_audits_passed": True, "compression_invoked": False, "compiler_or_prover_invoked": False,
                "applications": applications,
                "scope": "Frozen stack-safe inputs with identical operations and exact-return metadata. ZEKRA uses statically derived untyped execution adjacency; native relation acceptance sets differ. No fresh capture or authentication is claimed."}
    (output / "manifest.json").write_bytes(json_bytes(manifest))
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-campaign", type=Path, required=True,
                        help="existing signed 21-application campaign with shadow bundles and capture evidence")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = prepare_campaign(args.source_campaign, args.output)
    print(json.dumps({"output": str(args.output.resolve()), "application_count": manifest["application_count"],
                      "all_audits_passed": manifest["all_audits_passed"], "compression_invoked": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
