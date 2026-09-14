#!/usr/bin/env python3
"""Read-only audit of ZEKRA's released application inputs against the legacy CSV.

No circuit, prover, extractor, path compressor, or input formatter is invoked.
The report preserves the released partial-path semantics, including pending calls
at the final node, rather than imposing zkCFA64's balanced Complete relation.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
INPUT_NAMES = ("adjlist", "numified_adjlist", "translator", "recorded_path", "numified_path")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def revision(path: Path) -> str | None:
    result = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                            text=True, capture_output=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def input_revision(source: Path) -> str | None:
    upstream = source.resolve().parent
    if not (upstream / ".git").exists():
        # An archive can sit inside another checkout; its parent HEAD is not its source revision.
        return None
    return revision(upstream)


def p2(value: int, minimum: int) -> int:
    return max(minimum, 1 << max(0, value - 1).bit_length())


def read_path(path: Path, base: int) -> tuple[int, int, list[tuple[str, int, int | None]]]:
    lines = [line.split() for line in path.read_text().splitlines() if line.strip()]
    if not lines or len(lines[0]) != 2:
        raise ValueError(f"{path}: missing two-field path header")
    first, last = lines[0]
    if not first.startswith("initial_node=") or not last.startswith("final_node="):
        raise ValueError(f"{path}: invalid path header")
    initial = int(first.split("=", 1)[1], base)
    final = int(last.split("=", 1)[1], base)
    operations = []
    for index, fields in enumerate(lines[1:], 1):
        if fields[0] not in ("call", "jump", "ret"):
            raise ValueError(f"{path}: unknown operation at {index}")
        if len(fields) != (3 if fields[0] == "call" else 2):
            raise ValueError(f"{path}: malformed return metadata at {index}")
        operations.append((fields[0], int(fields[1], base),
                           int(fields[2], base) if len(fields) == 3 else None))
    return initial, final, operations


def read_adjacency(path: Path, base: int) -> dict[int, list[int]]:
    adjacency = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        source, *destinations = [int(token, base) for token in line.split()]
        if source in adjacency:
            raise ValueError(f"{path}: duplicate adjacency source {source}")
        adjacency[source] = destinations
    return adjacency


def audit_app(directory: Path, old: dict[str, str]) -> dict:
    errors = []
    hashes = {name: digest(directory / name) for name in INPUT_NAMES}
    translator = [int(token, 16) for token in (directory / "translator").read_text().split()]
    if len(set(translator)) != len(translator):
        raise ValueError(f"{directory.name}: translator contains duplicate addresses")
    labels = {address: index for index, address in enumerate(translator)}
    raw_adj = read_adjacency(directory / "adjlist", 16)
    numeric_adj = read_adjacency(directory / "numified_adjlist", 10)
    initial, final, operations = read_path(directory / "recorded_path", 16)
    num_initial, num_final, numeric_operations = read_path(directory / "numified_path", 10)
    if set(raw_adj) != set(translator) or set(numeric_adj) != set(range(len(translator))):
        errors.append("adjacency source inventory differs from translator")
    adjacency_matches = all(
        labels.get(source) in numeric_adj
        and {labels.get(destination) for destination in destinations}
        == set(numeric_adj[labels[source]])
        for source, destinations in raw_adj.items()
    )
    if not adjacency_matches:
        errors.append("raw/numeric adjacency mapping differs")
    mapped_operations = [(kind, labels.get(destination), labels.get(continuation)
                          if continuation is not None else None)
                         for kind, destination, continuation in operations]
    path_matches = (labels.get(initial) == num_initial and labels.get(final) == num_final
                    and mapped_operations == numeric_operations)
    if not path_matches:
        errors.append("raw/numeric path or call-continuation mapping differs")

    parameters = {key: int(old[key]) for key in (
        "adjlist_len", "path_len", "levels", "stack_depth", "label_bw", "bucket_bw", "addr_bw")}
    addresses = set(translator) | {initial, final}
    for source, destinations in raw_adj.items():
        addresses.add(source)
        addresses.update(destinations)
    for _, destination, continuation in operations:
        addresses.add(destination)
        if continuation is not None:
            addresses.add(continuation)
    node_capacity = p2(len(addresses), 8)
    old_rule = {"adjlist_len": node_capacity, "path_len": p2(len(operations) + 1, 16),
                "levels": 15, "stack_depth": 15,
                "label_bw": max(10, node_capacity.bit_length()),
                "bucket_bw": max(7, (node_capacity // 8).bit_length()), "addr_bw": 24}
    if parameters != old_rule:
        errors.append("CSV parameters differ from the original campaign rule")
    address_bits = max(addresses).bit_length()
    if min(addresses) <= 0 or address_bits > parameters["addr_bw"]:
        errors.append("source addresses do not fit the declared nonzero address width")
    if len(translator).bit_length() > parameters["label_bw"]:
        errors.append("translator labels exceed label width")

    encoded = {}
    level_counts = {}
    for source, destinations in numeric_adj.items():
        buckets = {}
        for destination in destinations:
            if destination not in numeric_adj:
                errors.append(f"unmapped adjacency destination {destination}")
            bucket, remainder = divmod(destination, 8)
            if bucket.bit_length() > parameters["bucket_bw"]:
                errors.append("adjacency bucket exceeds configured width")
            buckets[bucket] = buckets.get(bucket, 0) | (1 << remainder)
        value = 0
        # Preserve the formatter's first-appearance order of bucket groups.
        for bucket, mask in buckets.items():
            value = (value << (8 + parameters["bucket_bw"])) | (mask << parameters["bucket_bw"]) | bucket
        encoded[source] = value
        level_counts[source] = len(buckets)
    if max(level_counts.values()) > parameters["levels"]:
        errors.append("source adjacency needs more than the configured number of levels")
    field_budget = parameters["levels"] * (8 + parameters["bucket_bw"])
    if field_budget >= 254:
        errors.append("configured adjacency bit budget reaches the native field width")

    state = num_initial
    stack = []
    maximum_depth = 0
    return_count = 0
    underflows = []
    wrong_returns = []
    edge_failures = []
    visited_widths = []
    first_wide = None
    for index, (kind, destination, continuation) in enumerate(numeric_operations, 1):
        if state not in encoded:
            raise ValueError(f"{directory.name}: unmapped source at operation {index}")
        width = encoded[state].bit_length()
        visited_widths.append(width)
        if width > 32 and first_wide is None:
            first_wide = {"operation_index": index, "source_label": state, "kind": kind,
                          "encoded_adjacency_decimal": str(encoded[state]),
                          "encoded_adjacency_bits": width,
                          "value_mod_2_32_decimal": str(encoded[state] % (1 << 32))}
        if destination not in numeric_adj[state]:
            edge_failures.append(index)
        if kind == "call":
            stack.append(continuation)
            maximum_depth = max(maximum_depth, len(stack))
        elif kind == "ret":
            return_count += 1
            if not stack:
                underflows.append(index)
            elif stack.pop() != destination:
                wrong_returns.append(index)
        state = destination
    if underflows or wrong_returns or edge_failures or state != num_final:
        errors.append("released path violates its untyped adjacency, executed returns, or final node")
    if maximum_depth >= parameters["stack_depth"]:
        errors.append("call depth reaches the configured legacy stack bound")
    visited_max = max(visited_widths, default=0)
    expected_truncation = visited_max > 32
    if expected_truncation != (old["outcome"] == "unsatisfiable"):
        errors.append("visited-width diagnostic does not match the frozen unsatisfied outcome")
    changed = [name for name in INPUT_NAMES if digest(directory / name) != hashes[name]]
    if changed:
        errors.append("inputs changed during the audit: " + ", ".join(changed))
    return {
        "app": directory.name, "legacy_outcome": old["outcome"], "parameters": parameters,
        "parameters_match_original_rule": parameters == old_rule,
        "input_sha256": hashes, "translator_nodes": len(translator),
        "path_operations_excluding_initial": len(operations), "max_address_bits": address_bits,
        "raw_numeric_adjacency_match": adjacency_matches, "raw_numeric_path_metadata_match": path_matches,
        "max_stack_depth": maximum_depth, "final_stack_depth": len(stack),
        "remaining_continuation_labels": stack, "executed_return_count": return_count,
        "executed_returns_match": not underflows and not wrong_returns,
        "underflow_operations": underflows, "wrong_return_operations": wrong_returns,
        "untyped_adjacency_followed": not edge_failures, "invalid_edge_operations": edge_failures,
        "final_node_matches": state == num_final,
        "typed_cfg_audited": False,
        "semantics": "Released untyped adjacency and compressed partial path; only observed returns are checked. A nonempty final stack is retained, not repaired or rejected.",
        "required_adjacency_levels": max(level_counts.values()),
        "configured_adjacency_bit_budget": field_budget,
        "max_encoded_adjacency_bits": max(value.bit_length() for value in encoded.values()),
        "max_visited_encoded_adjacency_bits": visited_max,
        "first_visited_entry_above_32_bits": first_wide,
        "expected_original_truncation_failure": expected_truncation,
        "diagnostic_matches_frozen_outcome": expected_truncation == (old["outcome"] == "unsatisfiable"),
        "audit_passed": not errors, "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-root", type=Path, required=True, help="original campaign snapshot application directory")
    parser.add_argument("--legacy-results", type=Path, required=True, help="original campaign results.csv")
    parser.add_argument("--output", type=Path, required=True, help="new report directory")
    args = parser.parse_args()
    source, old_file, output = args.input_root.resolve(), args.legacy_results.resolve(), args.output.resolve()
    if output.exists():
        parser.error("output already exists; choose a new directory")
    if output == source or source in output.parents:
        parser.error("the report must not be written inside the input tree")
    old_hash = digest(old_file)
    with old_file.open(newline="") as stream:
        old_rows = [row for row in csv.DictReader(stream) if row["app"] != "crc32-control-500"]
    applications = sorted(path.name for path in source.iterdir() if path.is_dir())
    if len(old_rows) != 21 or sorted(row["app"] for row in old_rows) != applications:
        raise ValueError("expected exactly the same 21 released applications and CSV rows")
    rows = [audit_app(source / row["app"], row) for row in old_rows]
    issues = [f"{row['app']}: {error}" for row in rows for error in row["errors"]]
    if digest(old_file) != old_hash:
        issues.append("legacy-results CSV changed during the audit")
    report = {
        "schema": "zkcfa.zekra.released-input-audit.v1",
        "created_at": datetime.now(timezone.utc).isoformat(), "read_only_inputs": True,
        "prover_or_compiler_invoked": False, "input_root": str(source),
        "legacy_results": str(old_file), "legacy_results_sha256": old_hash,
        "audit_script_sha256": digest(Path(__file__)),
        "repository_revision": revision(ROOT), "zekra_revision": input_revision(source),
        "application_count": len(rows), "legacy_outcomes": dict(Counter(row["legacy_outcome"] for row in rows)),
        "all_executed_returns_match": all(row["executed_returns_match"] for row in rows),
        "all_final_nodes_match": all(row["final_node_matches"] for row in rows),
        "all_raw_numeric_metadata_match": all(row["raw_numeric_path_metadata_match"] and row["raw_numeric_adjacency_match"] for row in rows),
        "nonempty_final_stack_count": sum(row["final_stack_depth"] > 0 for row in rows),
        "maximum_stack_depth": max(row["max_stack_depth"] for row in rows),
        "wide_visited_entry_apps": [row["app"] for row in rows if row["expected_original_truncation_failure"]],
        "wide_entry_diagnostic_matches_all_outcomes": all(row["diagnostic_matches_frozen_outcome"] for row in rows),
        "interpretation": "Input-only diagnostic of the frozen released suite. It does not rerun or guarantee compiler/prover outcomes after a SmartMemory repair, and does not establish zkCFA64 typed-CFG or balanced Complete semantics.",
        "audit_passed": not issues, "issues": issues, "rows": rows,
    }
    output.mkdir(parents=True, exist_ok=False)
    (output / "audit.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    fields = ["app", "legacy_outcome", "max_address_bits", "max_stack_depth", "final_stack_depth",
              "executed_return_count", "executed_returns_match", "untyped_adjacency_followed",
              "raw_numeric_path_metadata_match", "required_adjacency_levels", "max_encoded_adjacency_bits",
              "max_visited_encoded_adjacency_bits", "expected_original_truncation_failure", "audit_passed"]
    with (output / "summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    (output / "README.md").write_text(
        "# Released ZEKRA input audit\n\n"
        "This is a read-only input audit, not a new proof experiment. `audit.json` records all five source-file hashes, original parameters, address widths, raw/numeric mappings, observed return behavior, final pending calls, and packed adjacency widths for each application. `summary.csv` is the compact view.\n\n"
        "The original paths follow untyped adjacency records and may end with pending calls. Do not insert returns, re-compress paths, infer typed CFG records, or require an empty final stack when comparing the original and repaired jars. The original fifteen adjacency levels and width floors must remain fixed.\n\n"
        "The nine historical unsatisfied outcomes exactly match paths that visit an adjacency entry wider than 32 bits. This script recomputes that diagnostic from the original inputs; it does not rerun the original compiler or predict that every repaired instance will prove within the resource limit.\n\n"
        "Reproduce from the repository root, choosing a new output directory:\n\n"
        "```sh\npython3 zekra/reproduce/scripts/audit_zekra_released_inputs.py --input-root /absolute/original/snapshot/zekra/ZEKRA/embench-iot-applications --legacy-results /absolute/original/results.csv --output /absolute/new/zekra-released-input-audit\n```\n\n"
        "The report intentionally does not claim typed CFG checking, a balanced complete execution, QEMU acquisition, or device signing for these released ZEKRA inputs.\n"
    )
    print(json.dumps({key: report[key] for key in (
        "audit_passed", "application_count", "legacy_outcomes", "nonempty_final_stack_count",
        "maximum_stack_depth", "wide_visited_entry_apps", "issues")}, sort_keys=True))
    return 0 if report["audit_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
