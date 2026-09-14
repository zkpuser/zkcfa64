#!/usr/bin/env python3
"""Materialize the optional lossy, shadow-stack-safe proof path."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Iterable

from .normalize import (
    EVIDENCE_BOUNDARY_FIELDS,
    EVIDENCE_FIELDS,
    EVIDENCE_SCHEMA,
    address,
    load_translator,
    load_typed_cfg,
    sha256_file,
    token,
)
from .provision import SCOPE_ADDRESS, SCOPE_TOKEN
from .projection import (
    Operation,
    shadow_safe_compress,
)


REPORT_SCHEMA = "zkcfa.raw.projection"
ALGORITHM_ID = "shadow-safe"
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")


def _require_regular(path: Path, description: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{description} is absent, non-regular, or symlinked: {path}")


def _load_json_object(path: Path, description: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read {description}: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{description} must contain a JSON object")
    return value


def _parse_header(header: str) -> tuple[int, int]:
    fields = header.split()
    if len(fields) != 2:
        raise ValueError(
            "recorded_path header must contain exactly initial_node and final_node"
        )
    values: dict[str, int] = {}
    for field in fields:
        name, separator, raw = field.partition("=")
        if not separator or name not in {"initial_node", "final_node"} or name in values:
            raise ValueError("recorded_path has a malformed or duplicate header field")
        try:
            values[name] = address(raw)
        except ValueError as error:
            raise ValueError(f"recorded_path header has an invalid address: {raw}") from error
    if set(values) != {"initial_node", "final_node"}:
        raise ValueError("recorded_path header is incomplete")
    return values["initial_node"], values["final_node"]


def parse_recorded_path(path: Path) -> tuple[str, int, int, list[Operation]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError("recorded_path is empty")
    entry, final = _parse_header(lines[0])
    operations: list[Operation] = []
    for line_number, line in enumerate(lines[1:], 2):
        fields = line.split()
        try:
            if len(fields) == 3 and fields[0] in {"call", "discontinuity"}:
                operations.append((fields[0], address(fields[1]), address(fields[2])))
            elif len(fields) == 2 and fields[0] in {"jump", "ret"}:
                operations.append((fields[0], address(fields[1]), None))
            else:
                raise ValueError("expected call dst aux, discontinuity dst src, jump dst, or ret dst")
        except ValueError as error:
            raise ValueError(f"recorded_path line {line_number} is malformed: {line}") from error
    if not operations:
        raise ValueError("recorded_path contains no operations")
    return lines[0], entry, final, operations


def _validate_operations(
    operations: list[Operation],
    *,
    entry: int,
    final: int,
    typed_edges: set[tuple[int, str, int]],
    nodes: set[int],
    context: str,
) -> None:
    """Check artifact shape and endpoint fidelity, not CFA compliance.

    Observed addresses need not occur in the approved graph. CFG membership,
    CRT declarations and return discipline are checked by the worker/proof.
    """
    if entry not in nodes or final not in nodes:
        raise ValueError(f"{context}: an endpoint is absent from translator")
    state = entry
    for row, (kind, destination, auxiliary) in enumerate(operations, 1):
        if kind in {"call", "discontinuity"}:
            if auxiliary is None:
                raise ValueError(f"{context}: operation {row} has no auxiliary address")
        elif kind not in {"jump", "ret"}:
            raise ValueError(f"{context}: unsupported operation kind {kind!r}")
        state = destination
    if state != final:
        raise ValueError(
            f"{context}: final row {token(state)} differs from header {token(final)}"
        )


def _validate_evidence(
    evidence: dict[str, object],
    *,
    recorded_path: Path,
    typed_cfg: Path,
) -> None:
    if set(evidence) != EVIDENCE_FIELDS or evidence.get("schema") != EVIDENCE_SCHEMA:
        raise ValueError("source trace evidence has missing or unknown fields")
    boundary = evidence.get("boundary")
    if (
        not isinstance(boundary, dict)
        or set(boundary) != EVIDENCE_BOUNDARY_FIELDS
        or boundary.get("complete") is not True
    ):
        raise ValueError("source trace evidence does not attest a complete QEMU boundary")
    if (
        boundary.get("root_entry_observed") is not True
        or boundary.get("root_return_observed") is not True
    ):
        raise ValueError("source trace evidence lacks the configured root entry/return boundary")
    if evidence.get("runtime_code_match") is not True:
        raise ValueError("source trace evidence does not attest runtime_code_match=true")
    expected_path = evidence.get("recorded_path_sha256")
    actual_path = sha256_file(recorded_path)
    if not isinstance(expected_path, str) or not HEX_SHA256.fullmatch(expected_path):
        raise ValueError("source trace evidence has an invalid recorded_path_sha256")
    if expected_path != actual_path:
        raise ValueError("source trace evidence recorded_path hash mismatch")

    expected_cfg = evidence.get("typed_cfg_sha256")
    if not isinstance(expected_cfg, str) or not HEX_SHA256.fullmatch(expected_cfg):
        raise ValueError("source trace evidence has an invalid typed_cfg_sha256")
    if expected_cfg != sha256_file(typed_cfg):
        raise ValueError("source trace evidence typed_cfg_sha256 mismatch")
    for field in ("event_count", "external_call_count"):
        if type(evidence.get(field)) is not int or evidence[field] < 0:
            raise ValueError(f"source trace evidence has an invalid {field}")


def _render(header: str, operations: list[Operation]) -> str:
    lines = [header]
    for kind, destination, auxiliary in operations:
        if kind in {"call", "discontinuity"}:
            if auxiliary is None:
                raise ValueError(f"cannot render {kind} without an auxiliary address")
            lines.append(f"{kind} {token(destination)} {token(auxiliary)}")
        else:
            lines.append(f"{kind} {token(destination)}")
    return "\n".join(lines) + "\n"


def materialize_shadow_safe_bundle(
    input_bundle: Path,
    output: Path,
    source_evidence: Path | None = None,
) -> dict[str, object]:
    input_bundle = input_bundle.resolve()
    output = output.resolve()
    if output.exists():
        raise ValueError(f"refusing to overwrite existing output: {output}")
    evidence_path = (
        source_evidence.absolute()
        if source_evidence is not None
        else input_bundle / "evidence.json"
    )
    translator = input_bundle / "translator"
    typed_cfg = input_bundle / "typed_cfg"
    recorded_path = input_bundle / "recorded_path"
    for path, description in (
        (translator, "source translator"),
        (typed_cfg, "source typed CFG"),
        (recorded_path, "source recorded path"),
        (evidence_path, "source trace evidence"),
    ):
        _require_regular(path, description)

    evidence = _load_json_object(evidence_path, "source trace evidence")
    _validate_evidence(evidence, recorded_path=recorded_path, typed_cfg=typed_cfg)
    nodes = load_translator(translator)
    if not nodes:
        raise ValueError("source translator is empty")
    typed_edges = load_typed_cfg(typed_cfg)
    if not typed_edges:
        raise ValueError("source typed CFG is empty")
    endpoint_pairs = [(source, destination) for source, _kind, destination in typed_edges]
    if len(endpoint_pairs) != len(set(endpoint_pairs)):
        raise ValueError("source typed CFG contains a type-aliased endpoint pair")

    header, entry, final, full_operations = parse_recorded_path(recorded_path)
    if entry != SCOPE_ADDRESS or final != SCOPE_ADDRESS:
        raise ValueError(
            f"source recorded_path must use the {SCOPE_TOKEN} entry/final envelope"
        )
    _validate_operations(
        full_operations,
        entry=entry,
        final=final,
        typed_edges=typed_edges,
        nodes=nodes,
        context="complete QEMU path",
    )

    compressed, _decisions = shadow_safe_compress(full_operations)
    _validate_operations(
        compressed,
        entry=entry,
        final=final,
        typed_edges=typed_edges,
        nodes=nodes,
        context="shadow-safe projected path",
    )
    compressed_text = _render(header, compressed)

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        shutil.copyfile(translator, temporary / "translator")
        shutil.copyfile(typed_cfg, temporary / "typed_cfg")
        shutil.copyfile(evidence_path, temporary / "source-evidence.json")
        (temporary / "recorded_path").write_text(compressed_text, encoding="utf-8")

        full_rows = len(full_operations) + 1
        compressed_rows = len(compressed) + 1
        report: dict[str, object] = {
            "schema": REPORT_SCHEMA,
            "algorithm": ALGORITHM_ID,
            "lossy": True,
            "shadow_stack_preserved": True,
            "loop_multiplicity_preserved": False,
            "full_rows": full_rows,
            "compressed_rows": compressed_rows,
            "full_recorded_path_sha256": sha256_file(recorded_path),
            "compressed_recorded_path_sha256": sha256_file(
                temporary / "recorded_path"
            ),
            "typed_cfg_sha256": sha256_file(typed_cfg),
            "translator_sha256": sha256_file(translator),
            "source_evidence_sha256": sha256_file(evidence_path),
        }
        (temporary / "projection.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if output.exists():
            raise ValueError(f"output appeared while materializing bundle: {output}")
        os.rename(temporary, output)
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    return report


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="materialize an explicit shadow-safe projected proof-input bundle"
    )
    parser.add_argument("--input-bundle", type=Path, required=True)
    parser.add_argument(
        "--source-evidence",
        type=Path,
        help="complete QEMU evidence (default: INPUT/evidence.json)",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = materialize_shadow_safe_bundle(
        args.input_bundle, args.output, args.source_evidence
    )
    print(
        "shadow-safe proof-input bundle: "
        f"{report['full_rows']} -> {report['compressed_rows']} rows; "
        f"output={args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
