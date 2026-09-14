#!/usr/bin/env python3
"""Generate balanced synthetic stack traces with a fixed CFG and transfer proportions.

L includes the initial JMP record; capacities are fully occupied. At each L, exactly
L/4 calls, L/4 returns, and L/2 JMP records are used. Changing D only changes nesting.
The fixtures are program models, not measured executions or acquisition evidence.
"""

import argparse
import hashlib
import json
from pathlib import Path

A, B, C = 0x400010, 0x400020, 0x400030
LENGTHS = (64, 128, 256, 512, 1024, 2048, 4096)
DEPTHS = (1, 2, 4, 8, 16, 32, 64, 128, 256)
EDGES = ((A, "cal", A), (A, "crt", B), (B, "jmp", A),
         (A, "jmp", C), (C, "jmp", A))


def case(length, depth):
    assert length >= 64 and length % 4 == 0 and 1 <= depth <= length // 4
    events = [{"row": 0, "kind": "jmp", "dst": A, "aux": 0, "hint": 0, "depth_after": 0}]
    stack = []

    def append(kind, dst, aux=0):
        hint = 0
        if kind == "cal":
            stack.append((aux, len(events)))
        elif kind == "ret":
            expected, hint = stack.pop()
            assert expected == dst
        events.append({"row": len(events), "kind": kind, "dst": dst, "aux": aux,
                       "hint": hint, "depth_after": len(stack)})

    remaining = length // 4
    while remaining:
        group = min(depth, remaining)
        for _ in range(group):
            append("cal", A, B)
        for _ in range(group):
            append("ret", B)
            append("jmp", A)
        remaining -= group
    while len(events) < length:
        append("jmp", C if events[-1]["dst"] == A else A)
    assert not stack and len(events) == length
    assert max(e["depth_after"] for e in events) == depth
    counts = {kind: sum(e["kind"] == kind for e in events) for kind in ("cal", "ret", "jmp")}
    assert counts == {"cal": length // 4, "ret": length // 4, "jmp": length // 2}
    for previous, event in zip(events, events[1:]):
        if event["kind"] in ("cal", "jmp"):
            assert (previous["dst"], event["kind"], event["dst"]) in EDGES
        if event["kind"] == "cal":
            assert (previous["dst"], "crt", event["aux"]) in EDGES
    return events, counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"Refusing to overwrite {output}")
    output.mkdir(parents=True)
    selected = {}
    for family, pairs in [
        ("length", [(length, 8) for length in LENGTHS]),
        ("depth", [(1024, depth) for depth in DEPTHS]),
        ("diagonal", [(length, length // 4) for length in LENGTHS]),
    ]:
        for pair in pairs:
            selected.setdefault(pair, []).append(family)
    cases = []
    for (length, depth), families in sorted(selected.items()):
        case_id = f"L{length:04d}-D{depth:04d}"
        target = output / case_id
        target.mkdir()
        events, counts = case(length, depth)
        ops = []
        for e in events[1:]:
            kind = {"cal": "call", "ret": "ret", "jmp": "jump"}[e["kind"]]
            ops.append(f"{kind} {e['dst']:#x}" + (f" {e['aux']:#x}" if kind == "call" else ""))
        names = ("row", "kind", "dst", "aux", "hint", "depth_after")
        files = {
            "translator": "".join(f"{x:#x}\n" for x in sorted((A, B, C))),
            "typed_cfg": "".join(f"{u:#x} {k} {v:#x}\n" for u, k, v in sorted(EDGES)),
            "recorded_path": f"initial_node={A:#x} final_node={events[-1]['dst']:#x}\n" + "\n".join(ops) + "\n",
            "events.tsv": "\t".join(names) + "\n" + "".join("\t".join(str(e[k]) for k in names) + "\n" for e in events),
            "events.json": json.dumps(events, indent=2) + "\n",
        }
        for name, content in files.items():
            (target / name).write_text(content)
        record = {
            "case_id": case_id, "families": families, "L": length, "active_rows": length,
            "ep_capacity": length, "actual_depth": depth, "zekra_depth_bound": depth,
            "binius_stack_pointer_bits": 15, "binius_depth_bound": 32767,
            "call_count": counts["cal"], "ret_count": counts["ret"], "jmp_count": counts["jmp"],
            "nodes": 3, "typed_edges": 5, "edge_capacity": 8,
            "checks": {"balanced_exact_returns": True, "forward_edges_valid": True,
                       "call_row_hints_valid": True, "actual_depth_attained": True},
            "sha256": {name: hashlib.sha256(content.encode()).hexdigest() for name, content in files.items()},
        }
        (target / "case.json").write_text(json.dumps(record, indent=2) + "\n")
        cases.append(record)
        print(case_id, ",".join(families), counts)
    manifest = {"schema": "zkcfa.research.stack-control-inputs.v1", "synthetic": True,
                "generation": "deterministic balanced recursive program model, without trace projection",
                "initial_row_convention": "L counts initial JMP as row 0; all capacities fully occupied",
                "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "cases": cases}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
