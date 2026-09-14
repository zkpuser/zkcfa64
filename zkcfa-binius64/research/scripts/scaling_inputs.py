#!/usr/bin/env python3
"""Audited synthetic CFA families for controlled circuit/proof scaling measurements.

These are program-model fixtures, not QEMU executions or signed acquisition evidence.
The graph/function skeleton is constructed before the path. Projection never adds CFG edges.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SIZES = (64, 128, 256, 512, 1024, 2048, 4096)
SCOPE = 0x400000


def projectors():
    sys.path.insert(0, str(ROOT / "zkcfa-tracer/provider"))
    from static.projection import shadow_safe_compress

    path = ROOT / "zkcfa-tracer/research/zekra_projection.py"
    spec = importlib.util.spec_from_file_location("static.scaling_zekra_projection", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return shadow_safe_compress, module.zekra_compress


def fitted(value, minimum):
    return 1 << (max(value, minimum) - 1).bit_length()


def fixed_graph(size):
    a, b, c, e, d = (SCOPE + 0x10 * i for i in range(1, 6))
    nodes = {SCOPE, a, b, c, e, d}
    edges = {(SCOPE, "cal", a), (SCOPE, "crt", SCOPE), (a, "jmp", b),
             (b, "cal", c), (b, "crt", d), (c, "jmp", e), (d, "jmp", b)}
    # Return sites follow the declared function skeleton, independently of loop executions.
    returns = {(e, d), (b, SCOPE)}
    loops = (size - 4) // 4
    operations = [("call", a, SCOPE), ("jump", b, None)]
    operations += [("call", c, d), ("jump", e, None),
                   ("ret", d, None), ("jump", b, None)] * loops
    operations.append(("ret", SCOPE, None))
    return nodes, edges, returns, operations, {"loop_repetitions": loops, "sites": 1}


def growing_graph(size):
    sites = size // 16
    blocks = [tuple(SCOPE + 0x100 + i * 0x100 + j * 0x10 for j in range(7))
              for i in range(sites)]
    # A0/A1 lead into B; B calls C, C jumps to E, E returns to D, D loops to B;
    # B can exit to X. X links to the next block or returns from the root function.
    nodes = {SCOPE}
    edges = {(SCOPE, "cal", blocks[0][2]), (SCOPE, "crt", SCOPE)}
    returns = set()
    for i, (a0, a1, b, c, e, d, x) in enumerate(blocks):
        nodes.update((b, c, e, d, x))
        edges.update({(b, "cal", c), (b, "crt", d), (c, "jmp", e),
                      (d, "jmp", b), (b, "jmp", x)})
        returns.add((e, d))
        if i:
            nodes.update((a0, a1))
            edges.update({(a0, "jmp", a1), (a1, "jmp", b)})
        if i < sites - 1:
            edges.add((x, "jmp", blocks[i + 1][0]))
        else:
            returns.add((x, SCOPE))
    operations = [("call", blocks[0][2], SCOPE)]
    for i, (a0, a1, b, c, e, d, x) in enumerate(blocks):
        if i:
            operations += [("jump", a1, None), ("jump", b, None)]
        operations += [("call", c, d), ("jump", e, None),
                       ("ret", d, None), ("jump", b, None)] * 3
        operations.append(("jump", x, None))
        operations.append(("jump", blocks[i + 1][0], None) if i < sites - 1
                          else ("ret", SCOPE, None))
    return nodes, edges, returns, operations, {"loop_repetitions": 3, "sites": sites}


def audit(nodes, edges, returns, operations):
    assert all(0 < x < 0xff0000 for x in nodes)
    assert all(u in nodes and v in nodes for u, _, v in edges)
    assert len({(u, v) for u, _, v in edges}) == len(edges)
    current = SCOPE
    stack = []
    max_depth = 0
    for kind, destination, auxiliary in operations:
        assert destination in nodes
        if kind == "call":
            assert (current, "cal", destination) in edges
            assert (current, "crt", auxiliary) in edges
            stack.append(auxiliary)
            max_depth = max(max_depth, len(stack))
        elif kind == "jump":
            assert (current, "jmp", destination) in edges
        elif kind == "ret":
            assert stack and stack.pop() == destination
            assert (current, destination) in returns
        else:
            raise ValueError(kind)
        current = destination
    assert current == SCOPE and not stack
    return {"typed_forward_edges_valid": True, "balanced_exact_returns": True,
            "static_return_edges_valid": True, "endpoints_match": True,
            "max_stack_depth": max_depth}


def render(operations):
    lines = [f"initial_node={SCOPE:#x} final_node={SCOPE:#x}"]
    for kind, destination, auxiliary in operations:
        lines.append(f"{kind} {destination:#x}" +
                     (f" {auxiliary:#x}" if kind == "call" else ""))
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"Refusing to replace existing inputs: {output}")
    shadow_project, zekra_project = projectors()
    output.mkdir(parents=True)
    cases = []
    for family, generator in [("fixed-cfg", fixed_graph), ("growing-cfg", growing_graph)]:
        for size in SIZES:
            nodes, edges, returns, complete, parameters = generator(size)
            assert len(complete) + 1 == size
            shadow, shadow_decisions = shadow_project(complete)
            zekra, zekra_decisions = zekra_project(complete)
            mode_rows = {}
            checks = {}
            hashes = {}
            for mode, operations in [("complete", complete), ("shadow", shadow), ("zekra", zekra)]:
                checks[mode] = audit(nodes, edges, returns, operations)
                target = output / family / str(size) / mode
                target.mkdir(parents=True)
                files = {"translator": "".join(f"{x:#x}\n" for x in sorted(nodes)),
                         "typed_cfg": "".join(f"{u:#x} {k} {v:#x}\n" for u, k, v in sorted(edges)),
                         "static_returns.tsv": "".join(f"{u:#x}\t{v:#x}\n" for u, v in sorted(returns)),
                         "recorded_path": render(operations)}
                hashes[mode] = {}
                for name, text in files.items():
                    (target / name).write_text(text)
                    hashes[mode][name] = hashlib.sha256(text.encode()).hexdigest()
                mode_rows[mode] = len(operations) + 1
            case = {"family": family, "source_ep_rows": size, "nodes": len(nodes),
                    "typed_edges": len(edges), "static_return_edges": len(returns),
                    "parameters": parameters, "rows_by_mode": mode_rows,
                    "binius_edge_cap": fitted(len(edges), 8),
                    "binius_ep_cap": {m: fitted(n, 16) for m, n in mode_rows.items()},
                    "shadow_and_zekra_paths_equal": shadow == zekra,
                    "audit": checks, "input_sha256": hashes,
                    "shadow_decisions": shadow_decisions, "zekra_decisions": zekra_decisions}
            (output / family / str(size) / "case.json").write_text(json.dumps(case, indent=2) + "\n")
            cases.append(case)
    paths = [Path(__file__), ROOT / "zkcfa-tracer/provider/static/projection.py",
             ROOT / "zkcfa-tracer/research/zekra_projection.py"]
    manifest = {"schema": "zkcfa.synthetic-scaling-inputs.v1", "research_only": True,
                "acquisition": "Deterministic synthetic program models; no QEMU capture or signatures.",
                "sizes": SIZES, "cases": cases,
                "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in paths}}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    for c in cases:
        print(c["family"], c["source_ep_rows"], "nodes", c["nodes"], "edges", c["typed_edges"],
              "rows", c["rows_by_mode"])


if __name__ == "__main__":
    main()
