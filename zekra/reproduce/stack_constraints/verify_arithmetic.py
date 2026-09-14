#!/usr/bin/env python3
"""Independently evaluate exported C6 arithmetic files and recount R1CS rows.

The jsnark arithmetic format uses mul/assert/xor/or as one R1CS row,
zerop as two rows, and an n-bit split as n bit checks plus one packing row.
Linear add/constant multiplication/pack operations need no R1CS rows.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def verify(arith, witness):
    values = {int(w): int(v, 16) for w, v in (line.split() for line in witness.read_text().splitlines())}
    constraints = 0
    gates = 0
    for line in arith.read_text().splitlines():
        text = line.split("#", 1)[0].strip()
        if not text:
            continue
        op = text.split()[0]
        if op in ("total", "input", "nizkinput", "output"):
            if op in ("input", "nizkinput", "output"):
                assert int(text.split()[1]) in values, text
            continue
        match = re.fullmatch(r"\S+ in (\d+) <([^>]*)> out (\d+) <([^>]*)>", text)
        assert match, text
        inputs = list(map(int, match[2].split()))
        outputs = list(map(int, match[4].split()))
        assert len(inputs) == int(match[1]) and len(outputs) == int(match[3])
        args = [values[w] for w in inputs]
        gates += 1
        if op == "assert":
            assert args[0] * args[1] % P == values[outputs[0]], text
            constraints += 1
            continue
        if op == "add":
            result = [sum(args) % P]
        elif op == "mul":
            assert len(args) == 2
            result = [args[0] * args[1] % P]
            constraints += 1
        elif op.startswith("const-mul-"):
            constant = op[len("const-mul-"):]
            factor = -int(constant[4:], 16) if constant.startswith("neg-") else int(constant, 16)
            result = [args[0] * factor % P]
        elif op == "zerop":
            result = [pow(args[0], -1, P), 1] if args[0] else [0, 0]
            constraints += 2
        elif op == "split":
            assert args[0] < (1 << len(outputs)), text
            result = [(args[0] >> i) & 1 for i in range(len(outputs))]
            constraints += len(outputs) + 1
        elif op == "pack":
            assert all(v in (0, 1) for v in args), text
            result = [sum(v << i for i, v in enumerate(args)) % P]
        elif op in ("xor", "or"):
            assert all(v in (0, 1) for v in args), text
            result = [args[0] ^ args[1] if op == "xor" else args[0] | args[1]]
            constraints += 1
        else:
            raise ValueError(f"unsupported gate: {op}")
        assert len(result) == len(outputs)
        for wire, value in zip(outputs, result):
            assert wire not in values or values[wire] == value, (text, wire)
            values[wire] = value
    return {"r1cs_constraints": constraints, "arithmetic_gates_evaluated": gates,
            "evaluated_wires": len(values), "satisfied": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    args = parser.parse_args()
    report = json.loads((args.campaign / "measurement.json").read_text())
    results = []
    for case in report["cases"]:
        directory = args.campaign / case["case_id"]
        outcome = verify(directory / "zekra_c6.arith", directory / "zekra_c6_Sample_Run1.in")
        assert outcome["r1cs_constraints"] == case["r1cs_constraints"], case["case_id"]
        outcome["case_id"] = case["case_id"]
        results.append(outcome)
        print(json.dumps(outcome), flush=True)
    result = {"schema": "zkcfa.zekra.stack-arithmetic-verification.v1",
              "verifier_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "modulus": str(P), "cases": results}
    (args.campaign / "arithmetic-verification.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
