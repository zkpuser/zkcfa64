#!/usr/bin/env python3
"""Reproduce the native-memory truncation negative/positive control in a new directory.

This 128-node acyclic synthetic fixture is excluded from performance aggregates.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

import run_scaling as scaling


def prepare(output):
    output.mkdir(parents=True, exist_ok=False)
    fixture = output / "input"
    fixture.mkdir()
    (fixture / "translator").write_text("".join(f"{n:#x}\n" for n in range(1, 129)))
    edges = [(128, n) for n in (8, 16, 24)] + [(n, n + 1) for n in range(8, 101)]
    (fixture / "typed_cfg").write_text("".join(f"{a:#x} jmp {b:#x}\n" for a, b in edges))
    (fixture / "recorded_path").write_text(
        "initial_node=0x80 final_node=0x65\n" + "".join(f"jump {n:#x}\n" for n in range(8, 102)))
    report = {"schema": "zkcfa.zekra.native-memory-control-preparation.v1",
              "description": "Synthetic 128-node acyclic raw24 fixture with 39-bit adjacency encoding",
              "excluded_from_formal_timings": True,
              "input_sha256": {file.name: scaling.sha(file) for file in sorted(fixture.iterdir())},
              "source_sha256": {file.name: scaling.sha(file) for file in (
                  Path(__file__), scaling.HERE / "run_scaling.py", scaling.HERE / "PatchNativeMemory.java",
                  scaling.HERE / "CheckNativeMemory.java")}}
    scaling.save(output / "preparation.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    if args.prepare_only:
        print(json.dumps(prepare(output), sort_keys=True))
        return 0
    prep = json.loads((output / "preparation.json").read_text())
    for name, expected in prep["input_sha256"].items():
        if scaling.sha(output / "input" / name) != expected:
            raise ValueError("prepared control fixture changed: " + name)
    for name, expected in prep["source_sha256"].items():
        if scaling.sha(scaling.HERE / name) != expected:
            raise ValueError("prepared control execution source changed: " + name)
    subprocess.run([sys.executable, str(scaling.HERE / "run_scaling.py"), "--input", str(output / "input"),
                    "--output", str(output / "repaired"), "--levels", "4", "--repetitions", "1"], check=True)
    repaired = json.loads((output / "repaired/measurement.json").read_text())
    if repaired["status"] != "verified":
        raise ValueError("positive repaired control did not verify")
    original = output / "original"
    (original / "source").mkdir(parents=True)
    for name in ("scripts", "zekra_java"):
        shutil.copytree(scaling.UPSTREAM / name, original / "source" / name)
    if scaling.sha(scaling.UPSTREAM / "xjsnark_backend.jar") != scaling.PINNED_JAR:
        raise ValueError("upstream jar changed")
    shutil.copy2(scaling.UPSTREAM / "xjsnark_backend.jar", original / "source/xjsnark_backend.jar")
    (original / "inputs").mkdir()
    formatted = {}
    for file in (output / "repaired/inputs").glob("in_*"):
        shutil.copy2(file, original / "inputs" / file.name)
        formatted[file.name] = scaling.sha(file)
        if scaling.sha(original / "inputs" / file.name) != formatted[file.name]:
            raise ValueError("control formatted inputs differ")
    parameters = repaired["input"]["parameters"]
    command = ["python3", "scripts/compile_circuit.py", "--zekra-dir", "zekra_java/zekra",
               "--input-dir", "/work/inputs", "--output-dir", "/work/inputs"]
    for name, value in parameters.items():
        command.extend(["--" + name.replace("_", "-"), str(value)])
    image = repaired["environment"]["compile_image"]["Id"]
    observed = scaling.run(scaling.docker_command(image, "amd64", original, command), original / "compile.log")
    text = (original / "compile.log").read_text()
    count = re.search(r"Total constraints: (\d+)", text)
    assertion = re.search(r"(?m)^(\d+)\*1!=(\d+)", text)
    if not count or not assertion or "Circuit was not satisfied" not in text:
        raise ValueError("negative original-jar control did not expose the expected assertion")
    witness, memory = map(int, assertion.groups())
    if int(count[1]) != repaired["r1cs_constraints"] or memory != witness % 2**32 or witness == memory:
        raise ValueError("negative control is not an equal-size native-memory 32-bit truncation")
    report = {"schema": "zkcfa.zekra.native-memory-repair-control.v3", "validated": True,
              "excluded_from_formal_timings": True, "input_sha256": prep["input_sha256"],
              "execution_sources_sha256": prep["source_sha256"], "parameters": parameters,
              "encoded_adjacency_max_bits": repaired["input"]["maximum_encoded_adjacency_bitwidth"],
              "formatted_inputs_sha256": formatted,
              "original": {"jar_sha256": scaling.PINNED_JAR, "sample_satisfied": False,
                           "groth16_attempted": False, "r1cs_constraints": int(count[1]),
                           "assertion": assertion[0], "witness_operand": witness, "memory_operand": memory,
                           "memory_equals_witness_mod_2_32": True, "compile": observed},
              "repaired": {"jar_sha256": repaired["sources"]["jar_after_sha256"],
                           "sample_satisfied": True, "groth16_verified": True,
                           "r1cs_constraints": repaired["r1cs_constraints"],
                           "measurement_path": str(output / "repaired/measurement.json"),
                           "measurement_sha256": scaling.sha(output / "repaired/measurement.json")}}
    scaling.save(output / "control.json", report)
    print(json.dumps({"validated": True, "original_sample_satisfied": False, "repaired_verified": True,
                      "r1cs_constraints": repaired["r1cs_constraints"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
