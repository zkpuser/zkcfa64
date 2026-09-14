#!/usr/bin/env python3
"""Measure released ZEKRA C6 R1CS constraints on valid synthetic stack traces.

Only an isolated copy is parameterized. The released gadget and the existing
native-field SmartMemory repair are retained; no Groth16 proving is performed.
"""
import argparse
import csv
import hashlib
import json
import re
import shutil
import subprocess
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ZEKRA = HERE.parents[1]
SOURCE = ZEKRA / "ZEKRA/zekra_java/components/zekra_c6/zekra_c6.java"
JAR = ZEKRA / "ZEKRA/xjsnark_backend.jar"
PINNED_JAR = "d6966c45ad659627027d19b4d8389d58a452f82ca416f1057efcdd428fbb535b"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(command, log, timeout=600):
    start = time.monotonic()
    with log.open("w") as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT,
                                timeout=timeout)
    return {"command": command, "returncode": result.returncode,
            "wall_seconds": time.monotonic() - start, "log_sha256": sha(log)}


def parameterize(length, depth, pointer_bits=None, *, released_source):
    source = released_source.read_text()
    source = source.replace("Config.writeCircuits = false;", "Config.writeCircuits = true;")
    for name, value in [("EXECUTION_PATH_SIZE", length), ("SHADOWSTACK_DEPTH", depth)]:
        source, count = re.subn(r"(private static int " + name + r" = )\d+;",
                               rf"\g<1>{value};", source)
        assert count == 1
    width = pointer_bits or depth.bit_length()
    source, count = re.subn(r"shadowStackTop = new UnsignedInteger\(4,",
                            f"shadowStackTop = new UnsignedInteger({width},", source)
    assert count == 1
    source, count = re.subn(r"(shadowStackTop.assign\([^\n]+), 4\);",
                            rf"\g<1>, {width});", source)
    assert count == 3
    pre_start = source.index("      public void pre() {")
    pre_end = source.index("      public void post()", pre_start)
    # Event values are assigned only after circuit generation, so private
    # branch kinds and memory indexes cannot constant-fold the measured gadget.
    sample = '''      public void pre() {
        try {
          java.util.List<String> rows = java.nio.file.Files.readAllLines(
              java.nio.file.Paths.get(System.getProperty("stack.events")));
          if (rows.size() != EXECUTION_PATH_SIZE + 1) throw new IllegalArgumentException("event count");
          boolean badReturn = Boolean.getBoolean("stack.badReturn");
          for (int i = 0; i < EXECUTION_PATH_SIZE; i++) {
            String[] row = rows.get(i + 1).split("\\t");
            int kind = row[1].equals("cal") ? 1 : row[1].equals("ret") ? 2 : 0;
            BigInteger dest = new BigInteger(row[2]);
            BigInteger ret = new BigInteger(row[3]);
            if (badReturn && kind == 2) { dest = dest.add(BigInteger.ONE); badReturn = false; }
            CircuitEvaluator evaluator = CircuitGenerator.__getActiveCircuitGenerator().__getCircuitEvaluator();
            EXECUTION_PATH[i][0].mapValue(BigInteger.valueOf(kind), evaluator);
            EXECUTION_PATH[i][1].mapValue(dest, evaluator);
            EXECUTION_PATH[i][2].mapValue(ret, evaluator);
            NUMIFIED_EXECUTION_PATH[i][0].mapValue(dest, evaluator);
            NUMIFIED_EXECUTION_PATH[i][1].mapValue(ret, evaluator);
          }
        } catch (java.io.IOException error) { throw new RuntimeException(error); }
      }
'''
    source = source.replace("    __generateCircuit();", """    __generateCircuit();
    System.out.println("STACK_MEMORY mode=" + shadowStackMem.getState().getMode()
      + " packing=" + shadowStackMem.getState().getPackingOption()
      + " index_bits=" + shadowStackMem.getState().getIndexBitsSplitted());""")
    # Recompute offsets because the logging statement changed constructor size.
    pre_start = source.index("      public void pre() {")
    pre_end = source.index("      public void post()", pre_start)
    return source[:pre_start] + sample + source[pre_end:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image", default="zkcfa-zekra:paper-ubuntu22.04")
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--pointer-bits", type=int)
    args = parser.parse_args()
    output = args.output.resolve()
    upstream = (ZEKRA / "ZEKRA").resolve()
    if output == upstream or upstream in output.parents:
        parser.error("output must be outside the upstream checkout")
    output.mkdir(parents=True, exist_ok=False)
    assert sha(JAR) == PINNED_JAR
    released_source = output / "released_zekra_c6.java"
    shutil.copy2(SOURCE, released_source)
    environment = json.loads(subprocess.check_output(
        ["docker", "image", "inspect", args.image], text=True))[0]
    report = {"schema": "zkcfa.zekra.stack-constraints.v1", "status": "running",
              "constraint_unit": "BN254 R1CS rows reported by xJsnark",
              "measurement_kind": "isolated released C6 gadget, compile and evaluate valid witness",
              "source_sha256": sha(released_source), "runner_sha256": sha(Path(__file__)),
              "original_jar_sha256": sha(JAR),
              "image": {k: environment[k] for k in ("Id", "Architecture", "Created")},
              "cases": []}

    def save():
        (output / "measurement.json").write_text(json.dumps(report, indent=2) + "\n")

    def docker(command, work="/work", timeout=600):
        return ["docker", "run", "--rm", "--network", "none", "--platform", "linux/amd64",
                "--volume", f"{output}:/work", "--workdir", work, args.image] + command

    shutil.copy2(JAR, output / "original.jar")
    for name in ("PatchNativeMemory.java", "CheckNativeMemory.java"):
        shutil.copy2(ZEKRA / "reproduce/scaling" / name, output / name)
    setup = "\n".join([
        "javac --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED PatchNativeMemory.java",
        "java --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED -cp .:original.jar PatchNativeMemory original.jar xjsnark_backend.jar",
        "javac -cp original.jar CheckNativeMemory.java",
        "java -cp .:original.jar CheckNativeMemory",
        "java -cp .:xjsnark_backend.jar CheckNativeMemory fixed",
        "java -version",
    ])
    report["setup"] = execute(docker(["sh", "-ec", setup]), output / "00-setup.log")
    assert report["setup"]["returncode"] == 0
    report["patched_jar_sha256"] = sha(output / "xjsnark_backend.jar")
    with zipfile.ZipFile(output / "original.jar") as old, zipfile.ZipFile(output / "xjsnark_backend.jar") as new:
        assert old.namelist() == new.namelist()
        changed = sorted(n for n in old.namelist() if old.read(n) != new.read(n))
        assert changed == ["backend/auxTypes/SmartMemory$2.class", "backend/auxTypes/SmartMemory$3.class",
                           "backend/auxTypes/SmartMemory$4.class", "backend/auxTypes/SmartMemory.class"]
        report["changed_jar_entries"] = changed
    save()
    manifest = json.loads((args.inputs / "manifest.json").read_text())
    report["input_manifest_sha256"] = sha(args.inputs / "manifest.json")
    cases = [c for c in manifest["cases"] if not args.case or c["case_id"] in args.case]
    assert cases
    for fixture in cases:
        length, depth = fixture["L"], fixture["zekra_depth_bound"]
        name = fixture["case_id"]
        assert 1 <= depth <= length // 2
        case = output / name
        case.mkdir()
        shutil.copy2(args.inputs / name / "events.tsv", case / "events.tsv")
        shutil.copy2(args.inputs / name / "case.json", case / "case.json")
        assert sha(case / "events.tsv") == fixture["sha256"]["events.tsv"]
        (case / "zekra_c6.java").write_text(parameterize(
            length, depth, args.pointer_bits, released_source=released_source))
        shell = "\n".join([
            "javac -d bin -cp /work/xjsnark_backend.jar zekra_c6.java",
            f"java -Xmx6g -Dstack.events=/work/{name}/events.tsv -cp bin:/work/xjsnark_backend.jar xjsnark.zekra_c6.zekra_c6",
        ])
        run = execute(docker(["sh", "-ec", shell], f"/work/{name}"), case / "compile-evaluate.log", 1200)
        log = (case / "compile-evaluate.log").read_text()
        counts = re.findall(r"Total Number of Constraints\s*:\s*(\d+)", log)
        passed = (run["returncode"] == 0 and len(counts) > 0 and
                  "Sample Run: Sample_Run1 finished!" in log and
                  not re.search(r"not satisfied|Error Detected|Exception|Error in", log, re.I))
        mode = re.search(r"STACK_MEMORY mode=(\d+) packing=(\d+) index_bits=(\d+)", log)
        record = {"case_id": name, "families": fixture["families"], "L": length, "D": depth,
                  "actual_max_depth": depth, "stack_pointer_bits": args.pointer_bits or depth.bit_length(),
                  "call_count": fixture["call_count"], "ret_count": fixture["ret_count"],
                  "jmp_count": fixture["jmp_count"], "events_sha256": sha(case / "events.tsv"),
                  "source_sha256": sha(case / "zekra_c6.java"), "execution": run,
                  "witness_satisfied": passed, "r1cs_constraints": int(counts[-1]) if counts else None,
                  "smart_memory_mode": int(mode[1]) if mode else None,
                  "smart_memory_packing": int(mode[2]) if mode else None,
                  "smart_memory_index_bits": int(mode[3]) if mode else None}
        for artifact in ("zekra_c6.arith", "zekra_c6_Sample_Run1.in"):
            if (case / artifact).exists():
                record[artifact + "_sha256"] = sha(case / artifact)
        report["cases"].append(record)
        save()
        print(json.dumps({k: record[k] for k in ("case_id", "r1cs_constraints", "witness_satisfied", "smart_memory_mode")}), flush=True)
        if not passed:
            raise RuntimeError(f"case {name} failed; inspect its retained log")
    # A wrong continuation must fail, proving the benchmark exercises return checks.
    target = output / cases[0]["case_id"]
    negative = target / "negative"
    negative.mkdir()
    command = ["java", "-Xmx6g", "-Dstack.badReturn=true", "-cp",
               "../bin:/work/xjsnark_backend.jar", f"-Dstack.events=/work/{target.name}/events.tsv",
               "xjsnark.zekra_c6.zekra_c6"]
    report["negative_return"] = execute(docker(command, f"/work/{target.name}/negative"), negative / "evaluate.log")
    text = (negative / "evaluate.log").read_text()
    report["negative_return"]["rejected"] = "Sample Run: Sample_Run1 finished!" not in text and bool(re.search(r"Error|Exception|not satisfied", text, re.I))
    assert report["negative_return"]["rejected"]
    with (output / "constraints.csv").open("w", newline="") as stream:
        fields = ["family", "case_id", "L", "D", "actual_max_depth", "stack_pointer_bits",
                  "call_count", "ret_count", "jmp_count", "r1cs_constraints", "witness_satisfied",
                  "smart_memory_mode", "smart_memory_packing", "smart_memory_index_bits"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for record in report["cases"]:
            for family in record["families"]:
                writer.writerow({"family": family, **{k: record[k] for k in fields[1:]}})
    report["status"] = "complete"
    save()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
