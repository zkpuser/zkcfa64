#!/usr/bin/env python3
"""Measure repaired ZEKRA on a same-source synthetic CFA scaling fixture.

No writes enter the upstream submodule. The output directory must be new.
"""
from __future__ import annotations

import argparse
import importlib.util
from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
UPSTREAM = ROOT / "zekra/ZEKRA"
COMPRESSOR = ROOT / "zkcfa-tracer/research/zekra_projection.py"
PINNED_UPSTREAM = "01a0152bfd9812a0569dce19965e7e92df30015d"
PINNED_JAR = "d6966c45ad659627027d19b4d8389d58a452f82ca416f1057efcdd428fbb535b"
NATIVE_BINARY = "/opt/jsnark/libsnark/build/libsnark/jsnark_interface/run_ppzksnark"
Operation = tuple[str, int, int | None]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot_upstream(destination: Path) -> dict:
    """Freeze committed compiler sources without copying ignored build products."""
    upstream, destination = UPSTREAM.resolve(), destination.resolve()
    if destination == upstream or upstream in destination.parents:
        raise ValueError("the source snapshot must be outside the upstream checkout")
    revision = capture(["git", "-C", str(upstream), "rev-parse", "HEAD"]).strip()
    if revision != PINNED_UPSTREAM:
        raise ValueError("upstream ZEKRA is not at the pinned revision")
    if capture(["git", "-C", str(upstream), "status", "--porcelain"]).strip():
        raise ValueError("upstream ZEKRA must be clean before taking a source snapshot")
    archive = subprocess.check_output([
        "git", "-C", str(upstream), "archive", "--format=tar", revision,
        "scripts", "zekra_java", "xjsnark_backend.jar",
    ])
    destination.mkdir()
    subprocess.run(["tar", "-xf", "-", "-C", str(destination)], input=archive, check=True)
    jar = destination / "xjsnark_backend.jar"
    if sha(jar) != PINNED_JAR:
        raise ValueError("upstream jar changed; native-memory patch must be reviewed")
    jar.rename(destination / "original.jar")
    return {
        "upstream_revision": revision,
        "upstream_dirty": "",
        "upstream_archive_sha256": hashlib.sha256(archive).hexdigest(),
        "java_before_sha256": sha(destination / "zekra_java/zekra/zekra.java"),
        "jar_before_sha256": sha(destination / "original.jar"),
    }


def save(path: Path, value: object) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temp.replace(path)


def run(command: list[str], log: Path, timeout: int = 1800) -> dict:
    start = time.monotonic()
    with log.open("w") as output:
        try:
            proc = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            rc = "timeout"
            if command[:2] == ["docker","run"] and "--name" in command:
                subprocess.run(["docker","rm","--force",command[command.index("--name")+1]],
                               stdout=output,stderr=subprocess.STDOUT,timeout=30)
        except KeyboardInterrupt:
            if command[:2] == ["docker","run"] and "--name" in command:
                subprocess.run(["docker","rm","--force",command[command.index("--name")+1]],
                               stdout=output,stderr=subprocess.STDOUT,timeout=30)
            raise
    return {"command": command, "returncode": rc, "wall_seconds": time.monotonic()-start,
            "log": str(log), "log_sha256": sha(log)}


def capture(command: list[str]) -> str:
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)


def p2(n: int, minimum: int = 1) -> int:
    return max(minimum, 1 << max(0, n-1).bit_length())


def addr(token: str) -> int:
    value = int(token, 16)
    if not 0 < value < (1 << 24):
        raise ValueError(f"fixture address outside nonzero raw24: {token}")
    return value


def load_compressor():
    spec = importlib.util.spec_from_file_location("zekra_projection", COMPRESSOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.zekra_compress


def read_fixture(directory: Path) -> tuple[list[int], set[tuple[int,str,int]], int, int, list[Operation]]:
    nodes = [addr(s) for s in (directory/"translator").read_text().split()]
    if len(set(nodes)) != len(nodes):
        raise ValueError("duplicate translator address")
    edges = set()
    for line in (directory/"typed_cfg").read_text().splitlines():
        s, kind, d = line.split()
        if kind not in {"jmp", "cal", "crt"}:
            raise ValueError("only jmp/cal/crt source typed edges are supported")
        edge = (addr(s), kind, addr(d))
        if edge in edges or edge[0] not in nodes or edge[2] not in nodes:
            raise ValueError("duplicate or unmapped typed edge")
        edges.add(edge)
    lines = (directory/"recorded_path").read_text().splitlines()
    match = re.fullmatch(r"initial_node=(\S+) final_node=(\S+)", lines[0])
    if not match:
        raise ValueError("invalid recorded_path header")
    initial, final = map(addr, match.groups())
    operations = []
    for line in lines[1:]:
        fields = line.split()
        if (fields[0] not in {"call", "jump", "ret"}
            or len(fields) != (3 if fields[0] == "call" else 2)):
            raise ValueError("invalid operation")
        operations.append((fields[0], addr(fields[1]), addr(fields[2]) if len(fields)==3 else None))
    return nodes, edges, initial, final, operations


def static_return_edges(nodes: list[int], edges: set[tuple[int,str,int]],
                        declared: set[tuple[int,int]] | None = None) -> set[tuple[int,int]]:
    """Expand returns from static callee traversal; never inspect an EP row.

    A generator sidecar may declare return transitions at nodes that also allow
    other edge kinds. Every declared return must be statically reachable from a
    callee with the matching caller CRT. Without a sidecar, terminal CFG nodes
    are the only return blocks. Neither branch inspects the execution path.
    """
    jumps, calls, crts = defaultdict(set), defaultdict(set), defaultdict(set)
    for source, kind, destination in edges:
        {"jmp": jumps, "cal": calls, "crt": crts}[kind][source].add(destination)
    result = set()
    for site, targets in list(calls.items()):
        if len(crts[site]) != 1:
            raise ValueError("fixture calls require one CRT at a call block")
        continuation = next(iter(crts[site]))
        for entry in targets:
            pending, visited, exits = [entry], set(), set()
            while pending:
                node = pending.pop()
                if node in visited:
                    continue
                visited.add(node)
                if declared is not None and (node, continuation) in declared:
                    exits.add(node)
                pending.extend(jumps[node])
                if calls[node]:
                    if len(crts[node]) != 1:
                        raise ValueError("ambiguous nested call continuation")
                    pending.extend(crts[node])
                elif not jumps[node] and declared is None:
                    exits.add(node)
            if not exits:
                raise ValueError(f"callee {entry:#x} has no statically reachable return")
            result.update((exit_node, continuation) for exit_node in exits)
    if declared is not None and result != declared:
        raise ValueError("a declared return is unreachable from any matching callee")
    return result


def audit(initial: int, final: int, operations: list[Operation], nodes: list[int],
          typed: set[tuple[int,str,int]], returns: set[tuple[int,int]]) -> dict:
    state, stack, peak = initial, [], 0
    for index, (kind, dest, aux) in enumerate(operations):
        if dest not in nodes or state not in nodes:
            raise ValueError(f"unmapped operation {index}")
        if kind == "call":
            if (state, "cal", dest) not in typed or (state, "crt", aux) not in typed:
                raise ValueError(f"invalid call/continuation at {index}")
            stack.append(aux)
            peak = max(peak, len(stack))
        elif kind == "jump":
            if (state, "jmp", dest) not in typed:
                raise ValueError(f"invalid jump at {index}")
        elif kind == "ret":
            if not stack or stack.pop() != dest or (state,dest) not in returns:
                raise ValueError(f"invalid return at {index}")
        state = dest
    if state != final or stack:
        raise ValueError("path has incorrect final state or nonempty stack")
    return {"operations": len(operations), "rows_with_initial": len(operations)+1,
            "max_stack_depth": peak, "valid_typed_edges_and_balanced_stack": True}


def prepare_inputs(source: Path, destination: Path, levels: int) -> dict:
    nodes, typed, initial, final, operations = read_fixture(source)
    return_sidecar = source/"static_returns.tsv"
    declared = None
    if return_sidecar.is_file():
        declared = {tuple(map(addr,line.split())) for line in return_sidecar.read_text().splitlines()}
        if any(len(edge)!=2 or edge[0] not in nodes or edge[1] not in nodes for edge in declared):
            raise ValueError("unmapped or malformed predefined return edge")
    returns = static_return_edges(nodes, typed, declared)
    original = audit(initial, final, operations, nodes, typed, returns)
    projected, decisions = load_compressor()(operations)
    compressed = audit(initial, final, projected, nodes, typed, returns)
    # Remove only the edge-kind tag. Static RET expansion is separately attributed.
    adjacency = {(s,d) for s,kind,d in typed} | returns
    by_source = {node: set() for node in nodes}
    for s,d in adjacency:
        by_source[s].add(d)
    labels = {node: index for index,node in enumerate(nodes)}
    required = max((len({labels[d]//8 for d in by_source[s]}) for s in nodes), default=0)
    if required > levels:
        raise ValueError(f"requires {required} adjacency levels, fixed campaign uses {levels}")
    adj_cap, ep_cap = p2(len(nodes),8), p2(len(projected),16)
    label_bits, bucket_bits = adj_cap.bit_length(), (adj_cap//8).bit_length()
    if levels*(bucket_bits+8) >= 254:
        raise ValueError("encoded neighbors exceed the upstream formatter's field limit")
    encoded_widths = []
    for node in nodes:
        buckets = {}
        for destination_node in sorted(by_source[node]):
            label = labels[destination_node]
            buckets[label//8] = buckets.get(label//8,0) | (1 << (label%8))
        encoded = 0
        for bucket, mask in buckets.items():
            encoded = (encoded << (bucket_bits+8)) | (mask << bucket_bits) | bucket
        encoded_widths.append(encoded.bit_length())
    destination.mkdir()
    (destination/"translator").write_text("\n".join(f"0x{node:x}" for node in nodes)+"\n")
    (destination/"adjlist").write_text("\n".join(" ".join(f"0x{d:x}" for d in [s]+sorted(by_source[s])) for s in nodes)+"\n")
    (destination/"numified_adjlist").write_text("\n".join(" ".join(str(labels[d]) for d in [s]+sorted(by_source[s])) for s in nodes)+"\n")
    for numeric, name in ((False,"recorded_path"),(True,"numified_path")):
        token = (lambda x: str(labels[x])) if numeric else (lambda x: f"0x{x:x}")
        rows = [f"initial_node={token(initial)} final_node={token(final)}"]
        for kind,dest,aux in projected:
            rows.append(f"{kind} {token(dest)}"+(f" {token(aux)}" if kind=="call" else ""))
        (destination/name).write_text("\n".join(rows)+"\n")
    return {
        "source_hashes": {name:sha(source/name) for name in ("translator","typed_cfg","recorded_path")},
        "projected_hashes": {path.name:sha(path) for path in destination.iterdir()},
        "projection": "repository original zekra_compress, rejected if typed/stack audit fails",
        "compressor_file": str(COMPRESSOR), "compressor_sha256":sha(COMPRESSOR),
        "compression_decisions": decisions, "original":original, "projected":compressed,
        "static_returns": {"method":("generator-declared return relation, validated by callee JMP/CRT reachability"
                                    if declared is not None else "callee JMP/CRT reachability and terminal blocks")
                                    + "; no execution-path-derived edges",
                           "count":len(returns),"edges":[[s,d] for s,d in sorted(returns)],
                           "sidecar_sha256":sha(return_sidecar) if return_sidecar.is_file() else None,
                           "sidecar_matches_static_reachability":return_sidecar.is_file()},
        "source_typed_edges":len(typed), "untyped_edges":len(adjacency),
        "maximum_outdegree":max(map(len,by_source.values())), "required_levels":required,
        "maximum_encoded_adjacency_bitwidth":max(encoded_widths),
        "encoded_adjacency_entries_above_32_bits":sum(bits>32 for bits in encoded_widths),
        "parameters":{"adjlist_len":adj_cap,"path_len":ep_cap,"adjlist_levels":levels,
                      "stack_depth":15,"label_bitwidth":label_bits,
                      "bucket_bitwidth":bucket_bits,"address_bitwidth":24},
    }


def docker_command(image: str, arch: str, output: Path, command: list[str]) -> list[str]:
    return ["docker","run","--rm","--network","none","--platform",f"linux/{arch}",
            "--name","zkcfa-scaling-"+uuid.uuid4().hex[:16],
            "--env","OMP_NUM_THREADS=8","--env","OMP_DYNAMIC=FALSE",
            "--volume",f"{output}:/work","--workdir","/work/source",image]+command


def native_measurements(report: dict, output: Path, native_image: str, timeout: int) -> None:
    """Keep excluded warmups separate from measured native proof invocations."""
    report_path = output / "measurement.json"
    phases = (("warmup", report["warmup_repetitions"], "warmup_runs"),
              ("measured", report["repetitions"], "runs"))
    for kind, count, field in phases:
        for repetition in range(1, count + 1):
            suffix = f"warmup{repetition}" if kind == "warmup" else f"r{repetition}"
            log = output / f"04-groth16-{suffix}.log"
            command = docker_command(native_image, "arm64", output,
                [NATIVE_BINARY, "gg", "/work/inputs/zekra.arith", "/work/inputs/zekra_Sample_Run1.in"])
            started = time.monotonic()
            try:
                result = run(command, log, timeout)
            except (OSError, KeyboardInterrupt) as error:
                result = {"command": command, "returncode": "interrupted" if isinstance(error, KeyboardInterrupt) else "launch-error",
                          "wall_seconds": time.monotonic() - started, "log": str(log),
                          "log_sha256": sha(log) if log.is_file() else None,
                          "error": str(error), "kind": kind, "repetition": repetition, "verified": False}
                report[field].append(result)
                save(report_path, report)
                raise
            text = log.read_text()

            def number(pattern: str):
                values = re.findall(pattern, text)
                return float(values[-1]) if values else None

            result.update({"kind": kind, "repetition": repetition,
                "qap_pre_degree": number(r"QAP pre degree: (\d+)"),
                "qap_degree": number(r"QAP degree: (\d+)"),
                "qap_variables": number(r"QAP number of variables: (\d+)"),
                "verified": result["returncode"] == 0 and "The verification result is: PASS" in text
                            and "The verification result is: FAIL" not in text})
            for key in ("qap_pre_degree", "qap_degree", "qap_variables"):
                if result[key] is not None:
                    result[key] = int(result[key])
            for key, phase in (("setup_s", "generator"), ("prove_s", "prover"), ("verify_s", "verifier_strong_IC")):
                result[key] = number(r"\(leave\) Call to r1cs_gg_ppzksnark_" + phase + r"[^\n]*\[([0-9.]+)s")
            if result["qap_pre_degree"] != report["r1cs_constraints"]:
                result["verified"] = False
                result["count_error"] = "compiler and Groth16 R1CS totals differ"
            if any(result[key] is None or not math.isfinite(result[key]) or result[key] < 0
                   for key in ("setup_s", "prove_s", "verify_s")):
                result["verified"] = False
                result["timing_error"] = "missing or invalid native phase timing"
            report[field].append(result)
            save(report_path, report)
            if not result["verified"]:
                raise ValueError(f"Groth16 {kind} repetition {repetition} did not verify")
    report["medians"] = {key: statistics.median(row[key] for row in report["runs"])
                         for key in ("setup_s", "prove_s", "verify_s", "wall_seconds")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",required=True,type=Path)
    parser.add_argument("--output",required=True,type=Path)
    parser.add_argument("--repetitions",type=int,default=3)
    parser.add_argument("--warmups",type=int,default=0,
                        help="excluded native invocations before the measured repetitions")
    parser.add_argument("--levels",type=int,choices=(2,4),default=2,
                        help="fixed per campaign, audited against every fixture")
    parser.add_argument("--compile-image",default="zkcfa-zekra:paper-ubuntu22.04")
    parser.add_argument("--native-image",default="zekra-native:local")
    parser.add_argument("--prepare-only",action="store_true")
    parser.add_argument("--timeout",type=int,default=1800)
    args = parser.parse_args()
    source, output = args.input.resolve(), args.output.resolve()
    if args.output.is_symlink():
        parser.error("output must be a new directory, not a symlink")
    if output == UPSTREAM.resolve() or UPSTREAM.resolve() in output.parents:
        parser.error("output must be outside the upstream checkout")
    if args.repetitions < 1 or args.repetitions > 10:
        parser.error("repetitions must be in 1..10")
    if args.warmups < 0 or args.warmups > 10:
        parser.error("warmups must be in 0..10")
    output.mkdir(parents=True,exist_ok=False)
    report = {"schema":"zkcfa.zekra.synthetic-scaling.v1","status":"preparing",
              "source":str(source),"output":str(output),"repetitions":args.repetitions,
              "measurement_kind":"synthetic relation benchmark, not QEMU/device capture",
              "backend":"ZEKRA with isolated native-field SmartMemory packing repair",
              "threads":{"OMP_NUM_THREADS":8,"OMP_DYNAMIC":"FALSE"},
              "warmup_repetitions":args.warmups,
              "warmup_policy":"Excluded invocations of this fixture before all measured repetitions; no timing-based exclusions.",
              "phases":[],"warmup_runs":[],"runs":[]}
    report_path = output/"measurement.json"
    try:
        report["input"] = prepare_inputs(source, output/"inputs", args.levels)
        if report["input"]["original"]["max_stack_depth"] >= 15:
            raise ValueError("fixture exceeds fixed stack depth 15")
        report["status"] = "prepared"
        save(report_path,report)
        if args.prepare_only:
            print(json.dumps({"status":"prepared","parameters":report["input"]["parameters"]})); return 0
        isolated = output/"source"
        report["sources"] = snapshot_upstream(isolated)
        for name in ("PatchNativeMemory.java","CheckNativeMemory.java"):
            shutil.copy2(HERE/name,isolated/name)
        report["sources"].update({"patch_source_sha256":sha(HERE/"PatchNativeMemory.java"),
                                  "runner_sha256":sha(Path(__file__))})
        info = json.loads(capture(["docker","info","--format","{{json .}} "]))
        def image_info(name: str) -> dict:
            result = json.loads(capture(["docker","image","inspect",name]))[0]
            return {key:result[key] for key in ("Id","RepoTags","RepoDigests","Architecture","Os","Created")}
        report["environment"] = {"docker_info":{key:info[key] for key in
                                 ("Architecture","NCPU","MemTotal","OperatingSystem","KernelVersion","ServerVersion")},
                                 "compile_image":image_info(args.compile_image),
                                 "native_image":image_info(args.native_image)}
        if report["environment"]["native_image"]["Architecture"] != "arm64":
            raise ValueError("prover image is not native arm64")
        if report["environment"]["docker_info"]["Architecture"] != "aarch64":
            raise ValueError("this campaign requires an arm64 Docker host")
        setup = ["sh","-ec", "javac --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED PatchNativeMemory.java; "
                 "java --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED -cp .:original.jar PatchNativeMemory original.jar xjsnark_backend.jar; "
                 "javac -cp original.jar CheckNativeMemory.java; "
                 "java -cp .:original.jar CheckNativeMemory; "
                 "java -cp .:xjsnark_backend.jar CheckNativeMemory fixed; java -version"]
        patch = run(docker_command(args.compile_image,"amd64",output,setup),output/"00-patch.log")
        report["phases"].append(patch)
        if patch["returncode"] != 0:
            raise ValueError("isolated backend repair failed")
        report["sources"]["jar_after_sha256"] = sha(isolated/"xjsnark_backend.jar")
        with zipfile.ZipFile(isolated/"original.jar") as before, zipfile.ZipFile(isolated/"xjsnark_backend.jar") as after:
            if before.namelist() != after.namelist():
                raise ValueError("repair changed jar entry inventory")
            changed = [name for name in before.namelist() if before.read(name) != after.read(name)]
            if sorted(changed) != ["backend/auxTypes/SmartMemory$2.class","backend/auxTypes/SmartMemory$3.class",
                                   "backend/auxTypes/SmartMemory$4.class","backend/auxTypes/SmartMemory.class"]:
                raise ValueError(f"repair changed unexpected jar entries: {changed}")
            report["sources"]["jar_changed_entries"] = changed
        env_command = ["sh","-ec",f"uname -m; sha256sum {NATIVE_BINARY}; "
                       "grep -E 'MULTICORE:|PERFORMANCE:|OPT_FLAGS:|USE_ASM:|CURVE:' /opt/jsnark/libsnark/build/CMakeCache.txt; "
                       f"ldd {NATIVE_BINARY}; git -C /opt/jsnark rev-parse HEAD; git -C /opt/jsnark/libsnark rev-parse HEAD"]
        metadata = run(docker_command(args.native_image,"arm64",output,env_command),output/"01-native-environment.log")
        report["phases"].append(metadata)
        if metadata["returncode"] != 0:
            raise ValueError("native environment check failed")
        env_text = (output/"01-native-environment.log").read_text()
        report["sources"]["native_binary_sha256"] = re.search(r"(?m)^([0-9a-f]{64})\s",env_text)[1]
        params = report["input"]["parameters"]
        formatter = ["python3","scripts/circuit_input_formatter.py","-a","/work/inputs/",
                     "--pad-adjlist-to",str(params["adjlist_len"]),"--pad-path-to",str(params["path_len"]),
                     "--adjlist-levels",str(args.levels),"--nonce-verifier","12353","--nonce-path","123",
                     "--nonce-translator","123","--nonce-adjlist","123",
                     "--label-bitwidth",str(params["label_bitwidth"]),"--bucket-bitwidth",str(params["bucket_bitwidth"]),
                     "--address-bitwidth","24"]
        formatted = run(docker_command(args.compile_image,"amd64",output,formatter),output/"02-format.log",args.timeout)
        report["phases"].append(formatted)
        if formatted["returncode"] != 0 or not (output/"inputs/in_recorded_path_digest").is_file():
            raise ValueError("input formatting failed")
        compiler = ["python3","scripts/compile_circuit.py","--zekra-dir","zekra_java/zekra",
                    "--input-dir","/work/inputs","--output-dir","/work/inputs"]
        for key,value in params.items():
            compiler.extend(["--"+key.replace("_","-"),str(value)])
        compiled = run(docker_command(args.compile_image,"amd64",output,compiler),output/"03-compile.log",args.timeout)
        report["phases"].append(compiled)
        text = (output/"03-compile.log").read_text()
        count = re.search(r"Total constraints: (\d+)",text)
        if count:
            report["r1cs_constraints"] = int(count[1])
        report["sources"]["java_after_sha256"] = sha(isolated/"zekra_java/zekra/zekra.java")
        if (compiled["returncode"] != 0 or not count or "Circuit was not satisfied" in text
            or "Error Detected" in text or not (output/"inputs/zekra.arith").is_file()
            or not (output/"inputs/zekra_Sample_Run1.in").is_file()):
            raise ValueError("circuit compilation or sample satisfaction failed")
        report["r1cs_constraints"] = int(count[1])
        report["sources"]["java_after_sha256"] = sha(isolated/"zekra_java/zekra/zekra.java")
        report["sources"]["arith_sha256"] = sha(output/"inputs/zekra.arith")
        report["sources"]["witness_sha256"] = sha(output/"inputs/zekra_Sample_Run1.in")
        report["status"] = "compiled"; save(report_path,report)
        native_measurements(report, output, args.native_image, args.timeout)
        report["status"] = "verified"
        save(report_path,report)
        print(json.dumps({key:report[key] for key in ("status","r1cs_constraints","medians")}))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        report["status"] = "failed"; report["error"] = str(error) or type(error).__name__; save(report_path,report)
        print(report["error"],file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())
