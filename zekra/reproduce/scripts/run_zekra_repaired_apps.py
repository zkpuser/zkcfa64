#!/usr/bin/env python3
"""Run repaired ZEKRA on its saved application inputs, with unchanged parameters.

The original compressed statements are NOT matched QEMU statements. Only the four
SmartMemory classes change. Every Docker container is isolated, resource limited,
inspected before removal, and owned by this campaign. No historical data is edited.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import statistics
import subprocess
import sys
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[3]
ORIGINAL_JAR = "d6966c45ad659627027d19b4d8389d58a452f82ca416f1057efcdd428fbb535b"
REPAIRED_JAR = "b8371b11132ded46b7148deaf05c8b3e2ce7177f3ec3fbc0918a8f85fcc2e685"
INPUTS = ("adjlist", "numified_adjlist", "translator", "recorded_path", "numified_path")
PRIORITY = ("minver", "nettle-aes", "md5sum")
NATIVE = "/opt/jsnark/libsnark/build/libsnark/jsnark_interface/run_ppzksnark"
PARAMS = {"adjlist_len": "adjlist-len", "path_len": "path-len", "levels": "adjlist-levels",
          "stack_depth": "stack-depth", "label_bw": "label-bitwidth",
          "bucket_bw": "bucket-bitwidth", "addr_bw": "address-bitwidth"}


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def capture(command):
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)


class Campaign:
    def __init__(self, args):
        self.args = args
        self.base = args.output.resolve()
        self.docker = shutil.which("docker")
        if not self.docker:
            raise RuntimeError("Docker CLI unavailable")
        self.active = None

    def prepare(self):
        upstream = ROOT / "zekra/ZEKRA"
        if capture(["git", "-C", str(upstream), "status", "--porcelain"]).strip():
            raise RuntimeError("upstream checkout must be clean")
        if sha(upstream / "xjsnark_backend.jar") != ORIGINAL_JAR:
            raise RuntimeError("upstream jar identity changed")
        baseline = list(csv.DictReader(self.args.baseline.open()))
        rows = {row["app"]: row for row in baseline}
        apps = sorted(path.name for path in (upstream / "embench-iot-applications").iterdir() if path.is_dir())
        if set(rows) != set(apps) | {"crc32-control-500"} or len(apps) != 21:
            raise RuntimeError("baseline does not contain exactly 21 applications plus control")
        images = json.loads(capture([self.docker, "image", "inspect", "zkcfa-zekra:paper-ubuntu22.04", "zekra-native:local"]))
        info = json.loads(capture([self.docker, "info", "--format", "{{json .}}"]))
        if [image["Architecture"] for image in images] != ["amd64", "arm64"] or info["Architecture"] != "aarch64":
            raise RuntimeError("formatter/native architecture mismatch")
        if info["NCPU"] < 8 or self.args.memory_gib * 2**30 >= info["MemTotal"]:
            raise RuntimeError("requested limits exceed Docker resources")
        self.base.mkdir(parents=True, exist_ok=False)
        source = self.base / "snapshot"
        source.mkdir()
        archive = subprocess.check_output(["git", "-C", str(upstream), "archive", "HEAD"])
        (self.base / "upstream.tar").write_bytes(archive)
        subprocess.run(["tar", "-xf", str(self.base / "upstream.tar"), "-C", str(source)], check=True)
        shutil.copy2(self.args.baseline, self.base / "released-results.csv")
        shutil.copy2(Path(__file__), self.base / "runner.py")
        (self.base / "cases").mkdir()
        patch_source = self.base / "patch/source"
        patch_source.mkdir(parents=True)
        shutil.copy2(source / "xjsnark_backend.jar", patch_source / "original.jar")
        for name in ("PatchNativeMemory.java", "CheckNativeMemory.java"):
            shutil.copy2(ROOT / "zekra/reproduce/scaling" / name, patch_source / name)
        hashes = {}
        for app in apps:
            for name in INPUTS:
                path = source / "embench-iot-applications" / app / name
                historical = self.args.historical_inputs / app / name
                if not historical.is_file() or sha(path) != sha(historical):
                    raise RuntimeError(f"saved historical input mismatch: {app}/{name}")
                hashes[f"{app}/{name}"] = sha(path)
        order = ["crc32-control-500", *PRIORITY, *[app for app in apps if app not in PRIORITY]]
        plan = {
            "schema": "zkcfa.zekra.repaired-applications.plan.v1", "created_utc": now(),
            "upstream_revision": capture(["git", "-C", str(upstream), "rev-parse", "HEAD"]).strip(),
            "upstream_archive_sha256": sha(self.base / "upstream.tar"),
            "runner_sha256": sha(Path(__file__)), "baseline_sha256": sha(self.base / "released-results.csv"),
            "historical_input_root": str(self.args.historical_inputs.resolve()), "input_sha256": hashes,
            "all_105_input_files_identical_to_historical": True,
            "compile_image": images[0]["Id"], "native_image": images[1]["Id"],
            "images": [{key: image.get(key) for key in ("Id", "Architecture", "Created")} for image in images],
            "docker": {key: info.get(key) for key in ("NCPU", "MemTotal", "Architecture", "ServerVersion", "KernelVersion")},
            "order": order, "original_rows": rows, "parameters_unchanged": True,
            "priority_repetitions": "one excluded warmup then three formal native runs; remaining cases one primary run",
            "memory_bytes": self.args.memory_gib * 2**30, "memory_swap_bytes": self.args.memory_gib * 2**30,
            "stage_timeout_seconds": self.args.timeout, "threads": 8, "cpus": 8,
            "scope": "Released compressed ZEKRA statements, including their original partial-execution scope. No QEMU pairing, re-projection, return insertion, parameter changes, or fresh Device authentication.",
            "timing_scope": "Native ARM64 libsnark generator/prover/strong-IC verifier; formatter/compiler and witness generation are separate phase wall times. Historical and new timings are different campaigns.",
            "memory_scope": "Per-container cgroup memory cap, different from historical Docker VM OOM allowance; capped failures are resource stops, not algorithmic limits.",
            "label": "zkcfa-repaired-apps-" + uuid.uuid4().hex[:12],
        }
        save(self.base / "plan.json", plan)
        return plan

    def run_container(self, workspace, arch, command, log, stage):
        name = self.plan["label"] + "-" + uuid.uuid4().hex[:8]
        image = self.plan["compile_image" if arch == "amd64" else "native_image"]
        cmd = [self.docker, "run", "--name", name, "--label", "zkcfa.repaired-apps=" + self.plan["label"],
               "--network", "none", "--platform", "linux/" + arch, "--cpus", "8",
               "--memory", str(self.plan["memory_bytes"]), "--memory-swap", str(self.plan["memory_swap_bytes"]),
               "--env", "OMP_NUM_THREADS=8", "--env", "OMP_DYNAMIC=FALSE", "--volume", str(workspace) + ":/work",
               "--workdir", "/work/source", image, *command]
        start = time.monotonic()
        record = {"stage": stage, "started_utc": now(), "command": cmd, "container": name}
        self.active = name
        timed_out = False
        interrupted = False
        print(json.dumps({"event": "stage-start", "stage": stage, "utc": now()}), flush=True)
        with log.open("x") as stream:
            proc = subprocess.Popen(cmd, stdout=stream, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
            try:
                proc.wait(timeout=self.plan["stage_timeout_seconds"])
            except subprocess.TimeoutExpired:
                timed_out = True
                subprocess.run([self.docker, "kill", name], stdout=stream, stderr=subprocess.STDOUT, timeout=30, check=False)
                proc.wait(timeout=30)
            except BaseException:
                interrupted = True
                subprocess.run([self.docker, "kill", name], stdout=stream, stderr=subprocess.STDOUT, timeout=30, check=False)
                proc.wait(timeout=30)
            finally:
                record.update({"completed_utc": now(), "wall_seconds": time.monotonic() - start,
                               "returncode": proc.returncode, "timed_out": timed_out, "interrupted": interrupted})
                try:
                    inspected = json.loads(capture([self.docker, "inspect", name]))[0]
                    record["state"] = inspected["State"]
                    record["host_limits"] = {key: inspected["HostConfig"].get(key) for key in ("Memory", "MemorySwap", "NanoCpus")}
                except subprocess.CalledProcessError as error:
                    record["inspect_error"] = error.output
                subprocess.run([self.docker, "rm", name], stdout=stream, stderr=subprocess.STDOUT, timeout=30, check=False)
                self.active = None
        record.update({"log": str(log.relative_to(self.base)), "log_sha256": sha(log)})
        with (self.base / "events.jsonl").open("a") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
        if interrupted:
            raise KeyboardInterrupt()
        return record

    def patch(self):
        directory = self.base / "patch"
        command = ["sh", "-ec", "javac --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED PatchNativeMemory.java; "
                   "java --add-exports java.base/jdk.internal.org.objectweb.asm=ALL-UNNAMED -cp .:original.jar PatchNativeMemory original.jar xjsnark_backend.jar; "
                   "javac -cp original.jar CheckNativeMemory.java; java -cp .:original.jar CheckNativeMemory; "
                   "java -cp .:xjsnark_backend.jar CheckNativeMemory fixed; java -version"]
        result = self.run_container(directory, "amd64", command, directory / "patch.log", "SmartMemory repair")
        if result["returncode"] != 0:
            raise RuntimeError("SmartMemory repair failed")
        before_path, after_path = directory / "source/original.jar", directory / "source/xjsnark_backend.jar"
        with zipfile.ZipFile(before_path) as before, zipfile.ZipFile(after_path) as after:
            if before.namelist() != after.namelist():
                raise RuntimeError("jar inventory changed")
            changed = sorted(name for name in before.namelist() if before.read(name) != after.read(name))
        expected = sorted(["backend/auxTypes/SmartMemory.class", *[f"backend/auxTypes/SmartMemory${i}.class" for i in (2, 3, 4)]])
        if changed != expected or sha(after_path) != REPAIRED_JAR:
            raise RuntimeError("repair does not match the evaluated synthetic repair")
        save(directory / "validation.json", {"original_sha256": sha(before_path), "repaired_sha256": sha(after_path),
             "changed_entries": changed, "exactly_existing_four_class_repair": True, "phase": result})
        command = ["sh", "-ec", f"uname -m; sha256sum {NATIVE}; "
                   "grep -E 'MULTICORE:|PERFORMANCE:|OPT_FLAGS:|USE_ASM:|CURVE:' /opt/jsnark/libsnark/build/CMakeCache.txt; "
                   f"ldd {NATIVE}; git -C /opt/jsnark rev-parse HEAD; git -C /opt/jsnark/libsnark rev-parse HEAD"]
        result = self.run_container(directory, "arm64", command, directory / "native-environment.log", "native environment")
        if result["returncode"] != 0:
            raise RuntimeError("native environment validation failed")

    @staticmethod
    def failure(phase, otherwise):
        if phase.get("timed_out"):
            return "timeout"
        if phase.get("state", {}).get("OOMKilled"):
            return "resource-stop-cgroup-oom"
        return otherwise

    def run_case(self, tag):
        base = self.base / "cases" / tag
        base.mkdir()
        source, inputs = base / "source", base / "inputs"
        source.mkdir(); inputs.mkdir()
        for name in ("scripts", "zekra_java"):
            shutil.copytree(self.base / "snapshot" / name, source / name)
        shutil.copy2(self.base / "patch/source/xjsnark_backend.jar", source / "xjsnark_backend.jar")
        app = "crc32" if tag == "crc32-control-500" else tag
        for name in INPUTS:
            shutil.copy2(self.base / "snapshot/embench-iot-applications" / app / name, inputs / name)
        old = self.plan["original_rows"][tag]
        result = {"app": tag, "started_utc": now(), "parameters": {key: int(old[key]) for key in PARAMS},
                  "historical": old, "input_sha256": {name: sha(inputs / name) for name in INPUTS},
                  "parameters_changed": False, "phases": [], "runs": [], "status": "preparing", "verified": False}
        destination = base / "result.json"
        save(destination, result)
        formatter = ["python3", "scripts/circuit_input_formatter.py", "-a", "/work/inputs/",
                     "--pad-adjlist-to", old["adjlist_len"], "--pad-path-to", old["path_len"],
                     "--adjlist-levels", old["levels"], "--label-bitwidth", old["label_bw"],
                     "--bucket-bitwidth", old["bucket_bw"], "--address-bitwidth", old["addr_bw"],
                     "--nonce-verifier", "12353", "--nonce-path", "123", "--nonce-translator", "123", "--nonce-adjlist", "123"]
        phase = self.run_container(base, "amd64", formatter, base / "format.log", tag + ":format")
        result["phases"].append(phase)
        if phase["returncode"] or not (inputs / "in_recorded_path_digest").is_file():
            result["status"] = self.failure(phase, "format-failed")
            save(destination, result); return result
        result["formatted_sha256"] = {path.name: sha(path) for path in sorted(inputs.glob("in_*"))}
        historical_formatted = self.args.historical_inputs.parents[1] / "reproduce/results/embench-suite" / tag
        result["historical_formatted_comparison"] = {
            name: (sha(historical_formatted / name) == expected if (historical_formatted / name).is_file() else None)
            for name, expected in result["formatted_sha256"].items()}
        compiler = ["python3", "scripts/compile_circuit.py", "--zekra-dir", "zekra_java/zekra",
                    "--input-dir", "/work/inputs", "--output-dir", "/work/inputs", "--components-dir", "zekra_java/components"]
        for key, option in PARAMS.items():
            compiler.extend(["--" + option, old[key]])
        phase = self.run_container(base, "amd64", compiler, base / "compile.log", tag + ":compile")
        result["phases"].append(phase)
        text = (base / "compile.log").read_text(errors="replace")
        count = re.findall(r"Total constraints: (\d+)", text)
        result["r1cs_constraints"] = int(count[-1]) if count else None
        result["satisfied"] = bool(count) and phase["returncode"] == 0 and "Circuit was not satisfied" not in text and "Error Detected" not in text
        result["compiled_files"] = {name: {"sha256": sha(inputs / name), "bytes": (inputs / name).stat().st_size}
                                    for name in ("zekra.arith", "zekra_Sample_Run1.in") if (inputs / name).is_file()}
        if not result["satisfied"] or len(result["compiled_files"]) != 2:
            result["status"] = self.failure(phase, "unsatisfied" if "Circuit was not satisfied" in text else "compile-failed")
            save(destination, result); return result
        result["status"] = "compiled"; save(destination, result)
        repetitions = 4 if tag in PRIORITY else 1
        for rep in range(repetitions):
            phase = self.run_container(base, "arm64", [NATIVE, "gg", "/work/inputs/zekra.arith", "/work/inputs/zekra_Sample_Run1.in"],
                                       base / f"native-{rep + 1}.log", tag + f":native-{rep + 1}/{repetitions}")
            text = (base / f"native-{rep + 1}.log").read_text(errors="replace")
            def number(pattern, integer=False):
                values = re.findall(pattern, text)
                return (int(values[-1]) if integer else float(values[-1])) if values else None
            phase.update({"repetition": rep + 1, "kind": "warmup" if repetitions > 1 and rep == 0 else "formal" if repetitions > 1 else "primary",
                          "qap_pre_degree": number(r"QAP pre degree: (\d+)", True), "qap_degree": number(r"QAP degree: (\d+)", True),
                          "qap_variables": number(r"QAP number of variables: (\d+)", True), "reported_proof_bits": number(r"Proof size in bits: (\d+)", True)})
            for key, name in (("setup_s", "generator"), ("prove_s", "prover"), ("verify_s", "verifier_strong_IC")):
                phase[key] = number(r"\(leave\) Call to r1cs_gg_ppzksnark_" + name + r"[^\n]*\[([0-9.]+)s")
            phase["verified"] = (phase["returncode"] == 0 and "The verification result is: PASS" in text
                                 and phase["qap_pre_degree"] == result["r1cs_constraints"]
                                 and all(phase[key] is not None for key in ("setup_s", "prove_s", "verify_s")))
            result["runs"].append(phase); save(destination, result)
            if not phase["verified"]:
                result["status"] = self.failure(phase, "native-failed")
                break
        else:
            result["status"] = "verified"; result["verified"] = True
        measured = [row for row in result["runs"] if row["kind"] != "warmup" and row["verified"]]
        result["formal_or_primary_verified"] = len(measured)
        if measured:
            result["timings"] = {key: {"samples": [row[key] for row in measured], "median": statistics.median(row[key] for row in measured),
                                       "min": min(row[key] for row in measured), "max": max(row[key] for row in measured)}
                                 for key in ("setup_s", "prove_s", "verify_s", "wall_seconds")}
        result["input_files_unchanged"] = all(sha(inputs / name) == result["input_sha256"][name] for name in INPUTS)
        result["completed_utc"] = now()
        save(destination, result)
        return result

    def summarize(self, status):
        results = [json.loads(path.read_text()) for path in sorted((self.base / "cases").glob("*/result.json"))]
        for row in results:
            directory = self.base / "cases" / row["app"] / "inputs"
            row["input_files_unchanged"] = all(sha(directory / name) == row["input_sha256"][name] for name in INPUTS)
        apps = [row for row in results if row["app"] != "crc32-control-500"]
        summary = {"schema": "zkcfa.zekra.repaired-applications.summary.v1", "status": status, "updated_utc": now(),
                   "planned_applications": 21, "recorded_applications": len(apps), "outcomes": dict(Counter(row["status"] for row in apps)),
                   "historical_outcomes": dict(Counter(row["historical"]["outcome"] for row in apps)),
                   "formal_and_primary_verified": sum(sum(run.get("verified", False) and run.get("kind") != "warmup" for run in row["runs"]) for row in results),
                   "all_input_files_unchanged": all(row.get("input_files_unchanged", True) for row in results),
                   "plan_sha256": sha(self.base / "plan.json"), "results": results,
                   "scope": self.plan["scope"], "timing_scope": self.plan["timing_scope"], "memory_scope": self.plan["memory_scope"]}
        save(self.base / "summary.json", summary)
        with (self.base / "results.csv").open("w", newline="") as stream:
            fields = ["app", *PARAMS, "old_outcome", "old_r1cs_constraints", "old_prove_s", "new_outcome", "satisfied", "verified",
                      "r1cs_constraints", "measured_runs", "setup_s", "prove_s", "verify_s", "memory_limit_bytes", "parameters_changed"]
            writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader()
            by_app = {row["app"]: row for row in results}
            for tag in self.plan["order"]:
                if tag not in by_app: continue
                row = by_app[tag]
                writer.writerow({"app": tag, **row["parameters"], "old_outcome": row["historical"]["outcome"],
                    "old_r1cs_constraints": row["historical"]["r1cs_constraints"], "old_prove_s": row["historical"]["prove_s"],
                    "new_outcome": row["status"], "satisfied": row.get("satisfied"), "verified": row["verified"],
                    "r1cs_constraints": row.get("r1cs_constraints"), "measured_runs": row.get("formal_or_primary_verified", 0),
                    **{key: row.get("timings", {}).get(key, {}).get("median", "") for key in ("setup_s", "prove_s", "verify_s")},
                    "memory_limit_bytes": self.plan["memory_bytes"], "parameters_changed": False})
        return summary

    def execute(self):
        self.plan = self.prepare()
        if self.args.prepare_only:
            print(json.dumps({"status": "prepared", "output": str(self.base)})); return 0
        try:
            self.patch()
            for tag in self.plan["order"]:
                result = self.run_case(tag)
                self.summarize("running")
                print(json.dumps({"event": "case-complete", "app": tag, "status": result["status"],
                                  "constraints": result.get("r1cs_constraints"), "timings": result.get("timings")}), flush=True)
                if tag == "crc32-control-500" and not result["verified"]:
                    raise RuntimeError("repaired control failed; refusing application campaign")
            summary = self.summarize("complete")
            print(json.dumps({"event": "campaign-complete", "outcomes": summary["outcomes"]}), flush=True)
            return 0
        except BaseException as error:
            save(self.base / "error.json", {"error": repr(error), "utc": now()})
            self.summarize("interrupted" if isinstance(error, KeyboardInterrupt) else "runner-error")
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True, help="original campaign results.csv")
    parser.add_argument("--historical-inputs", type=Path, required=True, help="original campaign snapshot/zekra/ZEKRA/embench-iot-applications")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--memory-gib", type=int, default=18)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.memory_gib <= 64 or args.timeout < 1:
        parser.error("positive timeout and a memory limit between 1 and 64 GiB required")
    os.umask(0o077)
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    return Campaign(args).execute()


if __name__ == "__main__":
    sys.exit(main())
