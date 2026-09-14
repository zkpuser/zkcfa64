#!/usr/bin/env python3
"""Isolated full ZEKRA RSS campaign: 21 released statements plus crc32 control.

Keep historical campaigns untouched. Each case uses one excluded native warmup
and three measured runs. Resume reuses completed stages and preserves interrupted
attempts. Run RSS instrumentation inside Linux containers, never on the macOS host.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import json
import math
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

import run_zekra_repaired_apps as prior

ROOT, INPUTS, PARAMS, NATIVE = prior.ROOT, prior.INPUTS, prior.PARAMS, prior.NATIVE
now, sha, save, capture = prior.now, prior.sha, prior.save, prior.capture
HERE = Path(__file__).resolve().parent
RSS_SCOPE = ("Linux wait4 ru_maxrss in bytes: maximum individual-process resident high-water mark "
             "of the command and its reaped descendants, not aggregate concurrent process-tree RSS. "
             "Full-pipeline RSS is the maximum of formatter, compiler/witness, and three "
             "measured native runs; the native warmup is excluded. Table VI uses the maximum of three measured native runs only, with their median retained separately. "
             "Failed-case observed RSS includes attempted phases/runs and is a lower bound when only "
             "sampled /proc VmHWM survived. Sampled summed VmRSS is recorded separately. "
             "Neither virtual address size nor cgroup memory usage is reported as RSS.")
TIMING_KEYS = ("setup_s", "prove_s", "verify_s", "wall_seconds")


def native_metrics(text, phase, constraints):
    def number(pattern, integer=False):
        values = re.findall(pattern, text)
        return (int(values[-1]) if integer else float(values[-1])) if values else None
    phase.update({"qap_pre_degree": number(r"QAP pre degree: (\d+)", True),
                  "qap_degree": number(r"QAP degree: (\d+)", True),
                  "qap_variables": number(r"QAP number of variables: (\d+)", True),
                  "reported_proof_bits": number(r"Proof size in bits: (\d+)", True)})
    for key, name in (("setup_s", "generator"), ("prove_s", "prover"), ("verify_s", "verifier_strong_IC")):
        phase[key] = number(r"\(leave\) Call to r1cs_gg_ppzksnark_" + name + r"[^\n]*\[([0-9.eE+-]+)s")
    phase["verified"] = (phase["returncode"] == 0 and not phase.get("measurement_error") and not phase.get("timed_out")
                         and "The verification result is: PASS" in text
                         and phase["qap_pre_degree"] == constraints
                         and all(phase[key] is not None and math.isfinite(phase[key]) and phase[key] >= 0 for key in TIMING_KEYS[:3]))
    return phase


def aggregate(result):
    measured = [row for row in result["runs"] if row["kind"] == "measured" and row.get("verified")]
    result["measured_verified_runs"] = len(measured)
    if measured:
        result["timings"] = {key: {"samples": [row[key] for row in measured],
                                   "median": statistics.median(row[key] for row in measured),
                                   "min": min(row[key] for row in measured), "max": max(row[key] for row in measured)}
                             for key in TIMING_KEYS}
    successful_scope = result["phases"] + measured
    attempted = result["phases"] + result["runs"]
    def peak(rows, key):
        values = [row[key] for row in rows if row.get(key) is not None]
        return max(values) if values else None
    result["rss"] = {
        "scope": RSS_SCOPE, "units": "bytes", "statistic": "maximum",
        "full_pipeline_peak_rss_bytes": peak(successful_scope, "peak_rss_bytes") if result.get("verified") else None,
        "native_measured_peak_rss_bytes": peak(measured, "peak_rss_bytes"),
        "native_measured_median_peak_rss_bytes": statistics.median(row["peak_rss_bytes"] for row in measured) if measured and all(row.get("peak_rss_bytes") is not None for row in measured) else None,
        "native_failed_attempt_peak_rss_bytes": peak([row for row in result["runs"] if not row.get("verified")], "peak_rss_bytes"),
        "native_failed_attempt_observed_peak_rss_bytes": peak([row for row in result["runs"] if not row.get("verified")], "observed_peak_rss_bytes"),
        "attempted_peak_rss_bytes": peak(attempted, "peak_rss_bytes"),
        "attempted_observed_peak_rss_bytes": peak(attempted, "observed_peak_rss_bytes"),
        "sampled_group_rss_peak_bytes": peak(attempted, "sampled_group_rss_peak_bytes"),
        "full_pipeline_exact": bool(result.get("verified")) and all(row.get("rss_complete") for row in successful_scope),
        "failed_attempts": [{key: row.get(key) for key in ("stage", "returncode", "peak_rss_bytes",
                              "observed_peak_rss_bytes", "rss_complete", "timed_out", "state")}
                            for row in attempted if row.get("returncode") or row.get("timed_out") or row.get("state", {}).get("OOMKilled")],
    }
    # Never publish a partial exact measurement as a complete full-pipeline value.
    if not result["rss"]["full_pipeline_exact"]:
        result["rss"]["full_pipeline_peak_rss_bytes"] = None
    return result


class Campaign(prior.Campaign):
    def prepare(self):
        if self.args.resume:
            self.plan = json.loads((self.base / "plan.json").read_text())
            if self.plan.get("schema") != "zkcfa.zekra.rss-applications.plan.v1":
                raise RuntimeError("not an RSS campaign snapshot")
            for name, digest in self.plan["instrumentation_sha256"].items():
                if sha(HERE / name) != digest or sha(self.base / "instrumentation" / name) != digest:
                    raise RuntimeError("runner/instrumentation changed; use the recorded version to resume")
            if sha(self.base / "upstream.tar") != self.plan["upstream_archive_sha256"] or sha(self.base / "released-results.csv") != self.plan["baseline_sha256"]:
                raise RuntimeError("saved campaign provenance changed")
            for name, digest in self.plan["input_sha256"].items():
                if sha(self.base / "snapshot/embench-iot-applications" / name) != digest:
                    raise RuntimeError("saved original input changed: " + name)
            capture([self.docker, "image", "inspect", self.plan["compile_image"], self.plan["native_image"]])
            return self.plan
        plan = super().prepare()
        instrumentation = self.base / "instrumentation"
        instrumentation.mkdir()
        names = (Path(__file__).name, "run_zekra_repaired_apps.py", "zekra_linux_rss.py")
        for name in names:
            shutil.copy2(HERE / name, instrumentation / name)
        # super.prepare copied the original runner for provenance; retain it by name.
        (self.base / "runner.py").rename(self.base / "original_repaired_runner.py")
        shutil.copy2(Path(__file__), self.base / "runner.py")
        plan.update({"schema": "zkcfa.zekra.rss-applications.plan.v1", "runner_sha256": sha(Path(__file__)),
                     "instrumentation_sha256": {name: sha(instrumentation / name) for name in names},
                     "priority_repetitions": "all 21 applications and control: one excluded warmup then three measured native runs; stop a case after its first failed run",
                     "native_warmups": 1, "native_measured_runs": 3, "memory_scope": RSS_SCOPE,
                     "rss_sample_interval_seconds": 0.1, "serial_cases": True,
                     "host_sw_vers": capture(["sw_vers"]) if sys.platform == "darwin" else None,
                     "label": "zkcfa-rss-apps-" + uuid.uuid4().hex[:12]})
        save(self.base / "plan.json", plan)
        return plan

    def run_container(self, workspace, arch, command, log, stage):
        # Every attempt has immutable logs and a final phase record. Pending records
        # survive a killed host runner and are reconciled against owned containers.
        attempts = workspace / "attempts" / log.stem
        attempts.mkdir(parents=True, exist_ok=True)
        for pending in sorted(attempts.glob("*/pending.json")):
            if (pending.parent / "phase.json").exists():
                continue
            record = json.loads(pending.read_text())
            was_running = False
            try:
                inspected = json.loads(capture([self.docker, "inspect", record["container"]]))[0]
                if inspected.get("Config", {}).get("Labels", {}).get("zkcfa.rss-apps") != self.plan["label"]:
                    raise RuntimeError("container ownership mismatch")
                was_running = bool(inspected["State"].get("Running"))
                if was_running:
                    subprocess.run([self.docker, "kill", record["container"]], check=True, capture_output=True, timeout=30)
                record["state"] = json.loads(capture([self.docker, "inspect", record["container"]]))[0]["State"]
                subprocess.run([self.docker, "rm", record["container"]], check=True, capture_output=True, timeout=30)
            except subprocess.CalledProcessError as error:
                record["recovery_inspect_error"] = str(error)
            rss_path = pending.parent / "rss.json"
            rss = json.loads(rss_path.read_text()) if rss_path.exists() else {}
            terminal = bool(record.get("state", {}).get("OOMKilled")) or (not was_running and ("ExitCode" in record.get("state", {}) or rss.get("complete")))
            record.update({"interrupted": not terminal, "completed_utc": now(),
                           "wall_seconds": rss.get("wall_seconds"), "recovered_after_host_interruption": True,
                           "returncode": record.get("state", {}).get("ExitCode", rss.get("returncode", 130))})
            self.finish_phase(record, pending.parent)
        previous = sorted(attempts.glob("*/phase.json"))
        if previous:
            phase = json.loads(previous[-1].read_text())
            if not phase.get("interrupted"):
                if phase["workload_command"] != command or phase["stage"] != stage:
                    raise RuntimeError("completed stage command changed")
                for path_key, digest_key in (("log", "log_sha256"), ("rss_file", "rss_sha256")):
                    if phase.get(path_key) and sha(self.base / phase[path_key]) != phase[digest_key]:
                        raise RuntimeError("completed stage evidence changed: " + phase[path_key])
                return phase
        number = len(list(attempts.iterdir())) + 1
        attempt = attempts / f"{number:03d}"
        attempt.mkdir()
        log = attempt / "output.log"
        name = self.plan["label"] + "-" + uuid.uuid4().hex[:8]
        image = self.plan["compile_image" if arch == "amd64" else "native_image"]
        rss_path = "/work/" + str((attempt / "rss.json").relative_to(workspace))
        wrapped = ["python3", "/instrumentation/zekra_linux_rss.py", "--output", rss_path,
                   "--timeout", str(self.plan["stage_timeout_seconds"]), "--", *command]
        cmd = [self.docker, "run", "--name", name, "--label", "zkcfa.rss-apps=" + self.plan["label"],
               "--network", "none", "--platform", "linux/" + arch, "--cpus", "8",
               "--memory", str(self.plan["memory_bytes"]), "--memory-swap", str(self.plan["memory_swap_bytes"]),
               "--env", "OMP_NUM_THREADS=8", "--env", "OMP_DYNAMIC=FALSE",
               "--volume", str(workspace) + ":/work", "--volume", str(self.base / "instrumentation") + ":/instrumentation:ro",
               "--workdir", "/work/source", image, *wrapped]
        record = {"stage": stage, "started_utc": now(), "command": cmd, "workload_command": command,
                  "container": name, "log": str(log.relative_to(self.base))}
        save(attempt / "pending.json", record)
        start = time.monotonic()
        self.active = name
        print(json.dumps({"event": "stage-start", "stage": stage, "utc": now(), "attempt": number}), flush=True)
        interrupted, timed_out = False, False
        with log.open("x") as stream:
            proc = subprocess.Popen(cmd, stdout=stream, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
            try:
                proc.wait(timeout=self.plan["stage_timeout_seconds"] + 30)
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
                interrupted = isinstance(error, KeyboardInterrupt)
                timed_out = not interrupted
                subprocess.run([self.docker, "kill", "--signal", "TERM", name], stdout=stream, stderr=subprocess.STDOUT, timeout=10, check=False)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    subprocess.run([self.docker, "kill", name], stdout=stream, stderr=subprocess.STDOUT, timeout=10, check=False)
                    proc.wait(timeout=10)
            finally:
                record.update({"completed_utc": now(), "wall_seconds": time.monotonic() - start,
                               "returncode": proc.returncode, "timed_out": timed_out, "interrupted": interrupted})
                try:
                    inspected = json.loads(capture([self.docker, "inspect", name]))[0]
                    if inspected["State"].get("Running"):
                        # A detached Docker client must not leave a workload running
                        # while the next supposedly serial stage starts.
                        subprocess.run([self.docker, "kill", name], stdout=stream, stderr=subprocess.STDOUT, timeout=30, check=True)
                        inspected = json.loads(capture([self.docker, "inspect", name]))[0]
                        record["interrupted"] = True
                        interrupted = True
                    record["state"] = inspected["State"]
                    if record["state"].get("OOMKilled"):
                        # Preserve a terminal OOM even if host interruption raced it.
                        record["interrupted"] = False
                    record["host_limits"] = {key: inspected["HostConfig"].get(key) for key in ("Memory", "MemorySwap", "NanoCpus")}
                except subprocess.CalledProcessError as error:
                    record["inspect_error"] = error.output
                self.finish_phase(record, attempt)
                subprocess.run([self.docker, "rm", name], stdout=stream, stderr=subprocess.STDOUT, timeout=30, check=False)
                self.active = None
        # Removal output also belongs to the preserved log.
        record["log_sha256"] = sha(log)
        save(attempt / "phase.json", record)
        with (self.base / "events.jsonl").open("a") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
        if interrupted:
            raise KeyboardInterrupt()
        return record

    def finish_phase(self, record, attempt):
        rss_file = attempt / "rss.json"
        rss = json.loads(rss_file.read_text()) if rss_file.exists() else {}
        record.update({"rss": rss, "rss_complete": rss.get("complete", False),
                       "peak_rss_bytes": rss.get("peak_rss_bytes"),
                       "observed_peak_rss_bytes": max(rss.get("peak_rss_bytes") or 0, rss.get("sampled_process_hwm_max_bytes") or 0) or None,
                       "sampled_group_rss_peak_bytes": rss.get("sampled_group_rss_peak_bytes"),
                       "timed_out": record.get("timed_out", False) or rss.get("timed_out", False)})
        if record.get("returncode") == 0 and (not record["rss_complete"] or not record.get("peak_rss_bytes")):
            record["measurement_error"] = "successful workload is missing complete positive Linux wait4 peak RSS"
        if rss_file.exists():
            record["rss_file"] = str(rss_file.relative_to(self.base))
            record["rss_sha256"] = sha(rss_file)
        if (attempt / "output.log").exists():
            record["log_sha256"] = sha(attempt / "output.log")
        save(attempt / "phase.json", record)

    def patch(self):
        validation = self.base / "patch/validation.json"
        if validation.exists():
            recorded = json.loads(validation.read_text())
            if sha(self.base / "patch/source/xjsnark_backend.jar") != recorded["repaired_sha256"]:
                raise RuntimeError("saved patched jar changed")
        # Parent patch calls our resumable stage launcher and rechecks all four classes.
        super().patch()

    def phase_text(self, phase):
        return (self.base / phase["log"]).read_text(errors="replace")

    def run_case(self, tag):
        base = self.base / "cases" / tag
        destination = base / "result.json"
        old = self.plan["original_rows"][tag]
        source, inputs = base / "source", base / "inputs"
        if destination.exists():
            result = json.loads(destination.read_text())
            if result.get("completed_utc"):
                if not all(sha(inputs / name) == result["input_sha256"][name] for name in INPUTS):
                    raise RuntimeError("completed case original inputs changed: " + tag)
                for name, metadata in result.get("compiled_files", {}).items():
                    if sha(inputs / name) != metadata["sha256"]:
                        raise RuntimeError("completed case compiled artifact changed: " + tag + "/" + name)
                return result
        else:
            base.mkdir(exist_ok=True)
            source.mkdir(exist_ok=True); inputs.mkdir(exist_ok=True)
            for name in ("scripts", "zekra_java"):
                shutil.copytree(self.base / "snapshot" / name, source / name, dirs_exist_ok=True)
            shutil.copy2(self.base / "patch/source/xjsnark_backend.jar", source / "xjsnark_backend.jar")
            app = "crc32" if tag == "crc32-control-500" else tag
            for name in INPUTS:
                shutil.copy2(self.base / "snapshot/embench-iot-applications" / app / name, inputs / name)
            result = {"app": tag, "started_utc": now(), "parameters": {key: int(old[key]) for key in PARAMS},
                      "historical": old, "input_sha256": {name: sha(inputs / name) for name in INPUTS},
                      "parameters_changed": False, "phases": [], "runs": [], "status": "preparing", "verified": False}
            save(destination, result)
        if not all(sha(inputs / name) == result["input_sha256"][name] for name in INPUTS):
            raise RuntimeError("case original inputs changed: " + tag)
        def finish(status):
            result["status"] = status
            result["completed_utc"] = now()
            result["input_files_unchanged"] = all(sha(inputs / name) == result["input_sha256"][name] for name in INPUTS)
            aggregate(result); save(destination, result)
            return result
        formatter = ["python3", "scripts/circuit_input_formatter.py", "-a", "/work/inputs/",
                     "--pad-adjlist-to", old["adjlist_len"], "--pad-path-to", old["path_len"],
                     "--adjlist-levels", old["levels"], "--label-bitwidth", old["label_bw"],
                     "--bucket-bitwidth", old["bucket_bw"], "--address-bitwidth", old["addr_bw"],
                     "--nonce-verifier", "12353", "--nonce-path", "123", "--nonce-translator", "123", "--nonce-adjlist", "123"]
        phase = self.run_container(base, "amd64", formatter, base / "format.log", tag + ":format")
        result["phases"] = [phase]
        save(destination, result)
        if phase.get("measurement_error"):
            return finish("rss-measurement-error")
        if phase["returncode"] or phase.get("timed_out") or not (inputs / "in_recorded_path_digest").is_file():
            return finish(self.failure(phase, "format-failed"))
        result["formatted_sha256"] = {path.name: sha(path) for path in sorted(inputs.glob("in_*"))}
        compiler = ["python3", "scripts/compile_circuit.py", "--zekra-dir", "zekra_java/zekra", "--input-dir", "/work/inputs",
                    "--output-dir", "/work/inputs", "--components-dir", "zekra_java/components"]
        for key, option in PARAMS.items():
            compiler.extend(["--" + option, old[key]])
        phase = self.run_container(base, "amd64", compiler, base / "compile.log", tag + ":compile")
        result["phases"].append(phase)
        text = self.phase_text(phase)
        count = re.findall(r"Total constraints: (\d+)", text)
        result["r1cs_constraints"] = int(count[-1]) if count else None
        result["satisfied"] = bool(count) and phase["returncode"] == 0 and not phase.get("timed_out") and "Circuit was not satisfied" not in text and "Error Detected" not in text
        result["compiled_files"] = {name: {"sha256": sha(inputs / name), "bytes": (inputs / name).stat().st_size}
                                    for name in ("zekra.arith", "zekra_Sample_Run1.in") if (inputs / name).is_file()}
        save(destination, result)
        if phase.get("measurement_error"):
            return finish("rss-measurement-error")
        if not result["satisfied"] or len(result["compiled_files"]) != 2:
            return finish(self.failure(phase, "unsatisfied" if "Circuit was not satisfied" in text else "compile-failed"))
        result["status"] = "compiled"
        save(destination, result)
        result["runs"] = []
        for rep in range(4):
            phase = self.run_container(base, "arm64", [NATIVE, "gg", "/work/inputs/zekra.arith", "/work/inputs/zekra_Sample_Run1.in"],
                                       base / f"native-{rep + 1}.log", tag + f":native-{rep + 1}/4")
            phase.update({"repetition": rep + 1, "kind": "warmup" if rep == 0 else "measured"})
            native_metrics(self.phase_text(phase), phase, result["r1cs_constraints"])
            result["runs"].append(phase)
            aggregate(result); save(destination, result)
            if phase.get("measurement_error"):
                return finish("rss-measurement-error")
            if not phase["verified"]:
                return finish(self.failure(phase, "native-failed"))
        result["verified"] = True
        return finish("verified")

    def summarize(self, status):
        results = [aggregate(json.loads(path.read_text())) for path in sorted((self.base / "cases").glob("*/result.json"))]
        apps = [row for row in results if row["app"] != "crc32-control-500"]
        summary = {"schema": "zkcfa.zekra.rss-applications.summary.v1", "status": status, "updated_utc": now(),
                   "planned_applications": 21, "recorded_applications": len(apps), "outcomes": dict(Counter(row["status"] for row in apps)),
                   "measured_verified_runs": sum(row["measured_verified_runs"] for row in results),
                   "plan_sha256": sha(self.base / "plan.json"), "results": results,
                   "scope": self.plan["scope"], "timing_scope": self.plan["timing_scope"], "memory_scope": RSS_SCOPE}
        save(self.base / "summary.json", summary)
        fields = ["app", *PARAMS, "old_outcome", "old_r1cs_constraints", "old_prove_s", "new_outcome", "satisfied", "verified",
                  "r1cs_constraints", "measured_runs", "setup_s", "prove_s", "verify_s", "format_wall_s", "compile_witness_wall_s",
                  "format_peak_rss_bytes", "compile_witness_peak_rss_bytes", "full_pipeline_peak_rss_bytes", "native_measured_peak_rss_bytes",
                  "native_measured_median_peak_rss_bytes", "native_failed_attempt_peak_rss_bytes", "native_failed_attempt_observed_peak_rss_bytes", "attempted_observed_peak_rss_bytes", "full_pipeline_exact", "memory_limit_bytes", "parameters_changed"]
        temporary = self.base / "results.csv.tmp"
        with temporary.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader()
            by_app = {row["app"]: row for row in results}
            for tag in self.plan["order"]:
                if tag not in by_app:
                    continue
                row = by_app[tag]
                phases = {phase["stage"].rsplit(":", 1)[-1]: phase for phase in row["phases"]}
                writer.writerow({"app": tag, **row["parameters"], "old_outcome": row["historical"]["outcome"],
                    "old_r1cs_constraints": row["historical"]["r1cs_constraints"], "old_prove_s": row["historical"]["prove_s"],
                    "new_outcome": row["status"], "satisfied": row.get("satisfied"), "verified": row["verified"],
                    "r1cs_constraints": row.get("r1cs_constraints"), "measured_runs": row["measured_verified_runs"],
                    **{key: row.get("timings", {}).get(key, {}).get("median") for key in TIMING_KEYS[:3]},
                    "format_wall_s": phases.get("format", {}).get("wall_seconds"),
                    "compile_witness_wall_s": phases.get("compile", {}).get("wall_seconds"),
                    "format_peak_rss_bytes": phases.get("format", {}).get("peak_rss_bytes"),
                    "compile_witness_peak_rss_bytes": phases.get("compile", {}).get("peak_rss_bytes"),
                    **{key: row["rss"][key] for key in ("full_pipeline_peak_rss_bytes", "native_measured_peak_rss_bytes", "native_measured_median_peak_rss_bytes", "native_failed_attempt_peak_rss_bytes", "native_failed_attempt_observed_peak_rss_bytes", "attempted_observed_peak_rss_bytes", "full_pipeline_exact")},
                    "memory_limit_bytes": self.plan["memory_bytes"], "parameters_changed": False})
        temporary.replace(self.base / "results.csv")
        return summary

    def execute(self):
        self.plan = self.prepare()
        import fcntl
        # Hold a host advisory lock throughout execution to preserve seriality.
        self.lock_stream = (self.base / "campaign.lock").open("a")
        try:
            fcntl.flock(self.lock_stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("another runner owns this campaign") from error
        if self.args.prepare_only:
            print(json.dumps({"status": "prepared", "output": str(self.base)})); return 0
        try:
            self.patch()
            for tag in self.plan["order"]:
                result = self.run_case(tag)
                self.summarize("running")
                print(json.dumps({"event": "case-complete", "app": tag, "status": result["status"],
                                  "constraints": result.get("r1cs_constraints"), "timings": result.get("timings"), "rss": result.get("rss")}), flush=True)
                if tag == "crc32-control-500" and not result["verified"]:
                    raise RuntimeError("repaired control failed; refusing application campaign")
            summary = self.summarize("complete")
            print(json.dumps({"event": "campaign-complete", "outcomes": summary["outcomes"]}), flush=True)
            return 0
        except BaseException as error:
            save(self.base / ("error-" + uuid.uuid4().hex[:8] + ".json"), {"error": repr(error), "utc": now()})
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
    parser.add_argument("--resume", action="store_true", help="reuse the saved immutable plan and completed stages; preserve and retry interrupted attempts")
    args = parser.parse_args()
    if not 1 <= args.memory_gib <= 64 or args.timeout < 1:
        parser.error("positive timeout and memory limit between 1 and 64 GiB required")
    os.umask(0o077)
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    return Campaign(args).execute()


if __name__ == "__main__":
    sys.exit(main())
