#!/usr/bin/env python3
"""Validate and freeze the complete synthetic CFA scaling comparison.

This exporter requires both fixture families and all seven requested sizes. Each
configuration must have three verified repetitions, except that the growing-CFG
ZEKRA 4096 case may contain one independently documented Docker OOM after a
successful circuit compilation. Failed or missing measurements never become
zeroes, and the resource-failed row remains part of the exported dataset.
The output is PREFIX.csv (three aggregate rows per fixture) and PREFIX.json (evidence snapshot).
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import math
from pathlib import Path
import re
import statistics
import sys

ROOT = Path(__file__).resolve().parents[3]
FAMILIES = ("growing-cfg", "fixed-cfg")
SIZES = (64, 128, 256, 512, 1024, 2048, 4096)
REPETITIONS = (1, 2, 3)
INPUT_NAMES = ("translator", "typed_cfg", "recorded_path")
METRICS = ("crypto_prove_s", "setup_s", "verify_s", "witness_localcheck_s",
           "prove_total_s", "process_wall_s")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


class Evidence:
    def __init__(self):
        self.files = {}

    def check(self, path, expected=None):
        path = path.resolve()
        actual = digest(path)
        require(expected is None or actual == expected, f"SHA-256 mismatch: {path}")
        prior = self.files.setdefault(str(path), actual)
        require(prior == actual, f"File changed during validation: {path}")
        return actual

    def read(self, path, expected=None):
        self.check(path, expected)
        return json.loads(path.read_text())

    def jsonl(self, path, expected=None):
        self.check(path, expected)
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def sources(self, mapping):
        require(bool(mapping), "Missing source-hash inventory")
        for name, expected in mapping.items():
            self.check(ROOT / name, expected)

    def log(self, record, directory):
        # Resolve against the supplied campaign, allowing a whole campaign to be
        # relocated without accidentally reading a different original directory.
        path = directory / Path(record["log"]).name
        self.check(path, record["log_sha256"])
        return path.read_text()


def p2(value, minimum=1):
    return max(minimum, 1 << (value - 1).bit_length())


def numeric(value, description):
    require(isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value) and value >= 0,
            f"Missing, negative, or non-finite measurement: {description}")
    return value


def summary(values):
    if all(value is None for value in values):
        return {"median": None, "min": None, "max": None}
    require(all(value is not None for value in values), "Partially missing metric")
    return {"median": statistics.median(values), "min": min(values), "max": max(values)}


def same_value(reports, name):
    values = {report[name] for report in reports}
    require(len(values) == 1, f"Nondeterministic configuration/count: {name}: {values}")
    return next(iter(values))


def load_inputs(directory, evidence):
    manifest = evidence.read(directory / "manifest.json")
    require(manifest["schema"] == "zkcfa.synthetic-scaling-inputs.v1", "Unknown input schema")
    require(manifest["research_only"] is True, "Inputs lack research-only designation")
    require(manifest["sizes"] == list(SIZES), "Unexpected scale set")
    evidence.sources(manifest["source_sha256"])
    cases = {}
    for case in manifest["cases"]:
        key = case["family"], case["source_ep_rows"]
        require(key not in cases, f"Duplicate input case: {key}")
        cases[key] = case
        base = directory / key[0] / str(key[1])
        require(evidence.read(base / "case.json") == case, f"Case/manifest disagreement: {key}")
        require(case["rows_by_mode"]["complete"] == key[1], f"Wrong source row count: {key}")
        require(case["binius_edge_cap"] == p2(case["typed_edges"], 8), f"Wrong edge capacity: {key}")
        for mode in ("complete", "shadow", "zekra"):
            paths = base / mode
            hashes = case["input_sha256"][mode]
            require(set(hashes) == {*INPUT_NAMES, "static_returns.tsv"}, f"Incomplete input inventory: {key}/{mode}")
            for name, expected in hashes.items():
                evidence.check(paths / name, expected)
            for name, count in (("translator", case["nodes"]), ("typed_cfg", case["typed_edges"]),
                                ("recorded_path", case["rows_by_mode"][mode]),
                                ("static_returns.tsv", case["static_return_edges"])):
                require(len((paths / name).read_text().splitlines()) == count, f"Wrong input length: {paths / name}")
            audit = case["audit"][mode]
            require(all(audit[name] is True for name in ("typed_forward_edges_valid", "balanced_exact_returns",
                        "static_return_edges_valid", "endpoints_match")), f"Failed input audit: {key}/{mode}")
            require(audit["max_stack_depth"] == 2, f"Unexpected stack depth: {key}/{mode}")
            require(case["binius_ep_cap"][mode] == p2(case["rows_by_mode"][mode], 16), f"Wrong EP capacity: {key}/{mode}")
        # The backends receive the same source workload and CFG, but their
        # projectors need not retain the same path. In particular, preserving
        # entry and steady-state predecessor boundaries can retain extra rows.
        for mode in ("shadow", "zekra"):
            for name in ("translator", "typed_cfg", "static_returns.tsv"):
                require(case["input_sha256"][mode][name]
                        == case["input_sha256"]["complete"][name],
                        f"Shared CFG input mismatch: {key}/{mode}/{name}")
        paths_equal = ((base / "shadow/recorded_path").read_bytes()
                       == (base / "zekra/recorded_path").read_bytes())
        require(case["shadow_and_zekra_paths_equal"] is paths_equal,
                f"Projected-path equality flag differs from files: {key}")
    require(set(cases) == {(f, n) for f in FAMILIES for n in manifest["sizes"]}, "Require every declared scale in both fixture families")
    return manifest, cases


def load_binius(directory, inputs, cases, evidence):
    metadata = evidence.read(directory / "metadata.json")
    require(metadata["schema"] == "zkcfa.synthetic-scaling-binius.v1", "Unknown Binius schema")
    require(metadata.get("status") == "complete" and metadata.get("completed_utc"), "Binius campaign incomplete")
    expected_attempts = len(cases) * 2 * len(REPETITIONS)
    require(metadata["repeats"] == len(REPETITIONS) and metadata["expected_attempts"] == expected_attempts,
            "Binius planned attempts differ from the complete input grid")
    require(metadata["rayon_threads"] == 8, "Binius thread budget differs")
    evidence.check(inputs / "manifest.json", metadata["manifest_sha256"])
    evidence.check(Path(metadata["binary"]), metadata["binary_sha256"])
    evidence.sources(metadata["source_sha256"])
    records = evidence.jsonl(directory / "runs.jsonl", metadata["runs_sha256"])
    warmups = evidence.jsonl(directory / "warmups.jsonl")
    require(len(records) == expected_attempts and len(warmups) == len(FAMILIES) * 2,
            "Wrong Binius measurement/warmup count")
    grouped, warmup_keys = defaultdict(list), set()
    for record in records + warmups:
        key = record["family"], record["source_ep_rows"]
        require(key in cases, f"Unknown Binius case: {key}")
        case, mode = cases[key], record["mode"]
        require(mode in ("complete", "shadow"), f"Unknown Binius mode: {mode}")
        require(record["status"] == "verified" and record["exit_code"] == 0, f"Failed Binius attempt: {key}/{mode}")
        report = record["report"]
        log = evidence.log(record, directory / "logs")
        stdout = log.split("\n--- stderr/resource observations ---\n", 1)[0].strip()
        require(json.loads(stdout) == report, f"Binius journal/log report differs: {key}/{mode}")
        require(report["verified"] is True and report["research_only"] is True
                and report["synthetic"] is True and report["acquisition_measured"] is False
                and report["provider_signatures_checked"] is False, f"Unexpected Binius evidence scope: {key}/{mode}")
        for name, expected in (("path_mode", mode), ("rows", case["rows_by_mode"][mode]),
                               ("nodes", case["nodes"]), ("edges", case["typed_edges"]),
                               ("edge_capacity", case["binius_edge_cap"]),
                               ("ep_capacity", case["binius_ep_cap"][mode]),
                               ("addr_bits", 24), ("rayon_num_threads", 8), ("log_inv_rate", 1)):
            require(report[name] == expected, f"Binius {name} differs: {key}/{mode}")
        require(report["input_sha256"] == {name: case["input_sha256"][mode][name] for name in INPUT_NAMES},
                f"Binius input identity differs: {key}/{mode}")
        argv = record["argv"]
        for option, expected in (("--path-mode", mode), ("--edge-cap", str(case["binius_edge_cap"])),
                                 ("--ep-cap", str(case["binius_ep_cap"][mode])), ("--log-inv-rate", "1")):
            require(argv.count(option) == 1 and argv[argv.index(option) + 1] == expected,
                    f"Binius invocation option differs: {key}/{mode}/{option}")
        require(argv.count("--typed-dir") == 1 and Path(argv[argv.index("--typed-dir") + 1]).parts[-3:]
                == (key[0], str(key[1]), mode), f"Binius invocation fixture differs: {key}/{mode}")
        constraints = sum(numeric(report[name], name) for name in
                          ("and_constraints", "imul_constraints", "bmul_constraints", "zero_constraints"))
        require(constraints == report["native_constraint_count"], f"Binius native count sum differs: {key}/{mode}")
        for name in ("crypto_prove_ms", "setup_ms", "verify_ms", "witness_localcheck_ms", "prove_total_ms"):
            numeric(report[name], name)
        require(math.isclose(report["prove_total_ms"], report["crypto_prove_ms"] + report["witness_localcheck_ms"],
                             abs_tol=0.01), f"Binius proving boundary differs: {key}/{mode}")
        numeric(record["process_controller_wall_ms"], "Binius process wall time")
        if record["warmup"]:
            require(record in warmups and key[1] == 64 and record["repetition"] == 0, "Misclassified Binius warmup")
            require((*key, mode) not in warmup_keys, "Duplicate Binius warmup")
            warmup_keys.add((*key, mode))
        else:
            require(record in records, "Formal run placed in warmup journal")
            grouped[(*key, mode)].append(record)
    require(warmup_keys == {(f, 64, m) for f in FAMILIES for m in ("complete", "shadow")}, "Incomplete warmup inventory")
    for key in [(f, n, m) for f, n in cases for m in ("complete", "shadow")]:
        require(sorted(r["repetition"] for r in grouped[key]) == list(REPETITIONS), f"Missing/duplicate Binius repetitions: {key}")
        reports = [record["report"] for record in grouped[key]]
        for name in ("native_constraint_count", "and_constraints", "imul_constraints", "bmul_constraints",
                     "zero_constraints", "gates", "committed_words", "value_words", "ep_capacity", "edge_capacity"):
            same_value(reports, name)
    return metadata, records, warmups, grouped


def last_number(text, pattern, name):
    values = re.findall(pattern, text)
    require(bool(values), f"Missing ZEKRA log field: {name}")
    return numeric(float(values[-1]), name)


def audit_oom(base, report, campaign, text, evidence):
    runs = report["runs"]
    require(len(runs) == 1, "Resource failure must have exactly one attempted repetition")
    run = runs[0]
    require(run["repetition"] == 1 and run["returncode"] == 137 and run["verified"] is False,
            "Resource failure must be an unverified first attempt with exit 137")
    require(report["r1cs_constraints"] > 0, "OOM case lacks a compiled circuit count")
    require(all(run[field] is None for field in ("setup_s", "prove_s", "verify_s", "qap_pre_degree",
                                               "qap_degree", "qap_variables")),
            "Expected OOM before setup/proving and before native QAP counts")
    require("Translating Constraints" in text and "r1cs_gg_ppzksnark_" not in text
            and "The verification result" not in text, "OOM log does not show the expected pre-setup boundary")
    command = run["command"]
    require(command.count("--name") == 1, "OOM command lacks a unique container name")
    name = command[command.index("--name") + 1]
    events_path = base / "docker-events.jsonl"
    events = evidence.jsonl(events_path)
    require(bool(events), "OOM case has no Docker events")
    container_ids = set()
    for event in events:
        actor = event["Actor"]
        attributes = actor["Attributes"]
        container_ids.add(actor["ID"])
        require(event["Type"] == "container" and attributes["name"] == name,
                "OOM evidence contains an unrelated container event")
        require(attributes["desktop.docker.io/binds/0/Source"] == report["output"]
                and attributes["desktop.docker.io/binds/0/Target"] == "/work"
                and attributes["image"] in report["environment"]["native_image"]["RepoTags"],
                "OOM event volume/image does not match the measured case")
    require(len(container_ids) == 1, "OOM/die events identify different containers")
    oom = [event for event in events if event["Action"] == "oom"]
    died = [event for event in events if event["Action"] == "die"]
    require(len(oom) == 1 and len(died) == 1, "Require one matching Docker oom and die event")
    require(died[0]["Actor"]["Attributes"]["exitCode"] == "137", "Docker die event is not exit 137")
    require(oom[0]["timeNano"] <= died[0]["timeNano"], "Docker OOM/die events are out of order")
    start = datetime.fromisoformat(campaign["start_utc"]).timestamp()
    end = datetime.fromisoformat(campaign["end_utc"]).timestamp()
    require(start <= oom[0]["time"] <= died[0]["time"] <= end, "OOM events fall outside the formal campaign")
    duration = numeric(float(died[0]["Actor"]["Attributes"]["execDuration"]), "Docker OOM duration")
    require(abs(run["wall_seconds"] - duration) < 3, "Docker duration differs from the failed process measurement")
    compiler = base / "source/scripts/compile_circuit.py"
    compiler_hash = evidence.check(ROOT / "zekra/ZEKRA/scripts/compile_circuit.py")
    evidence.check(compiler, compiler_hash)
    compiler_text = compiler.read_text()
    require("if 'Sample Run: Sample_Run1 finished!' in line:" in compiler_text
            and "if not successful_run(stdout):" in compiler_text
            and "Error Detected - Circuit was not satisfied with the inputs!" in compiler_text,
            "Cannot establish the frozen compiler's sample-satisfaction gate")
    return {"classification": "resource-failed", "reason": "Docker OOM during native constraint translation before setup/proving",
            "successful_repetitions": 0, "attempted": 1, "planned": 3, "skipped_after_failure": 2,
            "failed_attempt_wall_s": run["wall_seconds"], "container_name": name,
            "container_id": next(iter(container_ids)), "events": events,
            "events_text": events_path.read_text(), "events_sha256": evidence.check(events_path),
            "sample_satisfaction_evidence": {"compiler_script_sha256": compiler_hash,
                "explanation": "The frozen upstream compiler emits its Error Detected diagnostic unless captured Java stdout contains 'Sample Run: Sample_Run1 finished!'. The complete hashed compile log contains no such diagnostic and records both generated arithmetic and witness files. Successful raw Java stdout is not separately retained."},
            "constraint_count_evidence": "successful compiler output only; native QAP count unavailable"}


def load_zekra(directory, cases, evidence):
    campaign = evidence.read(directory / "campaign.json")
    require(campaign["schema"] == "zkcfa.zekra.scaling-campaign.v1", "Unknown ZEKRA campaign schema")
    require(campaign.get("end_utc"), "ZEKRA campaign has not ended")
    require(campaign["repetitions"] == 3 and campaign["OMP_NUM_THREADS"] == 8, "ZEKRA repetitions/threads differ")
    require(campaign["levels"] in (2, 4), "Unexpected ZEKRA adjacency levels")
    warmup_repetitions = campaign.get("warmup_repetitions", 0)
    require(warmup_repetitions in (0, 1), "Unexpected ZEKRA warmup count")
    if warmup_repetitions:
        require(campaign.get("warmup_source_ep_rows") == 64 and campaign.get("warmup_scope") == "per-family",
                "ZEKRA warmup policy differs from the scaling design")
    # Check completeness before expensive file hashing or any output creation.
    indexed, resource_failures = {}, {}
    for result in campaign["results"]:
        key = result["family"], result["source_ep_rows"]
        require(key not in indexed, f"Duplicate ZEKRA result: {key}")
        indexed[key] = result
        require((result["status"] == "verified" and result["returncode"] == 0)
                or (key == ("growing-cfg", 4096) and result["status"] == "failed" and result["returncode"] == 1),
                f"ZEKRA campaign contains an unsupported failed case: {key}")
    require(set(indexed) == set(cases), "ZEKRA campaign does not cover exactly the input grid")
    evidence.sources(campaign["source_sha256"])
    campaign_sources = {str((ROOT / name).resolve()): value for name, value in campaign["source_sha256"].items()}
    measurements = {}
    for key in cases:
        case, result = cases[key], indexed[key]
        base = directory / key[0] / str(key[1])
        report = evidence.read(base / "measurement.json", result["measurement_sha256"])
        measurements[key] = report
        is_oom = key == ("growing-cfg", 4096) and result["status"] == "failed"
        require(report["status"] == result["status"] and report["repetitions"] == 3,
                f"ZEKRA case/campaign status or repetition count differs: {key}")
        require(report["threads"] == {"OMP_NUM_THREADS": 8, "OMP_DYNAMIC": "FALSE"}, f"ZEKRA thread settings differ: {key}")
        inp = report["input"]
        require(inp["source_hashes"] == {name: case["input_sha256"]["complete"][name] for name in INPUT_NAMES},
                f"ZEKRA complete-source identity differs: {key}")
        for name, expected in inp["projected_hashes"].items():
            evidence.check(base / "inputs" / name, expected)
        require(inp["projected_hashes"]["recorded_path"] == case["input_sha256"]["zekra"]["recorded_path"],
                f"ZEKRA projection differs from the shared fixture: {key}")
        require(inp["projected_hashes"]["translator"] == case["input_sha256"]["zekra"]["translator"],
                f"ZEKRA translator differs: {key}")
        require(inp["source_typed_edges"] == case["typed_edges"], f"ZEKRA typed-edge count differs: {key}")
        for label, mode in (("original", "complete"), ("projected", "zekra")):
            audit = inp[label]
            require(audit["valid_typed_edges_and_balanced_stack"] is True
                    and audit["rows_with_initial"] == case["rows_by_mode"][mode]
                    and audit["operations"] + 1 == case["rows_by_mode"][mode]
                    and audit["max_stack_depth"] == 2, f"ZEKRA path audit differs: {key}/{label}")
        returns = inp["static_returns"]
        require(returns["sidecar_matches_static_reachability"] is True
                and returns["sidecar_sha256"] == case["input_sha256"]["complete"]["static_returns.tsv"]
                and returns["count"] == case["static_return_edges"], f"ZEKRA static-return identity differs: {key}")
        params = inp["parameters"]
        expected = {"adjlist_len": p2(case["nodes"], 8), "path_len": p2(case["rows_by_mode"]["zekra"] - 1, 16),
                    "adjlist_levels": campaign["levels"], "stack_depth": 15, "address_bitwidth": 24}
        expected.update(label_bitwidth=expected["adjlist_len"].bit_length(),
                        bucket_bitwidth=(expected["adjlist_len"] // 8).bit_length())
        require(params == expected and inp["required_levels"] <= campaign["levels"], f"ZEKRA capacity/width mismatch: {key}")
        environment = report["environment"]
        require(environment["native_image"]["Architecture"] == "arm64"
                and environment["docker_info"]["Architecture"] == "aarch64", f"ZEKRA prover is not native ARM64: {key}")
        sources = report["sources"]
        require(sources["upstream_dirty"] == "", f"ZEKRA upstream was dirty: {key}")
        for label, relative in (("runner_sha256", "run_scaling.py"), ("patch_source_sha256", "PatchNativeMemory.java")):
            require(sources[label] == campaign_sources[str(ROOT / "zekra/reproduce/scaling" / relative)],
                    f"Mixed ZEKRA source revisions: {key}/{relative}")
        for label, relative in (("jar_before_sha256", "source/original.jar"), ("jar_after_sha256", "source/xjsnark_backend.jar"),
                                ("java_after_sha256", "source/zekra_java/zekra/zekra.java"),
                                ("arith_sha256", "inputs/zekra.arith"), ("witness_sha256", "inputs/zekra_Sample_Run1.in")):
            evidence.check(base / relative, sources[label])
        require(len(report["phases"]) >= 4, f"Missing ZEKRA preparation phases: {key}")
        phase_logs = {}
        for phase in report["phases"]:
            require(phase["returncode"] == 0, f"Failed ZEKRA preparation phase: {key}")
            phase_logs[Path(phase["log"]).name] = evidence.log(phase, base)
        compiled = phase_logs["03-compile.log"]
        require("Successfully compiled the ZEKRA circuit." in compiled
                and "Circuit was not satisfied" not in compiled and "Error Detected" not in compiled,
                f"Unsatisfied ZEKRA sample: {key}")
        count = last_number(compiled, r"Total constraints: (\d+)", "compiler constraints")
        require(count == report["r1cs_constraints"] == result["r1cs_constraints"], f"ZEKRA compiler count differs: {key}")
        require(sources["native_binary_sha256"] in phase_logs["01-native-environment.log"], f"Native binary identity absent: {key}")
        warmups = report.get("warmup_runs", [])
        expected_warmups = warmup_repetitions if key[1] == 64 else 0
        require(report.get("warmup_repetitions", 0) == expected_warmups
                and sorted(run["repetition"] for run in warmups) == list(range(1, expected_warmups + 1)),
                f"Missing/duplicate ZEKRA warmups: {key}")
        require(all(run.get("kind") == "warmup" for run in warmups), f"Misclassified ZEKRA warmup: {key}")
        runs = report["runs"]
        if warmup_repetitions:
            require(all(run.get("kind") == "measured" for run in runs), f"Misclassified ZEKRA formal run: {key}")
        expected_repetitions = [1] if is_oom else list(REPETITIONS)
        require(sorted(r["repetition"] for r in runs) == expected_repetitions, f"Missing/duplicate ZEKRA repetitions: {key}")
        for run in warmups + runs:
            text = evidence.log(run, base)
            command = run["command"]
            require("linux/arm64" in command and "OMP_NUM_THREADS=8" in command
                    and "OMP_DYNAMIC=FALSE" in command, f"ZEKRA native command/thread settings differ: {key}")
            numeric(run["wall_seconds"], "ZEKRA process wall time")
            if is_oom and run not in warmups:
                resource_failures[key] = audit_oom(base, report, campaign, text, evidence)
                continue
            require(run["returncode"] == 0 and run["verified"] is True
                    and "The verification result is: PASS" in text, f"ZEKRA proof did not verify: {key}")
            require(last_number(text, r"QAP pre degree: (\d+)", "QAP pre degree") == run["qap_pre_degree"] == count,
                    f"ZEKRA native/compiler count mismatch: {key}")
            for field, phase in (("setup_s", "generator"), ("prove_s", "prover"), ("verify_s", "verifier_strong_IC")):
                actual = last_number(text, r"\(leave\) Call to r1cs_gg_ppzksnark_" + phase + r"[^\n]*\[([0-9.]+)s", field)
                require(actual == numeric(run[field], field), f"ZEKRA journal/log timing differs: {key}/{field}")
        if is_oom:
            require(report.get("medians") is None and result["medians"] is None, "OOM case must not have successful timing medians")
            continue
        for field in ("setup_s", "prove_s", "verify_s", "wall_seconds"):
            require(statistics.median(run[field] for run in runs) == report["medians"][field] == result["medians"][field],
                    f"ZEKRA precomputed median differs: {key}/{field}")
    for field in ("native_binary_sha256", "jar_after_sha256", "runner_sha256", "patch_source_sha256", "upstream_revision"):
        same_value([r["sources"] for r in measurements.values()], field)
    return campaign, measurements, resource_failures


def aggregate(cases, binius, zekra, resource_failures):
    rows = []
    for family in FAMILIES:
        for size in sorted(n for f, n in cases if f == family):
            case = cases[family, size]
            for mode, series in (("complete", "complete"), ("shadow", "stack-safe"), ("zekra", "zekra")):
                row = {"family": family, "source_ep_rows": size, "nodes": case["nodes"],
                       "typed_edges": case["typed_edges"], "series": series,
                       "projected_ep_rows": case["rows_by_mode"][mode], "status": "verified",
                       "repetitions": 3, "attempted": 3, "planned": 3, "skipped_after_failure": 0,
                       "failed_attempt_wall_s": None, "constraint_count_evidence": "native compiled count"}
                if mode != "zekra":
                    records = binius[family, size, mode]
                    reports = [record["report"] for record in records]
                    row.update(native_constraints=reports[0]["native_constraint_count"],
                               constraint_unit="Binius64 word constraints (AND+IMUL+BMUL+ZERO)",
                               edge_capacity=reports[0]["edge_capacity"], ep_capacity=reports[0]["ep_capacity"],
                               adjlist_capacity=None, adjlist_levels=None)
                    samples = [{"crypto_prove_s": report["crypto_prove_ms"] / 1000,
                                "setup_s": report["setup_ms"] / 1000,
                                "verify_s": report["verify_ms"] / 1000,
                                "witness_localcheck_s": report["witness_localcheck_ms"] / 1000,
                                "prove_total_s": report["prove_total_ms"] / 1000,
                                "process_wall_s": record["process_controller_wall_ms"] / 1000}
                               for record, report in zip(records, reports)]
                else:
                    report = zekra[family, size]
                    row.update(native_constraints=report["r1cs_constraints"], constraint_unit="scalar-field R1CS rows",
                               edge_capacity=None,
                               ep_capacity=report["input"]["parameters"]["path_len"],
                               adjlist_capacity=report["input"]["parameters"]["adjlist_len"],
                               adjlist_levels=report["input"]["parameters"]["adjlist_levels"])
                    failure = resource_failures.get((family, size))
                    if failure:
                        row.update(status="resource-failed", repetitions=0, attempted=1, skipped_after_failure=2,
                                   failed_attempt_wall_s=failure["failed_attempt_wall_s"],
                                   constraint_count_evidence=failure["constraint_count_evidence"])
                        samples = [{metric: None for metric in METRICS}]
                    else:
                        row["constraint_count_evidence"] = "compiler count matched native QAP pre degree in all repetitions"
                        samples = [{"crypto_prove_s": run["prove_s"], "setup_s": run["setup_s"], "verify_s": run["verify_s"],
                                    "witness_localcheck_s": None, "prove_total_s": None, "process_wall_s": run["wall_seconds"]}
                                   for run in report["runs"]]
                for metric in METRICS:
                    row.update({metric + "_" + statistic: value
                                for statistic, value in summary([sample[metric] for sample in samples]).items()})
                rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--binius", required=True, type=Path)
    parser.add_argument("--zekra", required=True, type=Path)
    parser.add_argument("--output-prefix", type=Path, default=ROOT / "zkcfa-binius64/research/data/scaling-comparison")
    args = parser.parse_args()
    csv_path = Path(str(args.output_prefix) + ".csv").resolve()
    json_path = Path(str(args.output_prefix) + ".json").resolve()
    require(not csv_path.exists() and not json_path.exists(), "Refusing to overwrite a frozen export; choose a new prefix")
    evidence = Evidence()
    manifest, cases = load_inputs(args.inputs.resolve(), evidence)
    # Validate ZEKRA first: an incomplete campaign should fail before re-reading
    # the already completed Binius proof logs or binary.
    campaign, measurements, resource_failures = load_zekra(args.zekra.resolve(), cases, evidence)
    metadata, records, warmups, grouped = load_binius(args.binius.resolve(), args.inputs.resolve(), cases, evidence)
    rows = aggregate(cases, grouped, measurements, resource_failures)
    require(len(rows) == len(cases) * 3, "Unexpected aggregate row count")
    counts = {"planned": sum(row["planned"] for row in rows),
              "attempted": sum(row["attempted"] for row in rows),
              "verified": sum(row["repetitions"] for row in rows),
              "resource_failed": len(resource_failures),
              "skipped_after_failure": sum(row["skipped_after_failure"] for row in rows)}
    planned = len(cases) * 3 * len(REPETITIONS)
    failures = len(resource_failures)
    require(counts == {"planned": planned, "attempted": planned - 2 * failures,
                       "verified": planned - 3 * failures, "resource_failed": failures,
                       "skipped_after_failure": 2 * failures},
            "Formal campaign accounting differs from the accepted design")
    status = "complete-with-resource-failure" if resource_failures else "complete-verified"
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    csv_text = buffer.getvalue()
    evidence.check(Path(__file__))
    snapshot = {
        "schema": "zkcfa.synthetic-scaling-comparison.v3", "status": status,
        "exported_utc": datetime.now(timezone.utc).isoformat(),
        "formal_campaign_counts": counts,
        "formal_attempts": {"binius": len(records), "zekra": counts["attempted"] - len(records), "total": counts["attempted"]},
        "comparison_scope": {
            "paired_by": "family and source EP row count; identical complete-source inputs and CFG",
            "same_projected_path_required": False,
            "all_projected_paths_equal": all(case["shadow_and_zekra_paths_equal"] for case in cases.values()),
            "projected_rows": [{"family": family, "source_ep_rows": size,
                                "rows_by_mode": cases[family, size]["rows_by_mode"],
                                "paths_equal": cases[family, size]["shadow_and_zekra_paths_equal"]}
                               for family, size in cases]},
        "measurement_batches": {
            "binius": {"directory": str(args.binius.resolve()),
                       "started_utc": metadata["started_utc"], "completed_utc": metadata["completed_utc"]},
            "zekra": {"directory": str(args.zekra.resolve()),
                      "started_utc": campaign["start_utc"], "completed_utc": campaign["end_utc"]},
            "policy": "Each backend retains its actual measurement dates, source hashes and logs. Reusing an unchanged, validated backend batch does not make it a newly executed or synchronized campaign."},
        "excluded": {"binius_warmups": len(warmups),
                     "zekra_warmups": sum(len(report.get("warmup_runs", [])) for report in measurements.values()),
                     "smokes": "All smoke and diagnostic campaign timings are excluded; only the supplied final formal campaign is read. Docker OOM events are retained as failure evidence."},
        "units": {"times": "seconds", "scale": "source EP rows including the initial row (N-1 transitions)",
                  "circuits": "Backend-native counts: Binius64 AND+IMUL+BMUL+ZERO word constraints versus ZEKRA scalar-field R1CS rows. Counts are not equivalent-cost units.",
                  "uncertainty": "Median and observed minimum/maximum of three repetitions; descriptive spread, not confidence intervals or significance tests.",
                  "missing": "JSON null and empty CSV cells mean unmeasured, never zero."},
        "interpretation": {
            "scope": "Synthetic control-flow relation fixtures, not compiled instruction CFGs, QEMU traces, device acquisition, or signed handoffs. Existing real-application campaigns are separate.",
            "families": {"growing-cfg": "At N source rows, m=N/16 sites; 7m-1 nodes and 8m-1 typed edges; three balanced loop repetitions per site. Each backend's actual projected rows and capacities are recorded separately.",
                         "fixed-cfg": "Six nodes and seven typed edges; only loop repetitions grow. Each backend's projected row count remains fixed for this controlled fixture."},
            "projection": "Comparisons use the same complete-source workload and CFG, with each backend's own projection. Projected-path equality is checked and reported, not assumed. Additional retained stack-safe rows preserve predecessor-address and stack boundary states. Return edges for ZEKRA come from a static sidecar validated by callee reachability, never extracted from runtime EP edges.",
            "proving": "Binius crypto_prove_ms/1000 and libsnark r1cs_gg_ppzksnark_prover wall seconds; both exclude circuit construction, setup, and witness preparation. Binius prove_total additionally includes witness filling/local checks; no matching isolated ZEKRA witness metric is available.",
            "setup": "Binius setup includes circuit build plus verifier/prover setup; ZEKRA setup is the Groth16 generator call. These setup fields have different boundaries.",
            "environment": "Binius runs natively on macOS ARM64; ZEKRA Groth16 runs native ARM64 Linux in Docker on the same machine, with eight threads each. ZEKRA Java preparation uses an amd64 container outside the reported proving phase. OS, implementation, proof system, and relation differences prevent attributing timings solely to one design choice.",
            "zekra": "The isolated repaired ZEKRA implementation and full source/environment hashes are frozen below. Its controlled-scaling measurements are separate from the historical unmodified ZEKRA application results; actual batch dates are reported explicitly.",
            "resource_failure": "The growing-CFG ZEKRA 4096 case, if present as resource-failed, retains its successful compiler circuit count. Docker OOM during native constraint translation prevents setup, proving, verification and a native QAP count. All timing summaries for this point are absent; the one failed attempt's process time is separately recorded and the remaining two planned repetitions were skipped. This is a measured environment resource boundary, not a successful proof or a universal impossibility result.",
            "legacy_report_wording": "Raw Binius reports retain the production path_statement string mentioning QEMU; their synthetic/research_only flags and this campaign scope are authoritative. No QEMU execution was measured."},
        "aggregate_rows": rows,
        "inputs_manifest": manifest,
        "binius": {"metadata": metadata, "formal_runs": records, "excluded_warmups": warmups},
        "zekra": {"campaign": campaign,
                  "resource_failures": [{"family": family, "source_ep_rows": size, "evidence": report}
                                        for (family, size), report in resource_failures.items()],
                  "measurements": [{"family": family, "source_ep_rows": size, "report": measurements[family, size]}
                                                          for family, size in cases]},
        "validated_files_sha256": evidence.files,
        "csv": {"path": str(csv_path), "sha256": hashlib.sha256(csv_text.encode()).hexdigest()}}
    # Serialize everything before creating either output so validation/encoding
    # failures cannot leave a partial dataset that appears ready for plotting.
    json_text = json.dumps(snapshot, indent=2, sort_keys=True, allow_nan=False) + "\n"
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.write_text(csv_text)
    json_path.write_text(json_text)
    print(json.dumps({"status": status, "rows": len(rows), "formal_campaign_counts": counts,
                      "csv": str(csv_path), "json": str(json_path)}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError) as error:
        print(f"Scaling export rejected: {error}", file=sys.stderr)
        raise SystemExit(1)
