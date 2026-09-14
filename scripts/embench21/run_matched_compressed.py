#!/usr/bin/env python3
"""Serial matched compressed-input Binius64/ZEKRA measurements.

Consumes prepare_matched_compressed.py's manifest; never compresses or learns CFG
edges. New directories only, with immutable attempts and checked resume. No old
performance measurements are imported. ZEKRA Setup is libsnark key generation.
"""
from __future__ import annotations

import argparse
import csv
import fcntl
import hashlib
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
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
# Saved campaigns keep these helpers together in their flat instrumentation directory.
if not (HERE / "run_zekra_rss_apps.py").is_file():
    sys.path.insert(0, str(ROOT / "zekra/reproduce/scripts"))
import run_zekra_rss_apps as rss
import process_control

BINIUS_SHA = "f275657ef5424b4fd2cab96ccf49797c49dec31e775372d3464934ee7070e727"
ORIGINAL_JAR_SHA = "d6966c45ad659627027d19b4d8389d58a452f82ca416f1057efcdd428fbb535b"
REPAIRED_JAR_SHA = "b8371b11132ded46b7148deaf05c8b3e2ce7177f3ec3fbc0918a8f85fcc2e685"
CHANGED_CLASSES = {"backend/auxTypes/SmartMemory.class", *(
    f"backend/auxTypes/SmartMemory${i}.class" for i in (2, 3, 4))}
COMMON_FILES = {"translator", "typed_cfg", "recorded_path"}
ZEKRA_FILES = set(rss.INPUTS)
SCHEMA = "zkcfa.matched-compressed.plan.v1"
BINIUS_TIMINGS = ("setup_ms", "circuit_build_ms", "verifier_setup_ms", "prover_setup_ms",
                  "witness_localcheck_ms", "crypto_prove_ms", "prove_total_ms", "verify_ms",
                  "input_preflight_ms", "total_ms")
INSTRUMENTATION = ("run_matched_compressed.py", "run_zekra_rss_apps.py",
                   "run_zekra_repaired_apps.py", "zekra_linux_rss.py", "process_control.py")
INSTRUMENTATION_SOURCES = {
    "run_matched_compressed.py": Path(__file__).resolve(),
    "run_zekra_rss_apps.py": Path(rss.__file__).resolve(),
    "run_zekra_repaired_apps.py": Path(rss.prior.__file__).resolve(),
    "zekra_linux_rss.py": Path(rss.__file__).with_name("zekra_linux_rss.py"),
    "process_control.py": Path(process_control.__file__).resolve(),
}
sha, save, now = rss.sha, rss.save, rss.now


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def inside(root, relative):
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()), "manifest path escapes prepared root")
    return path


def check_files(root, hashes):
    for name, digest in hashes.items():
        path = inside(root, name)
        require(path.is_file() and sha(path) == digest, f"file identity changed: {path}")


def validate_manifest(root, selected=None):
    manifest = json.loads((root / "manifest.json").read_text())
    require(manifest.get("schema") == "zkcfa.matched-compressed.inputs.v1"
            and manifest.get("all_audits_passed") is True, "unrecognized or unaudited prepared manifest")
    apps = manifest["applications"]
    require(isinstance(apps, list) and apps, "manifest applications must be a nonempty list")
    require(len(apps) == 21 and manifest.get("application_count") == 21, "prepared manifest must cover all 21 applications")
    names = [app["application"] for app in apps]
    require(len(names) == len(set(names)) and all(re.fullmatch(r"[a-z0-9][a-z0-9-]*", n) for n in names),
            "duplicate or invalid application names")
    if selected:
        require(len(selected) == len(set(selected)) and set(selected) <= set(names), "unknown/duplicate selected application")
    for app in apps:
        require(set(app["common_hashes"]) == COMMON_FILES and set(app["zekra_hashes"]) == ZEKRA_FILES,
                "manifest must identify exactly three common and five ZEKRA input files")
        check_files(inside(root, app["common_dir"]), app["common_hashes"])
        check_files(inside(root, app["zekra_dir"]), app["zekra_hashes"])
        require(app.get("audit_file") and app.get("audit_sha256"), "mandatory per-application audit missing")
        check_files(root, {app["audit_file"]: app["audit_sha256"]})
        require(app["binius"]["path_mode"] == "shadow", "shared inputs require the shadow profile")
        require(all(isinstance(app[k], int) and app[k] > 0 for k in ("rows", "edges", "nodes")), "invalid instance counts")
        b, z = app["binius"], app["zekra"]
        require(b["edge_cap"] >= app["edges"] and b["ep_cap"] >= app["rows"], "Binius capacity too small")
        require(z["path_len"] >= app["rows"] - 1 and z["adjlist_len"] >= app["nodes"], "ZEKRA capacity too small")
        require(z["addr_bw"] == 24 and z["levels"] * (z["bucket_bw"] + 8) < 254, "unsupported ZEKRA encoding")
    return manifest, [app for app in apps if not selected or app["application"] in selected]


def validate_jar_pair(original, repaired):
    require(sha(original) == ORIGINAL_JAR_SHA and sha(repaired) == REPAIRED_JAR_SHA, "unexpected original/repaired jar pin")
    with zipfile.ZipFile(original) as before, zipfile.ZipFile(repaired) as after:
        require(before.namelist() == after.namelist(), "jar entry inventory differs")
        changed = {n for n in before.namelist() if before.read(n) != after.read(n)}
    require(changed == CHANGED_CLASSES, "repair changed classes beyond four SmartMemory classes")
    return sorted(changed)


def validate_binius_build(binary, build_metadata, expected_sha256):
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None,
            "expected Binius SHA-256 must be 64 lowercase hexadecimal characters")
    require(sha(binary) == expected_sha256, "Binius binary differs from expected pin")
    build = json.loads(build_metadata.read_text())
    records = [build.get("binary"), build.get("binaries", {}).get("scaling")]
    declared = [record.get("sha256") for record in records if isinstance(record, dict)]
    require(bool(declared) and all(value == expected_sha256 for value in declared),
            "Binius build metadata does not bind the expected scaling executable")


def validate_binius(report, app, peak):
    require(report.get("schema") == "zkcfa.research.scaling.v1" and report.get("verified") is True, "missing verified Binius report")
    require(report.get("input_sha256") == app["common_hashes"], "Binius input hashes differ")
    for field, expected in {"rows": app["rows"], "edges": app["edges"], "nodes": app["nodes"],
                            "edge_capacity": app["binius"]["edge_cap"], "ep_capacity": app["binius"]["ep_cap"],
                            "path_mode": "shadow", "rayon_num_threads": 8, "log_inv_rate": 1,
                            "addr_bits": 24}.items():
        require(report.get(field) == expected, f"Binius {field} differs from plan")
    require(isinstance(peak, int) and peak > 0, "missing macOS RSS")
    require(isinstance(report.get("proof_bytes"), int) and report["proof_bytes"] > 0, "missing serialized proof size")
    for key in BINIUS_TIMINGS:
        value = report.get(key)
        require(isinstance(value, (int, float)) and math.isfinite(value) and value >= 0, f"invalid Binius timing {key}")


def stats(values):
    return {"samples": values, "median": statistics.median(values), "min": min(values), "max": max(values)}


def remember_identity(directory, names, filename):
    hashes = {n: sha(directory / n) for n in names}
    identity = directory / filename
    if identity.exists():
        require(json.loads(identity.read_text()) == hashes, f"intermediate artifacts changed: {identity}")
    else:
        save(identity, hashes)
    return hashes


def configured_java_hash(snapshot, params):
    """Compute the unchanged upstream compiler's expected parameter edits in memory."""
    namespace = {"__name__": "matched_configuration_audit"}
    script = snapshot / "scripts/compile_circuit.py"
    exec(compile(script.read_text(), str(script), "exec"), namespace)
    namespace.update(SHADOWSTACK_DEPTH=params["stack_depth"], LABEL_BITWIDTH=params["label_bw"],
                     BUCKET_BITWIDTH=params["bucket_bw"], ADDR_BITWIDTH=params["addr_bw"],
                     ADJLIST_SIZE=params["adjlist_len"], ADJLIST_LEVELS=params["levels"], EXECUTION_PATH_SIZE=params["path_len"])
    lines = namespace["read_component"](str(snapshot / "zekra_java/zekra/zekra.java"))
    lines = namespace["adjust_data_structures"](lines)
    lines = namespace["set_input_dir"](lines, "/work/inputs")
    lines = namespace["set_output_dir"](lines, "/work/inputs")
    return hashlib.sha256("".join(line + "\r\n" for line in lines).encode()).hexdigest()


class Campaign(rss.Campaign):
    """Reuse the audited Linux container/RSS/OOM lifecycle unchanged."""

    def prepare(self):
        if self.args.resume:
            self.plan = json.loads((self.base / "plan.json").read_text())
            require(self.plan["schema"] == SCHEMA, "not a matched compressed campaign")
            require(self.args.inputs.resolve() == Path(self.plan["prepared_root"]), "resume input root changed")
            requested_binary = getattr(self.args, "expected_binius_sha256", None)
            require(requested_binary is None or requested_binary == self.plan.get("binius_binary_sha256", BINIUS_SHA),
                    "resume Binius binary pin changed")
            requested = self.args.applications.split(",") if self.args.applications else None
            require(not requested or set(requested) == {a["application"] for a in self.plan["applications"]}, "resume application selection changed")
            for name, digest in self.plan["instrumentation_sha256"].items():
                require(sha(INSTRUMENTATION_SOURCES[name]) == digest, "runner changed; resume with saved instrumentation/run_matched_compressed.py")
            self.check_plan()
            images = json.loads(rss.capture([self.docker, "image", "inspect", self.plan["compile_image"], self.plan["native_image"]]))
            require([i["Id"] for i in images] == [self.plan["compile_image"], self.plan["native_image"]], "pinned images unavailable")
            return

        require(sys.platform == "darwin", "Binius RSS campaign requires macOS /usr/bin/time -l")
        prepared = self.args.inputs.resolve()
        selected = self.args.applications.split(",") if self.args.applications else None
        manifest, apps = validate_manifest(prepared, selected)
        info = json.loads(rss.capture([self.docker, "info", "--format", "{{json .}} "]))
        images = json.loads(rss.capture([self.docker, "image", "inspect", "zkcfa-zekra:paper-ubuntu22.04", "zekra-native:local"]))
        require(info["Architecture"] == "aarch64" and info["NCPU"] >= 8 and info["MemTotal"] > 18 * 2**30,
                "Docker must have ARM64, eight CPUs and more than 18 GiB")
        require([i["Architecture"] for i in images] == ["amd64", "arm64"], "compiler/native image architecture mismatch")
        binary = self.args.binius_binary.resolve()
        build_metadata = self.args.binius_build_metadata.resolve()
        original = ROOT / "zekra/ZEKRA/xjsnark_backend.jar"
        repaired = self.args.repaired_jar.resolve()
        for path in (binary, build_metadata, repaired):
            require(path.is_file(), f"required measurement artifact is missing: {path}")
        expected_binary = getattr(self.args, "expected_binius_sha256", None) or BINIUS_SHA
        validate_binius_build(binary, build_metadata, expected_binary)
        changed = validate_jar_pair(original, repaired)
        require(not rss.capture(["git", "-C", str(ROOT / "zekra/ZEKRA"), "status", "--porcelain"]).strip(), "ZEKRA upstream must be clean")
        (self.base / "instrumentation").mkdir()
        for name in INSTRUMENTATION:
            shutil.copy2(INSTRUMENTATION_SOURCES[name], self.base / "instrumentation" / name)
        (self.base / "frozen").mkdir()
        shutil.copy2(binary, self.base / "frozen/scaling")
        shutil.copy2(original, self.base / "frozen/original.jar")
        shutil.copy2(repaired, self.base / "frozen/xjsnark_backend.jar")
        shutil.copy2(build_metadata, self.base / "frozen/binius-build.json")
        for name in ("scripts", "zekra_java"):
            shutil.copytree(ROOT / "zekra/ZEKRA" / name, self.base / "frozen/source" / name)
        for name in ("PatchNativeMemory.java", "CheckNativeMemory.java"):
            shutil.copy2(ROOT / "zekra/reproduce/scaling" / name, self.base / "frozen" / name)
        shutil.copy2(prepared / "manifest.json", self.base / "frozen/prepared-manifest.json")
        (self.base / "cases").mkdir()
        for app in apps:
            base = self.base / "cases" / app["application"]
            for source_key, target in (("common_dir", "common"), ("zekra_dir", "zekra/inputs")):
                dest = base / target
                dest.mkdir(parents=True)
                for name in app["common_hashes" if source_key == "common_dir" else "zekra_hashes"]:
                    shutil.copy2(inside(prepared, app[source_key]) / name, dest / name)
            if app.get("audit_file"):
                shutil.copy2(inside(prepared, app["audit_file"]), base / "input-audit.json")
        fixed = {str(p.relative_to(self.base)): sha(p) for p in (self.base / "frozen").rglob("*") if p.is_file()}
        self.plan = {"schema": SCHEMA, "created_utc": now(), "repository_root": str(ROOT),
                     "prepared_root": str(prepared), "prepared_manifest_sha256": sha(prepared / "manifest.json"),
                     "applications": apps, "source_manifest_schema": manifest.get("schema"),
                     "compile_image": images[0]["Id"], "native_image": images[1]["Id"],
                     "image_metadata": images, "docker_info": {k: info[k] for k in ("Architecture", "NCPU", "MemTotal", "ServerVersion", "KernelVersion")},
                     "host": rss.capture(["sw_vers"]), "upstream_revision": rss.capture(["git", "-C", str(ROOT / "zekra/ZEKRA"), "rev-parse", "HEAD"]).strip(),
                     "instrumentation_sha256": {n: sha(self.base / "instrumentation" / n) for n in INSTRUMENTATION},
                     "frozen_sha256": fixed, "jar_changed_classes": changed,
                     "binius_binary_sha256": expected_binary,
                     "binius_build_metadata_sha256": fixed["frozen/binius-build.json"],
                     "stage_timeout_seconds": 900, "memory_bytes": 18 * 2**30, "memory_swap_bytes": 18 * 2**30,
                     "threads": 8, "native_warmups": 1, "native_measured_runs": 3,
                     "label": "zkcfa-matched-compressed-" + uuid.uuid4().hex[:12],
                     "prepared_scope": manifest["scope"],
                     "scope": manifest["scope"] + " Proof-only measurements; the frozen Binius research JSON retains its historical synthetic=true field. Binius setup includes construction/preprocessing; ZEKRA setup is keygen only. ZEKRA proof bits are group-element accounting, not serialized bytes.",
                     "binius_memory": "macOS time -l process RSS; 18 GiB sampled process-group guard (0.1 s), not a hard memory limit",
                     "order": "serial applications: four Binius invocations, then ZEKRA formatting/compilation and four native invocations; first of each backend excluded"}
        save(self.base / "plan.json", self.plan)
        self.check_plan()

    def check_plan(self):
        require(sha(Path(self.plan["prepared_root"]) / "manifest.json") == self.plan["prepared_manifest_sha256"], "prepared manifest changed")
        check_files(self.base, self.plan["frozen_sha256"])
        check_files(self.base / "instrumentation", self.plan["instrumentation_sha256"])
        expected_binary = self.plan.get("binius_binary_sha256", BINIUS_SHA)
        require(self.plan["frozen_sha256"]["frozen/scaling"] == expected_binary,
                "frozen Binius binary pin differs from plan")
        if "binius_build_metadata_sha256" in self.plan:
            require(self.plan["frozen_sha256"]["frozen/binius-build.json"] == self.plan["binius_build_metadata_sha256"],
                    "frozen Binius build metadata pin differs from plan")
            validate_binius_build(self.base / "frozen/scaling", self.base / "frozen/binius-build.json", expected_binary)
        for app in self.plan["applications"]:
            base = self.base / "cases" / app["application"]
            check_files(base / "common", app["common_hashes"])
            check_files(base / "zekra/inputs", app["zekra_hashes"])
            if app.get("audit_file"):
                require(sha(base / "input-audit.json") == app["audit_sha256"], "input audit changed")

    def native_environment(self):
        base = self.base / "environment"
        (base / "source").mkdir(parents=True, exist_ok=True)
        command = ["sh", "-ec", f"uname -m; sha256sum {rss.NATIVE}; "
                   "grep -E 'MULTICORE:|PERFORMANCE:|OPT_FLAGS:|USE_ASM:|CURVE:' /opt/jsnark/libsnark/build/CMakeCache.txt; "
                   f"ldd {rss.NATIVE}; git -C /opt/jsnark rev-parse HEAD; git -C /opt/jsnark/libsnark rev-parse HEAD"]
        phase = self.run_container(base, "arm64", command, base / "native-environment.log", "native-environment")
        require(phase["returncode"] == 0 and not phase.get("measurement_error"), "native environment validation failed")
        text = self.phase_text(phase)
        match = re.search(r"(?m)^([0-9a-f]{64})\s+" + re.escape(rss.NATIVE) + r"$", text)
        require(match is not None and "aarch64" in text, "native binary identity/architecture unavailable")
        identity = {"native_binary_sha256": match[1], "image": self.plan["native_image"],
                    "environment_log_sha256": phase["log_sha256"]}
        path = base / "identity.json"
        if path.exists():
            require(json.loads(path.read_text()) == identity, "native environment identity changed")
        else:
            save(path, identity)

    def binius_attempt(self, app, rep):
        base = self.base / "cases" / app["application"]
        lane = base / "binius/attempts" / f"run-{rep + 1}"
        lane.mkdir(parents=True, exist_ok=True)
        command = [str(self.base / "frozen/scaling"), "--typed-dir", str(base / "common"), "--path-mode", "shadow",
                   "--edge-cap", str(app["binius"]["edge_cap"]), "--ep-cap", str(app["binius"]["ep_cap"]), "--log-inv-rate", "1"]
        for pending in sorted(lane.glob("*/pending.json")):
            phase_path = pending.parent / "phase.json"
            if phase_path.exists():
                continue
            p = json.loads(pending.read_text())
            live = [r for r in process_control.process_table().values() if r["pgid"] == p.get("pgid") and not r["state"].startswith("Z")]
            require(not live, "interrupted Binius group is still running; stop it before resuming")
            p.update(interrupted=True, verified=False, status="interrupted", completed_utc=now())
            save(phase_path, p)
        previous = sorted(lane.glob("*/phase.json"))
        if previous:
            p = json.loads(previous[-1].read_text())
            if not p.get("interrupted"):
                require(p["workload_command"] == command, "completed Binius command changed")
                check_files(self.base, p["log_sha256"])
                if p.get("verified"):
                    validate_binius(p["report"], app, p["peak_rss_bytes"])
                return p
        attempt = lane / f"{len(list(lane.iterdir())) + 1:03d}"
        attempt.mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith("ZKCFA_")}
        env.update(RAYON_NUM_THREADS="8", OMP_NUM_THREADS="8", OMP_DYNAMIC="FALSE")
        p = {"repetition": rep + 1, "kind": "warmup" if rep == 0 else "measured", "started_utc": now(),
             "workload_command": command, "verified": False, "interrupted": False}
        save(attempt / "pending.json", p)
        start = time.monotonic()
        with (attempt / "stdout.log").open("x") as stdout, (attempt / "stderr.log").open("x") as stderr:
            proc = subprocess.Popen(["/usr/bin/time", "-l", *command], env=env, stdout=stdout, stderr=stderr, start_new_session=True)
            p["pgid"] = proc.pid
            save(attempt / "pending.json", p)
            interrupted = False
            try:
                p["sampled_group_rss_peak_bytes"] = 0
                while proc.poll() is None:
                    group = [r for r in process_control.process_table().values() if r["pgid"] == proc.pid and r["uid"] == os.getuid()]
                    resident = sum(r["rss_bytes"] for r in group)
                    p["sampled_group_rss_peak_bytes"] = max(p["sampled_group_rss_peak_bytes"], resident)
                    if resident >= self.plan["memory_bytes"]:
                        p["stop_reason"] = "rss-guard"
                        break
                    if time.monotonic() - start >= self.plan["stage_timeout_seconds"]:
                        p["stop_reason"] = "timeout"
                        break
                    time.sleep(0.1)
            except BaseException as error:
                interrupted = isinstance(error, (KeyboardInterrupt, SystemExit))
                p.update(interrupted=interrupted, controller_error=repr(error), stop_reason="interrupted" if interrupted else "controller-error")
            finally:
                cleanup = process_control.terminate_owned_group(proc)
                p.update(cleanup=cleanup, returncode=proc.returncode, wall_seconds=time.monotonic() - start, completed_utc=now())
        p["log_sha256"] = {str(path.relative_to(self.base)): sha(path) for path in (attempt / "stdout.log", attempt / "stderr.log")}
        matches = re.findall(r"(?m)^\s*(\d+)\s+maximum resident set size\s*$", (attempt / "stderr.log").read_text(errors="replace"))
        p["peak_rss_bytes"] = int(matches[-1]) if matches else None
        try:
            require(p["cleanup"]["complete"], "Binius process cleanup incomplete")
            require(p["returncode"] == 0 and not p.get("stop_reason"), "Binius invocation did not complete normally")
            report = json.loads((attempt / "stdout.log").read_text())
            check_files(base / "common", app["common_hashes"])
            validate_binius(report, app, p["peak_rss_bytes"])
            p.update(report=report, verified=True, status="verified")
        except (RuntimeError, ValueError, KeyError) as error:
            p.update(status=p.get("stop_reason", "failed"), error=str(error))
        save(attempt / "phase.json", p)
        require(p["cleanup"]["complete"], "cleanup unconfirmed; stop campaign rather than overlap workloads")
        if interrupted:
            raise KeyboardInterrupt()
        return p

    def binius_case(self, app):
        result = {"backend": "binius64", "application": app["application"], "runs": [], "verified": False, "status": "running"}
        path = self.base / "cases" / app["application"] / "binius/result.json"
        path.parent.mkdir(exist_ok=True)
        for rep in range(4):
            result["runs"].append(self.binius_attempt(app, rep))
            save(path, result)
            if not result["runs"][-1]["verified"]:
                result["status"] = result["runs"][-1]["status"]
                break
        measured = [p for p in result["runs"] if p["kind"] == "measured" and p["verified"]]
        result["measured_verified_runs"] = len(measured)
        if len(measured) == 3:
            result.update(verified=True, status="verified", timings_ms={k: stats([p["report"][k] for p in measured]) for k in BINIUS_TIMINGS},
                          peak_rss_bytes=max(p["peak_rss_bytes"] for p in measured), proof_bytes=stats([p["report"]["proof_bytes"] for p in measured]))
        result["completed_utc"] = now()
        save(path, result)
        return result

    def zekra_case(self, app):
        base = self.base / "cases" / app["application"] / "zekra"
        source, inputs = base / "source", base / "inputs"
        if not source.exists():
            shutil.copytree(self.base / "frozen/source", source)
            shutil.copy2(self.base / "frozen/xjsnark_backend.jar", source / "xjsnark_backend.jar")
        require(sha(source / "xjsnark_backend.jar") == REPAIRED_JAR_SHA, "case repaired jar changed")
        # The upstream compiler parameterizes this one Java file; all other copied
        # source files must still match the snapshot before any stage can execute.
        for relative, digest in self.plan["frozen_sha256"].items():
            if relative.startswith("frozen/source/"):
                name = relative.removeprefix("frozen/source/")
                if name != "zekra_java/zekra/zekra.java":
                    require(sha(source / name) == digest, f"case compiler source changed: {name}")
        expected_java = configured_java_hash(self.base / "frozen/source", app["zekra"])
        java = source / "zekra_java/zekra/zekra.java"
        original_java = self.plan["frozen_sha256"]["frozen/source/zekra_java/zekra/zekra.java"]
        require(sha(java) in {original_java, expected_java}, "case Java differs from original or expected configured source")
        check_files(inputs, app["zekra_hashes"])
        z = app["zekra"]
        result = {"backend": "zekra", "application": app["application"], "parameters": z, "phases": [], "runs": [], "verified": False, "status": "running"}
        def finish(status):
            if status != "verified" and result["phases"] and not result["runs"]:
                result["phases"][-1]["failure_reason"] = status
            result.update(status=status, completed_utc=now())
            rss.aggregate(result)
            check_files(inputs, app["zekra_hashes"])
            save(base / "result.json", result)
            return result
        formatter = ["python3", "scripts/circuit_input_formatter.py", "-a", "/work/inputs/",
                     "--pad-adjlist-to", str(z["adjlist_len"]), "--pad-path-to", str(z["path_len"]),
                     "--adjlist-levels", str(z["levels"]), "--label-bitwidth", str(z["label_bw"]),
                     "--bucket-bitwidth", str(z["bucket_bw"]), "--address-bitwidth", "24",
                     "--nonce-verifier", "12353", "--nonce-path", "123", "--nonce-translator", "123", "--nonce-adjlist", "123"]
        phase = self.run_container(base, "amd64", formatter, base / "format.log", app["application"] + ":format")
        result["phases"].append(phase)
        if phase["returncode"] or phase.get("measurement_error") or phase.get("timed_out") or not (inputs / "in_recorded_path_digest").is_file():
            return finish(self.failure(phase, "format-failed"))
        result["formatted_sha256"] = remember_identity(inputs, [p.name for p in sorted(inputs.glob("in_*"))], "formatted-identity.json")
        compiler = ["python3", "scripts/compile_circuit.py", "--zekra-dir", "zekra_java/zekra", "--input-dir", "/work/inputs", "--output-dir", "/work/inputs", "--components-dir", "zekra_java/components"]
        for key, option in rss.PARAMS.items():
            compiler.extend(["--" + option, str(z[key])])
        phase = self.run_container(base, "amd64", compiler, base / "compile.log", app["application"] + ":compile")
        result["phases"].append(phase)
        text = self.phase_text(phase)
        count = re.findall(r"Total constraints: (\d+)", text)
        result["r1cs_constraints"] = int(count[-1]) if count else None
        result["satisfied"] = bool(count) and phase["returncode"] == 0 and not phase.get("timed_out") and not phase.get("measurement_error") and "Circuit was not satisfied" not in text and "Error Detected" not in text
        compiled = ("zekra.arith", "zekra_Sample_Run1.in")
        if not result["satisfied"] or not all((inputs / n).is_file() for n in compiled):
            return finish(self.failure(phase, "compile-failed"))
        require(sha(java) == expected_java, "compiled Java parameters differ from prepared plan")
        result["configured_java_sha256"] = expected_java
        hashes = remember_identity(inputs, compiled, "compiled-identity.json")
        result["compiled_sha256"] = hashes
        save(base / "result.json", result)
        for rep in range(4):
            check_files(inputs, hashes)
            phase = self.run_container(base, "arm64", [rss.NATIVE, "gg", "/work/inputs/zekra.arith", "/work/inputs/zekra_Sample_Run1.in"],
                                       base / f"native-{rep + 1}.log", app["application"] + f":native-{rep + 1}/4")
            phase.update(repetition=rep + 1, kind="warmup" if rep == 0 else "measured")
            rss.native_metrics(self.phase_text(phase), phase, result["r1cs_constraints"])
            if not phase.get("reported_proof_bits"):
                phase.update(verified=False, measurement_error="missing group-element proof-bit accounting")
            result["runs"].append(phase)
            rss.aggregate(result)
            save(base / "result.json", result)
            if not phase["verified"]:
                return finish(self.failure(phase, "native-failed"))
        result["verified"] = True
        return finish("verified")

    def summarize(self, status):
        rows = []
        for app in self.plan["applications"]:
            for backend in ("binius", "zekra"):
                path = self.base / "cases" / app["application"] / backend / "result.json"
                r = json.loads(path.read_text()) if path.exists() else {"status": "not-run", "verified": False}
                row = {"application": app["application"], "backend": backend, "status": r["status"], "verified": r["verified"],
                       "rows": app["rows"], "edges": app["edges"], "measured_verified_runs": r.get("measured_verified_runs", 0),
                       "setup_s": None, "setup_scope": "construction/preprocessing" if backend == "binius" else "libsnark keygen only",
                       "crypto_prove_s": None, "verify_ms": None, "proof_bytes": None, "proof_bits_accounting": None, "peak_rss_bytes": None,
                       "failed_attempt_peak_rss_bytes": None, "failed_attempt_rss_is_lower_bound": None,
                       "failed_attempt_stage": None, "result": str(path.relative_to(self.base)) if path.exists() else None,
                       "result_sha256": sha(path) if path.exists() else None}
                if r["verified"]:
                    if backend == "binius":
                        t = r["timings_ms"]
                        row.update(setup_s=t["setup_ms"]["median"] / 1000, crypto_prove_s=t["crypto_prove_ms"]["median"] / 1000,
                                   verify_ms=t["verify_ms"]["median"], proof_bytes=r["proof_bytes"]["median"], peak_rss_bytes=r["peak_rss_bytes"])
                    else:
                        t = r["timings"]
                        row.update(setup_s=t["setup_s"]["median"], crypto_prove_s=t["prove_s"]["median"], verify_ms=t["verify_s"]["median"] * 1000,
                                   proof_bits_accounting=statistics.median(p["reported_proof_bits"] for p in r["runs"] if p["kind"] == "measured"),
                                   peak_rss_bytes=r["rss"]["native_measured_peak_rss_bytes"])
                else:
                    failures = [p for p in r.get("phases", []) if p.get("failure_reason") or p.get("returncode") or p.get("measurement_error") or p.get("timed_out") or p.get("state", {}).get("OOMKilled")]
                    failures += [p for p in r.get("runs", []) if not p.get("verified")]
                    if failures:
                        failed = max(failures, key=lambda p: p.get("peak_rss_bytes") or p.get("observed_peak_rss_bytes") or 0)
                        value = failed.get("peak_rss_bytes") or failed.get("observed_peak_rss_bytes") or None
                        row.update(failed_attempt_peak_rss_bytes=value,
                                   failed_attempt_rss_is_lower_bound=(failed.get("peak_rss_bytes") is None) if value else None,
                                   failed_attempt_stage=failed.get("stage", failed.get("kind")))
                rows.append(row)
        save(self.base / "summary.json", {"schema": "zkcfa.matched-compressed.summary.v1", "status": status, "updated_utc": now(),
                                          "plan_sha256": sha(self.base / "plan.json"), "scope": self.plan["scope"], "results": rows})
        temporary = self.base / "results.csv.tmp"
        with temporary.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader(); writer.writerows(rows)
        temporary.replace(self.base / "results.csv")

    def execute(self):
        self.prepare()
        self.summarize("prepared" if self.args.prepare_only else "running")
        if self.args.prepare_only:
            return 0
        try:
            self.native_environment()
            for app in self.plan["applications"]:
                self.check_plan()
                print(json.dumps({"event": "application-start", "application": app["application"], "utc": now()}), flush=True)
                self.binius_case(app)
                self.summarize("running")
                self.zekra_case(app)
                self.summarize("running")
            self.check_plan()
            self.summarize("complete")
            return 0
        except BaseException:
            self.summarize("interrupted")
            raise


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--binius-binary", type=Path,
                        help="scaling executable matching the expected SHA-256; required for a new campaign")
    parser.add_argument("--expected-binius-sha256",
                        help="expected SHA-256 for a fresh build; defaults to the original evaluated pin")
    parser.add_argument("--binius-build-metadata", type=Path,
                        help="build metadata JSON accompanying the evaluated executable; required for a new campaign")
    parser.add_argument("--repaired-jar", type=Path,
                        help="SmartMemory-repaired backend matching REPAIRED_JAR_SHA; required for a new campaign")
    parser.add_argument("--applications", help="comma-separated subset, retained in manifest order")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args(argv)
    if args.expected_binius_sha256 is not None and re.fullmatch(r"[0-9a-f]{64}", args.expected_binius_sha256) is None:
        parser.error("--expected-binius-sha256 must be 64 lowercase hexadecimal characters")
    if not args.resume:
        required = ("binius_binary", "binius_build_metadata", "repaired_jar")
        missing = ["--" + name.replace("_", "-") for name in required if getattr(args, name) is None]
        if missing:
            parser.error("new campaigns require " + ", ".join(missing))
    return args


def main():
    args = parse_args()
    os.umask(0o077)
    args.output = args.output.resolve()
    if not args.resume:
        args.output.mkdir(parents=True, exist_ok=False)
    def interrupt(_signum, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupt)
    with (args.output / ".campaign.lock").open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return Campaign(args).execute()


if __name__ == "__main__":
    sys.exit(main())
