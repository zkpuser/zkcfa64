#!/usr/bin/env python3
"""Run all or selected applications from the isolated released ZEKRA suite."""
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
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
PINNED_JAR = "d6966c45ad659627027d19b4d8389d58a452f82ca416f1057efcdd428fbb535b"


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def select_applications(requested, available):
    if requested is None:
        return sorted(available)
    selected = [name.strip() for name in requested.split(",")]
    if not all(selected) or len(set(selected)) != len(selected):
        raise ValueError("--applications must contain distinct, nonempty names")
    unknown = set(selected) - set(available)
    if unknown:
        raise ValueError("unknown applications: " + ", ".join(sorted(unknown)))
    return sorted(selected)


def coverage_issue(rows, expected):
    if sorted(row["app"] for row in rows) != sorted(expected):
        return "result set does not contain exactly the selected applications"
    return None


def prepare(base, requested=None, keep_artifacts=False):
    """Freeze clean upstream sources and current wrappers, without running a circuit."""
    upstream = ROOT / "zekra/ZEKRA"
    if base.resolve() == upstream.resolve() or upstream.resolve() in base.resolve().parents:
        raise ValueError("output must be outside the upstream checkout")
    if subprocess.check_output(["git", "-C", str(upstream), "status", "--porcelain"], text=True).strip():
        raise RuntimeError("upstream ZEKRA must be clean before taking a source snapshot")
    if digest(upstream / "xjsnark_backend.jar") != PINNED_JAR:
        raise RuntimeError("the legacy campaign requires the original upstream jar")
    available = sorted(path.name for path in (upstream / "embench-iot-applications").iterdir() if path.is_dir())
    selected = select_applications(requested, available)
    if len(available) != 21:
        raise RuntimeError("expected the 21 released upstream applications")
    for app in available:
        for name in ("adjlist", "numified_adjlist", "translator", "recorded_path", "numified_path"):
            if not (upstream / "embench-iot-applications" / app / name).is_file():
                raise RuntimeError(f"missing released input: {app}/{name}")
    real = shutil.which("docker")
    if not real:
        raise RuntimeError("Docker CLI is unavailable")
    images = json.loads(subprocess.check_output([real, "image", "inspect",
        "zkcfa-zekra:paper-ubuntu22.04", "zekra-native:local"], text=True))
    if [image["Architecture"] for image in images] != ["amd64", "arm64"]:
        raise RuntimeError("ZEKRA image architecture mismatch")
    archive = subprocess.check_output(["git", "-C", str(upstream), "archive", "HEAD"])
    base.mkdir(parents=True, exist_ok=False)
    snapshot = base / "snapshot/zekra"
    (snapshot / "ZEKRA").mkdir(parents=True)
    subprocess.run(["tar", "-xf", "-", "-C", str(snapshot / "ZEKRA")], input=archive, check=True)
    (snapshot / "reproduce").mkdir()
    shutil.copy2(ROOT / "zekra/reproduce/run-embench-suite.sh", snapshot / "reproduce/run-embench-suite.sh")
    (snapshot / ".zekra-campaign-snapshot").write_text("isolated ZEKRA source archive\n")
    helpers = base / "helpers"
    (helpers / "zekra-docker").mkdir(parents=True)
    shutil.copy2(Path(__file__).with_name("zekra_docker_proxy.py"), helpers / "zekra-docker/docker")
    (helpers / "zekra-docker/docker").chmod(0o755)
    shutil.copy2(Path(__file__), helpers / "run_zekra_campaign.py")
    frozen = [path for path in snapshot.rglob("*") if path.is_file()]
    frozen.extend(path for path in helpers.rglob("*") if path.is_file())
    prep = {
        "schema": "zkcfa.zekra21.preparation.v2", "prepared_at": now(),
        "wrapper_revision": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
        "zekra_revision": subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip(),
        "applications": selected, "available_applications": available,
        "keep_artifacts": keep_artifacts,
        "real_docker": real, "upstream_archive_sha256": hashlib.sha256(archive).hexdigest(),
        "paper22_image": images[0]["Id"], "native_image": images[1]["Id"],
        "original_jar_sha256": PINNED_JAR,
        "frozen_sources_sha256": {str(path.relative_to(base)): digest(path) for path in sorted(frozen)},
        "scope": "Original jar, levels 15, legacy compressed inputs; no QEMU/device acquisition is claimed.",
    }
    (base / "preparation.json").write_text(json.dumps(prep, indent=2) + "\n")
    return prep


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--cpus", type=int, default=8)
    parser.add_argument("--output", type=Path, required=True, help="new campaign directory, or prepared directory")
    parser.add_argument("--prepare-only", action="store_true", help="freeze sources and image IDs without circuit execution")
    parser.add_argument("--applications", help="prepare only: comma-separated application names (default: all 21)")
    parser.add_argument("--keep-artifacts", action="store_true", help="prepare only: retain per-case arithmetic circuits and witness inputs")
    parser.add_argument("--require-proofs", action="store_true", help="fail unless every selected application proves and verifies")
    args = parser.parse_args()
    if args.threads < 1 or args.cpus < 1:
        parser.error("--threads and --cpus must be positive")
    if not args.prepare_only and (args.applications is not None or args.keep_artifacts):
        parser.error("--applications and --keep-artifacts must be frozen with --prepare-only")
    os.umask(0o077)
    BASE = args.output.resolve()
    SNAPSHOT = BASE / "snapshot/zekra"
    WORK = SNAPSHOT / "reproduce/results/embench-suite"
    if args.prepare_only:
        prep = prepare(BASE, args.applications, args.keep_artifacts)
        print(json.dumps({"status": "prepared", "output": str(BASE), "applications": len(prep["applications"])}))
        return 0
    prep = read_json(BASE / "preparation.json")
    for relative, expected in prep["frozen_sources_sha256"].items():
        if digest(BASE / relative) != expected:
            raise RuntimeError("prepared source changed: " + relative)
    real = prep["real_docker"]
    images = json.loads(subprocess.check_output([
        real, "image", "inspect", prep["paper22_image"], prep["native_image"]
    ], text=True))
    if [row["Architecture"] for row in images] != ["amd64", "arm64"]:
        raise RuntimeError("ZEKRA image architecture mismatch")
    docker_info = json.loads(subprocess.check_output(
        [real, "info", "--format", "{{json .}}"], text=True
    ))
    if args.cpus > docker_info["NCPU"]:
        raise RuntimeError("requested CPU limit exceeds the Docker VM")
    if docker_info["Architecture"] != "aarch64":
        raise RuntimeError("this native-arm64 campaign requires an aarch64 Docker host")
    native_environment = subprocess.check_output([
        real, "run", "--rm", "--network", "none", "--platform", "linux/arm64", prep["native_image"],
        "sh", "-ec", "uname -m; sha256sum /opt/jsnark/libsnark/build/libsnark/jsnark_interface/run_ppzksnark; "
        "grep -E 'MULTICORE:|PERFORMANCE:|OPT_FLAGS:|USE_ASM:|CURVE:' /opt/jsnark/libsnark/build/CMakeCache.txt; "
        "ldd /opt/jsnark/libsnark/build/libsnark/jsnark_interface/run_ppzksnark; "
        "git -C /opt/jsnark rev-parse HEAD; git -C /opt/jsnark/libsnark rev-parse HEAD"
    ], text=True)
    (BASE / "native-environment.log").write_text(native_environment)
    started = {
        "schema": "zkcfa.zekra21.execution.v1", "started_at": now(),
        "threads": args.threads, "cpus": args.cpus,
        "docker": {key: docker_info.get(key) for key in (
            "NCPU", "MemTotal", "ServerVersion", "KernelVersion", "Architecture", "OSType"
        )},
        "images": [{key: row.get(key) for key in ("Id", "Architecture", "Created")}
                   for row in images],
        "wrapper_revision": prep["wrapper_revision"], "zekra_revision": prep["zekra_revision"],
        "statement": "legacy ZEKRA compressed inputs from the pinned upstream checkout",
        "preparation_sha256": digest(BASE / "preparation.json"),
        "execution_runner_sha256": digest(Path(__file__)),
        "original_jar_sha256": digest(SNAPSHOT / "ZEKRA/xjsnark_backend.jar"),
        "native_environment_log_sha256": digest(BASE / "native-environment.log"),
        "native_binary_sha256": re.search(r"(?m)^([0-9a-f]{64})\s", native_environment)[1],
        "source_files_sha256": {
            str(path.relative_to(SNAPSHOT)): digest(path)
            for app in sorted(set(prep["applications"]) | {"crc32"})
            for name in ("adjlist", "numified_adjlist", "translator", "recorded_path", "numified_path")
            for path in [SNAPSHOT / "ZEKRA/embench-iot-applications" / app / name]
        },
    }
    with (BASE / "started.json").open("x", encoding="utf-8") as stream:
        json.dump(started, stream, indent=2)
        stream.write("\n")
    label = BASE.parent.name + "-" + BASE.name
    env = os.environ.copy()
    for key in ("APPS", "OUT", "CONTROL", "KEEP_ARTIFACTS"):
        env.pop(key, None)
    env.update({
        "PATH": str(BASE / "helpers/zekra-docker") + os.pathsep + env["PATH"],
        "ZEKRA_REAL_DOCKER": real, "ZEKRA_RUN_LABEL": label,
        "ZEKRA_THREADS": str(args.threads), "ZEKRA_CPUS": str(args.cpus),
        "ZEKRA_DOCKER_EVENTS": str(BASE / "docker-events.private.jsonl"),
        "ZEKRA_PAPER22_IMAGE": prep["paper22_image"],
        "ZEKRA_NATIVE_IMAGE": prep["native_image"], "CONTROL": "1",
        "APPS": " ".join(prep["applications"]),
        "KEEP_ARTIFACTS": "1" if prep.get("keep_artifacts", False) else "0",
    })
    proc = None

    def stop_own_containers():
        ids = subprocess.check_output([
            real, "container", "ls", "--quiet", "--filter", "label=zkcfa.zekra21.run=" + label
        ], text=True).split()
        if ids:
            subprocess.run([real, "container", "stop", "--time", "5", *ids],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    def interrupted(signum, _frame):
        stop_own_containers()
        if proc is not None:
            proc.terminate()
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    with (BASE / "suite-console.private.log").open("x", encoding="utf-8") as stream:
        proc = subprocess.Popen(["bash", str(SNAPSHOT / "reproduce/run-embench-suite.sh")],
                                cwd=SNAPSHOT, env=env, stdin=subprocess.DEVNULL,
                                stdout=stream, stderr=subprocess.STDOUT)
        rc = proc.wait()
    source = WORK / "summary.csv"
    rows = list(csv.DictReader(source.open(encoding="utf-8"))) if source.exists() else []
    control = [row for row in rows if row["app"] == "crc32-control-500"]
    applications = [row for row in rows if row["app"] != "crc32-control-500"]
    issues = []
    if rc:
        issues.append("suite process exited with code " + str(rc))
    if len(control) != 1 or any(control[0].get(key) != value for key, value in (
        ("r1cs_constraints", "336230"), ("satisfied", "YES"), ("outcome", "proved")
    )):
        issues.append("CRC32 500/500 control did not prove and verify at 336230 constraints")
    coverage = coverage_issue(applications, prep["applications"])
    if coverage:
        issues.append(coverage)
    allowed = {"proved", "unsatisfiable", "host-memory"}
    for row in rows:
        if row["outcome"] not in allowed:
            issues.append(row["app"] + ": unexpected outcome " + row["outcome"])
        if row["outcome"] == "proved":
            log = WORK / "logs" / (row["app"] + "-03-groth16.log")
            if not log.exists() or "The verification result is: PASS" not in log.read_text(errors="replace"):
                issues.append(row["app"] + ": proof success lacks verification PASS evidence")
            else:
                count = re.search(r"QAP pre degree: (\d+)", log.read_text(errors="replace"))
                if count is None or count[1] != row["r1cs_constraints"]:
                    issues.append(row["app"] + ": compiled R1CS count differs from native QAP pre degree")
    events_path = BASE / "docker-events.private.jsonl"
    events = [json.loads(line) for line in events_path.read_text().splitlines()] if events_path.exists() else []
    for row in rows:
        if row["outcome"] == "proved":
            matching = [event for event in events if event["application"] == row["app"]
                        and event["stage"] == "groth16"]
            if len(matching) != 1 or matching[0]["docker_exit_code"] != 0:
                issues.append(row["app"] + ": verification lacks a successful native process exit")
        if row["outcome"] == "host-memory" and not any(
            event["application"] == row["app"] and event["stage"] == "groth16"
            and event.get("state", {}).get("OOMKilled") is True
            and event["docker_exit_code"] == 137 for event in events
        ):
            issues.append(row["app"] + ": exit 137 lacks an independently inspected Docker OOM state")
    all_verified = not coverage and all(row["outcome"] == "proved" for row in applications)
    if args.require_proofs and not all_verified:
        issues.append("not all selected applications proved and verified")
    for relative, expected in prep["frozen_sources_sha256"].items():
        # compile_circuit.py parameterizes only this source; the shell trap restores it.
        if digest(BASE / relative) != expected:
            issues.append("frozen source changed during execution: " + relative)
    summary = {
        "schema": "zkcfa.zekra21.summary.v1", "completed_at": now(),
        "coverage_complete": coverage is None and len(prep["applications"]) == 21,
        "selection_complete": coverage is None,
        "selected_applications": prep["applications"],
        "suite_application_count": len(prep.get("available_applications", prep["applications"])),
        "full_suite": len(prep["applications"]) == 21,
        "all_applications_verified": all_verified and not issues,
        "require_proofs": args.require_proofs,
        "kept_artifacts": prep.get("keep_artifacts", False),
        "validation_passed": not issues, "issues": issues, "process_exit_code": rc,
        "application_count": len(applications), "control": control,
        "outcomes": dict(Counter(row["outcome"] for row in applications)),
        "resource_events": [event for event in events if event["docker_exit_code"] != 0],
        "rows": applications,
        "csv_sha256": digest(source) if source.exists() else None,
        "execution_metadata_sha256": digest(BASE / "started.json"),
        "logs_sha256": {str(path.relative_to(BASE)): digest(path) for path in sorted((WORK / "logs").glob("*.log"))},
        "docker_events_sha256": digest(events_path) if events_path.exists() else None,
        "scope": "Prior-work legacy compressed relation; descriptive results, not matched QEMU instances.",
    }
    (BASE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if source.exists():
        (BASE / "results.csv").write_bytes(source.read_bytes())
    print(json.dumps({key: summary[key] for key in (
        "coverage_complete", "selection_complete", "validation_passed", "all_applications_verified",
        "application_count", "outcomes", "issues"
    )}, sort_keys=True))
    return 0 if not issues else 1


if __name__ == "__main__":
    sys.exit(main())
