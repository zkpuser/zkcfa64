#!/usr/bin/env python3
"""Run the repaired ZEKRA campaign while preserving Docker OOM events."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
SCALING = ROOT / "zekra/reproduce/scaling"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def attempt_events(run, observations):
    name = run["command"][run["command"].index("--name") + 1]
    relevant = [event for event in observations
                if event.get("Actor", {}).get("Attributes", {}).get("name") == name]
    oom = any(event.get("Action") == "oom" for event in relevant)
    died_137 = any(event.get("Action") == "die"
                   and event.get("Actor", {}).get("Attributes", {}).get("exitCode") == "137"
                   for event in relevant)
    return name, relevant, run["returncode"] == 137 and oom and died_137


def account_attempt(accounting, run, observations):
    accounting["actual_attempts"] += 1
    accounting["verified_attempts"] += int(run["verified"])
    name, relevant, documented_oom = attempt_events(run, observations)
    if not run["verified"]:
        accounting["oom_attempts"] += int(documented_oom)
        accounting["other_failed_attempts"] += int(not documented_oom)
    return name, relevant, documented_oom


def collect_accounting(campaign, output, observations):
    """Account against the full plan, retaining partial unindexed measurements."""
    keys = [(family, size) for family in campaign["families"] for size in campaign["sizes"]]
    if not keys or len(keys) != len(set(keys)):
        raise ValueError("invalid campaign grid")
    indexed = {}
    for case in campaign["results"]:
        key = case["family"], case["source_ep_rows"]
        if key not in keys or key in indexed:
            raise ValueError("duplicate or unexpected campaign result")
        indexed[key] = case
    repetitions = campaign["repetitions"]
    warmups = campaign.get("warmup_repetitions", 0)
    warmup_size = campaign.get("warmup_source_ep_rows", 64)
    if warmups and (campaign.get("warmup_scope") != "per-family" or warmup_size not in campaign["sizes"]):
        raise ValueError("unexpected campaign warmup plan")

    def counts(planned):
        return dict(planned_attempts=planned, actual_attempts=0, verified_attempts=0,
                    oom_attempts=0, other_failed_attempts=0, unexecuted_attempts=0)

    accounting = counts(len(keys) * repetitions)
    warmup_accounting = counts(len(campaign["families"]) * warmups)
    matched, incomplete_cases, case_events = [], [], {}
    observations_complete = True
    for family, size in keys:
        directory = output / family / str(size)
        path = directory / "measurement.json"
        case = indexed.get((family, size))
        missing = dict(family=family, source_ep_rows=size)
        if not path.is_file():
            if case is not None:
                raise ValueError("indexed campaign measurement is missing")
            missing["status"] = "record-missing" if directory.exists() else "not-started"
            observations_complete &= not directory.exists()
            incomplete_cases.append(missing)
            continue
        digest = sha(path)
        if case is not None and digest != case["measurement_sha256"]:
            raise ValueError("measurement differs from frozen campaign hash")
        try:
            measured = json.loads(path.read_text())
        except (ValueError, UnicodeError) as error:
            if case is not None:
                raise
            missing.update(status="record-invalid", measurement_sha256=digest, error=str(error))
            incomplete_cases.append(missing)
            observations_complete = False
            continue
        if case is None:
            missing.update(status="unindexed-measurement", measurement_status=measured.get("status"),
                           measurement_sha256=digest)
            incomplete_cases.append(missing)
            observations_complete &= measured.get("status") in ("verified", "failed")
        expected_warmups = warmups if size == warmup_size else 0
        if measured["repetitions"] != repetitions or measured.get("warmup_repetitions", 0) != expected_warmups:
            raise ValueError("measurement repetitions differ from campaign plan")
        per_case = []
        for kind, runs, budget, ledger in (
                ("warmup", measured.get("warmup_runs", []), expected_warmups, warmup_accounting),
                ("measured", measured.get("runs", []), repetitions, accounting)):
            if len(runs) > budget or [run["repetition"] for run in runs] != list(range(1, len(runs) + 1)):
                raise ValueError("invalid recorded repetition sequence")
            for run in runs:
                if run.get("kind", "measured") != kind:
                    raise ValueError("misclassified recorded attempt")
                name, relevant, documented_oom = account_attempt(ledger, run, observations)
                per_case.extend(relevant)
                if not run["verified"]:
                    matched.append(dict(family=family, source_ep_rows=size, kind=kind,
                        repetition=run["repetition"], container_name=name,
                        documented_docker_oom=documented_oom, returncode=run["returncode"]))
        for phase in measured.get("phases", []):
            if "--name" in phase["command"]:
                per_case.extend(attempt_events(phase, observations)[1])
        case_events[directory] = per_case
    for ledger in (accounting, warmup_accounting):
        ledger["unexecuted_attempts"] = (ledger["planned_attempts"] - ledger["actual_attempts"]
                                        if observations_complete else None)
    return (dict(accounting=accounting, warmup_accounting=warmup_accounting,
                 failed_attempts=matched, incomplete_cases=incomplete_cases,
                 attempt_accounting_complete=observations_complete), case_events)


def campaign_command(args, output):
    return [sys.executable, str(SCALING / "run_campaign.py"), "--inputs", str(args.inputs.resolve()),
            "--output", str(output), "--repetitions", str(args.repetitions),
            "--warmups", str(args.warmups), "--families", args.families]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--families", default="growing-cfg,fixed-cfg")
    args = parser.parse_args()
    families = args.families.split(",")
    if len(families) != len(set(families)) or any(name not in ("growing-cfg", "fixed-cfg") for name in families):
        parser.error("families must be a nonempty, distinct subset of growing-cfg,fixed-cfg")
    if not 1 <= args.repetitions <= 10 or not 0 <= args.warmups <= 10:
        parser.error("repetitions must be in 1..10 and warmups in 0..10")
    output = args.output.resolve()
    if args.output.is_symlink() or output.exists():
        raise ValueError("scaling output must be new")
    upstream, inputs = (ROOT / "zekra/ZEKRA").resolve(), args.inputs.resolve()
    if output == upstream or upstream in output.parents:
        raise ValueError("scaling output must be outside the upstream checkout")
    if output == inputs or inputs in output.parents:
        raise ValueError("scaling output must be outside the input directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    frozen = output.with_name(output.name + "-execution-sources")
    frozen.mkdir()
    sources = [SCALING / name for name in (
        "run_scaling.py", "run_campaign.py", "summarize_scaling.py", "PatchNativeMemory.java", "CheckNativeMemory.java")]
    sources.append(ROOT / "zkcfa-tracer/research/zekra_projection.py")
    sources.append(Path(__file__).resolve())
    hashes = {str(path): sha(path) for path in sources}
    for path in sources:
        shutil.copy2(path, frozen / path.name)
    (frozen / "manifest.json").write_text(json.dumps(hashes, indent=2) + "\n")
    event_path = output.with_name(output.name + "-docker-events.jsonl")
    since = datetime.now(timezone.utc).isoformat()
    command = campaign_command(args, output)
    collector_command = ["docker", "events", "--since", since, "--filter", "type=container",
                         "--filter", "event=oom", "--filter", "event=die", "--format", "{{json .}}"]
    with event_path.open("x") as events, event_path.with_suffix(".stderr.log").open("x") as errors:
        collector = subprocess.Popen(collector_command, stdout=events, stderr=errors)
        try:
            result = subprocess.run(command)
        finally:
            collector.terminate()
            collector.wait(timeout=15)
    if any(sha(path) != expected for path, expected in ((Path(name), value) for name, value in hashes.items())):
        raise ValueError("execution source changed during measurement")
    observations = [json.loads(line) for line in event_path.read_text().splitlines()]
    campaign = json.loads((output / "campaign.json").read_text())
    ledgers, case_events = collect_accounting(campaign, output, observations)
    for directory, events in case_events.items():
        (directory / "docker-events.jsonl").write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events))
    metadata = {"schema": "zkcfa.zekra.scaling-events.v1", "since_utc": since,
                "collector_command": collector_command, "campaign_command": command,
                "campaign_exit_code": result.returncode, "events_path": str(event_path),
                "events_sha256": sha(event_path), "execution_sources_sha256": hashes,
                **ledgers,
                "measurement_policy": "Original observations and missing timings preserved; only a matching OOM and die137 event classify memory exhaustion."}
    (output / "event-capture.json").write_text(json.dumps(metadata, indent=2) + "\n")
    subprocess.run([sys.executable, str(SCALING / "summarize_scaling.py"), str(output)], check=True)
    print(json.dumps(ledgers["accounting"], sort_keys=True))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
