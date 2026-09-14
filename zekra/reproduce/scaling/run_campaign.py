#!/usr/bin/env python3
"""Run selected fixed-parameter ZEKRA scaling families serially."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

SIZES = (64, 128, 256, 512, 1024, 2048, 4096)
FAMILIES = ("growing-cfg", "fixed-cfg")
INPUT_FILES = ("translator", "typed_cfg", "recorded_path", "static_returns.tsv")
ROOT = Path(__file__).resolve().parents[3]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def select_families(requested):
    names = requested.split(",")
    if not names or any(name not in FAMILIES for name in names) or len(names) != len(set(names)):
        raise ValueError("families must be a nonempty, distinct subset of growing-cfg,fixed-cfg")
    return tuple(name for name in FAMILIES if name in names)


def input_inventory(root, families):
    """Validate the shared seven-point grid and freeze selected complete inputs."""
    root = root.resolve()
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema") != "zkcfa.synthetic-scaling-inputs.v1" or manifest.get("sizes") != list(SIZES):
        raise ValueError("inputs must use the shared seven-point scaling manifest")
    cases = {}
    for case in manifest["cases"]:
        identity = (case["family"], case["source_ep_rows"])
        if identity in cases:
            raise ValueError(f"duplicate input case: {identity}")
        cases[identity] = case
    expected = {(family, size) for family in FAMILIES for size in SIZES}
    if set(cases) != expected:
        raise ValueError("input manifest does not contain the complete seven-point grid")
    hashes = {str(manifest_path): sha(manifest_path)}
    for family in families:
        for size in SIZES:
            case = cases[(family, size)]
            if case["rows_by_mode"]["complete"] != size:
                raise ValueError("complete input row count differs from source size")
            for name in INPUT_FILES:
                path = root / family / str(size) / "complete" / name
                if root not in path.resolve().parents or not path.is_file():
                    raise ValueError(f"input is missing or escapes its root: {path}")
                actual = sha(path)
                if actual != case["input_sha256"]["complete"][name]:
                    raise ValueError(f"input differs from frozen manifest: {path}")
                hashes[str(path)] = actual
    return hashes


def case_schedule(families, warmups):
    return [(family, size, warmups if size == SIZES[0] else 0)
            for family in families for size in SIZES]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", required=True, type=Path, help="shared scaling input root")
    parser.add_argument("--output", required=True, type=Path, help="new campaign directory")
    parser.add_argument("--repetitions", type=int, default=3, help="measured repetitions per case")
    parser.add_argument("--warmups", type=int, default=1, help="excluded invocations at source64 in each family")
    parser.add_argument("--families", default=",".join(FAMILIES), help="comma-separated family subset")
    args = parser.parse_args()
    try:
        families = select_families(args.families)
    except ValueError as error:
        parser.error(str(error))
    if not 1 <= args.repetitions <= 10 or not 0 <= args.warmups <= 10:
        parser.error("repetitions must be in 1..10 and warmups in 0..10")
    inputs, output = args.inputs.resolve(), args.output.resolve()
    upstream = ROOT / "zekra/ZEKRA"
    if args.output.is_symlink() or output.exists():
        parser.error("output must be a new directory, not a symlink")
    if output == upstream.resolve() or upstream.resolve() in output.parents:
        parser.error("output must be outside the upstream checkout")
    if output == inputs or inputs in output.parents:
        parser.error("output must be outside the input directory")
    input_hashes = input_inventory(inputs, families)
    here = Path(__file__).resolve().parent
    files = [here / name for name in ("run_scaling.py", "run_campaign.py", "PatchNativeMemory.java", "CheckNativeMemory.java")]
    files.append(ROOT / "zkcfa-tracer/research/zekra_projection.py")
    hashes = {str(path): sha(path) for path in files}
    output.mkdir(parents=True, exist_ok=False)
    frozen = output / "execution-sources"
    frozen.mkdir()
    for path in files:
        shutil.copy2(path, frozen / path.name)
    shutil.copy2(inputs / "manifest.json", output / "input-manifest.json")
    manifest = {
        "schema": "zkcfa.zekra.scaling-campaign.v1",
        "start_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_sha256": hashes, "input_sha256": input_hashes,
        "levels": 2, "OMP_NUM_THREADS": 8, "sizes": list(SIZES), "families": list(families),
        "repetitions": args.repetitions, "warmup_repetitions": args.warmups,
        "warmup_source_ep_rows": SIZES[0], "warmup_scope": "per-family",
        "results": [], "status": "running",
        "excluded_smokes": "No smoke result is included in this campaign.",
    }

    def save():
        temporary = output / "campaign.json.tmp"
        temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        temporary.replace(output / "campaign.json")

    save()
    try:
        for family, size, warmups in case_schedule(families, args.warmups):
            if any(sha(Path(name)) != expected for name, expected in {**hashes, **input_hashes}.items()):
                raise ValueError("execution sources or inputs changed during the campaign")
            result_dir = output / family / str(size)
            result_dir.parent.mkdir(exist_ok=True)
            command = [sys.executable, str(files[0]), "--input", str(inputs / family / str(size) / "complete"),
                       "--output", str(result_dir), "--levels", "2", "--repetitions", str(args.repetitions),
                       "--warmups", str(warmups)]
            print("START", family, size, flush=True)
            result = subprocess.run(command)
            path = result_dir / "measurement.json"
            if not path.is_file():
                result_dir.mkdir(exist_ok=True)
                path.write_text(json.dumps({"schema": "zkcfa.zekra.synthetic-scaling.v1", "status": "failed",
                    "error": "runner exited without a measurement record", "repetitions": args.repetitions,
                    "warmup_repetitions": warmups, "runs": [], "warmup_runs": []}, indent=2) + "\n")
            measured = json.loads(path.read_text())
            manifest["results"].append({"family": family, "source_ep_rows": size, "command": command,
                "returncode": result.returncode, "status": measured["status"],
                "r1cs_constraints": measured.get("r1cs_constraints"), "medians": measured.get("medians"),
                "measurement_sha256": sha(path)})
            save()
            print("DONE", family, size, measured["status"], flush=True)
        if any(sha(Path(name)) != expected for name, expected in {**hashes, **input_hashes}.items()):
            raise ValueError("execution sources or inputs changed during the campaign")
        manifest["status"] = "failed" if any(row["status"] != "verified" or row["returncode"] != 0
                                               for row in manifest["results"]) else "verified"
    except (Exception, KeyboardInterrupt) as error:
        manifest["status"] = "failed"
        manifest["error"] = str(error) or type(error).__name__
        print(manifest["error"], file=sys.stderr)
    finally:
        manifest["end_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
    return int(manifest["status"] != "verified")


if __name__ == "__main__":
    raise SystemExit(main())
