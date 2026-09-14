#!/usr/bin/env python3
"""Compile the production timestamped stack ablation on each shared input exactly once.

This is a deterministic circuit-size experiment. Single-run diagnostic timings in raw
logs are retained for reproducibility, not treated as a proving-performance benchmark.
"""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
KINDS = ("and_constraints", "imul_constraints", "bmul_constraints", "zero_constraints", "native_constraint_count")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=ROOT / "zkcfa64/target/release/examples/stack_control")
    args = parser.parse_args()
    inputs, output, binary = args.inputs.resolve(), args.output.resolve(), args.binary.resolve()
    if output.exists():
        raise SystemExit(f"Refusing to overwrite {output}")
    (output / "raw").mkdir(parents=True)
    (output / "logs").mkdir()
    manifest = json.loads((inputs / "manifest.json").read_text())
    environment = {k: v for k, v in os.environ.items() if not k.startswith("ZKCFA_")}
    environment["RAYON_NUM_THREADS"] = "8"
    crate = ROOT / "zkcfa64"
    sources = [Path(__file__), ROOT / "research/scripts/stack_control_inputs.py",
               crate / "Cargo.toml", crate / "Cargo.lock",
               *sorted((crate / "src").rglob("*.rs")),
               *sorted((crate / "examples").rglob("*.rs"))]
    metadata = {
        "schema": "zkcfa.research.stack-control-run.v1", "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(), "machine": platform.machine(), "logical_cpus": os.cpu_count(),
        "rustc": command(["rustc", "--version"]), "cargo": command(["cargo", "--version"]),
        "repository_head": command(["git", "rev-parse", "HEAD"], ROOT),
        "backend_head": command(["git", "rev-parse", "HEAD"], ROOT / "binius64"),
        "backend_status": command(["git", "status", "--short"], ROOT / "binius64"),
        "build": "RUSTFLAGS='-C target-cpu=native' cargo build --locked --offline --release --features stack-control --example stack_control",
        "binary_sha256": sha(binary), "input_manifest_sha256": sha(inputs / "manifest.json"),
        "source_sha256": {str(p.relative_to(ROOT)): sha(p) for p in sources},
        "rayon_num_threads": 8, "unique_cases": len(manifest["cases"]), "count_repetitions": 1,
        "proof_cases": ["L0064-D0008", "L1024-D0256"],
        "scope": "compiled-constraint differences between the full production relation and its RawShadow-disabled ablation, with both witnesses checked",
        "units": "native Binius64 AND, integer multiplication, binary-field multiplication, and ZERO constraints; not R1CS-equivalent gates",
        "constant_parameters": "raw24, InlineHint14, Complete mode, E_capacity=8, SP_BITS=15, depth_bound=32767",
        "controls": "same fixed 3-node/5-edge CFG; L/4 calls, L/4 returns, L/2 JMP rows including initial JMP; fully occupied EP capacity",
        "timings": "single-run diagnostics only; no runtime-performance claim"
    }
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    rows = []
    for case in manifest["cases"]:
        cid = case["case_id"]
        argv = [str(binary), "--typed-dir", str(inputs / cid), "--ep-cap", str(case["L"])]
        if cid in metadata["proof_cases"]:
            argv.append("--prove")
        result = subprocess.run(argv, env=environment, text=True, capture_output=True, timeout=600)
        (output / "logs" / (cid + ".stdout")).write_text(result.stdout)
        (output / "logs" / (cid + ".stderr")).write_text(result.stderr)
        if result.returncode:
            raise SystemExit(f"{cid} failed with {result.returncode}; see preserved logs")
        report = json.loads(result.stdout)
        assert report["active_rows"] == case["L"]
        assert report["input_sha256"] == {k: case["sha256"][k] for k in ("translator", "typed_cfg", "recorded_path")}
        assert all(c["constraints_verified"] and c["public_statement_checked"] for c in report["circuits"])
        if cid in metadata["proof_cases"]:
            assert report["circuits"][1]["proof_verified"]
        report["case"] = case
        report["command"] = argv
        (output / "raw" / (cid + ".json")).write_text(json.dumps(report, indent=2) + "\n")
        row = {"case_id": cid, "families": ";".join(case["families"]), "L": case["L"], "D": case["actual_depth"],
               "active_rows": case["active_rows"], "ep_capacity": case["ep_capacity"],
               "actual_depth": case["actual_depth"], "depth_bound": report["stack_depth_bound"],
               "call_count": case["call_count"], "ret_count": case["ret_count"], "jmp_count": case["jmp_count"],
               "witness_check_success": True, "proof_verified": cid in metadata["proof_cases"]}
        for prefix, circuit in zip(("without", "with"), report["circuits"]):
            row.update({f"{prefix}_{kind}": circuit[kind] for kind in KINDS})
        row.update({f"delta_{kind}": report["stack_delta"][kind] for kind in KINDS})
        # The four grand products use 4(L-1) BMULs; the pinned compiler also lowers
        # the two token selections per row to BMULs. CSV counts come from the
        # compiler, never from this independent implementation consistency check.
        assert row["delta_bmul_constraints"] == 4 * (case["L"] - 1) + 2 * case["L"]
        rows.append(row)
        with (output / "measurements.csv").open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        print(cid, "delta", report["stack_delta"], "witnesses checked", flush=True)
    # The fixed circuit parameters must make the size invariant to witness depth.
    depth_rows = [r for r in rows if "depth" in r["families"].split(";")]
    for kind in KINDS:
        assert len({r[f"delta_{kind}"] for r in depth_rows}) == 1
    metadata["completed_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    metadata["all_constraints_verified"] = True
    metadata["all_requested_proofs_verified"] = True
    metadata["depth_invariance_checked"] = True
    metadata["measurements_sha256"] = sha(output / "measurements.csv")
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    main()
