#!/usr/bin/env python3
"""Serialize native raw24 scaling proofs, preserving every attempt and source identity."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time


ROOT = Path(__file__).resolve().parents[3]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--binary", type=Path,
                        default=ROOT / "zkcfa-binius64/zkcfa64/target/release/examples/scaling",
                        help="frozen raw24 scaling executable; never a raw64-feature build")
    args = parser.parse_args()
    assert args.repeats >= 1
    inputs = args.inputs.resolve()
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"Refusing to overwrite measurement directory {output}")
    output.mkdir(parents=True)
    (output / "logs").mkdir()
    binary = args.binary.resolve()
    manifest = json.loads((inputs / "manifest.json").read_text())
    cases = manifest["cases"]
    environment = {k: v for k, v in os.environ.items() if not k.startswith("ZKCFA_")}
    environment["RAYON_NUM_THREADS"] = "8"
    crate = ROOT / "zkcfa-binius64/zkcfa64"
    sources = [Path(__file__), crate / "Cargo.toml", crate / "Cargo.lock",
               *sorted((crate / "src").rglob("*.rs")),
               *sorted((crate / "examples").rglob("*.rs"))]
    metadata = {"schema": "zkcfa.synthetic-scaling-binius.v1", "research_only": True,
                "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "platform": platform.platform(), "machine": platform.machine(),
                "logical_cpus": os.cpu_count(), "rayon_threads": 8,
                "cpu": subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip(),
                "memory_bytes": int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True)),
                "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
                "build": "cargo build --locked --offline --release --features experiments --example scaling; RUSTFLAGS=-C target-cpu=native; thin LTO",
                "binary": str(binary), "binary_sha256": digest(binary),
                "manifest_sha256": digest(inputs / "manifest.json"),
                "source_sha256": {str(p.relative_to(ROOT)): digest(p) for p in sources},
                "repeats": args.repeats, "expected_attempts": len(cases) * 2 * args.repeats,
                "order": "Serial jobs; ascending case order in odd rounds, descending in even rounds; alternate complete/shadow order per case/round.",
                "warmup": "One complete and one shadow proof at size 64 for each family, excluded from measurements.",
                "timing": "crypto_prove_ms excludes witness/local constraint check; prove_total_ms includes them. Setup and verification separately recorded. No acquisition/signatures."}
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")

    def invoke(case, mode, repetition, warmup=False):
        family, size = case["family"], case["source_ep_rows"]
        stem = f"{family}-{size}-{mode}-" + ("warmup" if warmup else f"r{repetition}")
        arguments = [str(binary), "--typed-dir", str(inputs / family / str(size) / mode),
                     "--path-mode", mode, "--edge-cap", str(case["binius_edge_cap"]),
                     "--ep-cap", str(case["binius_ep_cap"][mode]), "--log-inv-rate", "1"]
        started = time.monotonic()
        try:
            result = subprocess.run(["/usr/bin/time", "-l", *arguments], env=environment,
                                    text=True, capture_output=True, timeout=600)
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout or b""
            stderr = error.stderr or b""
            stdout = stdout.decode(errors="replace") if isinstance(stdout, bytes) else stdout
            stderr = stderr.decode(errors="replace") if isinstance(stderr, bytes) else stderr
            code = "timeout"
        log = output / "logs" / (stem + ".log")
        log.write_text(stdout + "\n--- stderr/resource observations ---\n" + stderr)
        record = {"family": family, "source_ep_rows": size, "mode": mode,
                  "repetition": repetition, "warmup": warmup, "exit_code": code,
                  "process_controller_wall_ms": (time.monotonic() - started) * 1000,
                  "argv": arguments, "log": str(log), "log_sha256": digest(log)}
        try:
            report = json.loads(stdout.strip())
            assert code == 0 and report["verified"]
            assert report["rows"] == case["rows_by_mode"][mode]
            assert report["input_sha256"] == {k: case["input_sha256"][mode][k]
                                               for k in ["translator", "typed_cfg", "recorded_path"]}
            record.update({"status": "verified", "report": report})
        except (ValueError, KeyError, AssertionError) as error:
            record.update({"status": "failed", "error": str(error)})
        journal = output / ("warmups.jsonl" if warmup else "runs.jsonl")
        with journal.open("a") as handle:
            handle.write(json.dumps(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        print(stem, record["status"], flush=True)
        if record["status"] != "verified":
            raise RuntimeError(f"Recorded unsuccessful attempt; stopping for inspection: {log}")

    for case in cases:
        if case["source_ep_rows"] == 64:
            for mode in ("complete", "shadow"):
                invoke(case, mode, 0, warmup=True)
    for repetition in range(1, args.repeats + 1):
        ordered = cases if repetition % 2 else list(reversed(cases))
        for index, case in enumerate(ordered):
            modes = ("complete", "shadow") if (index + repetition) % 2 else ("shadow", "complete")
            for mode in modes:
                invoke(case, mode, repetition)
    metadata["completed_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    metadata["status"] = "complete"
    metadata["runs_sha256"] = digest(output / "runs.jsonl")
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    main()
