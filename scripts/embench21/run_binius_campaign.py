#!/usr/bin/env python3
"""Run one serialized complete and shadow Binius64 proof per application."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import re
import subprocess
import time
from pathlib import Path


APPLICATIONS = (
    "aha-mont64",
    "crc32",
    "cubic",
    "edn",
    "huffbench",
    "matmult-int",
    "md5sum",
    "minver",
    "nbody",
    "nettle-aes",
    "nettle-sha256",
    "nsichneu",
    "picojpeg",
    "primecount",
    "sglib-combined",
    "slre",
    "st",
    "statemate",
    "tarfind",
    "ud",
    "wikisort",
)
FIELDS = (
    "application",
    "path_mode",
    "source_rows",
    "proof_rows",
    "edge_cap",
    "ep_cap",
    "encoding",
    "multiplicity_bits",
    "and_constraints",
    "bmul_constraints",
    "setup_ms",
    "prove_ms",
    "public_preflight_ms",
    "verify_ms",
    "proof_bytes",
    "wall_ms",
    "peak_rss_bytes",
    "verified",
    "public_bytes",
    "authority_provision_ms",
    "device_sign_ms",
    "status",
    "error",
    "returncode",
)
RSS = re.compile(r"^\s*(\d+)\s+maximum resident set size\s*$", re.MULTILINE)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def protocol_result(run: Path) -> dict[str, object]:
    value = json.loads((run / "protocol-result.json").read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("protocol result must be an object")
    return value


def proof_json(stdout: str) -> dict[str, object]:
    candidates = [line for line in stdout.splitlines() if line.startswith('{"schema":"zkcfa.raw.proof"')]
    if len(candidates) != 1:
        raise ValueError("proof process did not emit exactly one JSON report")
    value = json.loads(candidates[0])
    if value.get("verified") is not True:
        raise ValueError("proof report is not verified")
    return value


def persist_rows(output: Path, rows: list[dict[str, object]]) -> None:
    temporary = output / "results.csv.tmp"
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(output / "results.csv")


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--threads", type=int, default=8)
    args = parser.parse_args()
    campaign = args.campaign.resolve()
    binary = args.binary.resolve()
    output = campaign / "binius-results"
    if output.exists() or output.is_symlink():
        raise FileExistsError("Binius result directory must not already exist")
    output.mkdir(parents=True, mode=0o700)
    signed = campaign / "signed"
    suite = json.loads((signed / "bundles.json").read_text(encoding="utf-8"))
    indexed = {
        row["application"]: row
        for row in suite["applications"]
        if isinstance(row, dict) and isinstance(row.get("application"), str)
    }
    if tuple(indexed) != APPLICATIONS:
        raise ValueError("signed suite is not the ordered 21-application set")

    rows: list[dict[str, object]] = []
    for mode in ("complete", "shadow"):
        for index, application in enumerate(APPLICATIONS, 1):
            run_dir = signed / application / mode
            protocol = protocol_result(run_dir)
            challenge = protocol["challenge"]
            if not isinstance(challenge, dict):
                raise ValueError("protocol result omitted challenge")
            env = os.environ.copy()
            env.update(
                {
                    "RAYON_NUM_THREADS": str(args.threads),
                    "ZKCFA_PROVIDER_BUNDLE": str(run_dir / "bundle"),
                    "ZKCFA_AUTHORITY_PUBLIC": str(run_dir / "keys/public/authority.pem"),
                    "ZKCFA_AUTHORITY_SHA256": str(protocol["authority_sha256"]),
                    "ZKCFA_EXPECTED_CHALLENGE_ID": str(challenge["challenge_id"]),
                    "ZKCFA_EXPECTED_NONCE": str(challenge["nonce"]),
                    "ZKCFA_JSON": "1",
                }
            )
            print(
                json.dumps(
                    {"application": application, "index": index, "mode": mode, "status": "start"},
                    sort_keys=True,
                ),
                flush=True,
            )
            started = time.perf_counter()
            completed = subprocess.run(
                ["/usr/bin/time", "-l", str(binary)],
                cwd=binary.parent,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            wall_ms = (time.perf_counter() - started) * 1000
            stem = f"{mode}-{application}"
            (output / f"{stem}.stdout.log").write_text(completed.stdout, encoding="utf-8")
            (output / f"{stem}.stderr.log").write_text(completed.stderr, encoding="utf-8")
            try:
                if completed.returncode != 0:
                    raise RuntimeError(f"proof process returned {completed.returncode}")
                report = proof_json(completed.stdout)
            except (ValueError, RuntimeError) as error:
                rows.append({"application": application, "path_mode": mode,
                             "wall_ms": round(wall_ms, 3), "verified": "false",
                             "status": "failed", "error": str(error),
                             "returncode": completed.returncode})
                persist_rows(output, rows)
                print(json.dumps({"application": application, "mode": mode,
                                  "status": "failed", "returncode": completed.returncode}), flush=True)
                continue
            instance = report["instance"]
            capacity = report["capacity"]
            constraints = report["constraints"]
            phases = report["phases_ms"]
            projection = indexed[application]["projection"]
            source_rows = (
                instance["steps"]
                if mode == "complete"
                else projection["full_rows"]
            )
            rss_match = RSS.search(completed.stderr)
            row = {
                "application": application,
                "path_mode": mode,
                "source_rows": source_rows,
                "proof_rows": instance["steps"],
                "edge_cap": capacity["edge_cap"],
                "ep_cap": capacity["ep_cap"],
                "encoding": capacity["ep_encoding"],
                "multiplicity_bits": capacity["multiplicity_bits"],
                "and_constraints": constraints["and"],
                "bmul_constraints": constraints["bmul"],
                "setup_ms": phases["setup"],
                "prove_ms": phases["prove"],
                "public_preflight_ms": phases["public_preflight"],
                "verify_ms": phases["verify"],
                "proof_bytes": report["proof_bytes"],
                "wall_ms": round(wall_ms, 3),
                "peak_rss_bytes": int(rss_match.group(1)) if rss_match else "",
                "verified": str(report["verified"]).lower(),
                "public_bytes": protocol["public_bytes"],
                "authority_provision_ms": protocol["authority_provision_ms"],
                "device_sign_ms": protocol["device_sign_ms"],
                "status": "verified",
                "error": "",
                "returncode": completed.returncode,
            }
            rows.append(row)
            persist_rows(output, rows)
            print(
                json.dumps(
                    {
                        "application": application,
                        "mode": mode,
                        "prove_ms": row["prove_ms"],
                        "verify_ms": row["verify_ms"],
                        "peak_rss_bytes": row["peak_rss_bytes"],
                        "status": "pass",
                    },
                    sort_keys=True,
                ),
                flush=True,
            )

    csv_path = output / "results.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    metadata = {
        "schema": "zkcfa.embench21-binius-campaign.v1",
        "applications": len(APPLICATIONS),
        "runs": len(rows),
        "verified_runs": sum(row.get("verified") == "true" for row in rows),
        "runner_note": "Persists each result and continues after observed proof failures; failed attempts do not enter success aggregates.",
        "threads": args.threads,
        "binary_sha256": sha256(binary),
        "results_sha256": sha256(csv_path),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
    }
    (output / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    print(json.dumps(metadata, sort_keys=True))
    return 0 if all(row.get("verified") == "true" for row in rows) else 2


if __name__ == "__main__":
    raise SystemExit(main())
