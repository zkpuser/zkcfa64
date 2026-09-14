#!/usr/bin/env python3
"""Export measured statistics and excluded warmups from a frozen ZEKRA campaign."""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import re
import statistics

TIMINGS = ("setup_s", "prove_s", "verify_s", "wall_seconds")
SIZES = (64, 128, 256, 512, 1024, 2048, 4096)
LEGACY_SIZES = (64, 128, 256, 512, 1024, 4096)
FAMILIES = ("growing-cfg", "fixed-cfg")
ATTEMPT_FIELDS = ("repetition", "returncode", "verified", "qap_pre_degree", "qap_degree",
                  "qap_variables", *TIMINGS, "log_sha256", "error", "count_error", "timing_error")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def finite_nonnegative(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0


def audit_attempts(measurement, directory):
    """Validate evidence and compute medians using only a complete measured set."""
    formal = measurement.get("runs", [])
    warmups = measurement.get("warmup_runs", [])
    planned = measurement["repetitions"]
    warmup_planned = measurement.get("warmup_repetitions", 0)
    if not isinstance(planned, int) or planned < 1 or not isinstance(warmup_planned, int) or warmup_planned < 0:
        raise ValueError("invalid repetition plan")
    explicit = "warmup_repetitions" in measurement
    for kind, runs, count in (("warmup", warmups, warmup_planned), ("measured", formal, planned)):
        if len(runs) > count or [run["repetition"] for run in runs] != list(range(1, len(runs) + 1)):
            raise ValueError(f"missing, duplicate, or excess {kind} repetition")
        for index, run in enumerate(runs):
            if run.get("kind", "measured" if not explicit else None) != kind:
                raise ValueError("misclassified warmup or measured attempt")
            if not isinstance(run.get("verified"), bool):
                raise ValueError("attempt lacks a verification outcome")
            if not run["verified"] and index != len(runs) - 1:
                raise ValueError("attempt continued after a failed proof")
            if run.get("log_sha256") is not None:
                log = directory / Path(run["log"]).name
                if digest(log) != run["log_sha256"]:
                    raise ValueError("native log differs from frozen hash")
            elif run["verified"]:
                raise ValueError("verified attempt lacks a log hash")
            if not run["verified"]:
                continue
            text = log.read_text()
            if run["returncode"] != 0 or "The verification result is: PASS" not in text or "The verification result is: FAIL" in text:
                raise ValueError("verified attempt lacks successful native verification")
            if any(not finite_nonnegative(run.get(key)) for key in TIMINGS):
                raise ValueError("verified attempt lacks finite phase timing")
            counts = re.findall(r"QAP pre degree: (\d+)", text)
            if not counts or int(counts[-1]) != run.get("qap_pre_degree") or run["qap_pre_degree"] != measurement.get("r1cs_constraints"):
                raise ValueError("compiler and native R1CS totals differ")
            for key, phase in (("setup_s", "generator"), ("prove_s", "prover"), ("verify_s", "verifier_strong_IC")):
                values = re.findall(r"\(leave\) Call to r1cs_gg_ppzksnark_" + phase + r"[^\n]*\[([0-9.]+)s", text)
                if not values or float(values[-1]) != run[key]:
                    raise ValueError("native phase timing differs from log")
    warmup_complete = len(warmups) == warmup_planned and all(run["verified"] for run in warmups)
    if formal and not warmup_complete:
        raise ValueError("measured attempts started before successful warmups")
    complete = warmup_complete and len(formal) == planned and all(run["verified"] for run in formal)
    if measurement["status"] == "verified" and not complete:
        raise ValueError("verified case has an incomplete repetition plan")
    medians = ({key: statistics.median(run[key] for run in formal) for key in TIMINGS}
               if complete and measurement["status"] == "verified" else {key: None for key in TIMINGS})
    recorded = measurement.get("medians")
    if recorded is not None and any(recorded.get(key) != medians[key] for key in TIMINGS):
        raise ValueError("stored medians differ from measured repetitions")
    return medians


def validate_cases(manifest):
    sizes = manifest.get("sizes", list(LEGACY_SIZES))
    families = manifest.get("families", list(FAMILIES))
    if sizes not in (list(SIZES), list(LEGACY_SIZES)):
        raise ValueError("unknown scaling size grid")
    if not families or len(set(families)) != len(families) or not set(families) <= set(FAMILIES):
        raise ValueError("unknown or duplicate scaling family")
    identities = [(row["family"], row["source_ep_rows"]) for row in manifest["results"]]
    if len(set(identities)) != len(identities) or set(identities) != {(family, size) for family in families for size in sizes}:
        raise ValueError("campaign has missing, duplicate, or unexpected cases")
    warmups = manifest.get("warmup_repetitions", 0)
    if not isinstance(warmups, int) or warmups < 0:
        raise ValueError("invalid warmup count")
    if warmups and (manifest.get("warmup_source_ep_rows") != 64 or manifest.get("warmup_scope") != "per-family"):
        raise ValueError("unexpected warmup policy")
    return warmups


def summarize(campaign):
    manifest = json.loads((campaign / "campaign.json").read_text())
    if "end_utc" not in manifest:
        raise ValueError("campaign has not finished")
    warmups = validate_cases(manifest)
    summary, attempts, jars = [], [], set()
    for case in manifest["results"]:
        path = campaign / case["family"] / str(case["source_ep_rows"]) / "measurement.json"
        if digest(path) != case["measurement_sha256"]:
            raise ValueError(f"measurement differs from frozen manifest: {path}")
        measured = json.loads(path.read_text())
        if measured["status"] != case["status"] or measured["repetitions"] != manifest["repetitions"]:
            raise ValueError("case disagrees with campaign status or repetition plan")
        if measured["status"] == "verified" and case["returncode"] != 0:
            raise ValueError("verified case has a failed runner exit")
        expected_warmups = warmups if case["source_ep_rows"] == 64 else 0
        if measured.get("warmup_repetitions", 0) != expected_warmups:
            raise ValueError("case warmups differ from campaign plan")
        medians = audit_attempts(measured, path.parent)
        inp = measured.get("input", {})
        params = inp.get("parameters", {})
        jar = measured.get("sources", {}).get("jar_after_sha256")
        if jar:
            jars.add(jar)
        elif measured["status"] == "verified":
            raise ValueError("verified case lacks repaired jar identity")
        formal, excluded = measured.get("runs", []), measured.get("warmup_runs", [])
        summary.append({
            "family": case["family"], "source_ep_rows": case["source_ep_rows"], "backend": "ZEKRA-repaired",
            "status": measured["status"], "error": measured.get("error"),
            "source_typed_edges": inp.get("source_typed_edges"),
            "static_return_edges": inp.get("static_returns", {}).get("count"),
            "untyped_edges": inp.get("untyped_edges"), "projected_ep_rows": inp.get("projected", {}).get("rows_with_initial"),
            "adjlist_capacity": params.get("adjlist_len"), "ep_capacity": params.get("path_len"),
            "levels": params.get("adjlist_levels"), "required_levels": inp.get("required_levels"),
            "label_bitwidth": params.get("label_bitwidth"), "bucket_bitwidth": params.get("bucket_bitwidth"),
            "max_adjacency_bitwidth": inp.get("maximum_encoded_adjacency_bitwidth"),
            "r1cs_constraints": measured.get("r1cs_constraints"),
            "planned_repetitions": measured["repetitions"], "attempted_repetitions": len(formal),
            "verified_repetitions": sum(run["verified"] for run in formal),
            "planned_warmups": expected_warmups, "attempted_warmups": len(excluded),
            "verified_warmups": sum(run["verified"] for run in excluded),
            **medians, "measurement_sha256": digest(path),
        })
        for kind, records in (("warmup", excluded), ("measured", formal)):
            for attempt in records:
                attempts.append({"family": case["family"], "source_ep_rows": case["source_ep_rows"], "kind": kind,
                                 **{key: attempt.get(key) for key in ATTEMPT_FIELDS}})
    if len(jars) > 1:
        raise ValueError("cases did not use the same repaired jar")
    return summary, attempts, next(iter(jars), None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    campaign = parser.parse_args().campaign.resolve()
    summary, attempts, jar = summarize(campaign)
    for name, rows, fields in (
        ("zekra-scaling-summary.csv", summary, list(summary[0])),
        ("zekra-scaling-attempts.csv", attempts, ["family", "source_ep_rows", "kind", *ATTEMPT_FIELDS]),
    ):
        with (campaign / name).open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
    print(json.dumps({"cases": len(summary), "attempts": sum(row["attempted_repetitions"] for row in summary),
                      "verified": sum(row["verified_repetitions"] for row in summary),
                      "excluded_warmups": sum(row["attempted_warmups"] for row in summary),
                      "repaired_jar_sha256": jar}, sort_keys=True))


if __name__ == "__main__":
    main()
