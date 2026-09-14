#!/usr/bin/env python3
"""Freeze fresh primary/backend results and render paper tables without editing a manuscript.

Inputs: a completed signed primary campaign, its Binius results, the PLONK runner's
shadow results, and the independently validated legacy ZEKRA campaign. No historical
measurement is substituted for a missing or failed attempt.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import statistics

APPLICATIONS = (
    "aha-mont64", "crc32", "cubic", "edn", "huffbench", "matmult-int", "md5sum",
    "minver", "nbody", "nettle-aes", "nettle-sha256", "nsichneu", "picojpeg",
    "primecount", "sglib-combined", "slre", "st", "statemate", "tarfind", "ud", "wikisort",
)
METRICS = ("setup_ms", "prove_ms", "public_preflight_ms", "verify_ms", "proof_bytes",
           "wall_ms", "peak_rss_bytes", "proof_rows", "and_constraints", "bmul_constraints")
MISSING = {"", "--", "NA", "N/A", "null", "None"}


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_csv(path):
    with Path(path).open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("missing or duplicate CSV field names: " + str(path))
        rows = list(reader)
    if any(None in row or any(value is None for value in row.values()) for row in rows):
        raise ValueError("malformed CSV row: " + str(path))
    return rows


def truth(value):
    return value is True or isinstance(value, str) and value.lower() == "true"


def number(row, key, *, required=False):
    value = row.get(key)
    if value is None or str(value) in MISSING:
        if required:
            raise ValueError("successful result omitted " + key)
        return None
    if isinstance(value, bool):
        raise ValueError("boolean in numeric field " + key)
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError("invalid nonnegative measurement " + key)
    return int(result) if result.is_integer() else result


def unique(rows, fields, expected):
    result = {}
    for row in rows:
        key = tuple(row[field] for field in fields)
        if key in result:
            raise ValueError("duplicate measurement identity " + repr(key))
        result[key] = row
    if set(result) != set(expected):
        raise ValueError("incomplete or unexpected result set; missing=" +
                         repr(sorted(set(expected) - set(result))) + "; extra=" +
                         repr(sorted(set(result) - set(expected))))
    return result


def describe(values):
    values = [value for value in values if value is not None]
    if not values:
        return dict(n=0, median=None, minimum=None, maximum=None, total=None)
    return dict(n=len(values), median=statistics.median(values), minimum=min(values),
                maximum=max(values), total=sum(values))


def ratios(pairs):
    """Inputs must already be successful matched pairs; never divide aggregate medians."""
    pairs = [(a, b) for a, b in pairs if a is not None and b is not None and b > 0]
    if not pairs:
        return dict(n=0, median_ratio=None, ratio_of_sums=None, numerator_sum=None, denominator_sum=None)
    return dict(n=len(pairs), median_ratio=statistics.median(a / b for a, b in pairs),
                ratio_of_sums=sum(a for a, _ in pairs) / sum(b for _, b in pairs),
                numerator_sum=sum(a for a, _ in pairs), denominator_sum=sum(b for _, b in pairs))


def validate_success(row, *, backend):
    flag = truth(row.get("verified"))
    if backend == "plonk" and flag != (row.get("proof_outcome") == "verified"):
        raise ValueError("PLONK outcome/verified contradiction")
    if flag:
        if backend == "binius" and row.get("status", "verified") not in ("verified", "PASS"):
            raise ValueError("Binius status/verified contradiction")
        for field in ("setup_ms", "prove_ms", "verify_ms", "proof_bytes"):
            if number(row, field, required=True) <= 0:
                raise ValueError("successful proof has nonpositive " + field)
    return flag


def paired_artifact_audit(campaign, plonk_directory, app, prepared_run=None):
    files = []
    source = campaign / "signed" / app / "shadow" / "bundle"
    target = (Path(prepared_run) if prepared_run else plonk_directory / "reissued" / app / "shadow") / "bundle"
    for name in ("translator", "typed_cfg", "recorded_path"):
        left, right = digest(source / "private" / name), digest(target / "private" / name)
        if left != right:
            raise ValueError(app + ": source/reissued private artifacts differ")
        files.append(dict(name=name, sha256=left))
    left = read_json(source / "public/registry.json")["payload"]
    right = read_json(target / "public/registry.json")["payload"]
    if left["circuit"]["backend"] != "binius64" or right["circuit"]["backend"] != "plonk":
        raise ValueError(app + ": incorrect source/reissued backend")
    for field in ("edge_cap", "ep_cap", "path_mode"):
        if left["circuit"][field] != right["circuit"][field]:
            raise ValueError(app + ": source/reissued capacities or mode differ")
    left_report = read_json(source / "public/report.json")["payload"]
    right_report = read_json(target / "public/report.json")["payload"]
    for field in ("entry_raw", "final_raw", "binary_measurement", "scope_policy_digest"):
        if left_report[field] != right_report[field]:
            raise ValueError(app + ": source/reissued endpoint, code or scope differ")
    return dict(application=app, files=files, backend_and_public_context_match=True)


def zekra_proof_bits(log_path):
    text = Path(log_path).read_text(encoding="utf-8", errors="replace")
    if "The verification result is: PASS" not in text:
        raise ValueError("ZEKRA success lacks a verification PASS log")
    values = re.findall(r"Proof size in bits:\s*(\d+)", text)
    if len(values) != 1 or int(values[0]) <= 0:
        raise ValueError("ZEKRA success lacks one unambiguous reported proof bit count")
    return int(values[0])


def primary_constraint_audit(primary, directory):
    """Audit reported families without treating an omitted family as zero."""
    records = []
    for (app, mode), row in primary.items():
        if not validate_success(row, backend="binius"):
            continue
        path = directory / f"{mode}-{app}.stdout.log"
        reports = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("{"):
                try:
                    report = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(report, dict) and report.get("schema") == "zkcfa.raw.proof":
                    reports.append(report)
        if len(reports) != 1:
            raise ValueError(f"{app}/{mode}: expected exactly one primary proof report")
        report = reports[0]
        if (report.get("backend"), report.get("profile"), report.get("application"),
                report.get("path_mode"), report.get("verified")) != (
                "binius64", "raw24-full-key", app, mode, True):
            raise ValueError(f"{app}/{mode}: primary proof report identity or verdict mismatch")
        counts = report["constraints"]
        for key, field in (("and", "and_constraints"), ("bmul", "bmul_constraints")):
            if number(counts, key, required=True) != number(row, field, required=True):
                raise ValueError(f"{app}/{mode}: {key} count differs between CSV and proof report")
        reported = {key: number(counts, key, required=True) for key in counts}
        if any(not isinstance(value, int) for value in reported.values()):
            raise ValueError(f"{app}/{mode}: noninteger constraint count")
        records.append(dict(application=app, path_mode=mode, stdout_sha256=digest(path),
            reported_constraints=reported, csv_and_plus_bmul=reported["and"] + reported["bmul"]))
    imul = [record["reported_constraints"]["imul"] for record in records
            if "imul" in record["reported_constraints"]]
    zero = [record["reported_constraints"]["zero"] for record in records
            if "zero" in record["reported_constraints"]]
    summary = dict(successful_reports_checked=len(records),
        imul=dict(reported_in=len(imul), values=sorted(set(imul)),
            all_checked_reports_zero=bool(records) and len(imul) == len(records) and all(value == 0 for value in imul)),
        zero=dict(reported_in=len(zero), values=sorted(set(zero)),
            interpretation="an omitted ZERO count is unavailable, not zero"),
        paper_reduction_metric="reported AND + BMUL counts; excludes IMUL and ZERO; not a count of every constraint family")
    return records, summary


def backend_rows(primary, plonk, zekra, proof_bits, audits, zekra_oom_apps=()):
    rows = []
    for app in APPLICATIONS:
        b, p, z = primary[(app, "shadow")], plonk[(app, "shadow")], zekra[(app,)]
        b_ok, p_ok = validate_success(b, backend="binius"), validate_success(p, backend="plonk")
        matched = app in audits
        if p_ok and (not matched or not truth(p.get("backend_binding_checked"))):
            raise ValueError(app + ": successful PLONK proof lacks matched-input audit")
        if matched:
            for key in ("edge_cap", "ep_cap", "proof_rows"):
                if number(b, key) is not None and number(p, key) is not None and number(b, key) != number(p, key):
                    raise ValueError(app + ": paired result shape mismatch: " + key)
        paired = b_ok and p_ok and matched
        z_ok = z["outcome"] == "proved"
        z_oom = app in zekra_oom_apps
        if z["outcome"] == "host-memory" and not z_oom:
            raise ValueError(app + ": ZEKRA memory outcome lacks confirmed Docker OOM evidence")
        if z_ok:
            if z["satisfied"] != "YES":
                raise ValueError(app + ": ZEKRA proof contradicts satisfaction result")
            for key in ("keygen_s", "prove_s", "verify_s"):
                if number(z, key, required=True) <= 0:
                    raise ValueError(app + ": nonpositive ZEKRA phase time")
        r = dict(application=app, raw24_private_artifact_files_matched=3 if matched else 0,
            raw24_private_artifacts_byte_identical=matched,
            binius_plonk_raw_instance_directly_comparable=matched,
            binius_plonk_comparison_scope="same-new-primary-shadow-artifacts" if matched else "unavailable",
            binius_plonk_performance_directly_comparable=paired,
            binius_plonk_performance_scope="paired-verified-proofs" if paired else "unavailable",
            binius_status=b.get("status", "verified" if b_ok else "failed"), binius_verified=b_ok,
            binius_path_mode="shadow", binius_rows=number(b, "proof_rows"),
            binius_edge_cap=number(b, "edge_cap"), binius_ep_cap=number(b, "ep_cap"),
            binius_ep_encoding=b.get("encoding", ""),
            binius_and_constraints=number(b, "and_constraints"), binius_bmul_constraints=number(b, "bmul_constraints"),
            plonk_evidence_kind="plonk-cryptographic-proof" if p_ok else "attempt-without-verified-proof",
            plonk_attempt_outcome=p.get("proof_outcome", "missing"), plonk_verified=p_ok,
            plonk_reissue_outcome=p.get("reissue_outcome", "missing"),
            plonk_table_outcome=plonk_terminal_outcome(p),
            plonk_preflight_validation=p.get("preflight_outcome", "missing"), plonk_path_mode="shadow",
            plonk_rows=number(p, "proof_rows"), plonk_edges=number(p, "edges"),
            plonk_edge_cap=number(p, "edge_cap"), plonk_ep_cap=number(p, "ep_cap"),
            plonk_ep_encoding=p.get("encoding", ""), plonk_gates=number(p, "plonk_gates"),
            plonk_padded_domain=number(p, "padded_domain"), plonk_failure_note=p.get("failure_note", ""),
            plonk_wall_s=number(p, "proof_wall_ms") / 1000 if number(p, "proof_wall_ms") is not None else None,
            plonk_peak_rss_bytes=number(p, "proof_peak_rss_bytes"),
            plonk_peak_memory_footprint_bytes=number(p, "proof_peak_memory_footprint_bytes"),
            zekra_comparison_scope="legacy-compressed-statement-descriptive-only",
            zekra_outcome=z["outcome"], zekra_satisfied=z.get("satisfied") == "YES",
            zekra_docker_oom_confirmed=z_oom,
            zekra_adjlist_len=number(z, "adjlist_len"), zekra_path_len=number(z, "path_len"),
            zekra_r1cs_constraints=number(z, "r1cs_constraints"), zekra_qap_degree=number(z, "qap_degree"),
            zekra_qap_variables=number(z, "qap_variables"),
            zekra_reported_proof_bits=proof_bits.get(app),
            zekra_ceiling_bytes_equivalent=(proof_bits[app] + 7) // 8 if app in proof_bits else None)
        for key in ("setup_ms", "prove_ms", "verify_ms", "proof_bytes", "public_preflight_ms"):
            r["binius_" + key] = number(b, key) if b_ok else None
            source_key = "proof_public_preflight_ms" if key == "public_preflight_ms" else key
            r["plonk_" + key] = number(p, source_key) if p_ok else None
        r["binius_wall_ms"] = number(b, "wall_ms")
        r["binius_peak_rss_bytes"] = number(b, "peak_rss_bytes")
        for key in ("keygen_s", "prove_s", "verify_s"):
            r["zekra_" + key] = number(z, key) if z_ok else None
        for name, num, den in (
            ("plonk_over_binius_setup_ratio_descriptive", "plonk_setup_ms", "binius_setup_ms"),
            ("plonk_over_binius_prove_ratio", "plonk_prove_ms", "binius_prove_ms"),
            ("binius_over_plonk_verify_time_ratio", "binius_verify_ms", "plonk_verify_ms"),
            ("binius_over_plonk_proof_size_ratio", "binius_proof_bytes", "plonk_proof_bytes"),
        ):
            r[name] = r[num] / r[den] if paired and r[num] is not None and r[den] else None
        rows.append(r)
    return rows


def summarize(primary, backends, signed):
    summary = {"schema": "zkcfa.paper-empirical-export.v1", "primary": {}}
    for mode in ("complete", "shadow"):
        lane = [primary[(app, mode)] for app in APPLICATIONS]
        successful = [row for row in lane if validate_success(row, backend="binius")]
        protocol = [signed[app][mode] for app in APPLICATIONS]
        summary["primary"][mode] = dict(attempted=len(lane), verified=len(successful),
            metrics={key: describe(number(row, key) for row in successful) for key in METRICS},
            protocol={key: describe(number(row, key) for row in protocol) for key in
                ("public_bytes", "registry_bytes", "report_bytes", "authority_provision_ms", "device_sign_ms")},
            signed_reports_accepted=sum(row.get("online_verdict", {}).get("accepted") is True for row in protocol),
            replay_rejections=sum(bool(row.get("replay_rejection")) for row in protocol))
    apps = [app for app in APPLICATIONS if all(truth(primary[(app, mode)].get("verified"))
            for mode in ("complete", "shadow"))]
    c, s = [primary[(app, "complete")] for app in apps], [primary[(app, "shadow")] for app in apps]
    projection = dict(applications=apps, successful_pairs=len(apps),
        complete_over_shadow_proving=ratios([(number(a, "prove_ms"), number(b, "prove_ms")) for a, b in zip(c, s)]))
    for name, fields in (("rows", ("proof_rows",)), ("and_plus_bmul", ("and_constraints", "bmul_constraints"))):
        complete = sum(sum(number(row, field, required=True) for field in fields) for row in c)
        shadow = sum(sum(number(row, field, required=True) for field in fields) for row in s)
        projection[name] = dict(complete_total=complete, shadow_total=shadow,
            reduction_percent=100 * (1 - shadow / complete) if complete else None)
    projection["and_plus_bmul"]["definition"] = "sum of reported AND and BMUL counts; excludes IMUL and ZERO"
    summary["projection"] = projection
    if backends is not None:
        summary["backend"] = {}
        paired = [row for row in backends if row["binius_plonk_performance_directly_comparable"]]
        for backend in ("binius", "plonk", "zekra"):
            successful = [row for row in backends if row[backend + "_verified"]] if backend != "zekra" else [row for row in backends if row["zekra_outcome"] == "proved"]
            fields = ("setup_ms", "prove_ms", "verify_ms", "proof_bytes") if backend != "zekra" else ("keygen_s", "prove_s", "verify_s", "reported_proof_bits", "ceiling_bytes_equivalent")
            summary["backend"][backend] = dict(verified=len(successful),
                metrics={key: describe(row[backend + "_" + key] for row in successful) for key in fields})
        summary["backend"]["plonk"]["outcomes"] = dict(Counter(row["plonk_attempt_outcome"] for row in backends))
        summary["backend"]["zekra"]["outcomes"] = dict(Counter(row["zekra_outcome"] for row in backends))
        summary["backend"]["paired_applications"] = [row["application"] for row in paired]
        for label, num, den in (
            ("plonk_over_binius_proving", "plonk_prove_ms", "binius_prove_ms"),
            ("binius_over_plonk_verification", "binius_verify_ms", "plonk_verify_ms"),
            ("binius_over_plonk_proof_size", "binius_proof_bytes", "plonk_proof_bytes"),
            ("plonk_over_binius_setup_descriptive", "plonk_setup_ms", "binius_setup_ms"),
        ):
            summary["backend"][label] = ratios([(row[num], row[den]) for row in paired])
    summary["units"] = dict(source_times="milliseconds unless a field ends in _s",
        primary_table_times="seconds", backend_table_verify="milliseconds", binius_table_proof="KiB = bytes/1024",
        plonk_table_proof="serialized bytes", primary_table_rss="decimal GB = bytes/1e9",
        zekra_proof="libsnark-reported bit count; ceiling_bytes_equivalent is not a measured serialized-file size")
    summary["scope"] = dict(primary="one execution/proof per application and mode; successful-run medians",
        primary_constraints="AND + BMUL only; the scaling study reports a separate AND + IMUL + BMUL + ZERO metric",
        unavailable="failed/skipped proof phase values are empty, never replaced by preflight or historical data")
    if backends is not None:
        summary["scope"].update(paired_backend="new primary shadow Binius proofs and reissued PLONK proofs with identical private artifact bytes",
            zekra="separate legacy compressed statement; excluded from paired ratios",
            resource_outcomes="R denotes a configured RSS/domain guard, not system OOM or a measured maximum feasible capacity")
    return summary


def fmt(value, digits=3, divisor=1):
    return "--" if value is None else f"{value / divisor:.{digits}f}"


def count(value):
    if value is None:
        return "--"
    if int(value) != value:
        return f"{value:g}"
    return r"\num{" + str(int(value)) + "}" if value >= 1000 else str(int(value))


def plonk_terminal_outcome(row):
    """Retain the blocking earlier phase when no proof process was launched."""
    outcome = row.get("proof_outcome", "not-attempted")
    if outcome != "not-attempted":
        return outcome
    preflight = row.get("preflight_outcome", "")
    if preflight == "reissue-failed":
        return row.get("reissue_outcome", preflight)
    return preflight if preflight not in ("", "satisfied") else outcome


def outcome_symbol(outcome, *, oom_confirmed=False):
    if outcome in ("verified", "proved"):
        return "OK"
    if outcome in ("unsatisfiable", "unsatisfied"):
        return "U"
    if "timeout" in outcome:
        return "T"
    if outcome == "resource-terminated-rss" or outcome.startswith("resource-skipped-"):
        return "R"
    if outcome == "host-memory" and oom_confirmed:
        return "M"
    if "skip" in outcome or outcome == "not-attempted":
        return "S"
    return "F"


def primary_table(primary, summary):
    text = [r"\begin{table*}[!t]", r"\centering",
        r"\caption{Fresh signed Binius64 results. Time: s; proof size: KiB; RSS: decimal GB. Dashes denote unavailable proof measurements.}",
        r"\label{tab:app-results}", r"\footnotesize", r"\setlength{\tabcolsep}{3.2pt}",
        r"\renewcommand{\arraystretch}{0.88}", r"\begin{tabular}{lrrrrrrrrrrrr}", r"\toprule",
        r"& \multicolumn{6}{c}{Complete} & \multicolumn{6}{c}{Stack-safe} \\",
        r"\cmidrule(lr){2-7}\cmidrule(lr){8-13}",
        r"Application & Rows & Setup & Prove & Verify & $|\pi|$ & RSS & Rows & Setup & Prove & Verify & $|\pi|$ & RSS \\", r"\midrule"]
    for app in APPLICATIONS:
        cells = [app]
        for mode in ("complete", "shadow"):
            row = primary[(app, mode)]
            success = truth(row.get("verified"))
            cells.append(count(number(row, "proof_rows")))
            cells.extend(fmt(number(row, key) if success else None, divisor=1000) for key in ("setup_ms", "prove_ms", "verify_ms"))
            cells += [fmt(number(row, "proof_bytes") if success else None, 1, 1024), fmt(number(row, "peak_rss_bytes"), 2, 1e9)]
        text.append(" & ".join(cells) + r" \\")
    cells = ["Median"]
    for mode in ("complete", "shadow"):
        metrics = summary["primary"][mode]["metrics"]
        cells.append(count(metrics["proof_rows"]["median"]))
        cells.extend(fmt(metrics[key]["median"], divisor=1000) for key in ("setup_ms", "prove_ms", "verify_ms"))
        cells += [fmt(metrics["proof_bytes"]["median"], 1, 1024), fmt(metrics["peak_rss_bytes"]["median"], 2, 1e9)]
    text += [r"\midrule", " & ".join(cells) + r" \\", r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    return "\n".join(text) + "\n"


def backend_table(rows, summary):
    zekra_symbols = [outcome_symbol(row["zekra_outcome"], oom_confirmed=row["zekra_docker_oom_confirmed"]) for row in rows]
    symbols = set(zekra_symbols) | {outcome_symbol(row["plonk_table_outcome"]) for row in rows}
    descriptions = {"OK": "verified", "U": "unsatisfied", "R": "configured resource limit",
        "M": "Docker-confirmed OOM", "T": "timeout", "S": "not attempted", "F": "other failure"}
    order = [key for key in descriptions if key in symbols]
    legend = "; ".join(key + ": " + descriptions[key] for key in order) + "."
    text = [r"\begin{table*}[!t]", r"\centering",
        r"\caption{Fresh backend results; ZEKRA uses a separate legacy statement. " + legend + "}",
        r"\label{tab:backend-apps}", r"\scriptsize", r"\setlength{\tabcolsep}{2.2pt}",
        r"\renewcommand{\arraystretch}{0.88}", r"\begin{tabular}{@{}lrrrrrrrrrrr@{}}", r"\toprule",
        r"& & \multicolumn{3}{c}{Binius64} & \multicolumn{3}{c}{PLONK/KZG} & \multicolumn{4}{c}{ZEKRA} \\",
        r"\cmidrule(lr){3-5}\cmidrule(lr){6-8}\cmidrule(lr){9-12}",
        r"Application & Rows & Prove (s) & Verify (ms) & $|\pi|$ (KiB) & Prove (s) & Verify (ms) & $|\pi|$ (B) & R1CS & Prove (s) & Verify (ms) & Result \\", r"\midrule"]
    for row, z_symbol in zip(rows, zekra_symbols):
        cells = [row["application"], count(row["binius_rows"]), fmt(row["binius_prove_ms"], divisor=1000),
            fmt(row["binius_verify_ms"], 1), fmt(row["binius_proof_bytes"], 1, 1024),
            fmt(row["plonk_prove_ms"], divisor=1000) if row["plonk_verified"] else outcome_symbol(row["plonk_table_outcome"]),
            fmt(row["plonk_verify_ms"], 1), count(row["plonk_proof_bytes"]), count(row["zekra_r1cs_constraints"]),
            fmt(row["zekra_prove_s"]), fmt(row["zekra_verify_s"], 1, 0.001), z_symbol]
        text.append(" & ".join(cells) + r" \\")
    b, p, z = (summary["backend"][name]["metrics"] for name in ("binius", "plonk", "zekra"))
    outcomes = Counter(zekra_symbols)
    z_order = [key for key in descriptions if key in outcomes]
    statuses = "/".join(str(outcomes[key]) for key in z_order)
    cells = ["Median / " + "/".join(z_order), "--", fmt(b["prove_ms"]["median"], divisor=1000),
        fmt(b["verify_ms"]["median"], 1), fmt(b["proof_bytes"]["median"], 1, 1024),
        fmt(p["prove_ms"]["median"], 2, 1000), fmt(p["verify_ms"]["median"], 1), count(p["proof_bytes"]["median"]),
        "--", fmt(z["prove_s"]["median"], 2), fmt(z["verify_s"]["median"], 1, 0.001), statuses]
    text += [r"\midrule", " & ".join(cells) + r" \\", r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    return "\n".join(text) + "\n"


def check_metadata_csv(metadata_path, csv_path):
    metadata = read_json(metadata_path)
    recorded = metadata.get("results_sha256", metadata.get("csv_sha256"))
    if recorded != digest(csv_path):
        raise ValueError("CSV does not match completed campaign metadata: " + str(csv_path))
    return metadata


def row_sha256(row):
    return hashlib.sha256(json.dumps(row, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def merge_plonk_attempts(initial_path, retry_paths):
    """Choose the latest explicitly linked attempt, retaining every prior record."""
    paths = [initial_path, *retry_paths]
    selected, selected_sources, history, campaigns, seen = {}, {}, [], [], {}
    initial_metadata = None
    for index, path in enumerate(paths):
        path = path.resolve()
        metadata = check_metadata_csv(path.with_name('metadata.json'), path)
        identity = read_json(path.with_name('run-identity.json'))
        if metadata.get('run_identity') != identity:
            raise ValueError('PLONK metadata/identity mismatch: ' + str(path))
        csv_hash = digest(path)
        if csv_hash in seen:
            raise ValueError('duplicate PLONK attempt campaign')
        if index == 0:
            expected = [(app, 'shadow') for app in APPLICATIONS]
            initial_metadata = metadata
        else:
            link = read_json(path.with_name('retry-source.json'))
            if metadata.get('retry_source') != link:
                raise ValueError('retry source differs from completed metadata')
            if link['results_sha256'] not in seen:
                raise ValueError('retry does not link an earlier supplied attempt campaign')
            previous_path = seen[link['results_sha256']]
            if Path(link['results_path']).resolve() != previous_path:
                raise ValueError('retry source path differs from supplied original campaign')
            if link['metadata_sha256'] != digest(previous_path.with_name('metadata.json')):
                raise ValueError('retry source metadata changed')
            if identity.get('retry_source_results_sha256') != link['results_sha256']:
                raise ValueError('retry identity omitted its original attempt binding')
            for key in ('binary_sha256', 'source_manifest_sha256', 'threads', 'build_metadata_sha256'):
                if identity.get(key) != initial_metadata['run_identity'].get(key):
                    raise ValueError('retry changes paired measurement identity: ' + key)
            for key in ('threads', 'max_rss_bytes', 'proof_timeout_s', 'max_proof_domain'):
                if metadata.get(key) != initial_metadata.get(key):
                    raise ValueError('retry changes measurement resource configuration: ' + key)
            expected = [(item['application'], item['path_mode']) for item in link['original_attempts']]
            if len(expected) != len(set(expected)) or not expected:
                raise ValueError('retry source has duplicate or empty attempt set')
        rows = unique(read_csv(path), ('application', 'path_mode'), expected)
        if index:
            linked = {(item['application'], item['path_mode']): item for item in link['original_attempts']}
            for key, row in rows.items():
                previous = selected.get(key)
                if previous is None or validate_success(previous, backend='plonk'):
                    raise ValueError('retry cannot replace a successful or absent prior attempt')
                item = linked[key]
                if (row_sha256(previous) != row.get('source_attempt_row_sha256')
                        or item['row_sha256'] != row_sha256(previous) or item['row'] != previous
                        or row.get('source_attempt_results_sha256') != link['results_sha256']
                        or row.get('source_attempt_outcome') != previous['proof_outcome']
                        or selected_sources[key] != previous_path):
                    raise ValueError('retry does not preserve the immediately preceding attempt')
        for key, row in rows.items():
            validate_success(row, backend='plonk')
            stem = path.parent/'logs'/f'{key[1]}-{key[0]}.prove'
            log_hashes = {suffix:digest(Path(str(stem)+suffix)) for suffix in
                ('.stdout.log','.stderr.log','.controller.json') if Path(str(stem)+suffix).is_file()}
            if row.get('proof_controller_log'):
                controller_path = Path(row['proof_controller_log'])
                if controller_path.resolve() != Path(str(stem)+'.controller.json').resolve():
                    raise ValueError('PLONK controller diagnostic path differs from attempt')
                controller = read_json(controller_path)
                if truth(row.get('proof_cleanup_complete')) != controller.get('cleanup_complete'):
                    raise ValueError('PLONK cleanup verdict differs from preserved diagnostic')
                if row.get('proof_stop_reason') != controller.get('stop'):
                    raise ValueError('PLONK stop reason differs from preserved diagnostic')
                for field, source_field in (('proof_wall_ms','wall_ms'),('proof_peak_rss_bytes','peak_rss_bytes')):
                    if number(row,field,required=True) != number(controller,source_field,required=True):
                        raise ValueError('PLONK resource measurement differs from preserved diagnostic')
            selected[key], selected_sources[key] = row, path
            history.append(dict(application=key[0], path_mode=key[1], campaign_index=index,
                results_path=str(path), results_sha256=csv_hash, row_sha256=row_sha256(row),
                proof_log_sha256=log_hashes, row=row))
        seen[csv_hash] = path
        campaigns.append(dict(results_path=str(path), results_sha256=csv_hash,
            metadata_sha256=digest(path.with_name('metadata.json')), runner_sha256=metadata.get('runner_sha256'),
            process_controller_sha256=metadata.get('process_controller_sha256'), retry_source=metadata.get('retry_source')))
    for item in history:
        key = item['application'], item['path_mode']
        item['selected_for_table'] = Path(item['results_path']) == selected_sources[key]
    return selected, selected_sources, history, campaigns


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True, help="new primary campaign containing signed/ and binius-results/")
    parser.add_argument("--primary-only", action="store_true", help="export the completed 42-run primary campaign before backend campaigns finish")
    parser.add_argument("--plonk-results", type=Path)
    parser.add_argument("--plonk-retry-results", type=Path, action="append", default=[],
        help="linked retry CSV, in chronological order; every original attempt is retained in the export audit")
    parser.add_argument("--zekra-results", type=Path)
    parser.add_argument("--zekra-logs", type=Path, help="defaults to the ZEKRA campaign snapshot's Groth16 logs")
    parser.add_argument("--output", type=Path, required=True, help="new export directory; existing files are never overwritten")
    args = parser.parse_args(argv)
    if args.primary_only and any((args.plonk_results, args.plonk_retry_results, args.zekra_results, args.zekra_logs)):
        parser.error("--primary-only cannot be combined with backend inputs")
    if not args.primary_only and (args.plonk_results is None or args.zekra_results is None):
        parser.error("full exports require both --plonk-results and --zekra-results")
    campaign = args.campaign.resolve()
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError("refusing to overwrite a frozen export")
    primary_path = campaign / "binius-results/results.csv"
    primary_meta = check_metadata_csv(primary_path.with_name("metadata.json"), primary_path)
    source_manifest = campaign / "signed/bundles.json"
    primary = unique(read_csv(primary_path), ("application", "path_mode"),
        [(app, mode) for app in APPLICATIONS for mode in ("complete", "shadow")])
    signed = {row["application"]: row for row in read_json(source_manifest)["applications"]}
    if set(signed) != set(APPLICATIONS):
        raise ValueError("signed primary manifest has an unexpected application set")
    constraint_records, constraint_summary = primary_constraint_audit(primary, primary_path.parent)
    sources = dict(primary_results=dict(path=str(primary_path), sha256=digest(primary_path)),
        signed_manifest_sha256=digest(source_manifest), campaign_metadata=dict(primary=primary_meta))
    combined, audit, bits, attempt_history, attempt_campaigns = None, {}, {}, [], []
    files = [(primary_path, "results.csv")]
    if not args.primary_only:
        plonk_path, zekra_path = args.plonk_results.resolve(), args.zekra_results.resolve()
        plonk_meta = check_metadata_csv(plonk_path.with_name("metadata.json"), plonk_path)
        zekra_meta = check_metadata_csv(zekra_path.with_name("summary.json"), zekra_path)
        if zekra_meta.get("validation_passed") is not True or zekra_meta.get("coverage_complete") is not True:
            raise ValueError("ZEKRA campaign validation is incomplete; review its preserved issues before exporting")
        identity = read_json(plonk_path.with_name("run-identity.json"))
        if identity["source_manifest_sha256"] != digest(source_manifest):
            raise ValueError("PLONK was not prepared from this signed primary campaign")
        if plonk_meta.get("run_identity") != identity:
            raise ValueError("PLONK completed metadata and prepared identity disagree")
        if primary_meta.get("threads") != plonk_meta.get("threads"):
            raise ValueError("paired backends used different thread counts")
        native_build = plonk_meta.get("build_metadata") or {}
        if native_build.get("schema") == "zkcfa.v13.native-build.v1":
            if primary_meta["binary_sha256"] != native_build["binaries"]["zkcfa-raw24"]["sha256"]:
                raise ValueError("primary Binius binary differs from the paired native-build record")
        plonk, plonk_sources, attempt_history, attempt_campaigns = merge_plonk_attempts(plonk_path, args.plonk_retry_results)
        raw_zekra = read_csv(zekra_path)
        zekra = unique([row for row in raw_zekra if row["app"] != "crc32-control-500"], ("app",), [(app,) for app in APPLICATIONS])
        for (app, _), row in plonk.items():
            if truth(row.get("artifacts_byte_identical")):
                audit[app] = paired_artifact_audit(campaign, plonk_sources[(app, 'shadow')].parent, app,
                    row.get('prepared_run_directory'))
        logs = args.zekra_logs or zekra_path.parent / "snapshot/zekra/reproduce/results/embench-suite/logs"
        log_hashes = {}
        for (app,), row in zekra.items():
            if row["outcome"] == "proved":
                log = logs / (app + "-03-groth16.log")
                bits[app] = zekra_proof_bits(log)
                log_hashes[app] = digest(log)
                expected = [value for key, value in zekra_meta["logs_sha256"].items()
                            if key.endswith("/logs/" + log.name)]
                if expected != [log_hashes[app]]:
                    raise ValueError(app + ": proof log differs from validated ZEKRA summary")
        oom_apps = {event["application"] for event in zekra_meta.get("resource_events", [])
            if event.get("stage") == "groth16" and event.get("state", {}).get("OOMKilled") is True
            and event.get("docker_exit_code") == 137}
        combined = backend_rows(primary, plonk, zekra, bits, audit, oom_apps)
        files += [(plonk_path, "plonk-results.csv"), (zekra_path, "zekra-results.csv")]
        files += [(path.resolve(), f"plonk-retry-{index}-results.csv") for index, path in enumerate(args.plonk_retry_results, 1)]
        sources.update(plonk_results=dict(path=str(plonk_path), sha256=digest(plonk_path)),
            zekra_results=dict(path=str(zekra_path), sha256=digest(zekra_path)), zekra_proof_logs_sha256=log_hashes)
        sources["campaign_metadata"].update(plonk=plonk_meta,
            zekra_summary_sha256=digest(zekra_path.with_name("summary.json")))
        sources['plonk_attempt_campaigns'] = attempt_campaigns
    summary = summarize(primary, combined, signed)
    summary.update(created_utc=datetime.now(timezone.utc).isoformat(), sources=sources,
        exporter_sha256=digest(Path(__file__)), export_scope="primary-only" if args.primary_only else "primary-and-backends",
        primary_constraint_audit=constraint_summary)
    primary_tex = primary_table(primary, summary)
    if combined is not None:
        summary['backend']['plonk']['attempt_audit'] = dict(total_attempts=len(attempt_history),
            selected_applications=len(plonk), retry_attempts=len(attempt_history)-len(APPLICATIONS),
            all_attempt_outcomes=dict(Counter(item['row']['proof_outcome'] for item in attempt_history)),
            selection_rule='latest explicitly linked attempt, including a failed retry; never best-of timing selection',
            original_failed_attempts_preserved=True)
    backend_tex = backend_table(combined, summary) if combined is not None else None
    # Everything above is read-only and must succeed before any export is published.
    output.mkdir(parents=True)
    for source, name in files:
        shutil.copyfile(source, output / name)
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, allow_nan=False) + "\n")
    (output / "primary-constraint-audit.json").write_text(json.dumps(constraint_records, indent=2, sort_keys=True) + "\n")
    (output / "primary-table.tex").write_text(primary_tex)
    verdict = dict(output=str(output), export_scope=summary["export_scope"],
        primary_verified={mode: summary["primary"][mode]["verified"] for mode in ("complete", "shadow")})
    if combined is not None:
        with (output / "backend-comparison.csv").open("x", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(combined[0]))
            writer.writeheader()
            writer.writerows(combined)
        (output / "paired-input-audit.json").write_text(json.dumps(list(audit.values()), indent=2, sort_keys=True) + "\n")
        (output / "plonk-attempt-audit.json").write_text(json.dumps(attempt_history, indent=2, sort_keys=True) + "\n")
        attempt_fields = sorted(set().union(*(item['row'].keys() for item in attempt_history)))
        with (output / 'plonk-all-attempts.csv').open('x', encoding='utf-8', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=['campaign_index','selected_for_table','attempt_results_path',*attempt_fields])
            writer.writeheader()
            writer.writerows(dict(item['row'], campaign_index=item['campaign_index'],
                selected_for_table=item['selected_for_table'], attempt_results_path=item['results_path']) for item in attempt_history)
        (output / "backend-table.tex").write_text(backend_tex)
        verdict.update(paired_successful=len(summary["backend"]["paired_applications"]),
            zekra_reported_proof_bits=sorted(set(bits.values())))
    print(json.dumps(verdict, sort_keys=True))


if __name__ == "__main__":
    main()
