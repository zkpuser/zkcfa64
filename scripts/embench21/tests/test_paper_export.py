"""Paper aggregation checks with synthetic records, not cryptographic experiments."""
from __future__ import annotations

import importlib.util
from contextlib import redirect_stdout
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "paper_export", Path(__file__).resolve().parents[1] / "export_paper_data.py"
)
export = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(export)


class PaperExportChecks(unittest.TestCase):
    def fixture(self):
        primary, plonk, zekra, signed = {}, {}, {}, {}
        for app in export.APPLICATIONS:
            for mode in ("complete", "shadow"):
                primary[(app, mode)] = dict(application=app, path_mode=mode, verified="true",
                    status="verified", setup_ms="1000", prove_ms="2", verify_ms="3",
                    proof_bytes="2048", public_preflight_ms="0.4", wall_ms="1005",
                    peak_rss_bytes="1000000000", proof_rows="23", edge_cap="32", ep_cap="32",
                    encoding="inline14", and_constraints="100", bmul_constraints="50")
            plonk[(app, "shadow")] = dict(application=app, path_mode="shadow", verified="true",
                proof_outcome="verified", backend_binding_checked="true", preflight_outcome="satisfied",
                setup_ms="2000", prove_ms="6", verify_ms="1", proof_bytes="1930",
                proof_public_preflight_ms="5", proof_wall_ms="2010", proof_peak_rss_bytes="2000000000",
                proof_rows="23", edge_cap="32", ep_cap="32", encoding="inline14",
                plonk_gates="18607", padded_domain="32768")
            zekra[(app,)] = dict(app=app, outcome="proved", satisfied="YES", keygen_s="1",
                prove_s="0.2", verify_s="0.005", r1cs_constraints="35526")
            signed[app] = {mode: dict(public_bytes=3200, registry_bytes=1700, report_bytes=1500,
                authority_provision_ms=5, device_sign_ms=20, online_verdict={"accepted": True},
                replay_rejection="already consumed") for mode in ("complete", "shadow")}
        return primary, plonk, zekra, signed

    def test_failed_attempt_never_enters_success_medians_or_paired_ratios(self):
        primary, plonk, zekra, signed = self.fixture()
        plonk[("picojpeg", "shadow")].update(verified="false", proof_outcome="resource-terminated-rss",
            prove_ms="999999", proof_peak_rss_bytes="22000000000")
        bits = {app: 1019 for app in export.APPLICATIONS}
        rows = export.backend_rows(primary, plonk, zekra, bits, set(export.APPLICATIONS))
        failed = next(row for row in rows if row["application"] == "picojpeg")
        self.assertIsNone(failed["plonk_prove_ms"])
        self.assertEqual(failed["plonk_peak_rss_bytes"], 22000000000)
        self.assertIsNone(failed["plonk_over_binius_prove_ratio"])
        summary = export.summarize(primary, rows, signed)
        self.assertEqual(summary["backend"]["plonk"]["verified"], 20)
        self.assertEqual(summary["backend"]["plonk_over_binius_proving"]["n"], 20)
        self.assertEqual(summary["backend"]["plonk_over_binius_proving"]["median_ratio"], 3)
        self.assertEqual(summary["backend"]["plonk"]["metrics"]["prove_ms"]["median"], 6)

    def test_table_units_and_reported_bits_are_explicit(self):
        primary, plonk, zekra, signed = self.fixture()
        rows = export.backend_rows(primary, plonk, zekra, {app: 1019 for app in export.APPLICATIONS}, set(export.APPLICATIONS))
        summary = export.summarize(primary, rows, signed)
        self.assertIn("23 & 1.000 & 0.002 & 0.003 & 2.0 & 1.00", export.primary_table(primary, summary))
        self.assertIn(r"\num{35526} & 0.200 & 5.0 & OK", export.backend_table(rows, summary))
        self.assertEqual(rows[0]["zekra_reported_proof_bits"], 1019)
        self.assertEqual(rows[0]["zekra_ceiling_bytes_equivalent"], 128)
        self.assertNotIn("zekra_proof_bytes", rows[0])

    def test_median_pairwise_ratio_is_not_ratio_of_medians(self):
        result = export.ratios([(2, 1), (9, 3), (100, 50)])
        self.assertEqual(result["median_ratio"], 2)
        self.assertAlmostEqual(result["ratio_of_sums"], 111 / 54)

    def test_duplicate_identity_and_missing_success_value_are_rejected(self):
        row = {"application": "crc32", "path_mode": "shadow"}
        with self.assertRaisesRegex(ValueError, "duplicate"):
            export.unique([row, row], ("application", "path_mode"), [("crc32", "shadow")])
        with self.assertRaisesRegex(ValueError, "omitted"):
            export.validate_success({"verified": "true", "status": "verified"}, backend="binius")
        self.assertIsNone(export.number({"prove_ms": ""}, "prove_ms"))
        with self.assertRaises(ValueError):
            export.number({"prove_ms": "nan"}, "prove_ms")

    def test_proof_bits_require_actual_verification_log(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.log"
            path.write_text("Proof size in bits: 1019\nThe verification result is: PASS\n")
            self.assertEqual(export.zekra_proof_bits(path), 1019)
            path.write_text("Proof size in bits: 1019\n")
            with self.assertRaisesRegex(ValueError, "PASS"):
                export.zekra_proof_bits(path)

    def write_primary_logs(self, primary, directory):
        for (app, mode), row in primary.items():
            report = dict(schema="zkcfa.raw.proof", backend="binius64", profile="raw24-full-key",
                application=app, path_mode=mode, verified=True,
                constraints=dict(and_=100, imul=0, bmul=50))
            report["constraints"]["and"] = report["constraints"].pop("and_")
            (directory / f"{mode}-{app}.stdout.log").write_text(json.dumps(report) + "\n")

    def write_csv(self, path, rows):
        with path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    def write_primary_campaign(self, campaign, primary, signed):
        results = campaign / "binius-results"
        results.mkdir(parents=True)
        self.write_primary_logs(primary, results)
        self.write_csv(results / "results.csv", list(primary.values()))
        (results / "metadata.json").write_text(json.dumps(dict(threads=8,
            results_sha256=export.digest(results / "results.csv"))))
        (campaign / "signed").mkdir()
        (campaign / "signed/bundles.json").write_text(json.dumps(dict(applications=[
            dict(application=app, **lanes) for app, lanes in signed.items()])))

    def test_primary_constraint_audit_does_not_infer_unreported_zero(self):
        primary, _, _, _ = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            self.write_primary_logs(primary, directory)
            records, summary = export.primary_constraint_audit(primary, directory)
            self.assertEqual(len(records), 42)
            self.assertTrue(summary["imul"]["all_checked_reports_zero"])
            self.assertEqual(summary["zero"]["reported_in"], 0)
            self.assertEqual(summary["zero"]["values"], [])
            primary[("crc32", "shadow")]["and_constraints"] = "101"
            with self.assertRaisesRegex(ValueError, "count differs"):
                export.primary_constraint_audit(primary, directory)

    def test_primary_only_export_needs_no_backend_files_and_is_immutable(self):
        primary, _, _, signed = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            campaign = Path(directory) / "campaign"
            self.write_primary_campaign(campaign, primary, signed)
            output = Path(directory) / "export"
            argv = ["--campaign", str(campaign), "--primary-only", "--output", str(output)]
            with redirect_stdout(io.StringIO()):
                export.main(argv)
            summary = export.read_json(output / "summary.json")
            self.assertEqual(summary["export_scope"], "primary-only")
            self.assertNotIn("backend", summary)
            self.assertIn("excludes IMUL and ZERO", summary["projection"]["and_plus_bmul"]["definition"])
            self.assertEqual(set(path.name for path in output.iterdir()),
                {"results.csv", "summary.json", "primary-table.tex", "primary-constraint-audit.json"})
            with self.assertRaises(FileExistsError):
                export.main(argv)

    def test_resource_guard_is_distinct_from_confirmed_oom(self):
        self.assertEqual(export.outcome_symbol("resource-terminated-rss"), "R")
        self.assertEqual(export.outcome_symbol("resource-skipped-domain"), "R")
        self.assertEqual(export.outcome_symbol("resource-monitor-unavailable"), "F")
        self.assertEqual(export.outcome_symbol("timeout"), "T")
        self.assertEqual(export.outcome_symbol("host-memory"), "F")
        self.assertEqual(export.outcome_symbol("host-memory", oom_confirmed=True), "M")
        self.assertEqual(export.plonk_terminal_outcome(dict(proof_outcome="not-attempted",
            preflight_outcome="resource-terminated-rss")), "resource-terminated-rss")
        primary, plonk, zekra, signed = self.fixture()
        plonk[("picojpeg", "shadow")].update(verified="false", proof_outcome="resource-terminated-rss")
        zekra[("picojpeg",)]["outcome"] = "host-memory"
        with self.assertRaisesRegex(ValueError, "Docker OOM"):
            export.backend_rows(primary, plonk, zekra, {}, set(export.APPLICATIONS))
        rows = export.backend_rows(primary, plonk, zekra, {}, set(export.APPLICATIONS), {"picojpeg"})
        table = export.backend_table(rows, export.summarize(primary, rows, signed))
        self.assertIn("R: configured resource limit; M: Docker-confirmed OOM", table)
        self.assertNotIn("T: timeout", table)

    def test_full_export_checks_frozen_inputs_and_verified_zekra_logs(self):
        primary, plonk, zekra, signed = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            campaign = Path(directory) / "campaign"
            self.write_primary_campaign(campaign, primary, signed)
            pdir, zdir = campaign / "plonk-results", Path(directory) / "zekra"
            pdir.mkdir()
            zdir.mkdir()
            logs = zdir / "logs"
            logs.mkdir()
            hashes = {}
            for app in export.APPLICATIONS:
                plonk[(app, "shadow")]["artifacts_byte_identical"] = "true"
                for base, backend in ((campaign / "signed" / app / "shadow" / "bundle", "binius64"),
                        (pdir / "reissued" / app / "shadow" / "bundle", "plonk")):
                    (base / "private").mkdir(parents=True)
                    (base / "public").mkdir()
                    for name in ("translator", "typed_cfg", "recorded_path"):
                        (base / "private" / name).write_text(app + ":" + name)
                    (base / "public/registry.json").write_text(json.dumps(dict(payload=dict(circuit=dict(
                        backend=backend, edge_cap=32, ep_cap=32, path_mode="shadow")))))
                    (base / "public/report.json").write_text(json.dumps(dict(payload=dict(
                        entry_raw=1, final_raw=2, binary_measurement="same", scope_policy_digest="same"))))
                log = logs / (app + "-03-groth16.log")
                log.write_text("Proof size in bits: 1019\nThe verification result is: PASS\n")
                hashes["snapshot/logs/" + log.name] = export.digest(log)
            ppath, zpath = pdir / "results.csv", zdir / "results.csv"
            self.write_csv(ppath, list(plonk.values()))
            self.write_csv(zpath, list(zekra.values()))
            identity = dict(source_manifest_sha256=export.digest(campaign / "signed/bundles.json"))
            (pdir / "run-identity.json").write_text(json.dumps(identity))
            (pdir / "metadata.json").write_text(json.dumps(dict(threads=8, run_identity=identity,
                results_sha256=export.digest(ppath))))
            (zdir / "summary.json").write_text(json.dumps(dict(validation_passed=True, coverage_complete=True,
                logs_sha256=hashes, csv_sha256=export.digest(zpath))))
            argv = ["--campaign", str(campaign), "--plonk-results", str(ppath), "--zekra-results", str(zpath),
                "--zekra-logs", str(logs), "--output", str(Path(directory) / "full-export")]
            with redirect_stdout(io.StringIO()):
                export.main(argv)
            summary = export.read_json(Path(directory) / "full-export/summary.json")
            self.assertEqual(len(summary["backend"]["paired_applications"]), 21)
            self.assertEqual(summary["backend"]["zekra"]["metrics"]["reported_proof_bits"]["median"], 1019)
            (logs / "crc32-03-groth16.log").write_text("Proof size in bits: 1020\nThe verification result is: PASS\n")
            argv[-1] = str(Path(directory) / "changed-export")
            with self.assertRaisesRegex(ValueError, "proof log differs"):
                export.main(argv)
            self.assertFalse(Path(argv[-1]).exists())

    def test_linked_retry_retains_all_original_failures(self):
        _, plonk, _, _ = self.fixture()
        failed_apps = {'sglib-combined','wikisort','picojpeg'}
        for app in failed_apps:
            plonk[(app,'shadow')].update(verified='',proof_outcome='orchestration-failed',
                failure_note='[Errno 1] Operation not permitted')
        # A CSV has one shared header, including the diagnostic column on successes.
        for row in plonk.values():
            row.setdefault('failure_note','')
        with tempfile.TemporaryDirectory() as directory:
            initial, retry = Path(directory)/'initial', Path(directory)/'retry'
            initial.mkdir(); retry.mkdir()
            source = initial/'results.csv'
            self.write_csv(source,list(plonk.values()))
            original_bytes = source.read_bytes()
            identity = dict(binary_sha256={'prove':'same'},source_manifest_sha256='signed',threads=8)
            metadata = dict(run_identity=identity,threads=8,max_rss_bytes=20*(1<<30),
                proof_timeout_s=1800,max_proof_domain=1<<23,results_sha256=export.digest(source))
            (initial/'metadata.json').write_text(json.dumps(metadata))
            (initial/'run-identity.json').write_text(json.dumps(identity))
            previous = [row for row in export.read_csv(source) if row['application'] in failed_apps]
            link = dict(results_path=str(source),results_sha256=export.digest(source),
                metadata_sha256=export.digest(initial/'metadata.json'),original_attempts=[dict(
                    application=row['application'],path_mode='shadow',row_sha256=export.row_sha256(row),row=row)
                    for row in previous])
            retried = [dict(row,verified='false',proof_outcome='resource-terminated-rss',
                source_attempt_results_sha256=link['results_sha256'],source_attempt_row_sha256=export.row_sha256(row),
                source_attempt_outcome=row['proof_outcome']) for row in previous]
            rpath = retry/'results.csv'
            self.write_csv(rpath,retried)
            rid = dict(identity,retry_source_results_sha256=link['results_sha256'])
            (retry/'run-identity.json').write_text(json.dumps(rid))
            (retry/'retry-source.json').write_text(json.dumps(link))
            (retry/'metadata.json').write_text(json.dumps(dict(metadata,run_identity=rid,retry_source=link,
                results_sha256=export.digest(rpath))))
            selected, sources, history, campaigns = export.merge_plonk_attempts(source,[rpath])
            self.assertEqual(len(selected),21)
            self.assertEqual(len(history),24)
            self.assertEqual(len(campaigns),2)
            self.assertEqual(sum(item['selected_for_table'] for item in history),21)
            self.assertEqual(sum(item['row']['proof_outcome']=='orchestration-failed' for item in history),3)
            self.assertEqual(selected[('picojpeg','shadow')]['proof_outcome'],'resource-terminated-rss')
            self.assertEqual(source.read_bytes(),original_bytes)
            with self.assertRaisesRegex(ValueError,'duplicate'):
                export.merge_plonk_attempts(source,[rpath,rpath])


if __name__ == "__main__":
    unittest.main()
