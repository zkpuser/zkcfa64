"""Raw64 export provenance checks with synthetic logs; no measurement processes."""
import copy
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('raw64_export_audit',
    ROOT / 'zkcfa-binius64/research/scripts/summarize_raw64_comparison.py')
export = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(export)


class Raw64ExportAuditChecks(unittest.TestCase):
    def fixture(self, directory, profile='raw64'):
        log = directory / f'crc32-shadow-{profile}-r1.log'
        log.write_text('0.50 real 0.01 user 0.01 sys\n4096 maximum resident set size\n')
        payload = dict(exit_code=-15, wall_ms=501.23, log=str(log), signed_run='/diagnostic/crc32/shadow',
            protocol_result_sha256='a'*64, log_sha256=export.sha(log), timeout_seconds=1800,
            termination_reason='timeout', sampled_rss_at_stop_bytes=4096, peak_rss_bytes=4096,
            cleanup=dict(complete=False, errors=[dict(operation='signal-pid', errno=1)], remaining_pids=[123]),
            error='proof stopped: timeout; cleanup_complete=False', error_tail=log.read_text())
        sidecar = log.with_suffix('.controller.json')
        sidecar.write_text(json.dumps(payload))
        row = dict(payload, application='crc32', mode='shadow', profile=profile, repetition=1, session=1,
            runner_sha256='b'*64, controller_log=str(sidecar), controller_log_sha256=export.sha(sidecar))
        metadata = dict(process_controller_sha256='c'*64,
            sessions=[dict(session=1, process_controller_sha256='c'*64)])
        return row, metadata, sidecar

    def test_matching_sidecar_preserves_all_cleanup_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            row, metadata, _ = self.fixture(directory)
            audit = export.validate_controller_records([row], directory, metadata=metadata)
            self.assertEqual(audit[0]['content']['cleanup'], row['cleanup'])
            self.assertEqual(audit[0]['content']['termination_reason'], 'timeout')

    def test_digest_tampering_and_rehashed_content_tampering_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            row, metadata, sidecar = self.fixture(directory)
            changed = json.loads(sidecar.read_text())
            changed['cleanup']['complete'] = True
            sidecar.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, 'digest differs'):
                export.validate_controller_records([row], directory, metadata=metadata)
            row['controller_log_sha256'] = export.sha(sidecar)
            with self.assertRaisesRegex(ValueError, 'content differs'):
                export.validate_controller_records([row], directory, metadata=metadata)
            # JSON false and 0 must not be accepted as interchangeable evidence.
            changed['cleanup']['complete'] = 0
            sidecar.write_text(json.dumps(changed))
            row['controller_log_sha256'] = export.sha(sidecar)
            with self.assertRaisesRegex(ValueError, 'content differs'):
                export.validate_controller_records([row], directory, metadata=metadata)

    def test_declared_new_capability_cannot_fall_back_to_legacy(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            row, metadata, _ = self.fixture(directory)
            row.pop('controller_log'); row.pop('controller_log_sha256')
            with self.assertRaisesRegex(ValueError, 'omitted its controller sidecar'):
                export.validate_controller_records([row], directory, metadata=metadata)
            row.pop('cleanup')
            with self.assertRaisesRegex(ValueError, 'requires cleanup'):
                export.validate_controller_records([row], directory, metadata=metadata)
            legacy = dict(sessions=[dict(session=1)])
            self.assertEqual(export.validate_controller_records([row], directory, metadata=legacy), [])
            row['session'] = 999
            with self.assertRaisesRegex(ValueError, 'known controller-capability session'):
                export.validate_controller_records([row], directory, metadata=metadata)

    def test_sidecar_cannot_escape_attempt_path_or_use_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            row, metadata, sidecar = self.fixture(directory)
            linked = directory / 'other.controller.json'
            linked.symlink_to(sidecar)
            row['controller_log'] = str(linked)
            with self.assertRaisesRegex(ValueError, 'outside its measurement attempt'):
                export.validate_controller_records([row], directory, metadata=metadata)

    def test_new_failed_summary_requires_complete_matching_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            row, _, _ = self.fixture(Path(directory))
            index = export.grouped_summaries([row], {('crc32','shadow'):1})
            stored = [copy.deepcopy(index[('crc32','shadow','raw64')])]
            export.validate_stored_summaries(stored,index)
            stored[0].pop('failed_attempt_diagnostics')
            with self.assertRaisesRegex(ValueError, 'omits new failed-attempt'):
                export.validate_stored_summaries(stored,index)
            stored[0]['failed_attempt_diagnostics'] = []
            with self.assertRaisesRegex(ValueError, 'failed_attempt_diagnostics'):
                export.validate_stored_summaries(stored,index)
            stored[0]['failed_attempt_diagnostics'] = export.failure_diagnostics([row])
            stored[0]['failed_attempt_diagnostics'][0]['cleanup'] = dict(complete=True,errors=[])
            with self.assertRaisesRegex(ValueError, 'failed_attempt_diagnostics'):
                export.validate_stored_summaries(stored,index)

    def test_success_cannot_hide_a_stop_or_unconfirmed_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            row, metadata, _ = self.fixture(directory)
            row.update(exit_code=0,proof={'verified':True})
            with self.assertRaisesRegex(ValueError, 'contradicts its controller'):
                export.validate_controller_records([row], directory, metadata=metadata)

    def test_warmup_sidecar_and_controller_source_are_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            row, _, _ = self.fixture(directory)
            warmup = {k:v for k,v in row.items() if k not in
                ('application','mode','profile','repetition','runner_sha256','session')}
            source = directory/'process-controller-session1.py'
            source.write_text('# diagnostic fixture\n')
            metadata = dict(process_controller_sha256=export.sha(source),sessions=[dict(session=1,
                process_controller_source=str(source),process_controller_sha256=export.sha(source),warmups=[warmup])])
            audits = export.validate_controller_metadata(metadata,directory)
            self.assertEqual(audits[0]['kind'],'warmup')
            metadata['sessions'][0]['warmups'][0].pop('controller_log')
            with self.assertRaisesRegex(ValueError,'incomplete controller sidecar binding'):
                export.validate_controller_metadata(metadata,directory)
            metadata['sessions'][0]['warmups'] = []
            source.write_text('# changed\n')
            with self.assertRaisesRegex(ValueError,'controller differs'):
                export.validate_controller_metadata(metadata,directory)

    def test_cleanup_stop_status_is_explicit_and_cannot_continue_same_session(self):
        row = dict(session=1,cleanup=dict(complete=False))
        metadata = dict(sessions=[dict(session=1)])
        export.validate_cleanup_status(metadata,[row],'paused')
        with self.assertRaisesRegex(ValueError,'not paused'):
            export.validate_cleanup_status(metadata,[row],'complete_with_failures')
        with self.assertRaisesRegex(ValueError,'continued a session'):
            export.validate_cleanup_status(metadata,[row,dict(session=1)],'paused')
        with self.assertRaisesRegex(ValueError,'unrecognized'):
            export.validate_cleanup_status({},[],'unknown-failure')
        # A normal, fully cleaned timeout remains a failed sample in a completed campaign.
        export.validate_cleanup_status(metadata,[dict(session=1,termination_reason='timeout',cleanup=dict(complete=True))],
            'complete_with_failures')

    def test_success_statistics_and_pair_selection_are_unchanged(self):
        proof = dict(verified=True,application='crc32',path_mode='shadow',profile='raw24-full-key',
            instance=dict(nodes=1,edges=2,steps=3),capacity=dict(edge_cap=4,ep_cap=4,multiplicity_bits=1),
            constraints=dict(and_=10,imul=0,bmul=5),phases_ms=dict(setup=1,prove=2,public_preflight=0.1,verify=0.2),proof_bytes=64)
        proof['constraints']['and'] = proof['constraints'].pop('and_')
        records = [dict(application='crc32',mode='shadow',profile='raw24',repetition=1,exit_code=0,
            proof=proof,wall_ms=8,peak_rss_bytes=1024)]
        plan = {('crc32','shadow'):1}
        index = export.grouped_summaries(records,plan)
        self.assertEqual(index[('crc32','shadow','raw24')]['prove_ms'],dict(median=2,min=2,max=2))
        self.assertEqual(index[('crc32','shadow','raw64')]['status'],'pending')
        flat = export.flatten(index,dict(applications=['crc32'],modes=['shadow']),plan)
        self.assertFalse(flat[0]['paired_aggregate_included'])
        self.assertIsNone(flat[0]['wide_over_raw24_prove_ms'])

    def test_complete_export_retains_verified_failure_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign = Path(directory)/'synthetic-campaign'
            measurements = campaign/'measurements'
            measurements.mkdir(parents=True)
            records = []
            for profile in ('raw24','raw64'):
                row, _, sidecar = self.fixture(measurements,profile)
                row['cleanup'] = dict(complete=True,errors=[])
                row['error'] = 'proof stopped: timeout; cleanup_complete=True'
                sidecar.write_text(json.dumps({k:v for k,v in row.items() if k not in export.JOURNAL_ONLY_FIELDS}))
                row['controller_log_sha256'] = export.sha(sidecar)
                records.append(row)
            source = measurements/'process-controller-session1.py'
            source.write_text('# synthetic controller fixture\n')
            metadata = dict(applications=['crc32'],modes=['shadow'],repeats=1,expected_runs=2,
                status='complete_with_failures',successful_runs=0,attempted_runs=2,
                started_utc='2026-09-08T00:00:00Z',logical_cpus=8,platform='synthetic',
                process_controller_sha256=export.sha(source),sessions=[dict(session=1,
                    process_controller_source=str(source),process_controller_sha256=export.sha(source),warmups=[])])
            (measurements/'metadata.json').write_text(json.dumps(metadata))
            (measurements/'runs.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in records))
            index = export.grouped_summaries(records,{('crc32','shadow'):1})
            (measurements/'summary.json').write_text(json.dumps(list(index.values())))
            (campaign/'pair-audit.json').write_text(json.dumps(dict(all_passed=True,applications=1)))
            (campaign/'captures.json').write_text(json.dumps(dict(captures=[dict(lane='wide',application='crc32',
                addresses=dict(canonical_pc_equals_runtime_pc=True,runtime_bias='0x0',canonical_pc_bits=47))])))
            (campaign/'handoff-validation.json').write_text('{}')
            (campaign/'environment-and-validation.json').write_text(json.dumps(dict(cpu='synthetic',memory_bytes=1<<30,
                rustc='synthetic',build_profile='synthetic',rustflags='synthetic')))
            output, report = Path(directory)/'data',Path(directory)/'report.md'
            argv = ['summarize_raw64_comparison.py','--campaign',str(campaign),
                '--data-output',str(output),'--report',str(report)]
            with patch('sys.argv',argv), redirect_stdout(io.StringIO()):
                export.main()
            published = json.loads((output/'raw64-address-comparison.json').read_text())
            self.assertEqual(published['failed_runs'],2)
            self.assertEqual(published['controller_validation']['measurement_sidecars_verified'],2)
            self.assertEqual(len(published['controller_diagnostic_audits']),2)
            self.assertTrue(published['failure_records'][0]['cleanup']['complete'])
            self.assertEqual(published['aggregate_by_mode']['shadow']['paired_successful_cases'],0)
            self.assertIn('清理确认',report.read_text())


if __name__ == '__main__':
    unittest.main()
