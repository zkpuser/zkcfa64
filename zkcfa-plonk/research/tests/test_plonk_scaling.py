"""Guard against reporting projected inputs, padded domains, and failures as paired proofs."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('plonk_scaling', ROOT/'zkcfa-plonk/research/scripts/run_plonk_scaling.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class PlonkScalingChecks(unittest.TestCase):
    def test_seven_scale_manifest_requires_every_case_exactly_once(self):
        manifest = dict(schema='zkcfa.synthetic-scaling-inputs.v1', research_only=True,
                        sizes=[64, 128, 256, 512, 1024, 2048, 4096],
                        cases=[dict(family=family, source_ep_rows=size)
                               for family in ('fixed-cfg', 'growing-cfg') for size in runner.SIZES])
        planned = runner.planned_grid(manifest)
        self.assertEqual(list(planned), manifest['sizes'])
        self.assertEqual(len(planned) * 3, 21)
        for change in (
                lambda m: m['cases'].pop(),
                lambda m: m['cases'].append(m['cases'][0]),
                lambda m: m['sizes'].remove(2048)):
            altered = copy.deepcopy(manifest)
            change(altered)
            with self.assertRaises(ValueError):
                runner.planned_grid(altered)

    def fixture(self):
        hashes = {name: str(index)*64 for index, name in enumerate(runner.ARTIFACTS)}
        case = dict(source_ep_rows=64, nodes=27, typed_edges=31, binius_edge_cap=32,
                    binius_ep_cap=dict(complete=64), input_sha256=dict(complete=hashes))
        report = dict(schema='zkcfa.plonk.synthetic-scaling.v1', backend='plonk',
            profile='raw24-full-key', path_mode='complete', threads=8, preflight=False,
            satisfied=True, verified=True, input_sha256=hashes,
            instance=dict(nodes=27, edges=31, steps=64),
            capacity=dict(edge_cap=32, ep_cap=64),
            constraints=dict(plonk_gates=19000, raw_bound=19000, padded_domain=32768),
            phases_ms={key:1.0 for key in ('input_preflight', 'setup', 'srs_setup', 'key_compile_and_trim',
                'witness_localcheck', 'cryptographic_prove', 'proof_serialization', 'verify')})
        return case, report

    def test_native_complete_identity_is_mandatory(self):
        case, report = self.fixture()
        runner.audit_report(report, case, preflight=False)
        for modify in (
                lambda r:r.update(path_mode='shadow'),
                lambda r:r['instance'].update(steps=44),
                lambda r:r['input_sha256'].update(recorded_path='f'*64),
                lambda r:r['capacity'].update(ep_cap=32)):
            changed = copy.deepcopy(report)
            modify(changed)
            with self.subTest(report=changed), self.assertRaises(ValueError):
                runner.audit_report(changed, case, preflight=False)

    def test_nonverified_and_unavailable_crypto_times_are_rejected(self):
        case, report = self.fixture()
        for modify in (lambda r:r.update(verified=False),
                       lambda r:r['phases_ms'].pop('cryptographic_prove'),
                       lambda r:r['phases_ms'].update(cryptographic_prove=float('nan')),
                       lambda r:r['constraints'].update(padded_domain=16384)):
            changed = copy.deepcopy(report)
            modify(changed)
            with self.subTest(report=changed), self.assertRaises(ValueError):
                runner.audit_report(changed, case, preflight=False)

    def test_aggregation_excludes_warmup_and_failed_attempts(self):
        def row(value, *, warmup=False, verified=True):
            result = dict(source_ep_rows=64, warmup=warmup, outcome='verified' if verified else 'timeout',
                verified=verified, plonk_gates=19000, raw_bound=19000, padded_domain=32768, returncode=0)
            result.update({name:value for name in runner.METRICS})
            return result
        summary = runner.summarize([row(10), row(12), row(1000, warmup=True), row(9999, verified=False)])
        self.assertEqual(summary[0]['verified'], 2)
        self.assertEqual(summary[0]['measurements']['cryptographic_prove_ms']['median'], 11)
        self.assertEqual(summary[0]['plonk_gates'], 19000)
        self.assertEqual(summary[0]['padded_domain'], 32768)
        self.assertIsNone(summary[-1]['measurements']['cryptographic_prove_ms'])


if __name__ == '__main__':
    unittest.main()
