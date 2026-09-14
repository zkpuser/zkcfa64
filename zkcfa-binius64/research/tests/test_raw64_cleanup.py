"""Raw64 timeout record preservation with a fake process; no proofs are run."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('raw64_cleanup_checks',
    Path(__file__).resolve().parents[3] / 'zkcfa-binius64/research/scripts/run_raw64_comparison.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class Raw64CleanupChecks(unittest.TestCase):
    def test_timeout_keeps_wall_and_cleanup_error(self):
        class Process:
            pid, returncode = 123, -15
            def wait(self, timeout):
                raise runner.subprocess.TimeoutExpired('diagnostic-only',timeout)
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            protocol = dict(authority_sha256='test-only',challenge=dict(challenge_id='test-only',nonce='test-only'))
            (directory/'protocol-result.json').write_text(json.dumps(protocol))
            with patch.object(runner.subprocess,'Popen',return_value=Process()), \
                    patch.object(runner.process_control,'process_table',return_value={}), \
                    patch.object(runner.process_control,'terminate_owned_group',return_value={
                        'complete':False,'errors':[{'errno':1}]}):
                record = runner.run_one(directory/'unused-binary',directory,directory/'diagnostic.log')
            self.assertEqual(record['termination_reason'],'timeout')
            self.assertEqual(record['timeout_seconds'],1800)
            self.assertIn('wall_ms',record)
            self.assertEqual(record['cleanup']['errors'],[{'errno':1}])
            self.assertNotIn('proof',record)
            self.assertTrue(Path(record['controller_log']).is_file())
            record.update(application='crc32',mode='shadow',profile='raw64',repetition=1)
            summary = runner.summarize([record])[0]
            self.assertEqual(summary['failed_attempt_diagnostics'][0]['cleanup']['errors'],[{'errno':1}])


if __name__ == '__main__':
    unittest.main()
