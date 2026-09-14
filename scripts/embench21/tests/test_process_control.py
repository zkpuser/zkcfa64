"""No proof generation: PID ownership, exit races and cleanup failure evidence."""
import importlib.util
import os
from pathlib import Path
import signal
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('process_control_checks',
    Path(__file__).resolve().parents[1] / 'process_control.py')
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)


class Wrapper:
    pid, returncode = 100, 0
    def poll(self): return self.returncode


class ProcessControlChecks(unittest.TestCase):
    def member(self, **changes):
        return dict(dict(pid=101, ppid=100, pgid=100, uid=os.getuid(), rss_bytes=1024,
            state='S', started='original-start-time'), **changes)

    def test_orphan_child_cleanup_never_uses_group_signal_zero(self):
        row = self.member()
        with patch.object(control, 'process_table', side_effect=[{101:row},{101:row},{},{}]), \
                patch.object(control.os, 'kill') as kill, patch.object(control.os, 'killpg') as killpg:
            result = control.terminate_owned_group(Wrapper())
        self.assertTrue(result['complete'])
        kill.assert_called_once_with(101, signal.SIGTERM)
        killpg.assert_not_called()

    def test_changed_pid_identity_is_not_signalled(self):
        row = self.member()
        changed = self.member(started='reused-pid-start-time')
        with patch.object(control, 'process_table', side_effect=[{101:row},{101:changed},{},{}]), \
                patch.object(control.os, 'kill') as kill:
            self.assertTrue(control.terminate_owned_group(Wrapper())['complete'])
        kill.assert_not_called()

    def test_foreign_uid_is_preserved_and_cleanup_unconfirmed(self):
        row = self.member(uid=os.getuid()+1)
        with patch.object(control, 'process_table', return_value={101:row}), patch.object(control.os, 'kill') as kill:
            result = control.terminate_owned_group(Wrapper(), grace_seconds=0)
        self.assertFalse(result['complete'])
        self.assertEqual(result['foreign_pids'], [101])
        kill.assert_not_called()

    def test_permission_exit_race_preserves_error_then_confirms_exit(self):
        row = self.member()
        with patch.object(control, 'process_table', side_effect=[{101:row},{101:row},{},{}]), \
                patch.object(control.os, 'kill', side_effect=PermissionError(1, 'Operation not permitted')):
            result = control.terminate_owned_group(Wrapper())
        self.assertTrue(result['complete'])
        self.assertEqual(result['errors'][0]['errno'], 1)

    def test_unavailable_enumeration_does_not_claim_cleanup(self):
        with patch.object(control, 'process_table', side_effect=PermissionError(1, 'Operation not permitted')):
            result = control.terminate_owned_group(Wrapper())
        self.assertFalse(result['complete'])
        self.assertEqual(result['errors'][0]['operation'], 'enumerate-or-reap')


if __name__ == '__main__':
    unittest.main()
