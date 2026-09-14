"""Bounded cleanup of an explicitly created process group, without killpg probes.

Only members of the supplied Popen's group with the controller's UID are signalled.
Each PID's group, owner and start time are rechecked immediately before signalling.
The caller must persist the returned diagnostics and stop its campaign if cleanup
cannot be confirmed. A zombie cannot run or hold RSS; the wrapper itself is reaped.
"""
from __future__ import annotations

import os
import signal
import subprocess
import time


def process_table():
    text = subprocess.check_output(
        ['/bin/ps', '-axo', 'pid=,ppid=,pgid=,uid=,rss=,stat=,lstart='],
        stderr=subprocess.PIPE, text=True)
    rows = {}
    for line in text.splitlines():
        fields = line.split(None, 6)
        if len(fields) != 7:
            raise ValueError('incomplete ps process identity')
        pid, parent, group, uid, rss = map(int, fields[:5])
        rows[pid] = dict(pid=pid, ppid=parent, pgid=group, uid=uid,
                         rss_bytes=rss * 1024, state=fields[5], started=fields[6].strip())
    return rows


def identity(row):
    return row['pid'], row['pgid'], row['uid'], row['started']


def terminate_owned_group(process, *, grace_seconds=3):
    """Return evidence even on permission/lookup failures; never raise cleanup errors."""
    group, uid = process.pid, os.getuid()
    result = dict(complete=False, pgid=group, uid=uid, errors=[], signals=[],
                  remaining_pids=[], foreign_pids=[], zombie_pids=[])

    def scan():
        process.poll()  # Reap the wrapper independently of child/group liveness.
        table = process_table()
        members = [row for row in table.values() if row['pgid'] == group]
        result['foreign_pids'] = [row['pid'] for row in members if row['uid'] != uid]
        owned = [row for row in members if row['uid'] == uid]
        result['zombie_pids'] = [row['pid'] for row in owned if row['state'].startswith('Z')]
        active = [row for row in owned if not row['state'].startswith('Z')]
        result['remaining_pids'] = [row['pid'] for row in active]
        result['wrapper_returncode'] = process.returncode
        result['complete'] = not active and not result['foreign_pids'] and process.returncode is not None
        return active

    def signal_member(row, sig):
        current = process_table().get(row['pid'])
        if current is None or identity(current) != identity(row) or current['state'].startswith('Z'):
            return
        event = dict(pid=row['pid'], pgid=group, signal=int(sig), started=row['started'])
        result['signals'].append(event)
        try:
            os.kill(row['pid'], sig)
            event['result'] = 'sent'
        except OSError as error:
            event.update(result='signal-error', errno=error.errno)
            result['errors'].append(dict(operation='signal-pid', pid=row['pid'], signal=int(sig),
                                         errno=error.errno, error=str(error)))

    try:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            active = scan()
            if result['complete']:
                break
            children = [row for row in active if row['pid'] != group]
            # Let /usr/bin/time reap its child and emit resource statistics on TERM.
            targets = children if children and sig == signal.SIGTERM else active
            for row in sorted(targets, key=lambda item: item['pid'] == group):
                signal_member(row, sig)
            deadline = time.monotonic() + grace_seconds
            while time.monotonic() < deadline:
                scan()
                if result['complete']:
                    break
                time.sleep(0.05)
            if result['complete']:
                break
        scan()
    except BaseException as error:
        result['complete'] = False
        result['errors'].append(dict(operation='enumerate-or-reap', errno=getattr(error, 'errno', None),
                                     error=str(error)))
    return result
