#!/usr/bin/env python3
"""Linux-only wait4 RSS recorder. Execute inside the measured container.

ru_maxrss is the maximum individual-process resident high-water mark, including
children whose usage was reaped by the command; it is not simultaneous tree RSS.
/proc observations are explicitly sampled lower bounds, useful if OOM kills the
recorder before wait4 can finish. The recorder itself is excluded from samples.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
    temporary.replace(path)


def proc_sample(pgid):
    """Return resident memory only; statm/vsize/cgroup accounting are not used."""
    members = []
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            stat = (directory / "stat").read_text()
            fields = stat[stat.rindex(")") + 2:].split()
            if int(fields[2]) != pgid:
                continue
            status = (directory / "status").read_text()
            values = {}
            for line in status.splitlines():
                if line.startswith(("VmRSS:", "VmHWM:")):
                    key, value, unit = line.split()
                    if unit != "kB":
                        raise RuntimeError("unexpected Linux RSS unit")
                    values[key.rstrip(":")] = int(value) * 1024
            members.append({"pid": int(directory.name), "start_ticks": int(fields[19]),
                            "rss_bytes": values.get("VmRSS", 0),
                            "hwm_bytes": values.get("VmHWM", 0)})
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    return members


def run(output, command, timeout, interval=0.1):
    if sys.platform != "linux":
        raise RuntimeError("RSS collector must execute on Linux; no macOS unit conversion is inferred")
    if output.exists():
        raise RuntimeError("refusing to overwrite existing RSS record")
    started = time.monotonic()
    child = subprocess.Popen(command, start_new_session=True, stdin=subprocess.DEVNULL)
    record = {"schema": "zkcfa.zekra.linux-rss.v1", "method": "linux-wait4-ru_maxrss",
              "units": "bytes", "ru_maxrss_native_units": "KiB", "command": command,
              "pid": child.pid, "complete": False, "timed_out": False,
              "sample_interval_seconds": interval,
              "sampled_process_hwm_max_bytes": 0, "sampled_group_rss_peak_bytes": 0,
              "sample_count": 0, "processes": {}}
    save(output, record)
    stopped = None

    def stop(signum, _frame):
        nonlocal stopped
        stopped = signum

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while True:
        members = proc_sample(child.pid)
        record["sample_count"] += 1
        record["sampled_group_rss_peak_bytes"] = max(record["sampled_group_rss_peak_bytes"], sum(p["rss_bytes"] for p in members))
        for member in members:
            identity = str(member["pid"]) + ":" + str(member["start_ticks"])
            previous = record["processes"].get(identity, {})
            member["hwm_bytes"] = max(member["hwm_bytes"], previous.get("hwm_bytes", 0))
            record["processes"][identity] = member
            record["sampled_process_hwm_max_bytes"] = max(record["sampled_process_hwm_max_bytes"], member["hwm_bytes"])
        pid, status, usage = os.wait4(child.pid, os.WNOHANG)
        if pid:
            child.returncode = os.waitstatus_to_exitcode(status)
            record.update({"complete": True, "returncode": child.returncode,
                           "peak_rss_bytes": int(usage.ru_maxrss) * 1024,
                           "user_cpu_seconds": usage.ru_utime, "system_cpu_seconds": usage.ru_stime,
                           "wall_seconds": time.monotonic() - started,
                           "wait_status": status, "interrupted_signal": stopped})
            save(output, record)
            return child.returncode if child.returncode >= 0 else 128 - child.returncode
        if stopped or time.monotonic() - started >= timeout:
            record["timed_out"] = not bool(stopped)
            record["interrupted_signal"] = stopped
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        record["wall_seconds"] = time.monotonic() - started
        save(output, record)
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or args.timeout <= 0:
        parser.error("positive timeout and command required")
    return run(args.output, command, args.timeout)


if __name__ == "__main__":
    sys.exit(main())
