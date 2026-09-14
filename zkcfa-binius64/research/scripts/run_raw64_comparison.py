#!/usr/bin/env python3
"""Paired, serial measurements of signature-bound raw24 and raw64 proof bundles.

Each signed-root has APPLICATION/{complete,shadow}/protocol-result.json,
bundle/, and keys/public/authority.pem. No signing keys are read here.
Repeated runs measure offline cryptographic verification of the same statement;
they are not new device attestations or an online replay-protection test.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import platform
import re
import shlex
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'scripts/embench21'))
import process_control

PROOF_TIMEOUT_SECONDS = 1800


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def atomic_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def utc_now() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


def validate_report(report: dict, protocol: dict, run_dir: Path) -> None:
    if report.get('verified') is not True:
        raise ValueError('proof report is not verified')
    if report['profile'] != protocol['circuit']['profile']:
        raise ValueError('proof profile differs from signed circuit')
    if report['application'] != run_dir.parent.name or report['path_mode'] != run_dir.name:
        raise ValueError('proof application/path mode differs from requested case')
    for key in ('edge_cap', 'ep_cap'):
        if report['capacity'][key] != protocol['circuit'][key]:
            raise ValueError(f'proof {key} differs from signed circuit')


def run_one(binary: Path, run_dir: Path, log: Path) -> dict:
    protocol = json.loads((run_dir / "protocol-result.json").read_text())
    env = {key: value for key, value in os.environ.items() if not key.startswith("ZKCFA_")}
    env.update(
        ZKCFA_PROVIDER_BUNDLE=str(run_dir / "bundle"),
        ZKCFA_AUTHORITY_PUBLIC=str(run_dir / "keys/public/authority.pem"),
        ZKCFA_AUTHORITY_SHA256=protocol["authority_sha256"],
        ZKCFA_EXPECTED_CHALLENGE_ID=protocol["challenge"]["challenge_id"],
        ZKCFA_EXPECTED_NONCE=protocol["challenge"]["nonce"],
        ZKCFA_JSON="1",
    )
    command = [str(binary)]
    if platform.system() == "Darwin":
        command = ["/usr/bin/time", "-l", *command]
    start = time.perf_counter()
    timed_out = False
    interrupted = None
    cleanup = dict(complete=True, errors=[])
    sampled_rss_at_stop = None
    with log.open("x") as stream:
        result = subprocess.Popen(command, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                  start_new_session=True)
        try:
            result.wait(timeout=PROOF_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                sampled_rss_at_stop = sum(row['rss_bytes'] for row in process_control.process_table().values()
                    if row['pgid'] == result.pid and row['uid'] == os.getuid())
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
            cleanup = process_control.terminate_owned_group(result)
        except BaseException as error:
            interrupted = repr(error)
            cleanup = process_control.terminate_owned_group(result)
    elapsed = time.perf_counter() - start
    output = log.read_text()
    record = {
        "exit_code": result.returncode,
        "wall_ms": elapsed * 1000,
        "log": str(log),
        "signed_run": str(run_dir),
        "protocol_result_sha256": digest(run_dir / "protocol-result.json"),
        "log_sha256": digest(log),
        "timeout_seconds": PROOF_TIMEOUT_SECONDS,
        "termination_reason": "timeout" if timed_out else None,
        "cleanup": cleanup,
        "sampled_rss_at_stop_bytes": sampled_rss_at_stop,
    }
    if interrupted is not None:
        record.update(termination_reason='interrupted', controller_error=interrupted)
    rss = re.search(r"(\d+)\s+maximum resident set size", output)
    if rss:
        record["peak_rss_bytes"] = int(rss.group(1))
    try:
        reports = [json.loads(line) for line in output.splitlines() if line.startswith('{"schema":')]
        if timed_out or interrupted is not None or cleanup['complete'] is not True:
            raise ValueError('proof stopped: ' + str(record['termination_reason']) + '; cleanup_complete=' + str(cleanup['complete']))
        if result.returncode or len(reports) != 1:
            raise ValueError(f'process exit {result.returncode}; found {len(reports)} proof reports')
        report = reports[0]
        validate_report(report, protocol, run_dir)
    except (ValueError, KeyError, TypeError) as error:
        record['error'] = str(error)
        record["error_tail"] = output[-2500:]
        controller_log = log.with_suffix('.controller.json')
        with controller_log.open('x') as stream:
            stream.write(json.dumps(record, indent=2) + '\n')
        record['controller_log'] = str(controller_log)
        record['controller_log_sha256'] = digest(controller_log)
        return record
    record["proof"] = report
    return record


def summarize(records: list[dict], expected: dict[tuple[str, str], int] | None = None) -> list[dict]:
    groups: dict[tuple[str, str, str], list] = {}
    for row in records:
        groups.setdefault((row["application"], row["mode"], row["profile"]), []).append(row)
    summary = []
    for (application, mode, profile), runs in sorted(groups.items()):
        valid = [row for row in runs if row.get("proof", {}).get("verified")]
        row = dict(application=application, mode=mode, profile=profile,
                   successful_runs=len(valid), attempted_runs=len(runs))
        failures = [run for run in runs if not run.get('proof', {}).get('verified')]
        if failures:
            row['failed_attempt_diagnostics'] = [{key:run[key] for key in (
                'repetition','session','log','log_sha256','controller_log','controller_log_sha256',
                'exit_code','wall_ms','peak_rss_bytes','sampled_rss_at_stop_bytes','timeout_seconds',
                'termination_reason','controller_error','cleanup','error') if key in run} for run in failures]
        if expected is not None:
            row['expected_runs'] = expected[(application, mode)]
            row['status'] = ('pending' if len(runs) < row['expected_runs'] else
                             'complete' if len(valid) == len(runs) else 'complete_with_failures')
        if valid:
            first = valid[0]["proof"]
            for key in ("instance", "capacity", "constraints"):
                assert all(run["proof"][key] == first[key] for run in valid)
                row[key] = first[key]
            for phase in ("setup", "prove", "public_preflight", "verify"):
                values = [run["proof"]["phases_ms"][phase] for run in valid]
                row[f"{phase}_ms"] = dict(median=statistics.median(values), min=min(values), max=max(values))
            for field in ("proof_bytes", "wall_ms", "peak_rss_bytes"):
                values = [run["proof"][field] if field == "proof_bytes" else run[field]
                          for run in valid if field == "proof_bytes" or field in run]
                if values:
                    row[field] = dict(median=statistics.median(values), min=min(values), max=max(values))
        summary.append(row)
    return summary


def input_binding(run_dir: Path) -> dict:
    """Hash public and confidential proof inputs, but never read signing keys."""
    files = [run_dir / 'protocol-result.json', run_dir / 'keys/public/authority.pem']
    bundle = run_dir / 'bundle'
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError(f'not a regular bundle directory: {bundle}')
    for path in bundle.rglob('*'):
        if path.is_symlink():
            raise ValueError(f'symlinked proof input: {path}')
        if path.is_file():
            files.append(path)
    if len(files) <= 2:
        raise ValueError(f'empty bundle: {bundle}')
    return {str(path.relative_to(run_dir)): digest(path) for path in sorted(files)}


def record_key(row: dict) -> tuple[str, str, str, int]:
    return row['application'], row['mode'], row['profile'], row['repetition']


def load_records(output: Path, roots: dict[str, Path], expected: dict[tuple[str, str], int]) -> list[dict]:
    """Fail closed on duplicate, changed, truncated, or out-of-plan journal rows."""
    journal = output / 'runs.jsonl'
    if not journal.exists():
        return []
    raw = journal.read_text()
    if raw and not raw.endswith('\n'):
        raise ValueError('runs.jsonl has an incomplete final line; preserve and inspect it before resuming')
    rows, seen = [], set()
    for line_number, line in enumerate(raw.splitlines(), 1):
        row = json.loads(line)
        key = record_key(row)
        app, mode, profile, repetition = key
        if key in seen:
            raise ValueError(f'duplicate journal case at line {line_number}: {key}')
        seen.add(key)
        if profile not in roots or (app, mode) not in expected:
            raise ValueError(f'existing journal case is outside requested plan: {key}')
        if type(repetition) is not int or not 1 <= repetition <= expected[(app, mode)]:
            raise ValueError(f'target repeat count would discard an existing attempt: {key}')
        run_dir = roots[profile] / app / mode
        if row['signed_run'] != str(run_dir):
            raise ValueError(f'existing signed input path differs: {key}')
        protocol_path = run_dir / 'protocol-result.json'
        if row['protocol_result_sha256'] != digest(protocol_path):
            raise ValueError(f'existing signed protocol binding changed: {key}')
        log = Path(row['log'])
        if log.parent.resolve() != output or not log.is_file():
            raise ValueError(f'existing log is absent or outside output: {key}')
        if 'log_sha256' in row and row['log_sha256'] != digest(log):
            raise ValueError(f'existing log digest differs: {key}')
        if 'controller_log' in row:
            controller_log = Path(row['controller_log'])
            if controller_log.parent.resolve() != output or row['controller_log_sha256'] != digest(controller_log):
                raise ValueError(f'existing cleanup diagnostic differs: {key}')
        if 'proof' in row:
            validate_report(row['proof'], json.loads(protocol_path.read_text()), run_dir)
            reports = [json.loads(item) for item in log.read_text().splitlines()
                       if item.startswith('{"schema":')]
            if row.get('exit_code') != 0 or reports != [row['proof']]:
                raise ValueError(f'existing successful record differs from original log: {key}')
        rows.append(row)
    return rows


def check_pair_shapes(records: list[dict]) -> None:
    first = {}
    for row in records:
        if 'proof' not in row:
            continue
        case = row['application'], row['mode']
        instance = row['proof']['instance']
        if case in first and first[case] != instance:
            raise ValueError(f'unequal input shape: {case}')
        first[case] = instance


def unused_log(output: Path, label: str, session: int) -> Path:
    """Preserve a previous process's unjournaled/incomplete log verbatim."""
    original = output / f'{label}.log'
    if not original.exists():
        return original
    attempt = 1
    while True:
        candidate = output / f'{label}-session{session}-attempt{attempt}.log'
        if not candidate.exists():
            return candidate
        attempt += 1


def reject_live_legacy_writer(output: Path) -> None:
    """Older versions lack flock; reject their exact --output process too."""
    listing = subprocess.check_output(['ps', '-axo', 'pid=,command='], text=True)
    for line in listing.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2 or int(fields[0]) == os.getpid():
            continue
        try:
            arguments = shlex.split(fields[1])
        except ValueError:
            continue
        if not any(Path(value).name == Path(__file__).name for value in arguments):
            continue
        if '--output' in arguments:
            index = arguments.index('--output')
            if index + 1 < len(arguments) and Path(arguments[index + 1]).resolve() == output:
                raise ValueError(f'an existing measurement process still owns this output (PID {fields[0]})')


def execute(args: argparse.Namespace, output: Path) -> int:
    roots = {"raw24": args.raw24_root.resolve(), "raw64": args.raw64_root.resolve()}
    binaries = {"raw24": args.raw24_binary.resolve(), "raw64": args.raw64_binary.resolve()}
    applications = args.applications or sorted(path.name for path in roots["raw64"].iterdir()
                                              if path.is_dir() and (path / "complete/protocol-result.json").is_file())
    if not applications or len(set(applications)) != len(applications) or len(set(args.modes)) != len(args.modes):
        raise ValueError('applications and modes must be nonempty and contain no duplicates')
    cases = [(app, mode) for app in applications for mode in args.modes]
    expected, bindings, case_plan = {}, {}, []
    for app, mode in cases:
        configs = []
        for profile, root in roots.items():
            run_dir = root / app / mode
            protocol = json.loads((run_dir / 'protocol-result.json').read_text())
            wanted_profile = 'raw24-full-key' if profile == 'raw24' else 'raw64-typed-channels'
            if protocol['circuit']['profile'] != wanted_profile or protocol['circuit']['path_mode'] != mode:
                raise ValueError(f'mislabeled signed profile/mode: {app}/{mode}/{profile}')
            configs.append({key: protocol['circuit'][key]
                            for key in ('edge_cap', 'ep_cap', 'log_inv_rate', 'path_mode')})
            bindings[f'{app}/{mode}/{profile}'] = input_binding(run_dir)
        if configs[0] != configs[1]:
            raise ValueError(f'mismatched comparison parameters: {app}/{mode}')
        large = configs[0]['ep_cap'] >= args.large_ep_cap
        count = args.large_case_repeats if large else args.repeats
        expected[(app, mode)] = count
        case_plan.append(dict(application=app, mode=mode, **{k: v for k, v in configs[0].items() if k != 'path_mode'},
                              large_case=large, repeats_per_profile=count))
    current = {
        'schema': 'zkcfa.raw64.paired-measurement.v1',
        'platform': platform.platform(), 'architecture': platform.machine(),
        'logical_cpus': os.cpu_count(), 'repeats': args.repeats,
        'rayon_threads': os.environ.get('RAYON_NUM_THREADS'),
        'proof_timeout_seconds': PROOF_TIMEOUT_SECONDS,
        'process_controller_sha256': digest(Path(process_control.__file__)),
        'applications': applications, 'modes': args.modes,
        'binaries': {key: {'path': str(path), 'sha256': digest(path)} for key, path in binaries.items()},
        'roots': {key: str(path) for key, path in roots.items()},
        'order': 'serial paired profiles; profile order alternates per application/mode/repetition',
        'statement_reuse': 'Offline performance repetitions reuse each signed statement; one registry/device enrollment per bundle.',
        'timing_boundary': 'setup includes public circuit/key setup and private preflight; prove includes witness generation/local constraint check/proof; verify excludes signature preflight',
        'large_case_repeats': args.large_case_repeats, 'large_ep_cap': args.large_ep_cap,
        'case_plan': case_plan, 'expected_runs': 2 * sum(expected.values()),
        'input_bindings': bindings,
    }
    records = load_records(output, roots, expected) if args.resume else []
    if args.resume:
        metadata = json.loads((output / 'metadata.json').read_text())
        for key in ('schema', 'platform', 'architecture', 'logical_cpus', 'applications', 'modes', 'binaries', 'roots'):
            if metadata.get(key) != current[key]:
                raise ValueError(f'resume changes bound measurement configuration: {key}')
        for key in ('rayon_threads', 'proof_timeout_seconds'):
            if key in metadata and metadata[key] != current[key]:
                raise ValueError(f'resume changes bound measurement configuration: {key}')
        if 'input_bindings' in metadata and metadata['input_bindings'] != bindings:
            raise ValueError('resume changes a public/private proof input')
        # v1 journals bind each completed sample to protocol-result.json and its
        # signed commitments. First migration additionally freezes all file hashes.
        if 'input_bindings' not in metadata:
            metadata['legacy_input_binding_migration'] = (
                'Prior rows checked against recorded protocol SHA-256 and original proof logs; '
                'all public/private file hashes first frozen at this resume.')
        if not (output / 'metadata-before-first-resume.json').exists():
            atomic_json(output / 'metadata-before-first-resume.json', metadata)
        previous_plan = {key: metadata.get(key) for key in ('repeats', 'large_case_repeats', 'large_ep_cap', 'case_plan')}
        metadata.update(current)
    else:
        metadata = dict(current, started_utc=utc_now())
        previous_plan = None
    check_pair_shapes(records)
    sessions = metadata.setdefault('sessions', [])
    session = len(sessions) + 1
    runner_copy = output / f'measurement-runner-session{session}.py'
    with runner_copy.open('xb') as stream:
        stream.write(Path(__file__).read_bytes())
    controller_copy = output / f'process-controller-session{session}.py'
    with controller_copy.open('xb') as stream:
        stream.write(Path(process_control.__file__).read_bytes())
    sessions.append({'session': session, 'started_utc': utc_now(), 'resume': args.resume,
                     'runner_sha256': digest(runner_copy), 'runner_source': str(runner_copy),
                     'process_controller_sha256': digest(controller_copy), 'process_controller_source': str(controller_copy),
                     'previous_plan': previous_plan, 'expected_runs': current['expected_runs'],
                     'reused_attempts': len(records)})
    metadata.pop('completed_utc', None)
    metadata['pid'] = os.getpid()

    def persist(status: str, reason: str | None = None) -> None:
        metadata.update(status=status, attempted_runs=len(records),
                        successful_runs=sum('proof' in row for row in records))
        if reason is not None:
            metadata['pause_reason'] = reason
        else:
            metadata.pop('pause_reason', None)
        if status.startswith('complete'):
            metadata['completed_utc'] = utc_now()
        if status != 'running':
            sessions[-1]['ended_utc'] = utc_now()
            sessions[-1]['status'] = status
        atomic_json(output / 'summary.json', summarize(records, expected))
        atomic_json(output / 'metadata.json', metadata)

    def requested_stop(name: str) -> bool:
        if (output / name).exists():
            persist('paused', name)
            print(f'paused at safe boundary: {name}', flush=True)
            return True
        return False

    persist('running')
    if requested_stop('STOP_AFTER_CASE'):
        return 0
    seen = {record_key(row) for row in records}
    pending = len(seen) < current['expected_runs']
    if pending:
        warm_case = next(((app, mode) for app, mode in cases if app == 'crc32' and mode == 'shadow'),
                         min(cases, key=lambda case: next(item['ep_cap'] for item in case_plan
                                                        if (item['application'], item['mode']) == case)))
        # Every newly started process warms both profiles; never append to the journal.
        for profile in roots:
            warm_log = unused_log(output, f'warmup-{profile}', session)
            warm = run_one(binaries[profile], roots[profile] / warm_case[0] / warm_case[1], warm_log)
            sessions[-1].setdefault('warmups', []).append(warm)
            if 'proof' not in warm:
                persist('paused', f'{profile} warmup failed')
                return 1
    for repetition in range(max(expected.values())):
        for index, (application, mode) in enumerate(cases):
            if repetition >= expected[(application, mode)]:
                continue
            if requested_stop('STOP_AFTER_CASE'):
                return 0
            order = ['raw24', 'raw64'] if (index + repetition) % 2 == 0 else ['raw64', 'raw24']
            for profile in order:
                key = application, mode, profile, repetition + 1
                if key in seen:
                    continue
                label = f'{application}-{mode}-{profile}-r{repetition + 1}'
                log = unused_log(output, label, session)
                record = run_one(binaries[profile], roots[profile] / application / mode, log)
                record.update(application=application, mode=mode, profile=profile, repetition=repetition + 1,
                              runner_sha256=sessions[-1]['runner_sha256'], session=session)
                with (output / 'runs.jsonl').open('a') as stream:
                    stream.write(json.dumps(record) + '\n')
                    stream.flush()
                    os.fsync(stream.fileno())
                records.append(record)
                seen.add(key)
                check_pair_shapes(records)
                persist('running')
                print(f"{label}: {'verified' if 'proof' in record else 'FAILED'} ({record['wall_ms'] / 1000:.2f}s)", flush=True)
                if record.get('cleanup', {}).get('complete') is False or record.get('termination_reason') == 'interrupted':
                    persist('paused', 'cleanup unconfirmed or interrupted; attempt preserved before stopping')
                    return 1
            if requested_stop('STOP_AFTER_CASE'):
                return 0
        if requested_stop('STOP_AFTER_ROUND'):
            return 0
    if len(records) != current['expected_runs']:
        raise ValueError('completed schedule differs from expected attempt count')
    failed = any('proof' not in row for row in records)
    persist('complete_with_failures' if failed else 'complete')
    return int(failed)


def main() -> int:
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt('measurement interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw24-root", type=Path, required=True)
    parser.add_argument("--raw64-root", type=Path, required=True)
    parser.add_argument("--raw24-binary", type=Path, required=True)
    parser.add_argument("--raw64-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--large-case-repeats', type=int,
                        help='Repetitions for large cases (default: same as --repeats)')
    parser.add_argument('--large-ep-cap', type=int, default=65536,
                        help='EP capacity at or above which the case is large (default: 65536)')
    parser.add_argument("--applications", nargs="+")
    parser.add_argument("--modes", nargs="+", default=["complete", "shadow"], choices=["complete", "shadow"])
    args = parser.parse_args()
    if args.large_case_repeats is None:
        args.large_case_repeats = args.repeats
    if args.repeats < 1 or args.large_case_repeats < 1 or args.large_ep_cap < 1:
        parser.error('repeat counts and --large-ep-cap must be positive')
    output = args.output.resolve()
    if args.resume:
        if not (output / 'metadata.json').is_file():
            parser.error('--resume requires an existing measurement metadata.json')
        reject_live_legacy_writer(output)
    else:
        output.mkdir(parents=True, exist_ok=False)
    with (output / '.measurement.lock').open('a+') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.error('another measurement process owns this output')
        return execute(args, output)


if __name__ == "__main__":
    raise SystemExit(main())
