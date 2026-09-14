#!/usr/bin/env python3
"""Reissue fresh Binius statements to maintained PLONK; resource-bounded serialized runs.

prepare: authenticate/reissue all lanes, then full relation preflights where affordable.
prove: resume those exact preflighted statements, smallest observed domain first.
No historical performance measurement is copied into results. Capacity estimates are guards only.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import math
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts/embench21"))
import process_control

APPLICATIONS = ('aha-mont64','crc32','cubic','edn','huffbench','matmult-int','md5sum',
    'minver','nbody','nettle-aes','nettle-sha256','nsichneu','picojpeg','primecount',
    'sglib-combined','slre','st','statemate','tarfind','ud','wikisort')
FIELDS = ('application','path_mode','source_rows','proof_rows','edges','edge_cap','ep_cap',
    'encoding','estimated_gates_guard','estimated_domain_guard','reissue_outcome',
    'artifacts_byte_identical','reissue_ms','preflight_outcome','plonk_gates','padded_domain',
    'public_preflight_ms','preflight_wall_ms','preflight_peak_rss_bytes','proof_outcome',
    'setup_ms','prove_ms','verify_ms','proof_bytes','proof_wall_ms','proof_peak_rss_bytes',
    'proof_public_preflight_ms','proof_peak_memory_footprint_bytes',
    'backend_binding_checked','verified','failure_note','proof_returncode','proof_stop_reason',
    'proof_cleanup_complete','proof_cleanup_errors','proof_controller_log','prepared_run_directory',
    'source_attempt_results_sha256','source_attempt_row_sha256','source_attempt_outcome','prepared_statement_reused')
RSS = re.compile(r'^\s*(\d+)\s+maximum resident set size\s*$', re.MULTILINE)
FOOTPRINT = re.compile(r'^\s*(\d+)\s+peak memory footprint\s*$', re.MULTILINE)
SENSITIVE_HEX = re.compile(r'(?<![0-9a-f])[0-9a-f]{32,128}(?![0-9a-f])')

def redact(text):
    return SENSITIVE_HEX.sub('<redacted-hex>', text)

def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()

def load(path):
    return json.loads(Path(path).read_text())

def save_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    os.replace(temporary, path)

def save_rows(path, rows):
    temporary = path.with_suffix('.csv.tmp')
    with temporary.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)

def event(row, status):
    print(json.dumps({'application':row['application'], 'path_mode':row['path_mode'],
        'status':status, 'padded_domain':row.get('padded_domain','')}, sort_keys=True), flush=True)

def sample_group_rss(group):
    output = subprocess.check_output(['/bin/ps','-axo','pid=,pgid=,rss='],
        stderr=subprocess.PIPE, text=True)
    total = 0
    for line in output.splitlines():
        pid, pgid, rss = map(int, line.split())
        if pgid == group:
            total += rss * 1024
    return total

def terminate_group(process):
    return process_control.terminate_owned_group(process)

def timed(command, *, env, cwd, timeout, rss_limit, log_stem, sensitive=False):
    """Preserve stop/RSS/wall evidence even when cleanup cannot be confirmed."""
    started = time.perf_counter()
    stdout_path = Path(str(log_stem)+'.stdout.log')
    stderr_path = Path(str(log_stem)+'.stderr.log')
    peak = 0
    stop = ''
    process = None
    control_error = ''
    cleanup = dict(complete=True, errors=[])
    with stdout_path.open('w+') as out, stderr_path.open('w+') as err:
        try:
            process = subprocess.Popen(['/usr/bin/time','-l',*command], cwd=cwd, env=env,
                stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
            while process.poll() is None:
                elapsed = time.perf_counter() - started
                try:
                    peak = max(peak, sample_group_rss(process.pid))
                except (OSError, subprocess.CalledProcessError, ValueError):
                    stop = 'resource-monitor-unavailable'
                if elapsed > timeout:
                    stop = 'timeout'
                if peak > rss_limit:
                    stop = 'resource-terminated-rss'
                if stop:
                    break
                time.sleep(0.5)
        except KeyboardInterrupt:
            stop = 'interrupted'
        except Exception as error:
            stop = stop or ('launch-failed' if process is None else 'controller-error')
            control_error = redact(repr(error))
        finally:
            if process is not None:
                try:
                    cleanup = terminate_group(process)
                except BaseException as error:
                    cleanup = dict(complete=False, errors=[dict(operation='cleanup', error=redact(repr(error)))])
        out.seek(0); stdout = out.read()
        err.seek(0); stderr = err.read()
    match = RSS.search(stderr)
    if match:
        peak = max(peak, int(match.group(1)))
    footprint = FOOTPRINT.search(stderr)
    # Issuance stdout contains target nonce; retain it only in the private protocol result file.
    if sensitive and cleanup['complete']:
        stdout_path.write_text('[issuance result retained only in private protocol-result.json]\n')
    if cleanup['complete']:
        stderr_path.write_text(redact(stderr))
    result = {'returncode': process.returncode if process is not None else None,
        'wall_ms':round((time.perf_counter()-started)*1000,3),
        'peak_rss_bytes':peak,
        'peak_memory_footprint_bytes':int(footprint.group(1)) if footprint else '',
        'stop':stop, 'stdout':stdout, 'stderr':redact(stderr), 'control_error':control_error,
        'cleanup_complete':cleanup['complete'], 'cleanup':cleanup}
    sidecar = Path(str(log_stem)+'.controller.json')
    save_json(sidecar, {key:value for key,value in result.items() if key not in ('stdout','stderr')})
    result['controller_log'] = str(sidecar)
    return result

def report_json(stdout, schema):
    values = []
    for line in stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get('schema') == schema:
            values.append(value)
    if len(values) != 1:
        raise ValueError('missing or ambiguous '+schema+' report')
    if values[0].get('backend') != 'plonk':
        raise ValueError('unexpected proof backend')
    return values[0]

def process_status(result):
    return result['stop'] or ('cleanup-unconfirmed' if result.get('cleanup_complete') is False else
        '' if result['returncode'] == 0 else 'failed-'+str(result['returncode']))

def failure_note(result):
    lines = [x for x in result['stderr'].splitlines() if 'rror' in x or 'killed' in x.lower()]
    return (' '.join(lines) + ' ' + result.get('control_error','')).strip()[:400] or result['stop']

def row_sha256(row):
    return hashlib.sha256(json.dumps(row,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def retry_rows(source, selected, modes, identity, resource_limits=None):
    """Reuse authenticated prepared statements; never mutate the source attempt."""
    metadata = load(source.with_name('metadata.json'))
    if metadata['results_sha256'] != sha256(source):
        raise ValueError('retry source CSV differs from its completed metadata')
    for key, value in (resource_limits or {}).items():
        if metadata.get(key) != value:
            raise ValueError('retry must retain the original resource configuration: '+key)
    source_identity = load(source.with_name('run-identity.json'))
    if metadata['run_identity'] != source_identity:
        raise ValueError('retry source identity differs from completed metadata')
    for key in ('binary_sha256','source_manifest_sha256','threads','build_metadata_sha256'):
        if source_identity.get(key) != identity.get(key):
            raise ValueError('retry source uses a different '+key)
    with source.open() as stream:
        original = list(csv.DictReader(stream))
    wanted = {(app, mode) for app in selected for mode in modes}
    rows, audit = [], []
    for previous in original:
        key = previous['application'], previous['path_mode']
        if key not in wanted:
            continue
        if previous['proof_outcome'] in ('verified','not-attempted') or previous.get('verified') == 'true':
            raise ValueError('retry is restricted to completed failed attempts: '+repr(key))
        if previous['preflight_outcome'] != 'satisfied':
            raise ValueError('retry requires an authenticated satisfied preflight: '+repr(key))
        row = {field:previous.get(field,'') for field in FIELDS}
        for field in ('setup_ms','prove_ms','verify_ms','proof_bytes','proof_wall_ms','proof_peak_rss_bytes',
                'proof_public_preflight_ms','proof_peak_memory_footprint_bytes','verified','failure_note',
                'proof_returncode','proof_stop_reason','proof_cleanup_complete','proof_cleanup_errors','proof_controller_log',
                'reissue_ms','public_preflight_ms','preflight_wall_ms','preflight_peak_rss_bytes'):
            row[field] = ''
        row.update(proof_outcome='not-attempted', source_attempt_results_sha256=sha256(source),
            source_attempt_row_sha256=row_sha256(previous), source_attempt_outcome=previous['proof_outcome'],
            prepared_statement_reused='true',
            prepared_run_directory=previous.get('prepared_run_directory') or
                str(source.parent/'reissued'/key[0]/key[1]))
        rows.append(row)
        audit.append(dict(application=key[0],path_mode=key[1],row_sha256=row_sha256(previous),row=previous))
    if len(rows) != len(wanted) or {(r['application'],r['path_mode']) for r in rows} != wanted:
        raise ValueError('retry source must contain each selected lane exactly once')
    link = dict(results_path=str(source),results_sha256=sha256(source),
        metadata_sha256=sha256(source.with_name('metadata.json')), original_attempts=audit,
        reuse_scope='proof-only retry of the same authenticated prepared statement; reissuance and preflight timing fields remain empty')
    return rows, link

def proof_env(base, result):
    return dict(base, ZKCFA_PROVIDER_BUNDLE=str(result['bundle']),
        ZKCFA_AUTHORITY_PUBLIC=str(result['authority_public']),
        ZKCFA_AUTHORITY_SHA256=str(result['authority_sha256']),
        ZKCFA_EXPECTED_CHALLENGE_ID=str(result['challenge_id']),
        ZKCFA_EXPECTED_NONCE=str(result['nonce']), ZKCFA_JSON='1')

def check_reissuance(source_run, destination, target, row):
    """Audit backend and paired-input identity; Rust still authenticates signatures."""
    if target.get('schema') != 'zkcfa.plonk.reissuance.run':
        raise ValueError('unexpected reissuance result schema')
    if (target.get('provenance', {}).get('kind') != 'authenticated-reissuance'
            or target['provenance'].get('source_backend') != 'binius64'):
        raise ValueError('missing authenticated Binius64 source provenance')
    if Path(target['bundle']).resolve() != (destination/'bundle').resolve():
        raise ValueError('reissuance result names a different bundle')
    if Path(target['authority_public']).resolve() != (destination/'keys/public/authority.pem').resolve():
        raise ValueError('reissuance result names a different authority')
    if sha256(target['authority_public']) != target['authority_sha256']:
        raise ValueError('target authority pin mismatch')
    source_registry = load(source_run/'bundle/public/registry.json')['payload']
    target_registry = load(destination/'bundle/public/registry.json')['payload']
    source_report = load(source_run/'bundle/public/report.json')['payload']
    target_report = load(destination/'bundle/public/report.json')['payload']
    if source_registry['circuit']['backend'] != 'binius64' or target_registry['circuit']['backend'] != 'plonk':
        raise ValueError('source/target backend identity mismatch')
    for key in ('edge_cap', 'ep_cap', 'path_mode'):
        if target_registry['circuit'][key] != source_registry['circuit'][key]:
            raise ValueError('reissuance changed source capacity or path mode')
    for key in ('entry_raw', 'final_raw', 'binary_measurement', 'scope_policy_digest'):
        if source_report[key] != target_report[key]:
            raise ValueError('reissuance changed source endpoint, code or scope')
    for key in ('challenge_id', 'nonce'):
        if target_report[key] != target[key] or source_report[key] == target[key]:
            raise ValueError('target challenge was not independently replaced')
    if not all(sha256(source_run/'bundle/private'/name) ==
            sha256(destination/'bundle/private'/name)
            for name in ('translator', 'typed_cfg', 'recorded_path')):
        raise ValueError('reissued raw artifacts differ from source')
    if target_registry['circuit']['path_mode'] != row['path_mode']:
        raise ValueError('reissued path mode differs from selected lane')
    return target_report

def check_report(report, row, target, *, proof):
    if report.get('backend') != 'plonk' or report.get('profile') != 'raw24-full-key':
        raise ValueError('unexpected proof backend or profile')
    if report.get('application') != row['application'] or report.get('path_mode') != row['path_mode']:
        raise ValueError('report lane identity mismatch')
    for key in ('edge_cap', 'ep_cap'):
        if int(report['capacity'][key]) != int(row[key]):
            raise ValueError('report capacity differs from signed source')
    if proof:
        if report.get('verified') is not True:
            raise ValueError('proof was not verified')
        if (int(report['constraints']['plonk_gates']) != int(row['plonk_gates'])
                or int(report['constraints']['padded_domain']) != int(row['padded_domain'])
                or int(report['instance']['steps']) != int(row['proof_rows'])
                or report['capacity']['ep_encoding'] != row['encoding']):
            raise ValueError('proof shape differs from preflight')
        public = report['public_inputs']
        if public['H_ep'] != target['h_ep_raw24'] or public['H_cfg'] != target['h_cfg_raw24']:
            raise ValueError('proof commitments differ from authenticated target')
        signed = load(Path(target['bundle'])/'public/report.json')['payload']
        if int(public['entry'], 16) != signed['entry_raw'] or int(public['final_node'], 16) != signed['final_raw']:
            raise ValueError('proof endpoints differ from authenticated target')
    elif report.get('satisfied') is not True:
        raise ValueError('preflight was not satisfied')

def guard_estimate(edge_cap, ep_cap):
    # Deliberately conservative compared with retained ~155/EP + ~400/CFG measurements.
    # This is a scheduling heuristic, never an observed constraint/domain result.
    gates = 256 * ep_cap + 1024 * edge_cap + 100000
    return gates, 1 << (gates-1).bit_length()

def main():
    os.umask(0o077)
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt('campaign interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--campaign', type=Path, required=True)
    p.add_argument('--reissue-binary', type=Path, required=True)
    p.add_argument('--prove-binary', type=Path, required=True)
    p.add_argument('--phase', choices=('prepare','prove','all'), default='all')
    p.add_argument('--output-name', default='plonk-results')
    p.add_argument('--threads', type=int, default=8)
    p.add_argument('--max-proof-domain', type=int, default=1<<22)
    p.add_argument('--max-preflight-estimated-domain', type=int, default=1<<24)
    p.add_argument('--max-rss-gib', type=float, default=20)
    p.add_argument('--proof-timeout-s', type=float, default=1800)
    p.add_argument('--preflight-timeout-s', type=float, default=900)
    p.add_argument('--reissue-timeout-s', type=float, default=300)
    p.add_argument('--applications', default='')
    p.add_argument('--modes', default='shadow', help='comma-separated complete,shadow; paper backend comparison uses shadow')
    p.add_argument('--build-metadata', type=Path, help='optional caller-supplied JSON describing how these exact binaries were built')
    p.add_argument('--retry-from', type=Path, help='completed failed-attempt CSV; reuse its prepared statements in a new output directory')
    a = p.parse_args()
    campaign = a.campaign.resolve()
    if platform.system() != 'Darwin':
        raise ValueError('this runner requires macOS /usr/bin/time -l and ps')
    if not campaign.is_dir():
        raise ValueError('campaign directory does not exist')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', a.output_name):
        raise ValueError('output-name must be one plain directory name')
    limits = (a.threads, a.max_proof_domain, a.max_preflight_estimated_domain,
        a.max_rss_gib, a.proof_timeout_s, a.preflight_timeout_s, a.reissue_timeout_s)
    if any(not math.isfinite(x) or x <= 0 for x in limits):
        raise ValueError('threads and all resource limits must be finite and positive')
    output = campaign / a.output_name
    if output.is_symlink():
        raise ValueError('output cannot be a symlink')
    selected = tuple(filter(None,a.applications.split(','))) or APPLICATIONS
    modes = tuple(filter(None,a.modes.split(',')))
    if (not modes or len(set(selected)) != len(selected) or len(set(modes)) != len(modes)
            or any(x not in APPLICATIONS for x in selected)
            or any(x not in ('complete','shadow') for x in modes)):
        raise ValueError('unknown application or mode')
    if a.retry_from and not a.applications:
        raise ValueError('retry requires explicit --applications; successful attempts cannot be retried')
    # Resource monitoring must work before any large child begins. Run outside sandbox if necessary.
    sample_group_rss(os.getpgrp())
    base = {k:v for k,v in os.environ.items() if not k.startswith('ZKCFA_')}
    base['RAYON_NUM_THREADS'] = str(a.threads)
    binaries = {k:Path(v).resolve() for k,v in {'reissue':a.reissue_binary,'prove':a.prove_binary}.items()}
    for binary in binaries.values():
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError('binary is missing or not executable: '+str(binary))
    identity = {'binary_sha256':{key:sha256(path) for key,path in binaries.items()},
        'source_manifest_sha256':sha256(campaign/'signed/bundles.json'), 'threads':a.threads,
        'runner_sha256':sha256(Path(__file__)), 'process_controller_sha256':sha256(Path(process_control.__file__))}
    build_metadata = load(a.build_metadata) if a.build_metadata else None
    if build_metadata is not None:
        if not isinstance(build_metadata, dict):
            raise ValueError('build metadata must be a JSON object')
        if build_metadata.get('schema') == 'zkcfa.v13.native-build.v1':
            for role, key in (('reissue', 'zkcfa-reissue'), ('prove', 'zkcfa-plonk')):
                declared = build_metadata['binaries'][key]
                if (declared['sha256'] != identity['binary_sha256'][role]
                        or Path(declared['path']).resolve() != binaries[role]):
                    raise ValueError('build metadata does not identify supplied '+role+' binary')
        identity['build_metadata_sha256'] = sha256(a.build_metadata)
    prepared_retry, retry_link = None, None
    if a.retry_from:
        source = a.retry_from.resolve()
        if source.parent == output.resolve():
            raise ValueError('retry output must differ from the original attempt directory')
        prepared_retry, retry_link = retry_rows(source, selected, modes, identity, dict(
            max_rss_bytes=int(a.max_rss_gib*(1<<30)), proof_timeout_s=a.proof_timeout_s,
            max_proof_domain=a.max_proof_domain))
        identity['retry_source_results_sha256'] = retry_link['results_sha256']
        identity['retry_source_metadata_sha256'] = retry_link['metadata_sha256']
    rss_limit = int(a.max_rss_gib*(1<<30))
    if a.phase in ('prepare','all'):
        if output.exists():
            raise FileExistsError('prepare output already exists; use --phase prove to resume proofs')
        output.mkdir(mode=0o700)
        (output/'logs').mkdir(mode=0o700)
        (output/'reissued').mkdir(mode=0o700)
        save_json(output/'run-identity.json', identity)
        if retry_link:
            save_json(output/'retry-source.json', retry_link)
        suite = load(campaign/'signed/bundles.json')
        indexed = {r['application']:r for r in suite['applications']}
        if tuple(indexed) != APPLICATIONS:
            raise ValueError('signed suite must contain the ordered 21 applications')
        rows = prepared_retry if prepared_retry is not None else []
        for mode in (() if a.retry_from else modes):
            for app in sorted(selected, key=lambda x:(int(indexed[x][mode]['ep_cap']),x)):
                item = indexed[app]
                summary = item[mode]
                row = dict.fromkeys(FIELDS, '')
                row.update(application=app,path_mode=mode,source_rows=item['projection']['full_rows'],
                    edge_cap=summary['edge_cap'],ep_cap=summary['ep_cap'],proof_outcome='not-attempted')
                estimates = guard_estimate(int(row['edge_cap']),int(row['ep_cap']))
                row['estimated_gates_guard'],row['estimated_domain_guard'] = estimates
                source_run = campaign/'signed'/app/mode
                destination = output/'reissued'/app/mode
                destination.parent.mkdir(exist_ok=True,mode=0o700)
                stem = output/'logs'/f'{mode}-{app}'
                halt_after_lane = False
                try:
                    source = load(source_run/'protocol-result.json')
                    challenge = source['challenge']
                    event(row,'reissue-start')
                    command = [str(binaries['reissue']), '--source-bundle',str(source_run/'bundle'),
                        '--source-authority-public',str(source_run/'keys/public/authority.pem'),
                        '--source-authority-sha256',str(source['authority_sha256']),
                        '--source-challenge-id',str(challenge['challenge_id']),
                        '--source-nonce',str(challenge['nonce']),
                        '--source-enrollment',str(source_run/'staging-private/enrollment.json'),
                        '--target-challenge-id',secrets.token_hex(16),'--target-nonce',secrets.token_hex(32),
                        '--run-dir',str(destination)]
                    result = timed(command,env=base,cwd=output,timeout=a.reissue_timeout_s,rss_limit=rss_limit,
                        log_stem=Path(str(stem)+'.reissue'),sensitive=True)
                    halt_after_lane = not result['cleanup_complete']
                    row['reissue_ms'] = result['wall_ms']
                    row['reissue_outcome'] = process_status(result) or 'reissued'
                    if row['reissue_outcome'] != 'reissued':
                        row['preflight_outcome'] = 'reissue-failed'
                        row['failure_note'] = failure_note(result)
                    else:
                        (destination/'protocol-result.json').chmod(0o600)
                        target = load(destination/'protocol-result.json')
                        check_reissuance(source_run, destination, target, row)
                        row['artifacts_byte_identical'] = 'true'
                        row['backend_binding_checked'] = 'true'
                        if estimates[1] > a.max_preflight_estimated_domain:
                            row['preflight_outcome'] = 'resource-skipped-estimated-domain'
                            row['proof_outcome'] = 'resource-skipped-no-preflight'
                        else:
                            event(row,'preflight-start')
                            result = timed([str(binaries['prove']),'--preflight'],env=proof_env(base,target),
                                cwd=output,timeout=a.preflight_timeout_s,rss_limit=rss_limit,
                                log_stem=Path(str(stem)+'.preflight'))
                            halt_after_lane = not result['cleanup_complete']
                            row['preflight_wall_ms'] = result['wall_ms']
                            row['preflight_peak_rss_bytes'] = result['peak_rss_bytes']
                            status = process_status(result)
                            if status:
                                row['preflight_outcome'] = status
                                row['failure_note'] = failure_note(result)
                            else:
                                report = report_json(result['stdout'],'zkcfa.raw.preflight')
                                check_report(report, row, target, proof=False)
                                row.update(preflight_outcome='satisfied' if report['satisfied'] is True else 'unsatisfied',
                                    proof_rows=report['instance']['steps'],edges=report['instance']['edges'],
                                    encoding=report['capacity']['ep_encoding'],
                                    plonk_gates=report['constraints']['plonk_gates'],
                                    padded_domain=report['constraints']['padded_domain'],
                                    public_preflight_ms=report['public_preflight_ms'])
                except (OSError,ValueError,KeyError,RuntimeError) as error:
                    row['preflight_outcome'] = 'orchestration-failed'
                    row['failure_note'] = redact(str(error))[:400]
                rows.append(row)
                save_rows(output/'results.csv',rows)
                event(row,row['preflight_outcome'])
                if halt_after_lane:
                    raise RuntimeError('cleanup unconfirmed; saved attempt and stopped before the next benchmark')
                if 'interrupted' in (row['reissue_outcome'], row['preflight_outcome']):
                    raise KeyboardInterrupt('interrupted attempt recorded')
        save_rows(output/'results.csv', rows)
    else:
        if load(output/'run-identity.json') != identity:
            raise ValueError('resume requires identical binaries, source manifest and thread count')
        with (output/'results.csv').open() as stream:
            rows = list(csv.DictReader(stream))

    if a.phase in ('prove','all'):
        for row in sorted(rows,key=lambda r:(int(r['padded_domain'] or 1<<60),r['application'],r['path_mode'])):
            app,mode = row['application'],row['path_mode']
            if app not in selected or mode not in modes or row['preflight_outcome'] != 'satisfied':
                continue
            if row['proof_outcome'] not in ('not-attempted','resource-skipped-domain'):
                continue
            if int(row['padded_domain']) > a.max_proof_domain:
                row['proof_outcome'] = 'resource-skipped-domain'
                save_rows(output/'results.csv',rows)
                continue
            halt_after_lane = False
            try:
                prepared_run = Path(row['prepared_run_directory']) if row.get('prepared_run_directory') else output/'reissued'/app/mode
                target = load(prepared_run/'protocol-result.json')
                check_reissuance(campaign/'signed'/app/mode, prepared_run, target, row)
                event(row,'prove-start')
                result = timed([str(binaries['prove'])],env=proof_env(base,target),cwd=output,
                    timeout=a.proof_timeout_s,rss_limit=rss_limit,
                    log_stem=output/'logs'/f'{mode}-{app}.prove')
                halt_after_lane = not result['cleanup_complete']
                row['proof_wall_ms'] = result['wall_ms']
                row['proof_peak_rss_bytes'] = result['peak_rss_bytes']
                row['proof_peak_memory_footprint_bytes'] = result['peak_memory_footprint_bytes']
                row.update(proof_returncode=result['returncode'],proof_stop_reason=result['stop'],
                    proof_cleanup_complete=str(result['cleanup_complete']).lower(),
                    proof_cleanup_errors=json.dumps(result['cleanup']['errors'],separators=(',',':')),
                    proof_controller_log=result['controller_log'])
                row['proof_outcome'] = process_status(result)
                if row['proof_outcome']:
                    row['failure_note'] = failure_note(result)
                else:
                    report = report_json(result['stdout'],'zkcfa.raw.proof')
                    check_report(report, row, target, proof=True)
                    phases = report['phases_ms']
                    row.update(proof_outcome='verified' if report['verified'] is True else 'unverified',
                        setup_ms=phases['setup'],prove_ms=phases['prove'],verify_ms=phases['verify'],
                        proof_public_preflight_ms=phases['public_preflight'],
                        proof_bytes=report['proof_bytes'],verified=str(report['verified']).lower())
            except (OSError,ValueError,KeyError,RuntimeError) as error:
                row['proof_outcome'] = 'orchestration-failed'
                row['failure_note'] = redact(str(error))[:400]
            save_rows(output/'results.csv',rows)
            event(row,row['proof_outcome'])
            if halt_after_lane:
                raise RuntimeError('cleanup unconfirmed; saved attempt and stopped before the next benchmark')
            if row['proof_outcome'] == 'interrupted':
                raise KeyboardInterrupt('interrupted attempt recorded')

    metadata = {'schema':'zkcfa.embench21-maintained-plonk-campaign.v1','backend':'plonk',
        'phase':a.phase,'applications':len(selected),'modes':modes,'runs':len(rows),'threads':a.threads,
        'max_proof_domain':a.max_proof_domain,'max_preflight_estimated_domain':a.max_preflight_estimated_domain,
        'max_rss_bytes':rss_limit,'proof_timeout_s':a.proof_timeout_s,
        'preflight_timeout_s':a.preflight_timeout_s,'resource_monitor':'process-group RSS via ps; 0.5s polling',
        'estimated_domain_role':'conservative scheduling heuristic; never reported as measured circuit size',
        'reissue_binary_sha256':sha256(binaries['reissue']),'prove_binary_sha256':sha256(binaries['prove']),
        'results_sha256':sha256(output/'results.csv'),'platform':platform.platform(),
        'python':platform.python_version(),'time_command':'/usr/bin/time -l',
        'runner_sha256':sha256(Path(__file__)), 'run_identity':identity,
        'process_controller_sha256':sha256(Path(process_control.__file__)), 'retry_source':retry_link,
        'build_metadata':build_metadata,
        'verified_count':sum(r['verified']=='true' for r in rows),
        'preflight_satisfied_count':sum(r['preflight_outcome']=='satisfied' for r in rows)}
    save_json(output/'metadata.json',metadata)
    print(json.dumps(metadata,sort_keys=True),flush=True)
    return 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'runner-failed','error':redact(str(error))[:400]}),flush=True)
        raise SystemExit(1)
