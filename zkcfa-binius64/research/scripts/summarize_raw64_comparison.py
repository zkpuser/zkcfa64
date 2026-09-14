#!/usr/bin/env python3
"""Publish raw64 measurements with explicit plan, failure, and pair coverage."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import statistics
from pathlib import Path

PROFILES = ('raw24', 'raw64')
PHASES = ('setup', 'prove', 'public_preflight', 'verify')
METRICS = (*(f'{phase}_ms' for phase in PHASES), 'proof_bytes', 'wall_ms', 'process_wall_ms',
           'peak_rss_bytes', 'peak_memory_footprint_bytes')
# Identifies the measured sample with a paused parent; elapsed-time differences
# alone must not attribute unrelated samples to that cause.
PARENT_PAUSED_LOG_SHA256 = '9759e204f49ba58919b6b6f11bbe8de2076b59a393d72a35f4ba0e607002ae5f'
FAILURE_DIAGNOSTIC_FIELDS = (
    'repetition', 'session', 'log', 'log_sha256', 'controller_log', 'controller_log_sha256',
    'exit_code', 'wall_ms', 'peak_rss_bytes', 'sampled_rss_at_stop_bytes', 'timeout_seconds',
    'termination_reason', 'controller_error', 'cleanup', 'error')
JOURNAL_ONLY_FIELDS = {
    'application', 'mode', 'profile', 'repetition', 'runner_sha256', 'session',
    'controller_log', 'controller_log_sha256'}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def planned_repeats(metadata: dict) -> dict[tuple[str, str], int]:
    cases = {(app, mode) for app in metadata['applications'] for mode in metadata['modes']}
    if 'case_plan' in metadata:
        plan = {}
        for row in metadata['case_plan']:
            key = row['application'], row['mode']
            if key in plan or key not in cases:
                raise ValueError(f'duplicate or unexpected planned case: {key}')
            count = row['repeats_per_profile']
            if type(count) is not int or count < 1:
                raise ValueError(f'invalid planned repetition count: {key}')
            plan[key] = count
        if set(plan) != cases:
            raise ValueError('case_plan does not cover exactly the selected applications/modes')
    else:
        count = metadata['repeats']
        if type(count) is not int or count < 1:
            raise ValueError('invalid legacy repetition count')
        plan = {key: count for key in cases}
    expected = 2 * sum(plan.values())
    if metadata.get('expected_runs', expected) != expected:
        raise ValueError('metadata.expected_runs differs from case_plan')
    return plan


def successful(row: dict) -> bool:
    return row.get('exit_code') == 0 and row.get('proof', {}).get('verified') is True


def declared_controller_capabilities(metadata: dict) -> tuple[dict, bool]:
    sessions = {}
    for session in metadata.get('sessions', []):
        key = session.get('session')
        if key in sessions:
            raise ValueError('duplicate metadata session identity')
        sessions[key] = ('process_controller_sha256' in session or 'process_controller_source' in session)
    return sessions, 'process_controller_sha256' in metadata or any(sessions.values())


def validate_controller_records(records: list[dict], measurements: Path, *, kind='measurement',
                                metadata=None, require_controller=False) -> list[dict]:
    """Validate raw journal rows before resource enrichment adds derived fields."""
    audits = []
    sessions, current_capability = declared_controller_capabilities(metadata or {})
    for row in records:
        required = require_controller
        if metadata is not None:
            if row.get('session') in sessions:
                required = sessions[row['session']]
            elif current_capability:
                raise ValueError('record lacks a known controller-capability session: ' + row['log'])
        cleanup = row.get('cleanup')
        if required and 'cleanup' not in row:
            raise ValueError('declared controller capability requires cleanup diagnostics: ' + row['log'])
        if 'cleanup' in row:
            if (not isinstance(cleanup, dict) or type(cleanup.get('complete')) is not bool
                    or not isinstance(cleanup.get('errors'), list)):
                raise ValueError('invalid cleanup diagnostic: ' + row['log'])
        if successful(row) and (row.get('termination_reason') is not None or
                                cleanup is not None and cleanup['complete'] is False):
            raise ValueError('successful proof contradicts its controller stop/cleanup: ' + row['log'])
        linked = 'controller_log' in row or 'controller_log_sha256' in row
        if not successful(row) and cleanup is not None and not linked:
            raise ValueError('new failed record omitted its controller sidecar: ' + row['log'])
        if not linked:
            continue  # Legacy records did not have controller diagnostics.
        if not all(field in row for field in ('controller_log', 'controller_log_sha256')):
            raise ValueError('incomplete controller sidecar binding: ' + row['log'])
        if successful(row):
            raise ValueError('failure-only controller sidecar attached to a successful proof: ' + row['log'])
        path, log = Path(row['controller_log']), Path(row['log'])
        if (path.is_symlink() or not path.is_file() or path.parent.resolve() != measurements.resolve()
                or log.parent.resolve() != measurements.resolve()
                or path.resolve() != log.with_suffix('.controller.json').resolve()):
            raise ValueError('controller sidecar is outside its measurement attempt: ' + str(path))
        digest = sha(path)
        if row['controller_log_sha256'] != digest:
            raise ValueError('controller sidecar digest differs: ' + str(path))
        content = json.loads(path.read_text())
        expected = {key: value for key, value in row.items() if key not in JOURNAL_ONLY_FIELDS}
        if json.dumps(content, sort_keys=True, allow_nan=False) != json.dumps(expected, sort_keys=True, allow_nan=False):
            raise ValueError('controller sidecar content differs from raw journal record: ' + str(path))
        audits.append(dict(kind=kind, application=row.get('application'), mode=row.get('mode'),
            profile=row.get('profile'), repetition=row.get('repetition'), session=row.get('session'),
            path=str(path), sha256=digest, content=content))
    return audits


def validate_controller_metadata(metadata: dict, measurements: Path) -> list[dict]:
    """Validate warmup sidecars and the independently frozen imported controller."""
    audits = []
    for session in metadata.get('sessions', []):
        for field in ('process_controller_source', 'process_controller_sha256'):
            if field in session and not all(key in session for key in
                    ('process_controller_source', 'process_controller_sha256')):
                raise ValueError('incomplete session process-controller binding')
        if 'process_controller_source' in session:
            path = Path(session['process_controller_source'])
            if (path.is_symlink() or path.parent.resolve() != measurements.resolve()
                    or sha(path) != session['process_controller_sha256']):
                raise ValueError('frozen session process controller differs: ' + str(path))
        warmups = validate_controller_records(session.get('warmups', []), measurements, kind='warmup',
            require_controller='process_controller_sha256' in session or 'process_controller_source' in session)
        for audit in warmups:
            audit['session'] = session.get('session')
        audits.extend(warmups)
    if metadata.get('process_controller_sha256') is not None:
        sessions = metadata.get('sessions', [])
        if not sessions or sessions[-1].get('process_controller_sha256') != metadata['process_controller_sha256']:
            raise ValueError('current process-controller hash differs from the latest measurement session')
    return audits


def failure_diagnostics(records: list[dict]) -> list[dict]:
    return [{key: row[key] for key in FAILURE_DIAGNOSTIC_FIELDS if key in row}
            for row in records if not successful(row)]


def validate_cleanup_status(metadata: dict, records: list[dict], status: str) -> None:
    if status not in ('running', 'paused', 'complete', 'complete_with_failures'):
        raise ValueError('unrecognized measurement campaign status: ' + str(status))
    halted_sessions = set()
    for row in records:
        session = row.get('session')
        if session in halted_sessions:
            raise ValueError('journal continued a session after unconfirmed cleanup/interruption')
        if row.get('cleanup', {}).get('complete') is False or row.get('termination_reason') == 'interrupted':
            halted_sessions.add(session)
    sessions = metadata.get('sessions', [])
    current_session = sessions[-1].get('session') if sessions else None
    if current_session in halted_sessions and status != 'paused':
        raise ValueError('current controller stopped but metadata is not paused; retry a stable snapshot')
    if sessions and 'process_controller_sha256' in sessions[-1]:
        if any(not successful(row) for row in sessions[-1].get('warmups', [])) and status != 'paused':
            raise ValueError('current controller warmup failed but metadata is not paused')


def enrich_resources(records: list[dict]) -> list[dict]:
    """Read Darwin resource footers without changing the measurement journal."""
    enriched = []
    for original in records:
        row = dict(original)
        log = Path(row['log'])
        raw = log.read_bytes()
        actual_sha = hashlib.sha256(raw).hexdigest()
        if row.get('log_sha256', actual_sha) != actual_sha:
            raise ValueError(f'resource log digest differs: {log}')
        row['resource_log_sha256'] = actual_sha
        output = raw.decode('utf-8')
        elapsed = re.findall(
            r'^\s*(\d+(?:\.\d+)?)\s+real\s+\d+(?:\.\d+)?\s+user\s+\d+(?:\.\d+)?\s+sys\s*$',
            output, re.MULTILINE)
        if len(elapsed) > 1:
            raise ValueError(f'ambiguous Darwin process elapsed time: {log}')
        if elapsed:
            row['process_wall_ms'] = float(elapsed[0]) * 1000
        else:
            row.pop('process_wall_ms', None)
        for field, label in (('peak_rss_bytes', 'maximum resident set size'),
                             ('peak_memory_footprint_bytes', 'peak memory footprint')):
            matches = re.findall(r'^\s*(\d+)\s+' + re.escape(label) + r'\s*$', output, re.MULTILINE)
            if len(matches) > 1:
                raise ValueError(f'ambiguous resource footer for {label}: {log}')
            if matches:
                value = int(matches[0])
                if field in row and row[field] != value:
                    raise ValueError(f'journal resource metric differs from log: {field}/{log}')
                row[field] = value
            elif field == 'peak_memory_footprint_bytes':
                # A missing Darwin-specific field is unavailable, never zero.
                row.pop(field, None)
        enriched.append(row)
    return enriched


def memory_termination_evidence(campaign: Path, records: list[dict]) -> dict | None:
    path = campaign / 'picojpeg-raw64-memory-termination.json'
    if not path.exists():
        return None
    content = json.loads(path.read_text())
    if (content.get('schema') != 'zkcfa.raw64.system-termination-evidence.v1' or
        (content.get('application'), content.get('path_mode'), content.get('profile'), content.get('repetition')) !=
            ('picojpeg', 'complete', 'raw64-typed-channels', 1)):
        raise ValueError('unexpected picojpeg system termination evidence')
    matching = [row for row in records if (row['application'], row['mode'], row['profile'], row['repetition']) ==
                ('picojpeg', 'complete', 'raw64', 1)]
    if len(matching) != 1 or successful(matching[0]):
        raise ValueError('system termination evidence does not bind one failed attempt')
    related = (campaign / content['related_experiment_log']).resolve()
    if related != Path(matching[0]['log']).resolve():
        raise ValueError('system termination evidence refers to a different experiment log')
    saved_log = campaign / content['saved_log']
    if saved_log.parent.resolve() != campaign or sha(saved_log) != content['saved_log_sha256']:
        raise ValueError('system termination evidence log is outside campaign or has changed')
    log_text = saved_log.read_text()
    marker = f"memorystatus: killing largest compressed process {content['process_name']} [{content['process_id']}]"
    if marker not in log_text:
        raise ValueError('saved kernel record does not support the termination attribution')
    return {'path': str(path), 'sha256': sha(path), 'content': content,
            'saved_log_path': str(saved_log), 'saved_log_sha256': sha(saved_log),
            'related_experiment_log_sha256': matching[0]['resource_log_sha256'],
            'saved_log_text': log_text,
            'classification': 'system memory termination before a completed proof; not a constraint or cryptographic rejection'}


def grouped_summaries(records: list[dict], plan: dict) -> dict:
    """Recompute successful-sample statistics from the journal; never fill failures."""
    groups = {(app, mode, profile): [] for app, mode in plan for profile in PROFILES}
    seen = set()
    for record in records:
        key = record['application'], record['mode'], record['profile']
        repetition = record['repetition']
        unique = (*key, repetition)
        if key not in groups or type(repetition) is not int or not 1 <= repetition <= plan[key[:2]]:
            raise ValueError(f'journal attempt lies outside plan: {unique}')
        if unique in seen:
            raise ValueError(f'duplicate journal attempt: {unique}')
        seen.add(unique)
        if 'proof' in record and not successful(record):
            raise ValueError(f'contradictory success/exit status: {unique}')
        if successful(record):
            proof = record['proof']
            profile = 'raw24-full-key' if key[2] == 'raw24' else 'raw64-typed-channels'
            if (proof['application'], proof['path_mode'], proof['profile']) != (key[0], key[1], profile):
                raise ValueError(f'proof report is mislabeled: {unique}')
        groups[key].append(record)
    index = {}
    for key, runs in groups.items():
        valid = [row for row in runs if successful(row)]
        expected = plan[key[:2]]
        result = dict(application=key[0], mode=key[1], profile=key[2],
                      successful_runs=len(valid), attempted_runs=len(runs), expected_runs=expected,
                      status=('pending' if len(runs) < expected else
                              'complete' if len(valid) == expected else 'complete_with_failures'))
        failed = failure_diagnostics(runs)
        if failed:
            result['failed_attempt_diagnostics'] = failed
        if valid:
            first = valid[0]['proof']
            for field in ('instance', 'capacity', 'constraints'):
                if any(run['proof'][field] != first[field] for run in valid):
                    raise ValueError(f'instance/circuit changes within group: {key}')
                result[field] = first[field]
            for metric in METRICS:
                if metric.endswith('_ms') and metric[:-3] in PHASES:
                    values = [row['proof']['phases_ms'][metric[:-3]] for row in valid]
                elif metric == 'proof_bytes':
                    values = [row['proof'][metric] for row in valid]
                else:
                    values = [row[metric] for row in valid if metric in row]
                if any(not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 for value in values):
                    raise ValueError(f'invalid measurement: {key}/{metric}')
                if values:
                    result[metric] = dict(median=statistics.median(values), min=min(values), max=max(values))
        index[key] = result
    return index


def validate_stored_summaries(stored: list[dict], index: dict) -> None:
    seen = set()
    for row in stored:
        key = row['application'], row['mode'], row['profile']
        if key in seen or key not in index:
            raise ValueError(f'duplicate/unexpected stored summary: {key}')
        seen.add(key)
        actual = index[key]
        # Old summaries omit expected_runs/status. Preserve compatibility.
        for field in ('successful_runs', 'attempted_runs', 'expected_runs', 'status',
                      'instance', 'capacity', 'constraints', 'failed_attempt_diagnostics', *METRICS):
            different = (json.dumps(row.get(field), sort_keys=True, allow_nan=False) !=
                         json.dumps(actual.get(field), sort_keys=True, allow_nan=False)) if field == 'failed_attempt_diagnostics' else row.get(field) != actual.get(field)
            if field in row and different:
                raise ValueError(f'summary and journal differ at {key}/{field}; retry a stable snapshot')
        if ('failed_attempt_diagnostics' not in row and any('cleanup' in item or 'controller_log' in item
                for item in actual.get('failed_attempt_diagnostics', []))):
            raise ValueError(f'stored summary omits new failed-attempt cleanup diagnostics: {key}')
    attempted = {key for key, row in index.items() if row['attempted_runs']}
    if not attempted.issubset(seen):
        raise ValueError('stored summary omits attempted journal groups; retry a stable snapshot')


def flatten(index: dict, metadata: dict, plan: dict) -> list[dict]:
    rows = []
    for app in metadata['applications']:
        for mode in metadata['modes']:
            low, wide = (index[(app, mode, profile)] for profile in PROFILES)
            available = [value for value in (low, wide) if value['successful_runs']]
            if len(available) == 2:
                if low['instance'] != wide['instance']:
                    raise ValueError(f'paired input shape differs: {app}/{mode}')
                for field in ('edge_cap', 'ep_cap', 'multiplicity_bits'):
                    if low['capacity'][field] != wide['capacity'][field]:
                        raise ValueError(f'paired capacity differs: {app}/{mode}/{field}')
            first = available[0] if available else {}
            paired = low['status'] == wide['status'] == 'complete'
            row = dict(application=app, path_mode=mode, repetitions=plan[(app, mode)],
                       paired_aggregate_included=paired,
                       **{key: first.get('instance', {}).get(key) for key in ('nodes', 'edges', 'steps')},
                       **{key: first.get('capacity', {}).get(key) for key in ('edge_cap', 'ep_cap')})
            for profile, value in zip(PROFILES, (low, wide)):
                for field in ('successful_runs', 'attempted_runs', 'expected_runs', 'status'):
                    row[f'{profile}_{field}'] = value[field]
                for metric in METRICS:
                    row[f'{profile}_{metric}'] = value.get(metric, {}).get('median')
                for field in ('and', 'imul', 'bmul'):
                    row[f'{profile}_{field}_constraints'] = value.get('constraints', {}).get(field)
            for metric in METRICS:
                numerator, denominator = row[f'raw64_{metric}'], row[f'raw24_{metric}']
                row[f'wide_over_raw24_{metric}'] = (numerator / denominator
                    if paired and numerator is not None and denominator is not None and denominator > 0 else None)
            rows.append(row)
    return rows


def aggregate(flat: list[dict], modes: list[str]) -> dict:
    result = {}
    for mode in modes:
        cases = [row for row in flat if row['path_mode'] == mode]
        included = [row for row in cases if row['paired_aggregate_included']]
        metrics = [*(f'{profile}_{metric}' for profile in PROFILES for metric in METRICS),
                   *(f'wide_over_raw24_{metric}' for metric in METRICS)]
        values = dict(planned_cases=len(cases), paired_successful_cases=len(included),
                      excluded_cases=[row['application'] for row in cases if not row['paired_aggregate_included']],
                      metric_coverage={})
        for metric in metrics:
            samples = [row[metric] for row in included if row[metric] is not None]
            values[metric] = statistics.median(samples) if samples else None
            values['metric_coverage'][metric] = len(samples)
        result[mode] = values
    return result


def formatted(value: float | int | None, divisor: float = 1, digits: int = 2) -> str:
    return '—' if value is None else f'{value / divisor:.{digits}f}'


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign', type=Path, required=True)
    parser.add_argument('--data-output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    campaign = args.campaign.resolve()
    measurements = campaign / 'measurements'
    metadata = json.loads((measurements / 'metadata.json').read_text())
    summaries = json.loads((measurements / 'summary.json').read_text())
    raw = (measurements / 'runs.jsonl').read_text()
    if raw and not raw.endswith('\n'):
        raise ValueError('journal has an incomplete final line; retry after the current write')
    journal = [json.loads(line) for line in raw.splitlines()]
    controller_audits = validate_controller_records(journal, measurements, metadata=metadata)
    controller_audits.extend(validate_controller_metadata(metadata, measurements))
    records = enrich_resources(journal)
    termination = memory_termination_evidence(campaign, records)
    paused_parent_rows = [row for row in records if
                          (row['application'], row['mode'], row['profile'], row['repetition']) ==
                          ('picojpeg', 'shadow', 'raw64', 1) and
                          row['resource_log_sha256'] == PARENT_PAUSED_LOG_SHA256 and
                          row.get('process_wall_ms') is not None and
                          row['wall_ms'] - row['process_wall_ms'] > 1000]
    plan = planned_repeats(metadata)
    expected = 2 * sum(plan.values())
    index = grouped_summaries(records, plan)
    # Driver summaries contain journal observations, before export-only log enrichment.
    raw_failure_diagnostics = {
        key: failure_diagnostics([row for row in journal if (row['application'], row['mode'], row['profile']) == key])
        for key in index}
    for key, diagnostics in raw_failure_diagnostics.items():
        if diagnostics:
            index[key]['failed_attempt_diagnostics'] = diagnostics
    validate_stored_summaries(summaries, index)
    verified = sum(successful(row) for row in records)
    failures = len(records) - verified
    status = metadata.get('status', 'complete' if 'completed_utc' in metadata else 'running')
    validate_cleanup_status(metadata, journal, status)
    if status.startswith('complete'):
        if len(records) != expected or metadata.get('successful_runs') != verified:
            raise ValueError('completed metadata does not match the attempt journal')
        wanted = 'complete_with_failures' if failures else 'complete'
        if status != wanted:
            raise ValueError('completed status disagrees with recorded failures')
    if metadata.get('attempted_runs', len(records)) != len(records):
        raise ValueError('metadata attempt count and journal differ; retry a stable snapshot')
    audit = json.loads((campaign / 'pair-audit.json').read_text())
    if not audit['all_passed'] or audit['applications'] != len(metadata['applications']):
        raise ValueError('paired acquisition audit does not cover the measurement applications')
    captures = json.loads((campaign / 'captures.json').read_text())['captures']
    wide_captures = [row for row in captures if row['lane'] == 'wide' and row['application'] in metadata['applications']]
    if len(wide_captures) != len(metadata['applications']) or any(
        row['addresses']['canonical_pc_equals_runtime_pc'] is not True or
        int(row['addresses']['runtime_bias'], 0) != 0 or
        row['addresses']['canonical_pc_bits'] != 47 for row in wide_captures):
        raise ValueError('capture evidence does not establish the claimed real 47-bit PCs')
    flat = flatten(index, metadata, plan)
    aggregates = aggregate(flat, metadata['modes'])
    count_note = '、'.join(f'{count} 次 × {sum(value == count for value in plan.values())} 组应用/模式'
                          for count in sorted(set(plan.values())))
    method = ('Within each application/mode/profile, use only successful samples and report its actual '
              'successful/expected count. Cross-application aggregates include only pairs where both '
              'profiles completed every planned repetition successfully. Take the median across '
              'those paired cases; ratio medians use per-case raw64/raw24 ratios, not ratios of aggregate medians. '
              'Missing and failed values remain null. A one-sample result is descriptive, not a variability estimate.')
    args.data_output.mkdir(parents=True, exist_ok=True)
    with (args.data_output / 'raw64-address-comparison.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(flat[0]))
        writer.writeheader()
        writer.writerows(flat)
    environment = json.loads((campaign / 'environment-and-validation.json').read_text())
    environment['performance_scope'] = f'Paired real 47-bit captures; {expected} planned attempts under the measurement case_plan; excluded process warmups.'
    environment['performance_scope_note'] = 'Scheduling is taken from measurement metadata; the source environment snapshot may describe the initial plan.'
    published = {
        'schema': 'zkcfa.raw64.address-comparison.v1', 'status': status,
        'expected_runs': expected, 'attempted_runs': len(records), 'successful_runs': verified,
        'failed_runs': failures, 'measurement_metadata': metadata,
        'environment_and_validation': environment, 'aggregate_method': method,
        'paired_capture_audit': audit, 'aggregate_by_mode': aggregates,
        'summaries_with_ranges': list(index.values()),
        'resource_measurement_method': (
            'RSS and peak memory footprint are separate byte-valued Darwin time -l observations. '
            'process_wall_ms is the real elapsed field from time -l; wall_ms remains the original '
            'Python batch-parent observation and can include a paused parent waiting to collect an already finished child. '
            'Resource fields are read from each original log in memory; existing log hashes and '
            'journal RSS values are checked. Missing footprint is null/unavailable, never zero. '
            'Failed-attempt resource observations are retained here but excluded from timing aggregates.'),
        'resource_measurements': [
            {key: row.get(key) for key in ('application', 'mode', 'profile', 'repetition',
                                         'exit_code', 'wall_ms', 'process_wall_ms',
                                         'peak_rss_bytes', 'peak_memory_footprint_bytes',
                                         'log', 'resource_log_sha256')}
            for row in records],
        'failure_records': [row for row in records if not successful(row)],
        'controller_diagnostic_audits': controller_audits,
        'controller_validation': {
            'method': ('Sidecar paths, SHA-256 and complete contents are checked against raw records before '
                       'resource enrichment; failed_attempt_diagnostics must match the driver summary. '
                       'New failed records require sidecars; absent legacy diagnostics remain unavailable.'),
            'measurement_sidecars_verified': sum(row['kind'] == 'measurement' for row in controller_audits),
            'warmup_sidecars_verified': sum(row['kind'] == 'warmup' for row in controller_audits),
            'cleanup_unconfirmed_attempts': sum(row.get('cleanup', {}).get('complete') is False for row in journal),
            'failed_attempts_without_legacy_cleanup_record': sum(not successful(row) and 'cleanup' not in row for row in journal),
        },
        'system_memory_termination_evidence': termination,
        'batch_parent_pause_caveat': {
            'description': ('The first picojpeg/shadow/raw64 sample ran while its Python parent was '
                            'paused by SIGSTOP. The child continued '
                            'and completed before the parent resumed. Original wall_ms includes the pause; '
                            'process_wall_ms and child-reported proof phases/resources are retained separately.'),
            'affected_samples': [{key: row.get(key) for key in
                                 ('application', 'mode', 'profile', 'repetition', 'wall_ms', 'process_wall_ms',
                                  'log', 'resource_log_sha256')} for row in paused_parent_rows],
        } if paused_parent_rows else None,
        'provenance': {name: sha(campaign / name) for name in
            ('pair-audit.json', 'captures.json', 'handoff-validation.json', 'environment-and-validation.json',
             'measurements/runs.jsonl', 'measurements/summary.json', 'measurements/metadata.json')},
        'summary_generator_sha256': sha(Path(__file__)),
    }
    (args.data_output / 'raw64-address-comparison.json').write_text(json.dumps(published, indent=2) + '\n')
    state_label = {'running': '进行中', 'paused': '已暂停', 'complete': '已完成',
                   'complete_with_failures': '已完成，包含失败尝试'}.get(status, status)
    lines = ['# 真实 47 位程序地址与 raw64 成本实验', '',
             f"实验状态：**{state_label}**。测量时间见 JSON 的 `measurement_metadata`。", '',
             f"覆盖 {len(metadata['applications'])} 个应用、{len(metadata['modes'])} 种路径模式和 raw24/raw64 两种配置。"
             f'计划为每配置 {count_note}，共 **{expected} 次尝试**；已记录 **{len(records)} 次**，'
             f'成功 **{verified} 次**，失败 **{failures} 次**。每次启动测量批处理时分别预热两个配置，预热不计入统计。', '',
             '高地址组重新执行真实 x86-64 QEMU 程序，保留约 `0x55555555...` 的 47 位运行 PC，所有运行的 '
             '`runtime_bias=0`。低地址组使用原有规范化。配对审计确认 ELF、逐条执行序列、CFG 与 complete/shadow '
             '路径相同，只有证明输入中的地址基址不同。这里比较的是现实用户地址布局下的完整 raw24/raw64 构造。', '',
             '## 总体数据', '',
             '每应用先取成功运行的中位数；跨应用聚合仅纳入两种配置均完成全部计划次数且全部成功的配对案例。'
             '失败或尚未完成的配对不进入聚合，覆盖数量列在表中。时间单位为毫秒。', '',
             '| 模式 | 配对覆盖 | 配置 | Setup | Prove | Verify | 证明 KiB | 峰值 RSS MiB | 峰值 footprint MiB |',
             '|---|---:|---|---:|---:|---:|---:|---:|---:|']
    for mode, values in aggregates.items():
        coverage = f"{values['paired_successful_cases']}/{values['planned_cases']}"
        for profile in PROFILES:
            cells = [formatted(values[f'{profile}_{metric}'], divisor) for metric, divisor in
                     (('setup_ms', 1), ('prove_ms', 1), ('verify_ms', 1), ('proof_bytes', 1024),
                      ('peak_rss_bytes', 1048576), ('peak_memory_footprint_bytes', 1048576))]
            lines.append(f'| {mode} | {coverage} | {profile} | ' + ' | '.join(cells) + ' |')
    lines += ['', '以下为同一批成功配对的逐应用 raw64/raw24 比值中位数：', '',
              '| 模式 | 配对覆盖 | Setup 倍率 | Prove 倍率 | Verify 倍率 | 证明大小倍率 | RSS 倍率 | footprint 倍率 |',
              '|---|---:|---:|---:|---:|---:|---:|---:|']
    for mode, values in aggregates.items():
        cells = [formatted(values[f'wide_over_raw24_{metric}'], digits=3) for metric in
                 ('setup_ms', 'prove_ms', 'verify_ms', 'proof_bytes', 'peak_rss_bytes', 'peak_memory_footprint_bytes')]
        lines.append(f"| {mode} | {values['paired_successful_cases']}/{values['planned_cases']} | " + ' | '.join(cells) + ' |')
    lines += ['', '无有效样本显示“—”。若内存指标缺失，其覆盖数另见 JSON 的 `metric_coverage`。']
    large_complete = [row for row in flat if row['path_mode'] == 'complete' and
                      (row['application'] in ('picojpeg', 'wikisort') or
                       (row['ep_cap'] is not None and row['ep_cap'] >= metadata.get('large_ep_cap', 65536)))]
    if large_complete:
        lines += ['', '## 大型完整路径的时间与内存', '',
                  '每个配置完成全部计划次数且全部成功后才在本表列出中位数；未完成或有失败时显示“—”。'
                  'Wall 使用 `time -l` 的 real 字段，即 `process_wall_ms`；原始 Python 批处理观察值 `wall_ms` 另存于 CSV/JSON。'
                  'RSS 与 footprint 是不同的资源指标，不能互换。', '',
                  '| 应用 | 配置 | 成功/期望 | Setup s | Prove s | Wall s | 峰值 RSS GiB | 峰值 footprint GiB |',
                  '|---|---|---:|---:|---:|---:|---:|---:|']
        for row in large_complete:
            for profile in PROFILES:
                done = row[f'{profile}_status'] == 'complete'
                count = f"{row[f'{profile}_successful_runs']}/{row[f'{profile}_expected_runs']}"
                cells = [formatted(row[f'{profile}_{metric}'] if done else None, divisor) for metric, divisor in
                         (('setup_ms', 1000), ('prove_ms', 1000), ('process_wall_ms', 1000),
                          ('peak_rss_bytes', 1073741824), ('peak_memory_footprint_bytes', 1073741824))]
                lines.append(f"| {row['application']} | {profile} | {count} | " + ' | '.join(cells) + ' |')
    for mode in metadata['modes']:
        lines += ['', f"## {len(metadata['applications'])} 应用：{mode}", '',
                  '次数列为“成功/期望”；数值仅使用该配置已成功的样本。单次结果直接列出该次测量，'
                  '不提供重复稳定性结论。未完成或有失败的配对不纳入上面的总体聚合。', '',
                  '| 应用 | EP 行数 | raw24 成功/期望 | raw64 成功/期望 | raw24 Prove ms | raw64 Prove ms | raw24 Verify ms | raw64 Verify ms | raw24 KiB | raw64 KiB | 状态 |',
                  '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|']
        for row in flat:
            if row['path_mode'] != mode:
                continue
            counts = [f"{row[f'{profile}_successful_runs']}/{row[f'{profile}_expected_runs']}" for profile in PROFILES]
            cells = [formatted(row[f'{profile}_{metric}'], divisor) for metric, divisor in
                     (('prove_ms', 1), ('verify_ms', 1), ('proof_bytes', 1024)) for profile in PROFILES]
            if row['paired_aggregate_included']:
                case_status = '配对成功'
            else:
                states = []
                for profile in PROFILES:
                    failed = row[f'{profile}_attempted_runs'] - row[f'{profile}_successful_runs']
                    remaining = row[f'{profile}_expected_runs'] - row[f'{profile}_attempted_runs']
                    if failed:
                        states.append(f'{profile} 失败{failed}')
                    if remaining:
                        states.append(f'{profile} 待测{remaining}')
                case_status = '；'.join(states)
            steps = '—' if row['steps'] is None else str(row['steps'])
            lines.append(f"| {row['application']} | {steps} | " + ' | '.join([*counts, *cells, case_status]) + ' |')
    if failures:
        lines += ['', '## 失败尝试', '',
                  '失败不进入成功样本聚合，但保留进程终止前可观察到的 Wall、RSS 与 footprint。'
                  'Wall 同样取 `time -l` 的 real 字段；这些资源记录不表示证明完成。退出码本身不能单独确定原因。', '']
        if termination:
            event = termination['content']
            lines += [f"picojpeg complete/raw64 第 1 次尝试在 **{event['event_utc_time']}** 被 macOS 的 memorystatus 子系统"
                      f"终止；内核记录将 `{event['process_name']}[{event['process_id']}]` 标记为最大的压缩内存进程。"
                      '该尝试未产出完成的证明，归类为系统内存压力终止，不归类为电路约束或密码学验证失败。'
                      '系统原始记录、对应实验日志和来源哈希保存在 JSON 的 `system_memory_termination_evidence` 中。', '']
        lines += ['| 应用 | 模式 | 配置 | 次数 | 退出码 | 控制器终止原因 | 清理确认 | Wall s | 峰值 RSS GiB | 峰值 footprint GiB |',
                  '|---|---|---|---:|---:|---|---|---:|---:|---:|']
        for row in records:
            if not successful(row):
                resources = [formatted(row.get(metric), divisor) for metric, divisor in
                             (('process_wall_ms', 1000), ('peak_rss_bytes', 1073741824),
                              ('peak_memory_footprint_bytes', 1073741824))]
                cleanup = row.get('cleanup')
                cleanup_status = ('未记录' if cleanup is None else '已确认' if cleanup['complete'] else '未确认')
                if cleanup is not None and cleanup['errors']:
                    cleanup_status += f"（{len(cleanup['errors'])} 条诊断）"
                lines.append(f"| {row['application']} | {row['mode']} | {row['profile']} | {row['repetition']} | "
                             f"{row.get('exit_code', '—')} | {row.get('termination_reason') or '未记录'} | {cleanup_status} | " + ' | '.join(resources) + ' |')
    if paused_parent_rows:
        row = paused_parent_rows[0]
        lines += ['', '## 批处理暂停的计时说明', '',
                  '`picojpeg-shadow-raw64-r1` 测量期间，Python 父进程被 SIGSTOP 暂停，'
                  '证明子进程继续执行，并在父进程恢复前完成。'
                  f"因此原始批处理 `wall_ms` 为 **{formatted(row['wall_ms'])} ms**，而进程 `process_wall_ms` 为 "
                  f"**{formatted(row['process_wall_ms'])} ms**。原记录与日志均保留；父进程等待时间不加入这里展示的进程 Wall。"
                  '子进程记录的证明阶段耗时、证明结果和资源观测不受这次父进程暂停计时影响。']
    lines += ['', '## 实验口径与适用范围', '',
              f"- 主机：{environment['cpu']}，{formatted(environment['memory_bytes'], 1073741824, 0)} GiB 内存，"
              f"{metadata['logical_cpus']} 逻辑核；{metadata['platform']}；{environment['rustc']}。"
              f"构建配置：{environment['build_profile']}；RUSTFLAGS=`{environment['rustflags']}`。",
              '- 应用、模式和配置串行执行，轮次交替配置先后。次数遵循逐案例计划；减少大型案例的重复数限制了这些案例的波动评估。',
              '- 峰值 RSS 只表示进程驻留内存，不包含全部交换出去的页面。内存压力可能影响大型案例的耗时；具体系统资源观察以实验记录为准，不能将时间倍率解释为纯计算复杂度倍率。',
              '- 峰值 footprint 直接取 Darwin `time -l` 的 `peak memory footprint` 字段，反映系统对进程的内存占用核算；峰值 RSS 取 `maximum resident set size`。两者均按字节读取，表中转换为 MiB/GiB。footprint 不是 RSS，也不是进程虚拟地址空间大小。缺失时留空，不以 RSS 代替；逐次原始观察与日志哈希见 JSON。',
              '- `process_wall_ms` 来自 `time -l` 的 real 耗时；`wall_ms` 是 Python 批处理父进程的原始计时，两者都保留。进程 Wall 包含各阶段之外的开销，日志只保留到百分之一秒时相应精度为 10 ms；缺失不以父进程耗时替代。',
              '- Setup 包含电路构建、验证/证明密钥初始化和私密输入预检；Prove 包含见证生成、本地约束检查和密码学证明；Verify 是密码学验证，签名等 public preflight 另列于 CSV/JSON。',
              '- 每组签名语句在其计划次数内复用，测量离线密码学性能；这不表示在线 registry 接受重复 challenge。两模式保持原有不同保证。',
              '- raw64 每条 CFG/EP 记录使用三个 64 位字，按 JMP/CAL/CRT 三通道做成员检查，返回栈记录使用完整 128 位。还增加显式 CFG 行检查，因此这是两个具体实现的比较，不能把全部差异归因于地址位宽本身。',
              '- 真实执行覆盖一个常见 47 位 Linux 用户空间布局。56 位和设置 bit63 的地址属于单独的合成电路正例，不计入本表真实应用实验；未实测 57 位页表、内核或共享库内部控制流。',
              '- 成功样本的 min/max 和实际次数见 JSON；单样本的 min=max 仅表示只有一次测量。本机描述性结果不支持统计显著性结论或直接外推到其他处理器。',
              '- 实验使用独立采集的低地址/高地址输入；其性能结果不与其他应用或后端测量混合聚合。', '', '## 数据与复现', '',
              '- 完整逐应用数据：[CSV](../data/raw64-address-comparison.csv)。',
              '- 实际次数、覆盖、失败、波动范围、构建环境与来源哈希：[JSON](../data/raw64-address-comparison.json)。',
              '- 编码与安全边界：[RAW64.md](../../RAW64.md)。',
              '- 真实采集方法：[RAW64_ADDRESS_ACQUISITION.md](RAW64_ADDRESS_ACQUISITION.md)。',
              '- 完整日志与私密 bundle 保存在实验采集目录；日志位置和来源哈希见 JSON。复现实验使用 `--campaign` 指定该私密目录。', '']
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text('\n'.join(lines))
    print(json.dumps({'status': status, 'expected_runs': expected, 'attempted_runs': len(records),
                      'successful_runs': verified, 'failed_runs': failures,
                      'paired_coverage': {mode: value['paired_successful_cases'] for mode, value in aggregates.items()}}, indent=2))


if __name__ == '__main__':
    main()
