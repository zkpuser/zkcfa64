#!/usr/bin/env python3
"""Serial synthetic PLONK/KZG scaling on the exact Binius complete typed artifacts.

The Rust research example reuses the production relation and separates synthesis from crypto.
Inputs and binary are frozen under output; actual failures retain empty unavailable measurements.
This runner deliberately makes no acquisition or device authentication claim.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import statistics
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_plonk_campaign as control

SIZES = (64, 128, 256, 512, 1024, 2048, 4096)
ARTIFACTS = ('translator', 'typed_cfg', 'recorded_path')
METRICS = ('setup_ms', 'srs_setup_ms', 'key_compile_and_trim_ms', 'witness_localcheck_ms',
           'cryptographic_prove_ms', 'proof_serialization_ms', 'verify_ms', 'proof_bytes',
           'wall_ms', 'peak_rss_bytes', 'peak_memory_footprint_bytes')
FIELDS = ('family', 'source_ep_rows', 'path_mode', 'repetition', 'warmup', 'outcome',
          'nodes', 'edges', 'proof_rows', 'edge_cap', 'ep_cap', 'plonk_gates', 'raw_bound',
          'padded_domain', 'estimated_gates_guard', 'estimated_domain_guard',
          'input_preflight_ms', *METRICS, 'returncode', 'stop_reason', 'cleanup_complete',
          'wrong_endpoint_rejected', 'verified', 'started_utc', 'completed_utc',
          'translator_sha256', 'typed_cfg_sha256', 'recorded_path_sha256',
          'report_file', 'report_sha256', 'controller_log', 'failure_note')


def utc():
    return datetime.now(timezone.utc).isoformat()


def write_rows(path, rows):
    temporary = path.with_suffix('.csv.tmp')
    with temporary.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def audit_report(report, case, *, preflight):
    """Reject a projected, differently shaped, or unaudited substitute for Complete."""
    if (report.get('schema') != 'zkcfa.plonk.synthetic-scaling.v1'
            or report.get('backend') != 'plonk' or report.get('profile') != 'raw24-full-key'
            or report.get('path_mode') != 'complete' or report.get('threads') != 8
            or report.get('preflight') is not preflight or report.get('satisfied') is not True):
        raise ValueError('incorrect synthetic complete raw24 report identity')
    expected = case['input_sha256']['complete']
    if report['input_sha256'] != {name: expected[name] for name in ARTIFACTS}:
        raise ValueError('native input hashes differ from the Binius complete source')
    if report['instance'] != dict(nodes=case['nodes'], edges=case['typed_edges'], steps=case['source_ep_rows']):
        raise ValueError('native instance counts differ from complete source')
    capacities = report['capacity']
    if (capacities['edge_cap'] != case['binius_edge_cap']
            or capacities['ep_cap'] != case['binius_ep_cap']['complete']):
        raise ValueError('native capacities differ from Binius complete')
    c = report['constraints']
    if not (0 < c['plonk_gates'] <= c['raw_bound'] <= c['padded_domain']
            and c['padded_domain'] == 1 << (c['raw_bound'] - 1).bit_length()):
        raise ValueError('invalid observed gate count or padded domain')
    if not preflight and report.get('verified') is not True:
        raise ValueError('cryptographic proof has not verified')
    phases = report['phases_ms']
    required = ('input_preflight',) if preflight else (
        'input_preflight', 'setup', 'srs_setup', 'key_compile_and_trim',
        'witness_localcheck', 'cryptographic_prove', 'proof_serialization', 'verify')
    if any(not isinstance(phases.get(key), (int, float)) or not math.isfinite(phases[key])
           or phases[key] < 0 for key in required):
        raise ValueError('missing or nonfinite measured phase')


def planned_grid(manifest):
    if (manifest.get('schema') != 'zkcfa.synthetic-scaling-inputs.v1'
            or manifest.get('research_only') is not True or manifest.get('sizes') != list(SIZES)):
        raise ValueError('expected the complete seven-scale input manifest')
    indexed = {}
    for case in manifest['cases']:
        key = case['family'], case['source_ep_rows']
        if key in indexed:
            raise ValueError('duplicate input case in source manifest')
        indexed[key] = case
    expected = {(family, size) for family in ('fixed-cfg', 'growing-cfg') for size in manifest['sizes']}
    if set(indexed) != expected:
        raise ValueError('input manifest must cover every scale in both fixture families')
    return {size: indexed['growing-cfg', size] for size in manifest['sizes']}


def summarize(rows, sizes=SIZES):
    results = []
    for size in sizes:
        selected = [r for r in rows if int(r['source_ep_rows']) == size and r['warmup'] is False]
        good = [r for r in selected if r['outcome'] == 'verified' and r['verified'] is True]
        shapes = {(r['plonk_gates'], r['raw_bound'], r['padded_domain']) for r in selected
                  if r['plonk_gates'] != ''}
        if len(shapes) > 1:
            raise ValueError('observed shape changed between repetitions')
        result = dict(family='growing-cfg', source_ep_rows=size, path_mode='complete',
                      planned=3, attempted=sum(r['returncode'] != '' for r in selected),
                      verified=len(good), outcomes=[r['outcome'] for r in selected])
        if shapes:
            result.update(zip(('plonk_gates', 'raw_bound', 'padded_domain'), next(iter(shapes))))
        result['measurements'] = {}
        for name in METRICS:
            values = [float(r[name]) for r in good if r[name] != '']
            result['measurements'][name] = (dict(count=len(values), median=statistics.median(values),
                min=min(values), max=max(values)) if values else None)
        results.append(result)
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inputs', type=Path, required=True)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--build-metadata', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--max-rss-gib', type=float, default=20)
    p.add_argument('--proof-timeout-s', type=float, default=1800)
    p.add_argument('--max-proof-domain', type=int, default=1 << 23)
    p.add_argument('--max-preflight-estimated-domain', type=int, default=1 << 24)
    a = p.parse_args()
    if platform.system() != 'Darwin':
        raise ValueError('requires macOS time -l and process-group RSS monitor')
    if any(not math.isfinite(x) or x <= 0 for x in (a.max_rss_gib, a.proof_timeout_s,
            a.max_proof_domain, a.max_preflight_estimated_domain)):
        raise ValueError('resource limits must be finite and positive')
    control.sample_group_rss(os.getpgrp())
    os.umask(0o077)
    signal.signal(signal.SIGTERM, lambda _s, _f: (_ for _ in ()).throw(KeyboardInterrupt()))
    source, output, original_binary = a.inputs.resolve(), a.output.resolve(), a.binary.resolve()
    if output.exists():
        raise FileExistsError('refusing to overwrite an existing campaign')
    build = control.load(a.build_metadata)
    if build['binary']['sha256'] != control.sha256(original_binary):
        raise ValueError('build metadata does not match executable')
    manifest = control.load(source/'manifest.json')
    planned_inputs = planned_grid(manifest)
    sizes = manifest['sizes']
    planned_proofs = len(planned_inputs) * 3
    output.mkdir(parents=True, mode=0o700)
    for name in ('inputs', 'logs', 'reports', 'native'):
        (output/name).mkdir(mode=0o700)
    binary = output/'native/plonk-scaling'
    shutil.copy2(original_binary, binary)
    shutil.copy2(a.build_metadata, output/'build-metadata.json')
    shutil.copy2(source/'manifest.json', output/'source-manifest.json')
    inputs = {}
    audit = []
    for size in sizes:
        original = source/'growing-cfg'/str(size)
        case = control.load(original/'case.json')
        if (case != planned_inputs[size] or case['family'] != 'growing-cfg' or case['source_ep_rows'] != size
                or case['rows_by_mode']['complete'] != size):
            raise ValueError('source case identity or complete rows mismatch')
        target = output/'inputs'/str(size)
        target.mkdir()
        shutil.copy2(original/'case.json', target/'case.json')
        for name in (*ARTIFACTS, 'static_returns.tsv'):
            before = control.sha256(original/'complete'/name)
            if before != case['input_sha256']['complete'][name]:
                raise ValueError('source file hash differs from case manifest')
            shutil.copy2(original/'complete'/name, target/name)
            after = control.sha256(target/name)
            if after != before:
                raise ValueError('frozen input copy differs')
            audit.append(dict(source_path=str(original/'complete'/name), frozen_path=str(target/name),
                              sha256=after, mode='complete', source_ep_rows=size))
        inputs[size] = case
    control.save_json(output/'input-audit.json', dict(files=audit, all_byte_identical=True,
        source_manifest_sha256=control.sha256(source/'manifest.json'),
        scope='same complete raw24 typed artifacts and capacities as Binius; synthetic inputs'))
    base = {k:v for k,v in os.environ.items() if not k.startswith('ZKCFA_')}
    base['RAYON_NUM_THREADS'] = '8'
    rss_limit = int(a.max_rss_gib * (1 << 30))
    start = utc()
    rows, warmups, preflights = [], [], []
    identity = dict(schema='zkcfa.plonk.synthetic-scaling-campaign.v1', started_utc=start,
        binary_sha256=control.sha256(binary), build_metadata_sha256=control.sha256(output/'build-metadata.json'),
        runner_sha256=control.sha256(Path(__file__)), controller_sha256=control.sha256(Path(control.__file__)),
        process_controller_sha256=control.sha256(Path(control.process_control.__file__)),
        source_manifest_sha256=control.sha256(source/'manifest.json'), threads=8,
        repetitions=3, excluded_warmups=1, sizes=sizes, path_mode='complete',
        resource_limits=dict(max_rss_bytes=rss_limit, proof_timeout_s=a.proof_timeout_s,
            max_proof_domain=a.max_proof_domain,
            max_preflight_estimated_domain=a.max_preflight_estimated_domain),
        timing_scope=dict(cryptographic_prove='Prover::prove with precomputed key and synthesized witness; includes library witness cleanup',
            setup='fresh universal KZG SRS, public capacity-selected compile, commitment key trim',
            witness_localcheck='RawCircuit construction, gadget synthesis, local circuit satisfaction, public input equality',
            verify='serialized proof decoding and verification with independently reconstructed four public inputs'),
        platform=platform.platform(), python=platform.python_version(),
        statement_scope='synthetic relation benchmark; no acquisition or signature timings',
        commitment='production Poseidon over BLS12-381 scalar field',
        circuit_size='observed StandardComposer::total_size; padded domain is separate metadata')
    control.save_json(output/'run-identity.json', identity)

    def invoke(size, repetition, *, warmup=False, preflight=False, expected_shape=None):
        case = inputs[size]
        row = dict.fromkeys(FIELDS, '')
        row.update(family='growing-cfg', source_ep_rows=size, path_mode='complete', repetition=repetition,
                   warmup=warmup, edge_cap=case['binius_edge_cap'], ep_cap=case['binius_ep_cap']['complete'],
                   started_utc=utc())
        for name in ARTIFACTS:
            row[name+'_sha256'] = case['input_sha256']['complete'][name]
        estimate = control.guard_estimate(row['edge_cap'], row['ep_cap'])
        row['estimated_gates_guard'], row['estimated_domain_guard'] = estimate
        suffix = 'preflight' if preflight else 'warmup' if warmup else f'rep-{repetition}'
        stem = f'growing-cfg-{size}-{suffix}'
        if estimate[1] > a.max_preflight_estimated_domain:
            row.update(outcome='resource-skipped-estimated-domain', completed_utc=utc())
            return row
        if expected_shape:
            row.update({k:expected_shape[k] for k in ('plonk_gates', 'raw_bound', 'padded_domain')})
            if expected_shape['padded_domain'] > a.max_proof_domain:
                row.update(outcome='resource-skipped-observed-domain', completed_utc=utc())
                return row
        command = [str(binary), '--typed-dir', str(output/'inputs'/str(size)),
                   '--edge-cap', str(row['edge_cap']), '--ep-cap', str(row['ep_cap'])]
        if preflight:
            command.append('--preflight')
        if warmup:
            command.append('--negative-check')
        print(json.dumps(dict(source_ep_rows=size, stage=suffix, status='started')), flush=True)
        result = control.timed(command, env=base, cwd=output, timeout=a.proof_timeout_s,
                               rss_limit=rss_limit, log_stem=output/'logs'/stem)
        row.update(wall_ms=result['wall_ms'], peak_rss_bytes=result['peak_rss_bytes'],
            peak_memory_footprint_bytes=result['peak_memory_footprint_bytes'],
            returncode=result['returncode'], stop_reason=result['stop'],
            cleanup_complete=result['cleanup_complete'], controller_log=result['controller_log'], completed_utc=utc())
        status = control.process_status(result)
        row['outcome'] = status
        if status:
            row['failure_note'] = control.failure_note(result)
        else:
            try:
                reports = [json.loads(line) for line in result['stdout'].splitlines() if line.startswith('{')]
                if len(reports) != 1:
                    raise ValueError('missing or ambiguous native report')
                report = reports[0]
                audit_report(report, case, preflight=preflight)
                if expected_shape and report['constraints'] != expected_shape:
                    raise ValueError('proof constraints differ from preflight')
                report_path = output/'reports'/(stem+'.json')
                control.save_json(report_path, report)
                row.update(outcome='satisfied' if preflight else 'verified',
                    nodes=report['instance']['nodes'], edges=report['instance']['edges'], proof_rows=report['instance']['steps'],
                    report_file=str(report_path), report_sha256=control.sha256(report_path),
                    verified=report['verified'], wrong_endpoint_rejected=report.get('wrong_endpoint_rejected', ''))
                row.update(report['constraints'])
                for name, value in report['phases_ms'].items():
                    if name+'_ms' in FIELDS:
                        row[name+'_ms'] = value
                row['proof_bytes'] = report.get('proof_bytes', '')
            except (ValueError, KeyError) as error:
                row.update(outcome='audit-failed', failure_note=str(error))
        print(json.dumps(dict(source_ep_rows=size, stage=suffix, status=row['outcome'],
            plonk_gates=row['plonk_gates'], cryptographic_prove_ms=row['cryptographic_prove_ms'])), flush=True)
        if result['cleanup_complete'] is not True:
            control.save_json(output/'cleanup-unconfirmed-attempt.json', row)
            raise RuntimeError('cleanup unconfirmed; no following benchmark launched')
        if status == 'interrupted':
            control.save_json(output/'interrupted-attempt.json', row)
            raise KeyboardInterrupt()
        return row

    for size in sizes:
        before = invoke(size, 0, preflight=True)
        preflights.append(before)
        write_rows(output/'preflights.csv', preflights)
        expected_shape = {name:before[name] for name in ('plonk_gates', 'raw_bound', 'padded_domain')}
        if before['outcome'] == 'satisfied' and size == sizes[0]:
            warmup = invoke(size, 0, warmup=True, expected_shape=expected_shape)
            warmups.append(warmup)
            write_rows(output/'warmups.csv', warmups)
            if warmup['outcome'] != 'verified' or warmup['wrong_endpoint_rejected'] is not True:
                raise RuntimeError('warmup positive/altered-public-input integration check failed')
        for repetition in range(1, 4):
            if before['outcome'] == 'satisfied':
                row = invoke(size, repetition, expected_shape=expected_shape)
            else:
                row = dict(before, repetition=repetition, outcome='not-attempted-preflight-failed',
                           returncode='', wall_ms='', peak_rss_bytes='', peak_memory_footprint_bytes='')
            rows.append(row)
            write_rows(output/'results.csv', rows)
            control.save_json(output/'summary.json', dict(schema='zkcfa.plonk.synthetic-scaling-summary.v1',
                complete=len(rows) == planned_proofs, results=summarize(rows, sizes)))
    for entry in audit:
        if control.sha256(entry['source_path']) != entry['sha256'] or control.sha256(entry['frozen_path']) != entry['sha256']:
            raise ValueError('source/frozen input mutated during experiment')
    metadata = dict(identity, completed_utc=utc(), planned_proofs=planned_proofs,
        proof_processes=sum(r['returncode'] != '' for r in rows),
        verified_proofs=sum(r['verified'] is True for r in rows),
        excluded_warmup_verified=warmups[0]['verified'], altered_endpoint_rejected=warmups[0]['wrong_endpoint_rejected'],
        input_byte_identity=True, observed_input_files=len(audit),
        results_sha256=control.sha256(output/'results.csv'), summary_sha256=control.sha256(output/'summary.json'),
        preflights_sha256=control.sha256(output/'preflights.csv'), warmups_sha256=control.sha256(output/'warmups.csv'),
        input_audit_sha256=control.sha256(output/'input-audit.json'))
    control.save_json(output/'metadata.json', metadata)
    print(json.dumps(dict(status='complete', verified=metadata['verified_proofs'], planned=planned_proofs,
                         metadata=str(output/'metadata.json'))), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
