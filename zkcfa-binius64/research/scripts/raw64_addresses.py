#!/usr/bin/env python3
"""Acquire real x86-64 PIE traces with their high address bits retained.

Run inside the existing provider image, mounting this repository and the source
campaign at identical absolute host/container paths. The source campaign is
read only. This harness provisions a policy before each fresh QEMU execution;
it never relocates an already captured trace. The high lane requires a zero
runtime normalization bias, making every emitted instruction PC its actual
guest virtual address. The low lane retains the established raw24 namespace.

This evaluates 47-bit Linux user virtual addresses, not arbitrary 64-bit
canonical mappings, shared-library coverage, or native hardware acquisition.
Proof timing is deliberately delegated to the host-native experiment runner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

LOW_BASE = 0x400000
HIGH_BASE = 0x555555556000
SPECIAL_BASE = 0xFFFE0000
SPECIAL_END = 0xFFFF0000


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def save(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    tmp.replace(path)


def run(command: list[str], log: Path, *, env: dict[str, str]) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open('w') as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT,
                                env=env, timeout=600)
    if result.returncode:
        raise RuntimeError(f'command failed ({result.returncode}), see {log}')


def trace_range(trace: Path) -> dict[str, object]:
    lo, hi, count = 2 ** 64, 0, 0
    with trace.open() as stream:
        header = stream.readline().strip()
        match = re.fullmatch(r'zkcfa.scope.trace elf_sha256=([0-9a-f]{64}) runtime_bias=(0x[0-9a-f]+)', header)
        if not match:
            raise ValueError(f'unexpected trace header: {trace}')
        bias = int(match[2], 0)
        for line in stream:
            fields = line.split()
            if fields and fields[0] == 'insn':
                pc = int(fields[2], 0)
                lo, hi = min(lo, pc), max(hi, pc)
                count += 1
    if not count:
        raise ValueError('empty instruction trace')
    return {'runtime_bias': hex(bias), 'instruction_count': count,
            'canonical_pc_min': hex(lo), 'canonical_pc_max': hex(hi),
            'canonical_pc_bits': hi.bit_length(),
            'runtime_pc_min': hex(lo + bias), 'runtime_pc_max': hex(hi + bias),
            'runtime_pc_bits': (hi + bias).bit_length(),
            'runtime_pc_derivation': 'plugin canonical PC + measured runtime_bias',
            'canonical_pc_equals_runtime_pc': bias == 0}


def policy_at_base(source: Path, target: Path, base: int) -> None:
    policy = json.loads(source.read_text())
    delta = base - LOW_BASE
    for table in ('indirect_calls', 'indirect_jumps'):
        policy[table] = {hex(int(site, 0) + delta): [hex(int(dst, 0) + delta) for dst in dests]
                         for site, dests in policy[table].items()}
    save(target, policy)


def prepare(args: argparse.Namespace) -> None:
    source = args.source.resolve()
    out = args.output.resolve()
    provider = args.provider.resolve()
    if source == out or source in out.parents:
        raise ValueError('output must not modify or nest inside the source campaign')
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONPATH=str(provider), PYTHONDONTWRITEBYTECODE='1', LD_BIND_NOW='1')
    for key in tuple(env):
        if key.startswith('QEMU_') or key in {'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT'}:
            env.pop(key)
    manifest_path = source / 'inputs.json'
    manifest = json.loads(manifest_path.read_text())
    rows = manifest['applications']
    requested = set(args.applications.split(',')) if args.applications else {r['application'] for r in rows}
    if requested - {r['application'] for r in rows}:
        raise ValueError('unknown application')
    plugin = out / 'trace_scope.so'
    flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'glib-2.0'], text=True).split()
    run(['gcc', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
         '-I' + str(args.qemu.parent.parent / 'include'), '-DQEMU_PLUGIN',
         str(provider / 'qemu/trace_scope.c'), '-o', str(plugin), *flags], out / 'plugin-build.log', env=env)
    outcomes = []
    for row in rows:
        app = row['application']
        if app not in requested:
            continue
        source_app = source / 'inputs' / app
        if digest(source_app / app) != row['elf_sha256']:
            raise ValueError(f'{app}: input ELF hash differs')
        profile = row['runtime_profile']
        sysroot = source / 'sysroots' / profile
        if digest(sysroot / 'runtime-dependencies.json') != manifest['runtime_dependencies_sha256'][profile]:
            raise ValueError(f'{app}: runtime manifest hash differs')
        for lane in args.lanes.split(','):
            base = {'low': LOW_BASE, 'wide': args.high_base}[lane]
            app_out = out / 'inputs' / lane / app
            result_file = app_out / 'capture.json'
            if result_file.exists():
                previous = json.loads(result_file.read_text())
                if previous['canonical_base'] != hex(base) or previous['elf_sha256'] != row['elf_sha256']:
                    raise ValueError(f'{app}/{lane}: resume metadata mismatch')
                for name, sha in previous['artifact_sha256'].items():
                    if digest(app_out / name) != sha:
                        raise ValueError(f'{app}/{lane}: resume artifact changed: {name}')
                outcomes.append(previous)
                continue
            if app_out.exists():
                raise FileExistsError(f'incomplete lane exists: {app_out}')
            app_out.mkdir(parents=True)
            binary = app_out / app
            shutil.copy2(source_app / app, binary)
            artifacts = app_out / 'artifacts'
            logs = app_out / 'logs'
            command = [sys.executable, '-m', 'static.provision', '--architecture', 'x86_64',
                       '--canonical-bias', hex(base), '--external-entry', '--root-symbol', 'main',
                       '--caller-symbol', 'external-loader', '--application', app, '--elf', str(binary),
                       '--out-dir', str(artifacts), '--max-out-degree', '64',
                       '--runtime-dependencies', str(sysroot / 'runtime-dependencies.json'),
                       '--runtime-profile', profile]
            policy = source_app / 'indirect-policy.json'
            if policy.exists():
                new_policy = app_out / 'indirect-policy.json'
                policy_at_base(policy, new_policy, base)
                command += ['--indirect-policy', str(new_policy)]
            run(command, logs / 'provision.log', env=env)
            trace = app_out / 'trace.log'
            qemu_command = [str(args.qemu), '-L', str(sysroot), '-plugin',
                            f'{plugin},map={artifacts / "plugin-map.txt"},log={trace}', str(binary)]
            started = time.perf_counter()
            run(qemu_command, logs / 'qemu.log', env=env)
            capture_ms = (time.perf_counter() - started) * 1000
            measured = trace_range(trace)
            if lane == 'wide' and measured['canonical_pc_equals_runtime_pc'] is not True:
                raise ValueError(f'{app}: high lane did not preserve exact runtime addresses: {measured}')
            if lane == 'wide' and measured['canonical_pc_bits'] < 47:
                raise ValueError(f'{app}: high lane did not reach 47-bit addresses')
            run([sys.executable, '-m', 'static.normalize', '--map', str(artifacts / 'plugin-map.txt'),
                 '--trace', str(trace), '--typed-cfg', str(artifacts / 'typed_cfg'),
                 '--translator', str(artifacts / 'translator'), '--static-manifest',
                 str(artifacts / 'static-manifest.json'), '--output', str(artifacts / 'recorded_path'),
                 '--evidence', str(artifacts / 'evidence.json')], logs / 'normalize.log', env=env)
            evidence = json.loads((artifacts / 'evidence.json').read_text())
            if evidence['boundary']['complete'] is not True or evidence['runtime_code_match'] is not True:
                raise ValueError(f'{app}: incomplete or mismatched execution evidence')
            run([sys.executable, '-m', 'static.shadow_safe_bundle', '--input-bundle', str(artifacts),
                 '--output', str(app_out / 'shadow')], logs / 'projection.log', env=env)
            result = {'application': app, 'lane': lane, 'classification': 'fresh QEMU execution',
                      'canonical_base': hex(base), 'elf_sha256': digest(binary),
                      'source_campaign_manifest_sha256': digest(manifest_path),
                      'runtime_profile': profile, 'capture_ms': capture_ms, 'addresses': measured,
                      'provision_command': command, 'qemu_command': qemu_command,
                      'complete_boundary': True, 'runtime_code_match': True,
                      'complete_rows': len((artifacts / 'recorded_path').read_text().splitlines()) - 1,
                      'shadow_rows': len((app_out / 'shadow/recorded_path').read_text().splitlines()) - 1,
                      'artifact_sha256': {str(p.relative_to(app_out)): digest(p) for p in app_out.rglob('*') if p.is_file()}}
            save(result_file, result)
            outcomes.append(result)
            print(json.dumps({k: result[k] for k in ('application', 'lane', 'complete_rows', 'shadow_rows', 'addresses')}), flush=True)
        save(out / 'captures.json', {'schema': 'zkcfa.raw64-address-capture.v1',
             'source': str(source), 'source_manifest_sha256': digest(manifest_path),
             'provider_source_sha256': {str(p.relative_to(provider)): digest(p) for p in provider.rglob('*.py')},
             'plugin_source_sha256': digest(provider / 'qemu/trace_scope.c'),
             'plugin_sha256': digest(plugin), 'qemu_sha256': digest(args.qemu), 'captures': outcomes})


def sign(args: argparse.Namespace) -> None:
    sys.path[:0] = [str(args.provider), str(args.integration)]
    from bundle import build_signed_raw_bundle
    out = args.output.resolve()
    captures = json.loads((out / 'captures.json').read_text())
    summaries = []
    for capture in captures['captures']:
        app, lane = capture['application'], capture['lane']
        app_root = out / 'inputs' / lane / app
        for mode in ('complete', 'shadow'):
            run_dir = out / 'signed' / lane / app / mode
            result_path = run_dir / 'protocol-result.json'
            if result_path.exists():
                result = json.loads(result_path.read_text())
            else:
                kw = {'complete_source_artifacts': app_root / 'artifacts',
                      'source_trace_path': app_root / 'trace.log'} if mode == 'shadow' else {}
                result = build_signed_raw_bundle(run_dir=run_dir,
                    artifacts=app_root / ('artifacts' if mode == 'complete' else 'shadow'),
                    policy_artifacts=app_root / 'artifacts', binary=app_root / app,
                    trace_path=app_root / 'trace.log', path_mode=mode,
                    profile='raw64-typed-channels' if lane == 'wide' else 'raw24-full-key', **kw)
            summaries.append({'application': app, 'lane': lane, 'path_mode': mode,
                              'protocol_result': str(result_path), 'bundle': result['bundle'],
                              'authority_sha256': result['authority_sha256'],
                              'challenge': result['challenge'], 'circuit': result['circuit']})
            save(out / 'bundles.json', {'schema': 'zkcfa.raw64-address-bundles.v1', 'bundles': summaries})
            print(json.dumps({'application': app, 'lane': lane, 'path_mode': mode, 'bundle': result['bundle']}), flush=True)


def audit(args: argparse.Namespace) -> None:
    """Compare independently captured lanes; normalized strings are audit only."""
    out = args.output.resolve()
    captures = json.loads((out / 'captures.json').read_text())['captures']
    applications = sorted({row['application'] for row in captures})
    checks = []
    for app in applications:
        low, wide = (out / 'inputs' / lane / app for lane in ('low', 'wide'))
        wide_capture = json.loads((wide / 'capture.json').read_text())
        delta = int(wide_capture['canonical_base'], 0) - LOW_BASE

        def lower(match: re.Match[str]) -> str:
            address = int(match[0], 0)
            return hex(address - delta) if address >= int(wide_capture['canonical_base'], 0) else hex(address)

        passed = {}
        for relative in ('artifacts/translator', 'artifacts/typed_cfg',
                         'artifacts/recorded_path', 'shadow/recorded_path'):
            first = (low / relative).read_text().splitlines()
            second = re.sub(r'0x[0-9a-f]+', lower, (wide / relative).read_text()).splitlines()
            if relative.endswith(('translator', 'typed_cfg')):
                first, second = sorted(first), sorted(second)
            if first != second:
                raise ValueError(f'{app}: low/high control-flow mismatch in {relative}')
            passed[relative] = True
        def insns(path: Path, convert: bool) -> list[str]:
            with path.open() as stream:
                return [re.sub(r'0x[0-9a-f]+', lower, line) if convert else line
                        for line in stream if line.startswith('insn ')]
        if insns(low / 'trace.log', False) != insns(wide / 'trace.log', True):
            raise ValueError(f'{app}: independent executions took different instruction paths')
        passed['instruction_execution_sequence'] = True
        if digest(low / app) != digest(wide / app):
            raise ValueError(f'{app}: ELF differs between lanes')
        passed['same_elf'] = True
        if wide_capture['addresses']['canonical_pc_equals_runtime_pc'] is not True:
            raise ValueError(f'{app}: runtime address normalization remains in high lane')
        passed['high_pc_equals_actual_runtime_pc'] = True
        checks.append({'application': app, 'passed': passed})
    result = {'schema': 'zkcfa.raw64-address-pair-audit.v1',
              'all_passed': True, 'applications': len(applications),
              'comparison': 'address subtraction is used only in this read-only audit; no proof input is rewritten',
              'checks': checks}
    save(out / 'pair-audit.json', result)
    print(json.dumps({'applications': len(applications), 'all_passed': True}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('prepare', 'sign', 'audit'))
    parser.add_argument('--source', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--provider', required=True, type=Path)
    parser.add_argument('--integration', type=Path)
    parser.add_argument('--qemu', type=Path, default=Path('/opt/qemu/build/qemu-x86_64'))
    parser.add_argument('--high-base', type=lambda s: int(s, 0), default=HIGH_BASE)
    parser.add_argument('--applications')
    parser.add_argument('--lanes', default='low,wide')
    args = parser.parse_args()
    if args.operation == 'prepare':
        if not args.source:
            parser.error('prepare requires --source')
        prepare(args)
    elif args.operation == 'sign':
        if not args.integration:
            parser.error('sign requires --integration')
        sign(args)
    else:
        audit(args)


if __name__ == '__main__':
    main()
