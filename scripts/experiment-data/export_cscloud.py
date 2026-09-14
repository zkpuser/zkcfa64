#!/usr/bin/env python3
"""Export a public CSCloud data package from explicitly pinned, closed statistics."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime
import hashlib
import io
import json
import math
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile

APPS = tuple('aha-mont64 crc32 cubic edn huffbench matmult-int md5sum minver nbody nettle-aes nettle-sha256 nsichneu picojpeg primecount sglib-combined slre st statemate tarfind ud wikisort'.split())
SIZES = (64, 128, 256, 512, 1024, 2048, 4096)
BLOCKS = ('modes', 'controls', 'online', 'structural', 'matched', 'backends', 'released', 'repaired', 'repair-control', 'raw64')
CONTROL_SECTIONS = {'membership', 'matched512', 'zekra-matched512', 'backend-pair', 'mode-auth'}
STAGES = {
    'modes': ('acquisition', 'signing', 'mode-proofs'),
    'controls': ('membership', 'binius-matched512', 'zekra-matched512', 'backend-pair-benchmark'),
    'online': ('online',),
    'structural': ('binius-scaling', 'plonk-scaling', 'zekra-scaling', 'binius-stack', 'zekra-stack', 'zekra-stack-fixed', 'zekra-stack-verify', 'zekra-stack-fixed-verify'),
    'matched': ('matched-apps',), 'backends': ('matched-apps', 'plonk-apps', 'plonk-picojpeg-actual'),
    'released': ('zekra-released',), 'repaired': ('zekra-released', 'zekra-released-repaired'),
    'repair-control': ('zekra-repair-control',),
    'raw64': ('raw64-acquisition', 'raw64-audit', 'raw64-signing', 'raw64-proofs'),
}
SCIENTIFIC_FAILURE_STAGES = {'zekra-scaling', 'raw64-proofs'}
TOP_FIELDS = {'schema', 'rows', 'table_IV', 'aggregates', 'coverage', 'definition', 'pairs', 'plonk_selection',
              'sections', 'statistics', 'matched512_ratios', 'scaling', 'scaling_attempts', 'stack', 'units', 'policy', 'section'}
DROP_FIELDS = {'provenance', 'run_root', 'exported_utc', 'run_started_utc', 'evidence', 'command', 'commands',
               'argv', 'invocation', 'native_command', 'process_argv', 'warmup_metrics', 'source', 'keys',
               'stdout', 'stderr', 'stdout_text', 'stderr_text', 'log_text', 'trace', 'trace_text', 'raw_trace',
               'worker', 'private', 'payload', 'report', 'transcript', 'signature', 'nonce', 'challenge',
               'public_key', 'public_keys', 'keypair', 'keypairs', 'sk', 'blindcfg', 'blindep', 'r_cfg', 'r_ep',
               'pid', 'ppid', 'pgid', 'uid', 'gid', 'remaining_pids', 'foreign_pids', 'zombie_pids'}
SECRET_FIELD = re.compile(r'(^|_)(?:secret|seed|opening|openings|blind|blinding|private_key|secret_key|signing_key|secret_keys|private_keys)(?:_|$)', re.I)
PERSONAL_PATH = re.compile(r"(?<![A-Za-z0-9:/])/[A-Za-z0-9_.-]+(?:/[^\s\"'<>\[\]{},;]+)*|[A-Za-z]:\\[^\s\"']+|~/(?:[^\s\"']+)")
HASH = re.compile(r'[0-9a-f]{64}\Z')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()


def digest(path):
    with Path(path).open('rb') as stream:
        h = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def unique(rows, fields, expected):
    keys = [tuple(row[key] for key in fields) for row in rows]
    require(len(keys) == len(set(keys)) and set(keys) == set(expected), 'incomplete/duplicate grid: ' + ','.join(fields))


def reject_unfinished(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ('status', 'outcome', 'reported_proof_status', 'reported_preflight_status'):
                require(item not in ('running', 'pending', 'not-run', 'in-progress'), 'unfinished result: ' + str(item))
            reject_unfinished(item)
    elif isinstance(value, list):
        for item in value:
            reject_unfinished(item)


def validate_block(name, data):
    reject_unfinished(data)
    if name in ('controls', 'online'):
        require(data.get('schema') == 'zkcfa.control-results.v1', 'wrong control schema')
        expected = CONTROL_SECTIONS if name == 'controls' else {'online'}
        require(set(data['sections']) == expected, 'wrong selected control sections')
        if name == 'online':
            s = data['sections']['online']
            require(s['formal_verified'] == 5 and s['warmups_verified'] == 1, 'online schedule incomplete')
        else:
            for key in ('membership', 'matched512', 'backend-pair'):
                s = data['sections'][key]
                expected_variants = {'membership': {'binmult', 'indexed', 'logup'}, 'matched512': {'binius'}, 'backend-pair': {'fork', 'upstream'}}[key]
                require(set(s['results']) == expected_variants, 'control variants incomplete: ' + key)
                require(all(v['formal_verified'] == 5 and v['warmups_verified'] == 1 for v in s['results'].values()), 'control schedule incomplete')
            s = data['sections']['zekra-matched512']
            require(s['formal_verified'] == 5 and s['warmups_verified'] == 1, 'ZEKRA matched schedule incomplete')
        return
    if name == 'structural':
        require(data.get('schema') == 'zkcfa.final.structural-results.v1' and data.get('section') == 'all', 'full structural export required')
        expected = {('Binius64', f, n, m) for f in ('growing-cfg', 'fixed-cfg') for n in SIZES for m in ('complete', 'shadow')}
        expected |= {(b, 'growing-cfg', n, m) for b, m in (('PLONK', 'complete'), ('ZEKRA', 'zekra')) for n in SIZES}
        unique(data['scaling'], ('backend', 'family', 'source_ep_rows', 'mode'), expected)
        for row in data['scaling']:
            require(row['planned'] == 3 and row['attempted'] + row['not_attempted'] == 3
                    and row['verified'] + row['failed'] == row['attempted'], 'scaling accounting incomplete')
            require(row['full_three_run_errorbar'] is (row['verified'] == 3), 'invalid error-bar flag')
        points = {('length', n, 8) for n in SIZES} | {('depth', 1024, n) for n in (1,2,4,8,16,32,64,128,256)} | {('diagonal', n, n//4) for n in SIZES}
        expected = {(b,f,n,depth) for b in ('Binius64','ZEKRA') for f,n,depth in points}
        expected |= {('ZEKRA','fixed-pointer15',1024,n) for n in (1,8,32,256)}
        unique(data['stack'], ('backend','family','L','D'), expected)
        require(data['policy']['fresh_measurements_only'] is True and data['policy']['missing_runs_are_not_zero'] is True, 'wrong structural policy')
        return
    require(data.get('schema') == f'zkcfa.final-reproduction.applications.{name}.v1', 'wrong application schema: ' + name)
    rows = data['rows']
    if name == 'modes':
        unique(rows, ('application','mode'), ((a,m) for a in APPS for m in ('complete','shadow')))
    elif name == 'matched':
        unique(rows, ('application','backend'), ((a,b) for a in APPS for b in ('binius','zekra')))
    elif name == 'backends':
        unique(rows, ('application',), ((a,) for a in APPS))
        for row in rows:
            for backend in ('binius','zekra','plonk'):
                require(row[backend]['application'] == row['application'], 'backend/application mismatch')
        selection = data.get('plonk_selection')
        require(selection and selection['application'] == 'picojpeg', 'actual picojpeg supplemental result missing')
        require(selection['primary']['attempted'] == 0 and selection['supplement']['preflight_attempted'] == 1,
                'supplement must preserve the unexecuted primary scheduling record')
    elif name in ('released','repaired'):
        unique(rows, ('application',), ((a,) for a in (*APPS,'crc32-control-500')))
        require(sum(row['excluded_control'] is True for row in rows) == 1, 'released positive-control accounting wrong')
    elif name == 'raw64':
        unique(rows, ('application','mode','profile'), ((a,m,p) for a in APPS for m in ('complete','shadow') for p in ('raw24','raw64')))
    elif name == 'repair-control':
        unique(rows, ('control',), (('SmartMemory-native-field',),))
        require(rows[0]['validated'] is True and rows[0]['excluded_from_formal_timings'] is True, 'repair control not validated')


class Package:
    def __init__(self, root, repo):
        self.root = Path(root).resolve(strict=True)
        self.repo = Path(repo).resolve(strict=True)
        self.reads = {}
        self.identities = {'inputs': {}, 'sources': {}, 'binaries': {}, 'exporters': {}}
        self.selected = {}
        self.stages = {}

    def path(self, relative):
        require(isinstance(relative, str) and not Path(relative).is_absolute() and '..' not in PurePosixPath(relative).parts,
                'expected safe run-relative path')
        path = self.root / relative
        require(not any(p.is_symlink() for p in (path, *path.parents) if p.is_relative_to(self.root)), 'symlink evidence is not allowed')
        resolved = path.resolve(strict=True)
        require(resolved.is_relative_to(self.root) and resolved.is_file(), 'evidence escapes run or is not a file')
        return resolved

    def read(self, relative, expected=None):
        path = self.path(relative)
        require(path.stat().st_size <= 32 * 1024 * 1024, 'unexpectedly large metadata/statistics file')
        payload = path.read_bytes(); actual = digest_bytes(payload)
        require(expected is None or expected == actual, 'SHA256 mismatch: ' + relative)
        require(relative not in self.reads or self.reads[relative] == actual, 'input changed during packaging')
        self.reads[relative] = actual
        return json.loads(payload)

    def relative_identity(self, value, source=False):
        value = str(value)
        if Path(value).is_absolute():
            value = str(Path(value).resolve())
        for root, prefix in ((self.root, 'run/'), (self.repo, 'repo/')):
            if value == str(root):
                return prefix.rstrip('/')
            if value.startswith(str(root) + '/'):
                return prefix + value[len(str(root))+1:]
        require(not Path(value).is_absolute() and '..' not in PurePosixPath(value).parts,
                'identity outside this repository/run')
        return ('repo/' if source else 'run/') + value

    def remember(self, role, name, value, block):
        require(isinstance(value, str) and HASH.fullmatch(value), 'invalid identity SHA256')
        # Source/exporter versions can differ between frozen snapshots; retain each claim.
        key = (name, value)
        self.identities[role].setdefault(key, set()).add(block)

    def ledger(self, data, block, sources=False):
        require(isinstance(data, dict), 'identity ledger must be an object')
        for raw, value in data.items():
            name = self.relative_identity(raw, source=sources)
            low = name.lower(); filename = PurePosixPath(low).name
            if SECRET_FIELD.search(filename) or any(p in ('keys','secrets','.ssh') for p in PurePosixPath(low).parts):
                continue
            if sources or filename.endswith(('.rs','.py','.java','.c','.h','.s')) or filename in ('cargo.toml','cargo.lock','dockerfile','makefile'):
                self.remember('sources', name, value, block)
            elif '/bin/' in low or filename.endswith('.jar'):
                self.remember('binaries', name, value, block)
            elif filename in ('translator','typed_cfg','recorded_path','static_returns.tsv','events.tsv','events.json','adjlist','numified_adjlist','numified_path','inputs.json','manifest.json','case.json','pair-audit.json','captures.json') or filename.endswith(('.arith','.in')):
                self.remember('inputs', name, value, block)

    def stage(self, name, run, expected=None):
        record = self.read(f'logs/{name}.process.json', expected)
        require(record.get('stage') == name and record.get('status') in ('complete','failed') and record.get('finished_utc'), 'stage is not terminal: ' + name)
        require(record.get('exit_code') in ((0,1) if name in SCIENTIFIC_FAILURE_STAGES else (0,2) if name=='mode-proofs' else (0,)), 'stage did not close as required: ' + name)
        date = lambda v: datetime.fromisoformat(v.replace('Z','+00:00'))
        require(date(record['finished_utc']) >= date(record['started_utc']) >= date(run['started_utc']), 'stage is from another run: ' + name)
        self.stages[name] = {k:record[k] for k in ('stage','status','exit_code','started_utc','finished_utc','log_sha256','controller_sha256') if k in record}

    def load(self, name, spec, run):
        directory = spec['directory']
        require(isinstance(directory,str) and directory.startswith('exports/') and '..' not in PurePosixPath(directory).parts, 'only an explicit export directory may be selected')
        kind = 'control' if name in ('controls','online') else 'structural' if name == 'structural' else 'application'
        manifest_name = 'evidence.json' if kind == 'control' else 'structural-results.json' if kind == 'structural' else 'manifest.json'
        manifest = self.read(directory + '/' + manifest_name, spec['manifest_sha256'])
        self.selected[name] = dict(directory=directory,manifest=manifest_name,manifest_sha256=spec['manifest_sha256'])
        if kind == 'application':
            require(manifest.get('schema') == 'zkcfa.final-reproduction.application-export.v1' and Path(manifest['run_root']).resolve() == self.root and name in manifest['sections'], 'wrong application export identity')
            require(name+'.json' in manifest['output_sha256'] and name+'.csv' in manifest['output_sha256'], 'application statistics incomplete')
            data = self.read(directory+'/'+name+'.json', manifest['output_sha256'][name+'.json'])
            require(digest(self.path(directory+'/'+name+'.csv')) == manifest['output_sha256'][name+'.csv'], 'CSV hash differs')
            self.reads[directory+'/'+name+'.csv'] = manifest['output_sha256'][name+'.csv']
            evidence_ledger=manifest['evidence_sha256']
            self.ledger(evidence_ledger, name)
            self.remember('exporters', 'run/'+directory+'/exporter.py', manifest['exporter_sha256'], name)
        elif kind == 'control':
            require(manifest.get('schema') == 'zkcfa.control-export.evidence.v1' and Path(manifest['run_root']).resolve() == self.root, 'wrong control export identity')
            data = self.read(directory+'/results.json',manifest['results_sha256'])
            require(data['run_started_utc'] == run['started_utc'], 'control belongs to another run')
            evidence_ledger=manifest['files_sha256']
            self.ledger(evidence_ledger, name); self.ledger(manifest['source_sha256'], name, sources=True)
            self.remember('exporters', 'control_results.py',manifest['exporter_sha256'], name)
        else:
            data = manifest
            require(Path(data['run_root']).resolve() == self.root, 'structural export belongs to another run')
            p=data['provenance']; evidence_ledger=p['data_files_sha256']; self.ledger(evidence_ledger, name); self.ledger(p['source_files_sha256'],name,sources=True)
            self.remember('inputs','run/scaling-inputs/manifest.json',p['input_manifest_sha256'],name)
            self.remember('inputs','run/stack-inputs/manifest.json',p['stack_input_manifest_sha256'],name)
        validate_block(name,data)
        pinned={self.relative_identity(k):v for k,v in evidence_ledger.items()}
        for stage in STAGES[name]:
            expected=pinned.get(f'run/logs/{stage}.process.json')
            require(expected is not None or stage in ('acquisition','signing'), 'export does not bind required terminal stage: '+stage)
            self.stage(stage,run,expected)
        return data

    def clean(self, value):
        if isinstance(value,dict):
            return {self.clean(k):self.clean(v) for k,v in value.items()
                    if k not in DROP_FIELDS and not SECRET_FIELD.search(k) and not k.endswith(('_argv','_command'))}
        if isinstance(value,list):
            return [self.clean(v) for v in value]
        if isinstance(value,float):
            require(math.isfinite(value), 'non-finite statistic')
        if isinstance(value,str):
            for root, replacement in ((self.root,'run'),(self.repo,'repo')):
                value=value.replace(str(root),replacement)
            value=PERSONAL_PATH.sub('[external-path]',value)
            require('-----BEGIN ' not in value, 'key/certificate material in statistics')
        return value

    def public(self, data):
        return self.clean({k:v for k,v in data.items() if k in TOP_FIELDS})

    def metadata(self, run):
        build=self.read('native-build.json'); env=self.read('baseline/environment.json')
        require(build.get('schema')=='zkcfa.native-build.v1' and build.get('status')=='complete', 'native build incomplete')
        self.ledger(build['source_sha256'],'native-build',sources=True)
        for name,binary in build['binaries'].items():
            self.remember('binaries',self.relative_identity(binary['path']),binary['sha256'],'native-build')
        require(build['submodules'] and build['binaries'] and build['source_sha256'], 'build identities missing')
        hardware = {key: value.strip() for line in env['hardware'].splitlines() if ':' in line for key,value in [line.split(':',1)] if key in ('hw.memsize','hw.logicalcpu','machdep.cpu.brand_string')}
        environment = {key:env[key] for key in ('macos','rustc','cargo')}
        environment['hardware']=hardware
        environment['docker']={k:v for k,v in env['docker'].items() if k in ('Architecture','NCPU','MemTotal','ServerVersion','KernelVersion','OperatingSystem')}
        environment['images']=[{k:v for k,v in row.items() if k in ('Id','RepoTags','Architecture','Os')} for row in env['images']]
        bm=self.read('binius-scaling/metadata.json')
        pm=self.read('plonk-scaling/run-identity.json')
        environment['binius_scaling']={k:bm[k] for k in ('platform','machine','logical_cpus','rayon_threads','cpu','memory_bytes','rustc') if k in bm}
        environment['plonk_scaling']={k:pm[k] for k in ('platform','python','threads','resource_limits') if k in pm}
        return self.clean(dict(schema='zkcfa.paper-reproduction.identities.v1',
            run={k:run[k] for k in ('started_utc','root_revision','paper_revision','manuscript_sha256')},
            environment=environment,
            build={k:build[k] for k in ('repository_revision','rustc','rustflags','release_lto','submodules')},
            stages=self.stages,
            artifact_identities={role:[dict(path=name,sha256=value,blocks=sorted(blocks)) for (name,value),blocks in sorted(items.items())] for role,items in self.identities.items()},
            note='Hashes identify inputs, binaries and frozen source versions; their contents and private logs are not included. Different source versions retain separate block attribution.'))


def assert_path_safe(value):
    if isinstance(value, dict):
        for key, item in value.items():
            assert_path_safe(key); assert_path_safe(item)
    elif isinstance(value, list):
        for item in value: assert_path_safe(item)
    elif isinstance(value, str):
        require(not PERSONAL_PATH.search(value), 'absolute machine path survived public projection')


def csv_bytes(rows):
    columns=list(dict.fromkeys(k for row in rows for k in row))
    text=io.StringIO(newline='');writer=csv.DictWriter(text,fieldnames=columns);writer.writeheader()
    writer.writerows({k:json.dumps(v,sort_keys=True,allow_nan=False) if isinstance(v,(dict,list)) else v for k,v in row.items()} for row in rows)
    return text.getvalue().encode()


def metric_rows(value, prefix=()):
    rows=[]
    if isinstance(value,dict):
        if {'median','min','max'} <= set(value) and ('n' in value or 'count' in value):
            rows.append(dict(metric='.'.join(prefix),n=value.get('n',value.get('count')),median=value['median'],minimum=value['min'],maximum=value['max']))
        else:
            for k,v in value.items(): rows.extend(metric_rows(v,(*prefix,k)))
    return rows


def selection_check(selection):
    require(selection.get('schema')=='zkcfa.paper-data.selection.v1', 'wrong selection schema')
    blocks=selection.get('blocks',{})
    require(set(blocks)==set(BLOCKS), 'final package requires exactly these blocks: '+', '.join(BLOCKS))
    missing=[name for name,spec in blocks.items() if not isinstance(spec,dict) or not isinstance(spec.get('directory'),str) or not HASH.fullmatch(str(spec.get('manifest_sha256','')))]
    require(not missing, 'final blocks are missing or unpinned: '+', '.join(missing))


README = '''# Paper reproduction data

This package contains the measured statistics used in the CSCloud paper, together with environment, input, binary and source identities. Reproduction inputs, dependencies and execution instructions are provided by the repository.

- `modes.json/csv`: the two authenticated raw24 modes for all 21 applications.
- `controls.json/csv`: membership comparisons, matched512, backend-fork cost and public-authentication metrics.
- `online.json/csv`: five fresh online measurements after one excluded warmup.
- `structural.json`, `scaling.csv`, `scaling-attempts.csv`, `stack.csv`: the seven-point scaling grid, real failure accounting and stack counts.
- `matched.json/csv` and `backends.json/csv`: matched application comparisons, with the actual PLONK picojpeg supplement retaining the original unexecuted scheduling record.
- `released.json/csv`, `repaired.json/csv`, `repair-control.json/csv`: original ZEKRA results and the separately identified repair diagnostics.
- `raw64.json/csv`: paired address-width results, including actual failures and unequal repetition schedules.
- `identities.json`: environment and artifact SHA256 identities; paths beginning `repo/` are repository-relative and `run/` are relative to the reproduction run.
- `manifest.json`: exact selected export identities and SHA256 for every packaged file except the manifest itself.

Read each JSON definition/timing scope before comparing values. Missing/unexecuted observations are not zero. Partial successes and failures are preserved. Warmups and preflights do not enter formal timing medians. Scaling min–max error bars require three verified formal samples. Stack-count observations are not repeated timing benchmarks. RSS and macOS footprint are distinct. ZEKRA proof-bit accounting is not a serialized-byte measurement.

CSV files are regenerated from the public JSON rather than copied from working directories. Nested CSV cells contain JSON. Control CSVs contain flattened median/minimum/maximum records; complete sample lists remain in JSON. Statistical values are unchanged. Operational command fields and private-material fields are omitted; known local paths are made relative and other machine paths are redacted.

No private signing keys, commitment openings, raw acquisition traces, proof transcripts, binaries, source contents or large logs are included. Artifact hashes identify those inputs without copying their contents. Source versions may differ between explicitly attributed frozen stages.

Reproduction entry points and dependencies are documented in the repository root README and the component READMEs. Use the recorded source revisions, input manifests and toolchain/image identities. The measured hardware and resource limits are part of the reported experiment. This package is assembled only after all required statistical exports close; a terminal resource failure is retained as a scientific result.

'''


def prepare(root,repo,selection):
    selection_check(selection)
    package=Package(root,repo);run=package.read('run.json')
    require(run.get('schema')=='zkcfa.final-reproduction.v1' and run['policy']['fresh_measurements_only'] is True, 'not a fresh run')
    require(selection.get('run_started_utc')==run['started_utc'], 'selection belongs to another run')
    data={name:package.public(package.load(name,selection['blocks'][name],run)) for name in BLOCKS}
    files={}
    encoded=lambda value:(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
    for name,value in data.items():
        files[name+'.json']=encoded(value)
        if name=='structural':
            for field,file in (('scaling','scaling.csv'),('scaling_attempts','scaling-attempts.csv'),('stack','stack.csv')):
                files[file]=csv_bytes(value[field])
        else:
            rows=value.get('rows') or metric_rows(value)
            require(rows,'empty statistics block: '+name)
            files[name+'.csv']=csv_bytes(rows)
    files['identities.json']=encoded(package.metadata(run));files['README.md']=README.encode()
    for name,payload in files.items():
        if name.endswith('.json'):
            assert_path_safe(json.loads(payload))
        elif name.endswith('.csv'):
            for row in csv.reader(io.StringIO(payload.decode())):
                for cell in row:
                    if cell.startswith(('{','[')):
                        try: assert_path_safe(json.loads(cell)); continue
                        except json.JSONDecodeError: pass
                    assert_path_safe(cell)
        else:
            assert_path_safe(payload.decode())
    manifest=dict(schema='zkcfa.paper-reproduction.package.v1',complete=True,
        selection_sha256=digest_bytes(encoded(selection)),selected_exports=package.selected,
        package_tool_sha256=digest(Path(__file__)),files_sha256={k:digest_bytes(v) for k,v in sorted(files.items())},
        policy=dict(final_blocks_required=list(BLOCKS),fresh_measurements_only=True,private_material_included=False,
                    raw_traces_included=False,logs_included=False,failures_preserved=True),
        validation_scope='Pins and statistical coverage checked here; source exporters performed full measurement/log validation. The packager does not reopen private evidence or execute experiments.')
    files['manifest.json']=encoded(manifest)
    for relative,expected in package.reads.items():
        require(digest(package.path(relative))==expected, 'selected statistics changed while packaging')
    return files,manifest



PACKAGE_FILES = ({name + '.json' for name in BLOCKS}
                 | {name + '.csv' for name in BLOCKS if name != 'structural'}
                 | {'scaling.csv', 'scaling-attempts.csv', 'stack.csv',
                    'identities.json', 'README.md', 'manifest.json'})


def validate_files(files):
    """Check the complete public package before installation or replacement."""
    require(set(files) == PACKAGE_FILES, 'package must contain exactly the 25 expected files')
    require(all(isinstance(payload, bytes) for payload in files.values()), 'package payloads must be bytes')
    manifest = json.loads(files['manifest.json'])
    require(manifest.get('schema') == 'zkcfa.paper-reproduction.package.v1'
            and manifest.get('complete') is True, 'not a complete public package')
    hashes = manifest.get('files_sha256', {})
    require(set(hashes) == PACKAGE_FILES - {'manifest.json'}, 'package manifest has an unexpected file set')
    for name, expected in hashes.items():
        require(isinstance(expected, str) and HASH.fullmatch(expected)
                and digest_bytes(files[name]) == expected, 'package SHA256 mismatch: ' + name)
    require(HASH.fullmatch(str(manifest.get('selection_sha256', '')))
            and HASH.fullmatch(str(manifest.get('package_tool_sha256', ''))), 'package identity hashes are missing')
    selection_check(dict(schema='zkcfa.paper-data.selection.v1', blocks=manifest.get('selected_exports', {})))
    policy = manifest.get('policy', {})
    require(policy.get('final_blocks_required') == list(BLOCKS)
            and policy.get('fresh_measurements_only') is True
            and policy.get('failures_preserved') is True
            and all(policy.get(key) is False for key in ('private_material_included', 'raw_traces_included', 'logs_included')),
            'public package policy differs')
    for name in BLOCKS:
        data = json.loads(files[name + '.json'])
        validate_block(name, data)
        assert_path_safe(data)
    identities = json.loads(files['identities.json'])
    require(identities.get('schema') == 'zkcfa.paper-reproduction.identities.v1', 'wrong identities schema')
    assert_path_safe(identities)
    return manifest


def no_symlinks(path):
    require(not any(part.is_symlink() for part in (path, *path.parents)),
            'output paths must not contain symlinks')


def read_package(directory):
    """Read only a recognized flat package; never accept arbitrary user files."""
    no_symlinks(directory)
    require(directory.is_dir(), 'replacement requires an existing public package directory')
    entries = list(directory.iterdir())
    require({entry.name for entry in entries} == PACKAGE_FILES,
            'existing package has missing or extra files')
    require(all(entry.is_file() and not entry.is_symlink() for entry in entries),
            'existing package must contain only regular files, without symlinks')
    files = {entry.name: entry.read_bytes() for entry in entries}
    validate_files(files)
    return {name: digest_bytes(payload) for name, payload in files.items()}


def output_path(root, output, manifest):
    original = Path(output).absolute()
    no_symlinks(original)
    output = original.resolve()
    root = Path(root).resolve(strict=True)
    require(root.is_dir(), 'run root must be a directory')
    require(not root.is_relative_to(output), 'output must not contain the source run')
    if output.is_relative_to(root):
        require(output.is_relative_to(root / 'exports'), 'output in this run must be under exports')
    for spec in manifest['selected_exports'].values():
        relative = spec['directory']
        require(relative.startswith('exports/') and '..' not in PurePosixPath(relative).parts,
                'selected export directory must be run-relative under exports')
        source = (root / relative).resolve()
        require(source.is_relative_to(root), 'selected export directory escapes the run')
        require(not output.is_relative_to(source) and not source.is_relative_to(output),
                'output must not overlap a selected source export directory')
    return output


def write_package(root, output, files, replace=False):
    """Install a validated package, restoring the previous package on failure."""
    manifest = validate_files(files)
    output = output_path(root, output, manifest)
    if replace:
        previous = read_package(output)
    else:
        require(not output.exists(), 'output already exists; use --replace for a valid public package')
        previous = None
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix='.' + output.name + '-new-', dir=output.parent))
    backup_root = None
    preserve_backup = False
    try:
        for name, payload in files.items():
            (temp / name).write_bytes(payload)
        read_package(temp)
        no_symlinks(output)
        if replace:
            require(read_package(output) == previous, 'existing package changed while preparing its replacement')
            backup_root = Path(tempfile.mkdtemp(prefix='.' + output.name + '-backup-', dir=output.parent))
            backup = backup_root / 'package'
            # Protect the old package even if rename succeeds before an interrupt is raised.
            preserve_backup = True
            try:
                output.rename(backup)
                temp.rename(output)
            except BaseException:
                if backup.exists():
                    try:
                        backup.rename(output)
                    except OSError as error:
                        raise ValueError('replacement failed; original package retained at ' + str(backup)) from error
                preserve_backup = False
                raise
            preserve_backup = False
        else:
            require(not output.exists() and not output.is_symlink(), 'output appeared during packaging')
            temp.rename(output)
    finally:
        if temp.exists():
            shutil.rmtree(temp)
        if backup_root is not None and backup_root.exists() and not preserve_backup:
            shutil.rmtree(backup_root)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-root', type=Path, required=True, help='original reproduction run containing closed strict exports')
    parser.add_argument('--repo-root', type=Path, default=Path(__file__).resolve().parents[2],
                        help='repository root used to normalize source identities (default: this repository)')
    parser.add_argument('--selection', type=Path, required=True,
                        help='selection JSON naming all ten export directories and their manifest SHA256 pins')
    parser.add_argument('--output', type=Path,
                        help='package directory (default: <repo-root>/experiment-data/cscloud)')
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--check', action='store_true', help='validate inputs and the prepared package without writing files')
    action.add_argument('--replace', action='store_true', help='replace an existing valid 25-file package with rollback on failure')
    args = parser.parse_args(argv)
    selection = json.loads(args.selection.read_text())
    files, manifest = prepare(args.run_root, args.repo_root, selection)
    validate_files(files)
    output = args.output if args.output is not None else args.repo_root / 'experiment-data/cscloud'
    if not args.check:
        write_package(args.run_root, output, files, replace=args.replace)
    print(json.dumps(dict(status='validated' if args.check else 'packaged', blocks=list(BLOCKS),
                          files=len(files), output=None if args.check else str(output.resolve()))))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, OSError) as error:
        raise SystemExit('export rejected: ' + str(error))
