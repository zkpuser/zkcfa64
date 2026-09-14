"""Small synthetic tests; no experiments, subprocesses or private input reads."""
import copy
import contextlib
import io
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('export_cscloud', Path(__file__).resolve().parents[1] / 'export_cscloud.py')
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)
H = 'a' * 64
START = '2026-09-14T10:00:00+00:00'
END = '2026-09-14T11:00:00+00:00'


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, allow_nan=False) + '\n')
    return p.digest(path)


def sample():
    return dict(n=5, median=2, min=1, max=3, samples=[1, 2, 2, 2, 3])


def successful_control():
    return dict(formal_verified=5, warmups_verified=1, metrics={'crypto_prove_ms': sample()})


def documents():
    rows=lambda **values: dict(status='verified', verified=True, n=3, prove_s=2, **values)
    out={}
    out['modes']=dict(rows=[rows(application=a,mode=m) for a in p.APPS for m in ('complete','shadow')])
    out['matched']=dict(rows=[rows(application=a,backend=b) for a in p.APPS for b in ('binius','zekra')])
    primary=dict(application='picojpeg',attempted=0,status='resource-skipped-no-preflight')
    actual=dict(application='picojpeg',preflight_attempted=1,status='proof-failed',verified=False)
    out['backends']=dict(rows=[dict(application=a,**{b:rows(application=a) for b in ('binius','zekra','plonk')}) for a in p.APPS],plonk_selection=dict(application='picojpeg',primary=primary,supplement=actual))
    for name in ('released','repaired'):
        out[name]=dict(rows=[rows(application=a,excluded_control=a=='crc32-control-500') for a in (*p.APPS,'crc32-control-500')])
    out['raw64']=dict(rows=[rows(application=a,mode=m,profile=b) for a in p.APPS for m in ('complete','shadow') for b in ('raw24','raw64')])
    out['repair-control']=dict(rows=[dict(control='SmartMemory-native-field',validated=True,excluded_from_formal_timings=True)])
    for name in tuple(out):
        out[name]['schema']=f'zkcfa.final-reproduction.applications.{name}.v1'
    out['controls']=dict(schema='zkcfa.control-results.v1',run_started_utc=START,sections={
        'membership':dict(results={key:successful_control() for key in ('binmult','indexed','logup')}),
        'matched512':dict(results={'binius':successful_control()}),
        'backend-pair':dict(results={key:successful_control() for key in ('fork','upstream')}),
        'zekra-matched512':successful_control(), 'mode-auth':dict(metrics=sample())})
    out['online']=dict(schema='zkcfa.control-results.v1',run_started_utc=START,sections={'online':successful_control()})
    grid=[('Binius64',f,n,m) for f in ('growing-cfg','fixed-cfg') for n in p.SIZES for m in ('complete','shadow')]
    grid += [(b,'growing-cfg',n,m) for b,m in (('PLONK','complete'),('ZEKRA','zekra')) for n in p.SIZES]
    scaling=[dict(backend=b,family=f,source_ep_rows=n,mode=m,planned=3,attempted=3,not_attempted=0,verified=3,failed=0,full_three_run_errorbar=True,measurements={'crypto_prove_s':dict(count=3,median=2,min=1,max=3,values=[1,2,3])}) for b,f,n,m in grid]
    failed=next(row for row in scaling if row['backend']=='ZEKRA' and row['source_ep_rows']==4096)
    failed.update(attempted=1,not_attempted=2,verified=0,failed=1,full_three_run_errorbar=False,measurements={},failure_kinds={'docker-oom':1,'not-recorded-after-campaign-stop':2})
    stack=[]
    for b in ('Binius64','ZEKRA'):
        stack += [dict(backend=b,family='length',L=n,D=8) for n in p.SIZES]
        stack += [dict(backend=b,family='depth',L=1024,D=n) for n in (1,2,4,8,16,32,64,128,256)]
        stack += [dict(backend=b,family='diagonal',L=n,D=n//4) for n in p.SIZES]
    stack += [dict(backend='ZEKRA',family='fixed-pointer15',L=1024,D=n) for n in (1,8,32,256)]
    out['structural']=dict(schema='zkcfa.final.structural-results.v1',section='all',scaling=scaling,stack=stack,
        scaling_attempts=[dict(backend='ZEKRA',source_ep_rows=4096,kind='measured',verified=False,outcome='docker-oom')],
        policy=dict(fresh_measurements_only=True,missing_runs_are_not_zero=True))
    return out


class Fixture:
    def __init__(self, root):
        self.repo=root;self.run=root/'output'/'fresh';self.docs=documents()
        write(self.run/'run.json',dict(schema='zkcfa.final-reproduction.v1',started_utc=START,root_revision='0'*40,paper_revision='1'*40,manuscript_sha256=H,policy={'fresh_measurements_only':True}))
        write(self.run/'native-build.json',dict(schema='zkcfa.native-build.v1',status='complete',repository_revision='0'*40,rustc='rustc test',rustflags='-C target-cpu=native',release_lto='thin',submodules={'backend':'1'*40},binaries={'prover':dict(path=str(self.run/'bin/prover'),sha256=H)},source_sha256={'src/main.rs':H}))
        write(self.run/'baseline/environment.json',dict(hardware='hw.memsize: 1024\nhw.logicalcpu: 8\nmachdep.cpu.brand_string: Test CPU\nhostname: Private Host',macos='Test OS',rustc='rustc test',cargo='cargo test',docker=dict(NCPU=8,MemTotal=1024,Name='Private VM'),images=[dict(Id='sha256:'+H,Architecture='arm64',Os='linux',Name='Private Image')]))
        write(self.run/'binius-scaling/metadata.json',dict(platform='Test OS',rayon_threads=8))
        write(self.run/'plonk-scaling/run-identity.json',dict(threads=8,resource_limits={'max_proof_domain':123}))
        self.stage_hashes={}
        for stage in {s for stages in p.STAGES.values() for s in stages}:
            self.stage_hashes[f'logs/{stage}.process.json']=write(self.run/f'logs/{stage}.process.json',dict(stage=stage,status='failed' if stage=='zekra-scaling' else 'complete',exit_code=1 if stage=='zekra-scaling' else 0,started_utc=START,finished_utc=END,log_sha256=H,controller_sha256=H))
        self.selection=dict(schema='zkcfa.paper-data.selection.v1',run_started_utc=START,blocks={})
        for name in p.BLOCKS:self.export(name)

    def export(self,name):
        folder=self.run/'exports'/name;folder.mkdir(parents=True,exist_ok=True)
        data=copy.deepcopy(self.docs[name]);ledger={f'logs/{s}.process.json':self.stage_hashes[f'logs/{s}.process.json'] for s in p.STAGES[name]}
        ledger['inputs/example/translator']=H
        ledger['keys/never-read.ed25519']=H
        if name=='structural':
            data['run_root']=str(self.run)
            data['provenance']=dict(data_files_sha256=ledger,source_files_sha256={'src/main.rs':H},input_manifest_sha256=H,stack_input_manifest_sha256=H)
            manifest='structural-results.json';digest=write(folder/manifest,data)
        elif name in ('controls','online'):
            h=write(folder/'results.json',data);manifest='evidence.json'
            digest=write(folder/manifest,dict(schema='zkcfa.control-export.evidence.v1',run_root=str(self.run),results_sha256=h,files_sha256=ledger,source_sha256={str(self.repo/'src/main.rs'):H},exporter_sha256=H))
        else:
            h=write(folder/(name+'.json'),data);(folder/(name+'.csv')).write_bytes(p.csv_bytes(data['rows']));manifest='manifest.json'
            digest=write(folder/manifest,dict(schema='zkcfa.final-reproduction.application-export.v1',run_root=str(self.run),sections=[name],output_sha256={name+'.json':h,name+'.csv':p.digest(folder/(name+'.csv'))},evidence_sha256=ledger,exporter_sha256=H))
        self.selection['blocks'][name]=dict(directory='exports/'+name,manifest_sha256=digest)

    def prepare(self):return p.prepare(self.run,self.repo,self.selection)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='zkcfa-package-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.f=Fixture(self.root)

    def test_full_package_preserves_real_failure_and_excludes_private_data(self):
        self.f.docs['modes']['rows'][0].update(private_key='TOP SECRET KEY',opening='TOP SECRET OPENING',raw_trace='TOP SECRET TRACE',argv=['/Users/private/prover'],diagnostic='cannot open /Users/someone/private/file or /mnt/private-person/log',source=str(self.f.run/'private/worker.json'))
        self.f.export('modes');files,manifest=self.f.prepare()
        body=b'\n'.join(files.values()).decode()
        for forbidden in ('TOP SECRET','/Users/','Private Host','Private VM','Private Image','never-read.ed25519','/mnt/private-person'):
            self.assertNotIn(forbidden,body)
        self.assertTrue(manifest['complete']);self.assertEqual(set(manifest['selected_exports']),set(p.BLOCKS))
        self.assertTrue(all(name.endswith(('.json','.csv','.md')) for name in files))
        d=json.loads(files['structural.json']);failed=next(row for row in d['scaling'] if row['backend']=='ZEKRA' and row['source_ep_rows']==4096)
        self.assertEqual((failed['failed'],failed['not_attempted'],failed['measurements']),(1,2,{}))
        self.assertNotIn('crypto_prove_s',failed['measurements'])
        out=self.root/'deliverable';p.write_package(self.f.run,out,files)
        self.assertEqual({path.name for path in out.iterdir()},set(files))
        for name,expected in manifest['files_sha256'].items():self.assertEqual(p.digest(out/name),expected)

    def test_missing_final_block_does_not_write(self):
        self.f.selection['blocks']['raw64']['manifest_sha256']=None
        with self.assertRaisesRegex(ValueError,'missing or unpinned'):self.f.prepare()
        self.assertFalse((self.root/'deliverable').exists())

    def test_extra_or_omitted_block_rejected(self):
        del self.f.selection['blocks']['backends']
        with self.assertRaisesRegex(ValueError,'requires exactly'):self.f.prepare()

    def test_manifest_pin_tamper_rejected(self):
        self.f.selection['blocks']['matched']['manifest_sha256']='b'*64
        with self.assertRaisesRegex(ValueError,'SHA256 mismatch'):self.f.prepare()

    def test_csv_tamper_rejected(self):
        (self.f.run/'exports/modes/modes.csv').write_text('tampered')
        with self.assertRaisesRegex(ValueError,'CSV hash'):self.f.prepare()

    def test_duplicate_application_or_missing_2048_rejected(self):
        self.f.docs['modes']['rows'][-1]=self.f.docs['modes']['rows'][0];self.f.export('modes')
        with self.assertRaisesRegex(ValueError,'incomplete/duplicate'):self.f.prepare()
        self.f.docs['modes']=documents()['modes'];self.f.export('modes')
        self.f.docs['structural']['scaling']=[r for r in self.f.docs['structural']['scaling'] if r['source_ep_rows']!=2048];self.f.export('structural')
        with self.assertRaisesRegex(ValueError,'incomplete/duplicate'):self.f.prepare()

    def test_current_stage_must_match_export_terminal_record(self):
        path=self.f.run/'logs/matched-apps.process.json';v=json.loads(path.read_text());v.update(status='running',finished_utc=None,exit_code=None)
        write(path,v)
        with self.assertRaisesRegex(ValueError,'SHA256 mismatch'):self.f.prepare()
        self.f.stage_hashes['logs/matched-apps.process.json']=p.digest(path);self.f.export('matched')
        with self.assertRaisesRegex(ValueError,'not terminal'):self.f.prepare()

    def test_wrong_run_and_parent_escape_rejected(self):
        self.f.selection['run_started_utc']='2020-01-01T00:00:00+00:00'
        with self.assertRaisesRegex(ValueError,'another run'):self.f.prepare()
        self.f.selection['run_started_utc']=START;self.f.selection['blocks']['modes']['directory']='exports/../old'
        with self.assertRaisesRegex(ValueError,'explicit export'):self.f.prepare()

    def test_symlink_export_rejected(self):
        source=self.f.run/'exports/modes/modes.json';data=source.read_bytes();source.unlink()
        outside=self.root/'outside.json';outside.write_bytes(data);source.symlink_to(outside)
        with self.assertRaisesRegex(ValueError,'symlink'):self.f.prepare()

    def test_output_existing_dangling_and_source_overlap_rejected(self):
        existing=self.root/'existing';existing.mkdir()
        dangling=self.root/'dangling';dangling.symlink_to(self.root/'missing')
        for output in (existing,dangling,self.f.run/'inputs'/'new'):
            with self.assertRaises(ValueError):p.write_package(self.f.run,output,{'README.md':b'OK'})

    def test_nonfinite_or_pem_cannot_be_packaged(self):
        package=p.Package(self.f.run,self.f.repo)
        with self.assertRaisesRegex(ValueError,'non-finite'):package.clean({'prove_s':float('nan')})
        with self.assertRaisesRegex(ValueError,'key/certificate'):package.clean({'diagnostic':'-----BEGIN PRIVATE KEY-----'})

    def test_preflight_and_attempts_are_not_changed_into_success(self):
        self.f.docs['raw64']['rows'][0].update(status='not-run',verified=False,n=0);self.f.export('raw64')
        with self.assertRaisesRegex(ValueError,'unfinished'):self.f.prepare()
        self.f.docs['raw64']['rows'][0].update(status='timeout');self.f.export('raw64')
        files,_=self.f.prepare();row=json.loads(files['raw64.json'])['rows'][0]
        self.assertFalse(row['verified']);self.assertEqual(row['n'],0);self.assertEqual(row['status'],'timeout')


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='zkcfa-publication-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.f = Fixture(self.root)
        self.output = self.root / 'experiment-data' / 'cscloud'
        self.selection_path = self.root / 'selection.json'
        write(self.selection_path, self.f.selection)

    def arguments(self, *extra):
        return ['--run-root', str(self.f.run), '--selection', str(self.selection_path),
                '--repo-root', str(self.root), *extra]

    def invoke(self, arguments):
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            result = p.main(arguments)
        self.assertEqual(result, 0)
        return json.loads(stdout.getvalue())

    def snapshot(self, directory):
        return {path.relative_to(directory).as_posix(): path.read_bytes()
                for path in directory.rglob('*') if path.is_file()}

    def install(self):
        files, _ = self.f.prepare()
        self.assertEqual(len(files), 25)
        p.write_package(self.f.run, self.output, files)
        return files

    def changed_files(self):
        self.f.docs['modes']['rows'][0]['prove_s'] = 7
        self.f.export('modes')
        write(self.selection_path, self.f.selection)
        files, _ = self.f.prepare()
        return files

    def test_cli_requires_run_root_and_selection(self):
        for arguments in ([], ['--run-root', str(self.f.run)],
                          ['--selection', str(self.selection_path)]):
            with self.subTest(arguments=arguments), mock.patch.object(p, 'prepare') as prepare:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    p.main(arguments)
                self.assertEqual(error.exception.code, 2)
                prepare.assert_not_called()

    def test_cli_default_repo_comes_from_script_location(self):
        expected_repo = Path(p.__file__).resolve().parents[2]
        files, manifest = self.f.prepare()
        with mock.patch.object(p, 'prepare', return_value=(files, manifest)) as prepare:
            with mock.patch.object(p, 'write_package') as install:
                self.invoke(['--run-root', str(self.f.run), '--selection', str(self.selection_path)])
        self.assertEqual(Path(prepare.call_args.args[1]), expected_repo)
        self.assertEqual(Path(install.call_args.args[1]), expected_repo / 'experiment-data' / 'cscloud')

    def test_cli_default_output_is_under_explicit_repo(self):
        report = self.invoke(self.arguments())
        self.assertEqual(report['status'], 'packaged')
        self.assertEqual(Path(report['output']), self.output)
        files, _ = self.f.prepare()
        self.assertEqual(self.snapshot(self.output), files)

    def test_cli_output_override(self):
        other = self.root / 'public-package'
        report = self.invoke(self.arguments('--output', str(other)))
        self.assertEqual(Path(report['output']), other)
        self.assertTrue((other / 'manifest.json').is_file())
        self.assertFalse(self.output.exists())

    def test_cli_check_does_not_create_or_modify_output(self):
        with mock.patch.object(p, 'write_package', side_effect=AssertionError('check wrote output')):
            report = self.invoke(self.arguments('--check'))
        self.assertEqual(report['status'], 'validated')
        self.assertFalse(self.output.exists())
        self.install()
        before = self.snapshot(self.output)
        self.changed_files()
        with mock.patch.object(p, 'write_package', side_effect=AssertionError('check replaced output')):
            report = self.invoke(self.arguments('--check'))
        self.assertEqual(report['status'], 'validated')
        self.assertEqual(self.snapshot(self.output), before)

    def test_cli_replace_is_explicit_and_updates_complete_package(self):
        before = self.install()
        after = self.changed_files()
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
            p.main(self.arguments())
        self.assertEqual(self.snapshot(self.output), before)
        self.invoke(self.arguments('--replace'))
        self.assertEqual(self.snapshot(self.output), after)
        self.assertNotEqual(after['modes.json'], before['modes.json'])
        self.assertEqual({path.name for path in self.output.parent.iterdir()}, {'cscloud'})

    def test_replace_refuses_extra_file_or_directory(self):
        self.install()
        after = self.changed_files()
        for name, directory in (('local-notes.txt', False), ('untracked', True)):
            extra = self.output / name
            if directory:
                extra.mkdir()
            else:
                extra.write_text('local material must survive')
            before = self.snapshot(self.output)
            with self.subTest(name=name), self.assertRaises(ValueError):
                p.write_package(self.f.run, self.output, after, replace=True)
            self.assertEqual(self.snapshot(self.output), before)
            self.assertTrue(extra.exists())
            if directory:
                extra.rmdir()
            else:
                extra.unlink()

    def test_replace_refuses_hash_tampering(self):
        self.install()
        after = self.changed_files()
        (self.output / 'README.md').write_text('not the hashed README')
        before = self.snapshot(self.output)
        with self.assertRaises(ValueError):
            p.write_package(self.f.run, self.output, after, replace=True)
        self.assertEqual(self.snapshot(self.output), before)

    def test_replace_refuses_incomplete_manifest_even_if_remaining_hashes_match(self):
        self.install()
        after = self.changed_files()
        manifest_path = self.output / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        del manifest['files_sha256']['raw64.csv']
        (self.output / 'raw64.csv').unlink()
        write(manifest_path, manifest)
        before = self.snapshot(self.output)
        with self.assertRaises(ValueError):
            p.write_package(self.f.run, self.output, after, replace=True)
        self.assertEqual(self.snapshot(self.output), before)

    def test_replace_refuses_symlink_member_even_with_matching_bytes(self):
        self.install()
        after = self.changed_files()
        member = self.output / 'README.md'
        outside = self.root / 'readme-outside.md'
        outside.write_bytes(member.read_bytes())
        member.unlink()
        member.symlink_to(outside)
        before = self.snapshot(self.output)
        with self.assertRaises(ValueError):
            p.write_package(self.f.run, self.output, after, replace=True)
        self.assertTrue(member.is_symlink())
        self.assertEqual(self.snapshot(self.output), before)
        self.assertEqual(outside.read_bytes(), before['README.md'])

    def test_replace_refuses_symlink_output_and_parent(self):
        before = self.install()
        after = self.changed_files()
        alias = self.root / 'alias-package'
        alias.symlink_to(self.output, target_is_directory=True)
        parent_alias = self.root / 'alias-parent'
        parent_alias.symlink_to(self.output.parent, target_is_directory=True)
        dangling = self.root / 'dangling-package'
        dangling.symlink_to(self.root / 'missing-package')
        for output in (alias, parent_alias / 'cscloud', dangling):
            with self.subTest(output=output.name), self.assertRaises(ValueError):
                p.write_package(self.f.run, output, after, replace=True)
            self.assertEqual(self.snapshot(self.output), before)
        self.assertTrue(alias.is_symlink())
        self.assertTrue(dangling.is_symlink())

    def test_failed_install_restores_original_package(self):
        before = self.install()
        after = self.changed_files()
        original_rename = Path.rename
        failures = []

        def fail_new_install(source, target):
            if source.name.startswith('.cscloud-new-') and Path(target) == self.output:
                failures.append(source)
                raise OSError('injected installation failure')
            return original_rename(source, target)

        with mock.patch.object(Path, 'rename', fail_new_install):
            with self.assertRaisesRegex(OSError, 'injected installation failure'):
                p.write_package(self.f.run, self.output, after, replace=True)
        self.assertEqual(len(failures), 1)
        self.assertEqual(self.snapshot(self.output), before)
        self.assertEqual({path.name for path in self.output.parent.iterdir()}, {'cscloud'})

    def test_interrupt_after_old_package_moves_keeps_all_previous_data(self):
        before = self.install()
        after = self.changed_files()
        original_rename = Path.rename
        backups = []

        def interrupt_after_backup_move(source, target):
            result = original_rename(source, target)
            if source == self.output:
                backups.append(Path(target))
                raise KeyboardInterrupt('injected interruption after backup move')
            return result

        with mock.patch.object(Path, 'rename', interrupt_after_backup_move):
            with self.assertRaises(KeyboardInterrupt):
                p.write_package(self.f.run, self.output, after, replace=True)
        self.assertEqual(len(backups), 1)
        preserved = [path for path in (self.output, backups[0])
                     if path.is_dir() and self.snapshot(path) == before]
        self.assertTrue(preserved, 'interruption must restore or retain the complete original package')

    def test_invalid_new_package_never_replaces_previous_data(self):
        before = self.install()
        after = self.changed_files()
        after['modes.json'] = b'{}\n'
        with self.assertRaises(ValueError):
            p.write_package(self.f.run, self.output, after, replace=True)
        self.assertEqual(self.snapshot(self.output), before)

    def test_output_cannot_overwrite_selected_exports_or_run_source(self):
        files, _ = self.f.prepare()
        for output in (self.f.run, self.root, self.f.run / 'exports',
                       self.f.run / 'exports' / 'modes',
                       self.f.run / 'exports' / 'modes' / 'public'):
            with self.subTest(output=output.name), self.assertRaises(ValueError):
                p.write_package(self.f.run, output, files, replace=True)
        self.f.prepare()


if __name__ == '__main__':
    unittest.main()
