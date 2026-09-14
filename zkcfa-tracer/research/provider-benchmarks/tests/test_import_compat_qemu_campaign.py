from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "import_compat_qemu_campaign.py"
SPEC = importlib.util.spec_from_file_location("import_compat_qemu_campaign", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def regular_files(root: Path, *, omit: set[str] | None = None) -> list[str]:
    omitted = omit or set()
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.relative_to(root).as_posix() not in omitted
    )


def write_sums(root: Path) -> None:
    names = regular_files(root, omit={"SHA256SUMS"})
    (root / "SHA256SUMS").write_text(
        "".join(f"{sha256(root / name)}  {name}\n" for name in names),
        encoding="ascii",
    )


class PublishedCampaignFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir()
        (root / "logs").mkdir()
        self.qemu_revision = MODULE.EXPECTED_QEMU_REVISION
        self.rows = self._make_inputs()
        self.runtime_snapshot, self.runtime_bindings = self._make_runtime_manifests()
        self.qemu_rows = self._make_qemu()
        self._make_other_lanes()
        self._make_campaign()

    def _make_inputs(self) -> list[dict[str, object]]:
        inputs = self.root / "inputs"
        (inputs / "bin").mkdir(parents=True)
        (inputs / "policies").mkdir()
        rows: list[dict[str, object]] = []
        for name in MODULE.APPLICATIONS:
            contents = f"ELF fixture for {name}\n".encode("ascii")
            binary = inputs / "bin" / name
            binary.write_bytes(contents)
            binary.chmod(0o500)
            profile = "ubuntu22" if name == "crc32" else "ubuntu20"
            row: dict[str, object] = {
                "name": name,
                "elf_sha256": digest(contents),
                "runtime_profile": profile,
                "toolchain": f"{profile}-toolchain",
                "sources": ["main.c"],
            }
            if name in MODULE.INDIRECT_APPLICATIONS:
                row["indirect_policy"] = f"policies/{name}.json"
                write_json(
                    inputs / "policies" / f"{name}.json",
                    {
                        "schema": "zkcfa.indirect-target-policy.v1",
                        "application": name,
                        "elf_sha256": row["elf_sha256"],
                        "indirect_calls": {},
                        "indirect_jumps": {},
                        "rationale": "test fixture",
                    },
                )
            rows.append(row)
        write_json(
            inputs / "manifest.json",
            {
                "schema": MODULE.SUITE_SCHEMA,
                "applications": rows,
                "toolchains": {
                    "ubuntu20-toolchain": {"runtime_profile": "ubuntu20"},
                    "ubuntu22-toolchain": {"runtime_profile": "ubuntu22"},
                },
            },
        )
        write_json(inputs / "recovery-provenance.json", {"fixture": "recovery"})
        write_json(
            inputs / "functional-oracle-provenance.json",
            {"fixture": "functional-oracle"},
        )
        names = regular_files(inputs)
        inventory = {
            name: {"bytes": (inputs / name).stat().st_size, "sha256": sha256(inputs / name)}
            for name in names
        }
        self.input_manifest = {
            "schema": MODULE.INPUT_SCHEMA,
            "source_suite_root": "/untrusted/do-not-follow",
            "applications": list(MODULE.APPLICATIONS),
            "files": inventory,
            "snapshot": "read-once-regular-file-copy-v1",
        }
        write_json(inputs / "input-manifest.json", self.input_manifest)
        write_sums(inputs)
        return rows

    def _make_runtime_manifests(
        self,
    ) -> tuple[dict[str, object], dict[str, dict[str, str]]]:
        root = self.root / "runtime-manifests"
        root.mkdir()
        profiles: dict[str, dict[str, object]] = {}
        bindings: dict[str, dict[str, str]] = {}
        for profile in MODULE.RUNTIME_PROFILES:
            relative = f"{profile}/runtime-dependencies.json"
            path = root / relative
            path.parent.mkdir()
            write_json(
                path,
                {
                    "schema": "zkcfa.runtime-dependencies",
                    "runtime_profile": profile,
                    "binding": "eager",
                    "loader_scope": "trusted-out-of-scope",
                    "environment": {"LD_BIND_NOW": "1"},
                    "files": [
                        {"path": name, "sha256": digest(f"{profile}:{name}".encode())}
                        for name in MODULE.RUNTIME_DEPENDENCY_FILES
                    ],
                },
            )
            profiles[profile] = {
                "path": relative,
                "source": f"/trusted-runtime/{profile}/runtime-dependencies.json",
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
            bindings[profile] = {
                "root": f"/runtime/{profile}",
                "manifest": f"/runtime/{profile}/runtime-dependencies.json",
                "manifest_sha256": sha256(path),
            }
        snapshot: dict[str, object] = {
            "schema": MODULE.RUNTIME_MANIFEST_SNAPSHOT_SCHEMA,
            "profiles": profiles,
            "snapshot": "read-once-regular-file-copy-v1",
        }
        write_json(root / "manifest.json", snapshot)
        write_sums(root)
        return snapshot, bindings

    @staticmethod
    def boundary() -> dict[str, object]:
        return {
            "boundary_kind": "external-root-entry-and-captured-return",
            "captured_return_continuation_matched": True,
            "complete": True,
            "external_root_entry_observed": True,
            "root_address": "0x401000",
            "root_entry_observed": True,
            "root_exit_block": "0x401000",
            "root_return_observed": True,
            "scope_call_address": "SCOPE_RETURN",
            "scope_call_observed": False,
            "scope_exit_address": "SCOPE_RETURN",
            "scope_exit_observed": True,
            "sentinel": "SCOPE_RETURN",
        }

    def _make_qemu(self) -> list[dict[str, object]]:
        qemu = self.root / "qemu"
        environment = qemu / "environment"
        environment.mkdir(parents=True)
        plugin = environment / "trace_scope.so"
        plugin.write_bytes(b"trace plugin fixture\n")
        (environment / "plugin-build.log").write_text("fixture build\n", encoding="ascii")
        write_json(
            environment / "environment.json",
            {
                "schema": MODULE.QEMU_ENVIRONMENT_SCHEMA,
                "python_version": "fixture",
                "qemu_path": "/qemu",
                "qemu_revision": self.qemu_revision,
                "qemu_version": "fixture",
                "plugin_build_command": ["cc"],
                "plugin_sha256": sha256(plugin),
                "provider_path": "/provider",
                "provider_sources": {
                    name: sha256(MODULE.DEFAULT_PROVIDER_ROOT / name)
                    for name in MODULE.PROVIDER_SOURCE_FILES
                },
                "runtime_bindings": self.runtime_bindings,
                "input_contract": "single-host-snapshot-direct-read-only-mount-v1",
            },
        )

        outcomes: list[dict[str, object]] = []
        for row in self.rows:
            name = str(row["name"])
            elf_hash = str(row["elf_sha256"])
            app = qemu / name
            artifacts = app / "artifacts"
            logs = app / "logs"
            artifacts.mkdir(parents=True)
            logs.mkdir()
            for log_name in ("normalize.log", "provision.log", "qemu.log"):
                (logs / log_name).write_text(f"{name} {log_name}\n", encoding="ascii")
            (artifacts / "translator").write_text(
                "0x401000\nSCOPE_RETURN\n", encoding="ascii"
            )
            (artifacts / "typed_cfg").write_text(
                "SCOPE_RETURN cal 0x401000\n"
                "SCOPE_RETURN crt SCOPE_RETURN\n",
                encoding="ascii",
            )
            (artifacts / "plugin-map.txt").write_text(
                "zkcfa.provider.map\n"
                "trace_schema zkcfa.scope.trace\n"
                f"elf_sha256 {elf_hash}\n"
                "architecture x86_64\n"
                "scope_call 0xffff0000\n"
                "root_entry 0x401000\n"
                "scope_return 0xffff0000\n"
                "root_ret 0x401000\n"
                "exec_range 0x401000 0x401001\n"
                "insn 0x401000 1 0x401000 ret 0 c3\n",
                encoding="ascii",
            )
            (artifacts / "recorded_path").write_text(
                "initial_node=SCOPE_RETURN final_node=SCOPE_RETURN\n"
                "call 0x401000 SCOPE_RETURN\n"
                "ret SCOPE_RETURN\n",
                encoding="ascii",
            )
            (app / "trace.log").write_text(
                f"zkcfa.scope.trace elf_sha256={elf_hash} runtime_bias=0x0\n"
                "begin scope_call=0xffff0000 root=0x401000 "
                "scope_return=0xffff0000 "
                "boundary_kind=external-root-entry-and-captured-return\n"
                "insn 0 0x401000\n"
                "scope_exit 0xffff0000 return_continuation_matched=1\n"
                "end count=1 complete=1 runtime_code_match=1\n",
                encoding="ascii",
            )
            boundary = self.boundary()
            write_json(
                artifacts / "evidence.json",
                {
                    "schema": "zkcfa.raw.evidence",
                    "boundary": boundary,
                    "event_count": 1,
                    "external_call_count": 0,
                    "recorded_path_sha256": sha256(artifacts / "recorded_path"),
                    "runtime_code_match": True,
                    "typed_cfg_sha256": sha256(artifacts / "typed_cfg"),
                },
            )
            static_policy: dict[str, object] = {
                "schema": "zkcfa.indirect-target-policy",
                "policy_sha256": None,
                "calls": {},
                "jumps": {},
            }
            if name in MODULE.INDIRECT_APPLICATIONS:
                policy = {
                    "schema": "zkcfa.indirect-target-policy",
                    "application": name,
                    "elf_sha256": elf_hash,
                    "indirect_calls": {},
                    "indirect_jumps": {},
                }
                write_json(app / "indirect-policy.json", policy)
                static_policy = {
                    "schema": "zkcfa.indirect-target-policy",
                    "policy_sha256": sha256(app / "indirect-policy.json"),
                    "calls": {},
                    "jumps": {},
                }
            static_manifest: dict[str, object] = {
                "schema": "zkcfa.static",
                "application": name,
                "architecture": "x86_64",
                "elf_sha256": elf_hash,
                "primary_elf_executable_ranges": [
                    {"start": "0x401000", "end": "0x401001"}
                ],
                "runtime_profile": row["runtime_profile"],
                "runtime_dependencies_sha256": self.runtime_bindings[
                    str(row["runtime_profile"])
                ]["manifest_sha256"],
                "proof_path_compression": "none",
                "trace_schema": "zkcfa.scope.trace",
                "plugin_map_sha256": sha256(artifacts / "plugin-map.txt"),
                "translator_sha256": sha256(artifacts / "translator"),
                "typed_cfg_sha256": sha256(artifacts / "typed_cfg"),
                "scope_policy": {
                    "boundary_kind": boundary["boundary_kind"],
                    "root_symbol": "main",
                    "external_entry": True,
                    "require_complete_entry_exit": True,
                    "root_address": boundary["root_address"],
                    "root_exit_blocks": [boundary["root_exit_block"]],
                    "scope_call_address": boundary["scope_call_address"],
                    "scope_return_address": boundary["scope_exit_address"],
                    "sentinel": "SCOPE_RETURN",
                },
                "external_call_policy": {
                    "runtime_dependencies": json.loads(
                        (
                            self.root
                            / "runtime-manifests"
                            / str(row["runtime_profile"])
                            / "runtime-dependencies.json"
                        ).read_text()
                    )
                },
            }
            static_manifest["indirect_target_policy"] = static_policy
            write_json(artifacts / "static-manifest.json", static_manifest)
            file_names = regular_files(app)
            outcome: dict[str, object] = {
                "application": name,
                "status": "COMPLETE",
                "input": {
                    "absolute_path": f"/campaign/inputs/bin/{name}",
                    "copied_by_lane": False,
                    "recompiled": False,
                    "sha256_before": elf_hash,
                    "sha256_immediately_before_execution": elf_hash,
                    "sha256_after_capture": elf_hash,
                },
                "guest_exit_status": 0,
                "boundary": boundary,
                "event_count": 1,
                "external_call_count": 0,
                "recorded_path_rows_including_header": 3,
                "commands": {"provision": [], "qemu": [], "normalize": []},
                "elapsed_seconds": 0.01,
                "files": {
                    item: {
                        "bytes": (app / item).stat().st_size,
                        "sha256": sha256(app / item),
                    }
                    for item in file_names
                },
            }
            write_json(app / "manifest.json", outcome)
            write_sums(app)
            outcomes.append(outcome)
        summary = {
            "schema": MODULE.QEMU_SCHEMA,
            "applications": outcomes,
            "complete": 21,
            "failed": 0,
            "input_hashes_after": {
                str(row["name"]): str(row["elf_sha256"]) for row in self.rows
            },
            "inputs_unchanged": True,
            "qemu_revision": self.qemu_revision,
            "runtime_bindings": self.runtime_bindings,
            "trace_plugin_sha256": sha256(plugin),
        }
        write_json(qemu / "capture.json", summary)
        write_sums(qemu)
        return outcomes

    def _make_other_lanes(self) -> None:
        compat = self.root / "compat"
        comparison = self.root / "comparison"
        compat.mkdir()
        comparison.mkdir()
        write_json(
            compat / "capture.json",
            {
                "schema": MODULE.COMPAT_SCHEMA,
                "applications": [
                    {"application": name, "status": "COMPLETE"}
                    for name in MODULE.APPLICATIONS
                ],
                "complete": 21,
                "failed": 0,
                "inputs_unchanged": True,
            },
        )
        write_sums(compat)
        write_json(
            comparison / "summary.json",
            {
                "schema": MODULE.COMPARISON_SCHEMA,
                "applications": [
                    {
                        "application": name,
                        "status": "ACCEPT",
                        "comparison_accepts": True,
                    }
                    for name in MODULE.APPLICATIONS
                ],
                "accepted": 21,
                "failed": 0,
                "all_fresh_same_elf_comparisons_accepted": True,
                "compatibility_classes": {"fixture": 21},
            },
        )
        write_sums(comparison)

    def _make_campaign(self) -> None:
        campaign = {
            "schema": MODULE.CAMPAIGN_SCHEMA,
            "status": "COMPLETE",
            "applications": list(MODULE.APPLICATIONS),
            "application_count": 21,
            "elapsed_seconds": 1,
            "input_snapshot": self.input_manifest,
            "input_snapshot_sha256sums": sha256(self.root / "inputs/SHA256SUMS"),
            "runtime_manifest_snapshot": self.runtime_snapshot,
            "runtime_manifest_snapshot_sha256sums": sha256(
                self.root / "runtime-manifests/SHA256SUMS"
            ),
            "lanes": {
                "qemu": {
                    "complete": 21,
                    "capture_sha256": sha256(self.root / "qemu/capture.json"),
                    "sha256sums": sha256(self.root / "qemu/SHA256SUMS"),
                },
                "compat": {
                    "complete": 21,
                    "capture_sha256": sha256(self.root / "compat/capture.json"),
                    "sha256sums": sha256(self.root / "compat/SHA256SUMS"),
                },
                "comparison": {
                    "accepted": 21,
                    "compatibility_classes": {"fixture": 21},
                    "summary_sha256": sha256(self.root / "comparison/summary.json"),
                    "sha256sums": sha256(self.root / "comparison/SHA256SUMS"),
                },
            },
            "implementations": {
                "runner_sha256": "5" * 64,
                "executor_sha256": "6" * 64,
                "policy_sha256": "7" * 64,
                "comparator_sha256": "8" * 64,
                "qemu_revision": self.qemu_revision,
            },
            "claims": dict(MODULE.EXPECTED_CLAIMS),
        }
        write_json(self.root / "campaign.json", campaign)
        write_sums(self.root)

    def reseal_qemu_application(self, application: str) -> None:
        app = self.root / "qemu" / application
        manifest_path = app / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"] = {
            name: {"bytes": (app / name).stat().st_size, "sha256": sha256(app / name)}
            for name in regular_files(app, omit={"manifest.json", "SHA256SUMS"})
        }
        write_json(manifest_path, manifest)
        write_sums(app)
        capture_path = self.root / "qemu/capture.json"
        capture = json.loads(capture_path.read_text())
        index = MODULE.APPLICATIONS.index(application)
        capture["applications"][index] = manifest
        write_json(capture_path, capture)
        write_sums(self.root / "qemu")
        campaign_path = self.root / "campaign.json"
        campaign = json.loads(campaign_path.read_text())
        campaign["lanes"]["qemu"]["capture_sha256"] = sha256(capture_path)
        campaign["lanes"]["qemu"]["sha256sums"] = sha256(
            self.root / "qemu/SHA256SUMS"
        )
        write_json(campaign_path, campaign)
        write_sums(self.root)

    def reseal_qemu_revision(self, revision: str) -> None:
        environment_path = self.root / "qemu/environment/environment.json"
        environment = json.loads(environment_path.read_text())
        environment["qemu_revision"] = revision
        write_json(environment_path, environment)

        capture_path = self.root / "qemu/capture.json"
        capture = json.loads(capture_path.read_text())
        capture["qemu_revision"] = revision
        write_json(capture_path, capture)
        write_sums(self.root / "qemu")

        campaign_path = self.root / "campaign.json"
        campaign = json.loads(campaign_path.read_text())
        campaign["implementations"]["qemu_revision"] = revision
        campaign["lanes"]["qemu"]["capture_sha256"] = sha256(capture_path)
        campaign["lanes"]["qemu"]["sha256sums"] = sha256(
            self.root / "qemu/SHA256SUMS"
        )
        write_json(campaign_path, campaign)
        write_sums(self.root)


class ImportCompatQemuCampaignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.source = self.base / "published"
        self.fixture = PublishedCampaignFixture(self.source)
        self.suite = self.base / "trusted-suite"
        shutil.copytree(self.source / "inputs", self.suite)
        (self.suite / "input-manifest.json").unlink()
        (self.suite / "SHA256SUMS").unlink()
        self.output = self.base / "proof-inputs"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def import_campaign(
        self,
        *,
        source: Path | None = None,
        destination: Path | None = None,
        trusted_suite: Path | None = None,
        provider_root: Path = MODULE.DEFAULT_PROVIDER_ROOT,
        expected_qemu_revision: str = MODULE.EXPECTED_QEMU_REVISION,
        expected_campaign_sha256s_sha256: str | None = None,
    ) -> dict[str, object]:
        campaign = source or self.source
        expected = expected_campaign_sha256s_sha256 or sha256(
            campaign / "SHA256SUMS"
        )
        return MODULE.import_campaign(
            campaign,
            destination or self.output,
            trusted_suite or self.suite,
            expected_campaign_sha256s_sha256=expected,
            provider_root=provider_root,
            expected_qemu_revision=expected_qemu_revision,
        )

    def test_imports_complete_21_app_layout_atomically(self) -> None:
        summary = self.import_campaign()
        self.assertEqual(summary["passed"], 21)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(
            [row["application"] for row in summary["results"]],
            list(MODULE.APPLICATIONS),
        )
        self.assertTrue(
            summary["import_contract"][
                "shadow_must_be_projected_from_imported_complete_registry"
            ]
        )
        self.assertTrue(
            summary["import_contract"]["recorded_path_recomputed_from_raw_trace"]
        )
        self.assertTrue(
            summary["import_contract"]["trace_evidence_recomputed_from_raw_trace"]
        )
        self.assertEqual(
            summary["trusted_provider"]["identity_sha256"],
            summary["tracer_revision"].removeprefix(
                "provider-source-set-sha256:"
            ),
        )
        self.assertEqual(
            summary["source_campaign"]["expected_sha256s_sha256"],
            sha256(self.source / "SHA256SUMS"),
        )
        for app in MODULE.APPLICATIONS:
            tracer = self.output / app / "tracer"
            self.assertEqual(
                {path.name for path in tracer.iterdir()},
                {app, "trace.log", "registry"},
            )
            self.assertEqual(
                {path.name for path in (tracer / "registry").iterdir()},
                set(MODULE.REGISTRY_FILES),
            )
            self.assertEqual(
                sha256(tracer / app), sha256(self.source / "inputs/bin" / app)
            )
            self.assertEqual(stat.S_IMODE((tracer / app).stat().st_mode), 0o500)
            result = json.loads(
                (self.output / app / "trace-result.json").read_text()
            )
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["guest_exit_status"], 0)
        self.assertFalse(any(self.output.rglob("compressed")))

    def test_rejects_trusted_suite_elf_byte_difference(self) -> None:
        binary = self.suite / "bin/nbody"
        binary.chmod(0o700)
        binary.write_bytes(b"different trusted ELF\n")
        with self.assertRaisesRegex(MODULE.CampaignImportError, "trusted suite bytes"):
            self.import_campaign()
        self.assertFalse(self.output.exists())

    def test_rejects_trusted_suite_provenance_byte_difference(self) -> None:
        write_json(
            self.suite / "functional-oracle-provenance.json",
            {"fixture": "different"},
        )
        with self.assertRaisesRegex(MODULE.CampaignImportError, "trusted suite bytes"):
            self.import_campaign()

    def test_rejects_campaign_snapshot_as_its_own_trusted_suite(self) -> None:
        with self.assertRaisesRegex(MODULE.CampaignImportError, "must be external"):
            self.import_campaign(trusted_suite=self.source / "inputs")

    def test_rejects_resealed_malformed_runtime_manifest_snapshot(self) -> None:
        runtime_path = (
            self.source
            / "runtime-manifests/ubuntu20/runtime-dependencies.json"
        )
        runtime = json.loads(runtime_path.read_text())
        runtime["loader_scope"] = "untrusted"
        write_json(runtime_path, runtime)
        snapshot_path = self.source / "runtime-manifests/manifest.json"
        snapshot = json.loads(snapshot_path.read_text())
        snapshot["profiles"]["ubuntu20"]["bytes"] = runtime_path.stat().st_size
        snapshot["profiles"]["ubuntu20"]["sha256"] = sha256(runtime_path)
        write_json(snapshot_path, snapshot)
        write_sums(self.source / "runtime-manifests")
        campaign_path = self.source / "campaign.json"
        campaign = json.loads(campaign_path.read_text())
        campaign["runtime_manifest_snapshot"] = snapshot
        campaign["runtime_manifest_snapshot_sha256sums"] = sha256(
            self.source / "runtime-manifests/SHA256SUMS"
        )
        write_json(campaign_path, campaign)
        write_sums(self.source)
        with self.assertRaisesRegex(
            MODULE.CampaignImportError, "runtime dependency manifest"
        ):
            self.import_campaign()

    def test_rejects_existing_output_without_touching_sentinel(self) -> None:
        self.output.mkdir()
        sentinel = self.output / "sentinel"
        sentinel.write_text("keep\n", encoding="ascii")
        with self.assertRaises(FileExistsError):
            self.import_campaign()
        self.assertEqual(sentinel.read_text(encoding="ascii"), "keep\n")

    def test_publish_race_leaves_no_visible_partial_output(self) -> None:
        with mock.patch.object(
            MODULE, "rename_noreplace", side_effect=FileExistsError("race")
        ):
            with self.assertRaises(FileExistsError):
                self.import_campaign()
        self.assertFalse(self.output.exists())
        self.assertEqual(
            [path for path in self.base.iterdir() if ".import-" in path.name], []
        )

    def test_rejects_three_elf_measurement_rebinding_after_resealing(self) -> None:
        app = "nbody"
        manifest_path = self.source / "qemu" / app / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["input"]["sha256_after_capture"] = "9" * 64
        write_json(manifest_path, manifest)
        self.fixture.reseal_qemu_application(app)
        with self.assertRaisesRegex(MODULE.CampaignImportError, "three ELF"):
            self.import_campaign()
        self.assertFalse(self.output.exists())

    def test_rejects_forged_self_consistent_recorded_path(self) -> None:
        app = "nbody"
        recorded_path = self.source / f"qemu/{app}/artifacts/recorded_path"
        recorded_path.write_text(
            "initial_node=SCOPE_RETURN final_node=SCOPE_RETURN\n"
            "call 0x401000 SCOPE_RETURN\n"
            "jump 0x401000\n"
            "ret SCOPE_RETURN\n",
            encoding="ascii",
        )
        evidence_path = self.source / f"qemu/{app}/artifacts/evidence.json"
        evidence = json.loads(evidence_path.read_text())
        evidence["recorded_path_sha256"] = sha256(recorded_path)
        write_json(evidence_path, evidence)
        manifest_path = self.source / f"qemu/{app}/manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["recorded_path_rows_including_header"] = 4
        write_json(manifest_path, manifest)
        self.fixture.reseal_qemu_application(app)

        with self.assertRaisesRegex(
            MODULE.CampaignImportError, "trusted provider normalization"
        ):
            self.import_campaign()
        self.assertFalse(self.output.exists())

    def test_rejects_wrong_exact_qemu_revision_after_resealing(self) -> None:
        self.fixture.reseal_qemu_revision("4" * 40)
        with self.assertRaisesRegex(
            MODULE.CampaignImportError, "exact caller-trusted commit"
        ):
            self.import_campaign()
        self.assertFalse(self.output.exists())

    def test_rejects_wrong_caller_campaign_checksum_trust_root(self) -> None:
        with self.assertRaisesRegex(
            MODULE.CampaignImportError, "caller-provided trust root"
        ):
            self.import_campaign(expected_campaign_sha256s_sha256="0" * 64)
        self.assertFalse(self.output.exists())

    def test_rejects_boolean_guest_exit_after_resealing(self) -> None:
        app = "slre"
        manifest_path = self.source / "qemu" / app / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["guest_exit_status"] = False
        write_json(manifest_path, manifest)
        self.fixture.reseal_qemu_application(app)
        with self.assertRaisesRegex(MODULE.CampaignImportError, "three ELF"):
            self.import_campaign()

    def test_rejects_incomplete_boundary_after_resealing(self) -> None:
        app = "primecount"
        evidence_path = self.source / "qemu" / app / "artifacts/evidence.json"
        evidence = json.loads(evidence_path.read_text())
        evidence["boundary"]["scope_exit_observed"] = False
        write_json(evidence_path, evidence)
        manifest_path = self.source / "qemu" / app / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["boundary"] = evidence["boundary"]
        write_json(manifest_path, manifest)
        self.fixture.reseal_qemu_application(app)
        with self.assertRaisesRegex(MODULE.CampaignImportError, "complete measured"):
            self.import_campaign()

    def test_rejects_forged_self_consistent_evidence_after_resealing(self) -> None:
        app = "nbody"
        evidence_path = self.source / f"qemu/{app}/artifacts/evidence.json"
        evidence = json.loads(evidence_path.read_text())
        evidence["boundary"]["root_exit_block"] = "0xdeadbeef"
        write_json(evidence_path, evidence)
        manifest_path = self.source / f"qemu/{app}/manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["boundary"] = evidence["boundary"]
        write_json(manifest_path, manifest)
        self.fixture.reseal_qemu_application(app)

        with self.assertRaisesRegex(
            MODULE.CampaignImportError, "trusted provider recomputation"
        ):
            self.import_campaign()
        self.assertFalse(self.output.exists())

    def test_rejects_evidence_hash_rebinding_after_resealing(self) -> None:
        app = "matmult-int"
        evidence_path = self.source / "qemu" / app / "artifacts/evidence.json"
        evidence = json.loads(evidence_path.read_text())
        evidence["recorded_path_sha256"] = "a" * 64
        write_json(evidence_path, evidence)
        self.fixture.reseal_qemu_application(app)
        with self.assertRaisesRegex(MODULE.CampaignImportError, "evidence/static"):
            self.import_campaign()

    def test_rejects_static_hash_rebinding_after_resealing(self) -> None:
        app = "wikisort"
        static_path = self.source / "qemu" / app / "artifacts/static-manifest.json"
        static_manifest = json.loads(static_path.read_text())
        static_manifest["typed_cfg_sha256"] = "b" * 64
        write_json(static_path, static_manifest)
        self.fixture.reseal_qemu_application(app)
        with self.assertRaisesRegex(MODULE.CampaignImportError, "evidence/static"):
            self.import_campaign()

    def test_rejects_allowlist_extra_even_when_fully_checksum_bound(self) -> None:
        app = "aha-mont64"
        extra = self.source / "qemu" / app / "artifacts/extra"
        extra.write_text("bound but forbidden\n", encoding="ascii")
        self.fixture.reseal_qemu_application(app)
        with self.assertRaisesRegex(MODULE.CampaignImportError, "file inventory|entry set"):
            self.import_campaign()

    def test_rejects_symlink_even_if_target_has_expected_bytes(self) -> None:
        binary = self.source / "inputs/bin/nbody"
        target = self.base / "nbody-real"
        target.write_bytes(binary.read_bytes())
        binary.unlink()
        binary.symlink_to(target)
        with self.assertRaisesRegex(MODULE.CampaignImportError, "symlink"):
            self.import_campaign()

    def test_rejects_noncanonical_21_order_after_resealing(self) -> None:
        campaign_path = self.source / "campaign.json"
        campaign = json.loads(campaign_path.read_text())
        campaign["applications"][0], campaign["applications"][1] = (
            campaign["applications"][1],
            campaign["applications"][0],
        )
        write_json(campaign_path, campaign)
        write_sums(self.source)
        with self.assertRaisesRegex(MODULE.CampaignImportError, "canonical COMPLETE"):
            self.import_campaign()


if __name__ == "__main__":
    unittest.main()
