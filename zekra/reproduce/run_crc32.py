#!/usr/bin/env python3
"""Assert the released CRC32 result in a disposable, committed-source snapshot."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone
import uuid


COMPONENT = Path(__file__).resolve().parents[1]
SOURCE = COMPONENT / "ZEKRA"
PIN = "01a0152bfd9812a0569dce19965e7e92df30015d"
RUNNER = "/opt/jsnark/libsnark/build/libsnark/jsnark_interface/run_ppzksnark"
HASHES = {
    "Encoded adjacency list hash": "5985449892039608890456185764561858730723264824691156509074284478893635440892",
    "Translator hash": "5551575237474407726413860559067084002486780251770875449597188721978322980717",
    "Recorded execution path hash": "21393937064302472340191694070938458033674045799645644822430973995137600407803",
}


def capture(*command):
    return subprocess.check_output(command, text=True).strip()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_inventory(source):
    """Include ignored files and symlink targets, but never traverse .git."""
    inventory = {}
    for base, dirs, files in os.walk(source, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name != ".git")
        for name in sorted(set(dirs + files) - {".git"}):
            path = Path(base) / name
            key = str(path.relative_to(source))
            if path.is_symlink():
                inventory[key] = {"symlink": os.readlink(path)}
            elif path.is_file():
                inventory[key] = {"sha256": sha256(path), "mode": path.stat().st_mode & 0o777}
    return inventory


def source_state(source):
    return {
        "commit": capture("git", "-C", str(source), "rev-parse", "HEAD"),
        "status": capture("git", "-C", str(source), "status", "--porcelain"),
        "files": source_inventory(source),
    }


def validate_output(output, source):
    if output.is_symlink():
        raise ValueError(f"Output must be a new directory, not a symbolic link: {output}")
    output, source = output.resolve(), source.resolve()
    if output == source or source in output.parents:
        raise ValueError("Output must be outside the upstream ZEKRA source tree")
    if output.exists():
        raise ValueError(f"Output already exists; choose a new directory: {output}")
    return output


def snapshot(source, output, pin):
    archive = output / "source.tar"
    subprocess.run(["git", "-C", str(source), "archive", "--format=tar",
                    f"--output={archive}", pin], check=True)
    work = output / "work" / "ZEKRA"
    work.mkdir(parents=True)
    with tarfile.open(archive) as stream:
        # The archive is from the pinned local Git object, not a downloaded tar.
        for member in stream.getmembers():
            destination = (work / member.name).resolve()
            if destination != work and work not in destination.parents:
                raise ValueError(f"Unsafe archive member: {member.name}")
            if member.issym() or member.islnk():
                raise ValueError(f"Unexpected link in upstream archive: {member.name}")
        stream.extractall(work)
    return work


def require_markers(text, markers):
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise RuntimeError("Expected upstream result absent: " + "; ".join(missing))


def proof_metrics(text):
    require_markers(text, ["The verification result is: PASS"])
    if "The verification result is: FAIL" in text:
        raise RuntimeError("Proof log also contains a failed verification")
    result = {"verified": True}
    for key, phase in (("setup_s", "generator"), ("prove_s", "prover"),
                       ("verify_s", "verifier_strong_IC")):
        match = re.search(r"\(leave\) Call to r1cs_gg_ppzksnark_" + phase + r"\s+\[([\d.]+)s", text)
        if not match:
            raise RuntimeError(f"Missing native phase timing: {phase}")
        result[key] = float(match[1])
    for key, label in (("qap_pre_degree", "QAP pre degree"), ("qap_degree", "QAP degree"),
                       ("qap_variables", "QAP number of variables"), ("proof_bits", "Proof size in bits")):
        match = re.search(re.escape(label) + r": (\d+)", text)
        if match:
            result[key] = int(match[1])
    return result


class Run:
    def __init__(self, output, work, threads, timeout):
        self.output, self.work = output, work
        self.threads, self.timeout = threads, timeout
        self.stages = []
        self.prefix = "zekra-crc32-" + uuid.uuid4().hex[:12]

    def stage(self, name, image, command, *, shim=False):
        container = self.prefix + "-" + name.split("-")[0]
        args = ["docker", "run", "--name", container, "--init", "--network", "none",
                "--volume", f"{self.work}:/workspace/ZEKRA",
                "--workdir", "/workspace/ZEKRA", "--env", f"OMP_NUM_THREADS={self.threads}",
                "--env", "OMP_DYNAMIC=FALSE"]
        if shim:
            args += ["--volume", f"{self.output / 'harness' / 'sitecustomize.py'}:/opt/zekra-reproduce-shim/sitecustomize.py:ro",
                     "--env", "PYTHONPATH=/opt/zekra-reproduce-shim"]
        args += [image, *command]
        logfile = self.output / f"{name}.log"
        record = {"name": name, "command": args, "log": logfile.name}
        self.stages.append(record)
        print(f"Running {name} ...", flush=True)
        start = time.monotonic()
        try:
            with logfile.open("w") as log:
                completed = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT,
                                           timeout=self.timeout)
            record["exit_code"] = completed.returncode
        finally:
            record["wall_s"] = time.monotonic() - start
            try:
                inspected = subprocess.run(["docker", "inspect", "--format", "{{json .State}}", container],
                                           capture_output=True, text=True, timeout=30)
                if inspected.returncode == 0:
                    record["container_state"] = json.loads(inspected.stdout)
                else:
                    record["inspection_error"] = inspected.stderr.strip() or f"docker inspect exited {inspected.returncode}"
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                record["inspection_error"] = str(error)
            finally:
                try:
                    removed = subprocess.run(["docker", "rm", "--force", container],
                                             capture_output=True, text=True, timeout=30)
                    record["cleanup_exit_code"] = removed.returncode
                    if removed.returncode:
                        record["cleanup_error"] = removed.stderr.strip() or f"docker rm exited {removed.returncode}"
                except (OSError, subprocess.TimeoutExpired) as error:
                    record["cleanup_error"] = str(error)
            if logfile.exists():
                record["log_sha256"] = sha256(logfile)
        if record["exit_code"]:
            raise RuntimeError(f"{name} exited {record['exit_code']}; see {logfile}")
        if record.get("inspection_error") or record.get("cleanup_error"):
            raise RuntimeError(f"{name} container inspection or cleanup failed; see summary.json")
        return logfile.read_text(errors="replace")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New output directory (default: zekra/output/crc32-<UTC timestamp>)")
    parser.add_argument("--compiler-image", default="zkcfa-zekra:paper-ubuntu22.04")
    parser.add_argument("--prover-image", default="zekra-native:local")
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--stage-timeout", type=int, default=1800, help="Seconds per container stage")
    parser.add_argument("--prepare-only", action="store_true", help="Freeze source and harness without Docker or proving")
    args = parser.parse_args(argv)
    if args.threads < 1 or args.stage_timeout < 1:
        parser.error("threads and stage-timeout must be positive")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = validate_output(args.output or COMPONENT / "output" / f"crc32-{stamp}", SOURCE)
    before = source_state(SOURCE)
    if before["commit"] != PIN or before["status"]:
        raise ValueError(f"Require clean upstream ZEKRA at {PIN}; source was not changed")
    output.mkdir(parents=True)
    (output / "source-before.json").write_text(json.dumps(before, indent=2) + "\n")
    summary = {"status": "running", "upstream_commit": PIN, "threads": args.threads,
               "started_utc": stamp, "output": str(output), "stages": [],
               "timing_scope": "libsnark native-image phase times; amd64 extraction/formatting/compilation are separate wall times"}
    try:
        work = snapshot(SOURCE, output, PIN)
        harness = output / "harness"
        harness.mkdir()
        for path in (Path(__file__), COMPONENT / "reproduce" / "sitecustomize.py",
                     COMPONENT / "Dockerfile.zekra-paper22", COMPONENT / "Dockerfile.zekra-native",
                     COMPONENT / "requirements-paper22.txt"):
            shutil.copy2(path, harness / path.name)
        summary["harness_sha256"] = {p.name: sha256(p) for p in sorted(harness.iterdir())}
        summary["source_archive_sha256"] = sha256(output / "source.tar")
        if args.prepare_only:
            summary["status"] = "prepared"
        else:
            images = {}
            for role, tag in (("compiler", args.compiler_image), ("prover", args.prover_image)):
                info = json.loads(capture("docker", "image", "inspect", tag))[0]
                images[role] = {"tag": tag, "id": info["Id"], "architecture": info["Architecture"], "os": info["Os"]}
            summary["images"] = images
            if images["compiler"]["architecture"] != "amd64":
                raise ValueError("The released CRC32 extractor requires the amd64 compiler image")
            docker_info = json.loads(capture("docker", "info", "--format", "{{json .}}"))
            summary["docker"] = {key: docker_info[key] for key in
                                 ("ServerVersion", "Architecture", "NCPU", "MemTotal", "OperatingSystem")}
            native_arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(summary["docker"]["Architecture"], summary["docker"]["Architecture"])
            if images["prover"]["architecture"] != native_arch:
                raise ValueError("Prover image must match the Docker server architecture for native measurements")
            compiler, prover = images["compiler"]["id"], images["prover"]["id"]
            run = Run(output, work, args.threads, args.stage_timeout)
            summary["stages"] = run.stages
            environment = ('set -e; cat /etc/os-release; uname -m; gcc --version; ldd --version; '
                           'test "$(git -C /opt/jsnark rev-parse HEAD)" = 0955389d0aae986ceb25affc72edf37a59109250; '
                           'test "$(git -C /opt/jsnark/libsnark rev-parse HEAD)" = a37253cb4dfb6f0f9458f7136c87b6baf4a486f1; '
                           f'sha256sum {RUNNER}; '
                           "grep -E 'MULTICORE:|PERFORMANCE:|OPT_FLAGS:|USE_ASM:|CURVE:' /opt/jsnark/libsnark/build/CMakeCache.txt")
            run.stage("00-compiler-environment", compiler, ["bash", "-lc", environment + '; java -version; python3 --version; python3 -c "import angr, networkx; print(angr.__version__, networkx.__version__)"'])
            run.stage("01-prover-environment", prover, ["bash", "-lc", environment])
            extracted = run.stage("02-extractor", compiler, ["python3", "scripts/extractor.py", "-a", "./embench-iot-applications/crc32"], shim=True)
            require_markers(extracted, ["CFG has 88 nodes and 106 edges", "Execution path length pre compression: 3090",
                                       "Execution path length post compression: 24", "Execution path is valid according to the adjlist: True"])
            summary["extraction"] = {"cfg_nodes": 88, "cfg_edges": 106, "path_before": 3090, "path_after": 24, "valid": True}
            formatted = run.stage("03-formatter", compiler, ["python3", "scripts/circuit_input_formatter.py", "-a", "./embench-iot-applications/crc32/",
                "--pad-adjlist-to", "500", "--pad-path-to", "500", "--adjlist-levels", "15", "--nonce-verifier", "12353",
                "--nonce-path", "123", "--nonce-translator", "123", "--nonce-adjlist", "123", "--label-bitwidth", "10", "--bucket-bitwidth", "7", "--address-bitwidth", "24"])
            require_markers(formatted, [f"{key}: {value}" for key, value in HASHES.items()])
            summary["poseidon_hashes"] = HASHES
            compiled = run.stage("04-compile", compiler, ["python3", "scripts/compile_circuit.py", "--zekra-dir", "zekra_java/zekra",
                "--adjlist-len", "500", "--adjlist-levels", "15", "--path-len", "500", "--stack-depth", "15", "--label-bitwidth", "10",
                "--bucket-bitwidth", "7", "--address-bitwidth", "24", "--input-dir", "./embench-iot-applications/crc32", "--components-dir", "zekra_java/components", "-v"])
            require_markers(compiled, ["Total constraints: 336230"])
            if "Circuit was not satisfied" in compiled or "Error Detected" in compiled:
                raise RuntimeError("Circuit compilation reported an unsatisfied circuit")
            summary["constraints"] = 336230
            summary["artifacts"] = {str(p.relative_to(output)): {"sha256": sha256(p), "bytes": p.stat().st_size}
                                    for p in [work / "zekra.arith", work / "zekra_Sample_Run1.in",
                                              *(work / "embench-iot-applications" / "crc32" / name for name in ("adjlist", "recorded_path", "translator"))]}
            proof = run.stage("05-groth16", prover, [RUNNER, "gg", "zekra.arith", "zekra_Sample_Run1.in"])
            summary["groth16"] = proof_metrics(proof)
            if summary["groth16"].get("qap_pre_degree") != summary["constraints"]:
                raise RuntimeError("Native QAP pre degree does not match the compiled constraint count")
            summary["status"] = "passed"
    except (Exception, KeyboardInterrupt) as error:
        summary["status"] = "failed"
        summary["error"] = f"{type(error).__name__}: {error}"
    finally:
        after = source_state(SOURCE)
        (output / "source-after.json").write_text(json.dumps(after, indent=2) + "\n")
        summary["upstream_unchanged"] = before == after
        if not summary["upstream_unchanged"]:
            summary["status"] = "failed"
            summary["source_error"] = "Upstream source changed during reproduction"
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"CRC32 {summary['status']}: {output / 'summary.json'}", flush=True)
    return int(summary["status"] == "failed")


def interrupted(*_):
    raise KeyboardInterrupt("Reproduction interrupted")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
