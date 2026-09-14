# ZEKRA reproduction harness

This directory reproduces the ZEKRA baseline used in the zkCFA64 paper: compile
its control-flow circuit, generate a Groth16 proof, and verify it. The upstream
implementation stays unchanged; every run uses an isolated source snapshot.

## Directory layout

| Path | Purpose |
| --- | --- |
| `ZEKRA/` | Pinned upstream implementation and 21 released application inputs. |
| `reproduce/` | CRC32 and application runners, input audits, scaling and repair experiments. |
| `reproduce/tests/` | Host-only tests for the reproduction tools. |
| `output/` | Ignored source snapshots, generated circuits, inputs, logs and results. |

All commands below run from the **repository root**.

## Build the environments

Requirements: Git, Python 3.10+, Docker, and support for `linux/amd64` containers.
The 21-application runner requires an **ARM64 Docker host**; the CRC32 runner
also supports an AMD64 host with a matching native prover image. The default
application configuration uses eight CPUs and eight OpenMP threads.

```sh
git submodule update --init --recursive -- zekra/ZEKRA
docker build --platform linux/amd64 -f zekra/Dockerfile.zekra-paper22 \
  -t zkcfa-zekra:paper-ubuntu22.04 zekra
docker build -f zekra/Dockerfile.zekra-native -t zekra-native:local zekra
make test-zekra
```

The first image provides the pinned Ubuntu/GCC/Python/xJsnark compiler environment.
The second builds libsnark for native proving. Runs record both image identities
and keep compilation wall time separate from native setup/prove/verify timings.

## Accepted inputs

- **CRC32:** the clean upstream checkout at commit `01a0152bfd9812a0569dce19965e7e92df30015d`.
  The runner extracts the bundled C application and uses the published 500/500 capacities.
- **Application suite:** the upstream `embench-iot-applications/` directories, each
  containing `adjlist`, `numified_adjlist`, `translator`, `recorded_path`, and
  `numified_path`. The runner uses these saved compressed inputs and derives
  capacities from their graph and path sizes; it does not rerun acquisition.
- **Selection:** `--applications` accepts distinct, comma-separated names from the
  list below. Selection and artifact retention are fixed during preparation.
- **Suite output:** preparation requires a new directory outside `ZEKRA/`; execution
  requires that prepared directory and unchanged frozen source files.

```text
aha-mont64, crc32, cubic, edn, huffbench, matmult-int, md5sum,
minver, nbody, nettle-aes, nettle-sha256, nsichneu, picojpeg,
primecount, sglib-combined, slre, st, statemate, tarfind, ud, wikisort
```

These entry points consume upstream inputs, not signed Binius64 or PLONK bundles.
Custom typed inputs and patched-jar experiments have separate
[scaling](reproduce/scaling/README.md) and [application](reproduce/APPLICATIONS.md) workflows.

## Run

Reproduce the complete CRC32 extraction, compilation and proof:

```sh
make reproduce-zekra
```

Run three applications and the automatic CRC32 calibration control:

```sh
run_dir="$PWD/zekra/output/apps3"
python3 zekra/reproduce/scripts/run_zekra_campaign.py \
  --output "$run_dir" --prepare-only \
  --applications cubic,matmult-int,aha-mont64 --keep-artifacts
python3 zekra/reproduce/scripts/run_zekra_campaign.py \
  --output "$run_dir" --threads 8 --cpus 8 --require-proofs
```

For all 21 applications, omit `--applications` during preparation. Omit
`--require-proofs` when collecting the original implementation's known failures;
the runner still checks coverage and validates every reported success.

## Expected output

| Run | Success condition | Retained output |
| --- | --- | --- |
| CRC32 | CFG 88/106, path 3090/24, three published hashes, 336230 constraints, verification `PASS`. | New `output/crc32-<UTC timestamp>/`: `summary.json`, stage logs, source inventories, `work/ZEKRA/zekra.arith` and `zekra_Sample_Run1.in`. |
| Application suite | `validation_passed=true`; with `--require-proofs`, also `all_applications_verified=true`. | The chosen directory: `preparation.json`, `started.json`, `results.csv`, `summary.json`, source snapshot and per-application logs. |

With `--keep-artifacts`, each application's circuit and witness remain under
`snapshot/zekra/reproduce/results/embench-suite/<application>/`. The upstream CLI
generates and verifies proofs in memory; it does not export a serialized proof file.

`selection_complete` covers the requested subset; `coverage_complete` requires all
21 applications. The original jar has known unsatisfied samples and a recorded
memory-limited case, so complete coverage does not imply 21 valid proofs. Failed
checks return a nonzero exit code. See the [CRC32 guide](reproduce/README.md) and
[application guide](reproduce/APPLICATIONS.md) for result fields and failure diagnosis.

The harness uses the [MIT License](LICENSE); upstream code retains its own license.
