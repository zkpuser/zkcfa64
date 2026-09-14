# zkCFA64

zkCFA64 is a research implementation of zero-knowledge control-flow attestation.
It captures a program's execution with QEMU, signs the resulting trace commitment,
and uses Binius64 or PLONK to prove that the execution follows the approved
control-flow graph and call/return policy. The repository also includes an
isolated reproduction of the ZEKRA comparison baseline.

**Start with the CRC32 demo below.** It creates the sample program, trace, signing
keys, challenges, and proof inputs automatically; no application data is needed.

## Requirements

The reference environment is **macOS with Docker Desktop**. You need:

- **Git**, **Python 3.10+**, **Bash**, and **Make**.
- **Docker** running Linux containers, with permission to run `docker` commands.
- Network access for the initial image builds and dependency downloads.

The Docker workflow installs Rust, QEMU, Java, and compiler dependencies inside
containers. Initial image builds and downloads take extra time; images and download
caches are reused, but each new run compiles its own Rust binaries. The full workflow
also needs `linux/amd64` container support for ZEKRA compilation, including emulation
on ARM64 hosts. Native component builds have separate requirements in their READMEs.

On Linux, ensure the host user can read private directories created by containers.
With default rootful Docker, these can be root-owned with mode `0700`, preventing
the host script from reading issuance metadata. That setup needs ownership mapping
before using this quickstart.

## Get the source

```sh
git clone --recurse-submodules https://github.com/zkpuser/zkcfa64.git
cd zkcfa64
```

For an existing checkout, initialize its pinned dependencies:

```sh
git submodule update --init --recursive
```

Run all remaining commands from the **repository root**. Check the checkout and
Docker before starting:

```sh
make check
docker info
```

`make check` validates layout, document links, and script syntax; it does not run
proofs. Keep the three dependency submodules at their recorded, clean revisions.

## First run

```sh
bash scripts/run-crc32-pipeline.sh --quick --output ../zkcfa64-first-run
```

This creates a new directory beside the checkout and runs:

1. Build and trace the bundled AArch64 CRC32 demo with QEMU.
2. Generate an authenticated execution bundle with disposable keys and challenges.
3. Generate and verify a **Binius64 proof**.
4. Reissue the same execution for PLONK, authenticate it, and check its circuit
   with **PLONK preflight**.

`--quick` still builds the tools and runs a real Binius64 proof. It skips the
provider's runtime negative/reproducibility checks, PLONK proof generation, and
ZEKRA. Provider unit tests still run when its image is built.

A successful run exits with code `0` and ends with:

```text
CRC32 pipeline passed. Private run directory: <absolute output path>
```

The output directory must be **new and outside the checkout**. Choose another name
for each run. Without `--output`, the script creates a private temporary directory
and prints its location.

## Find the results

Paths below are relative to your output directory:

| Path | What to inspect |
| --- | --- |
| `logs/04-binius-proof.log` | Final JSON record with `schema="zkcfa.raw.proof"` and `verified=true`. |
| `logs/07-plonk-proof.log` | Quick run: `schema="zkcfa.raw.preflight"`, `satisfied=true`. Full run: `schema="zkcfa.raw.proof"`, `verified=true`. |
| `provider/static/` | Demo executable, QEMU trace, and normalized CFG/path artifacts. |
| `provider/signed-binius/` | Binius64 bundle, generated keys, and `protocol-result.json`. |
| `plonk/reissued/` | PLONK bundle, generated keys, and reissuance metadata. |
| `zekra/summary.json` | Full run only: `status="passed"`, proof timings, artifact hashes, and source-isolation checks. |

Proof logs contain diagnostics as well as the final JSON record. Preflight success
means the circuit checks passed; it is not a PLONK proof. The proof CLIs verify
proofs in memory and report their sizes without exporting standalone proof files.
Keep run directories private: they contain traces, commitment openings, and signing
keys. The workflow also stores Rust build products under `cargo-target/` in that directory.

## End-to-end CRC32 reproduction

After the first run, execute the full workflow in a new directory:

```sh
bash scripts/run-crc32-pipeline.sh --output ../zkcfa64-full-run
```

This adds provider negative/reproducibility checks, a complete PLONK proof and
verification, and the upstream ZEKRA CRC32 control. ZEKRA must reproduce the
published CFG, path, three hashes, **336230 constraints**, and verification `PASS`.
Its source remains unchanged because compilation runs in an isolated snapshot.

The provider's small CRC32 demo and ZEKRA's released CRC32 workload are separate
inputs. This command checks integration; use the documented paper campaigns for
matched performance comparisons.

Other useful options:

```sh
# Preview commands without building or proving.
bash scripts/run-crc32-pipeline.sh --dry-run

# Run both zkCFA64 proof backends without the ZEKRA baseline.
bash scripts/run-crc32-pipeline.sh --stages provider,binius,plonk --output ../zkcfa64-backends-run
```

Selecting either proof backend requires `provider` in the same invocation.
Use `bash scripts/run-crc32-pipeline.sh --help` for all options.

## Choose your next step

| Goal | Start here |
| --- | --- |
| Capture a different program and issue signed inputs | [Trace provider](zkcfa-tracer/provider/README.md) |
| Run Binius64 with your own signed bundle | [Binius64 backend](zkcfa-binius64/README.md) |
| Run PLONK or reissue a Binius64 bundle | [PLONK backend](zkcfa-plonk/README.md) |
| Reproduce ZEKRA CRC32 or selected applications | [ZEKRA harness](zekra/README.md) |
| Reproduce the paper's application measurements | [Embench-21 workflow](scripts/embench21/README.md) and [matched comparison](scripts/embench21/MATCHED_COMPRESSED.md) |
| Inspect the paper's measured results and sample statistics | [Published experiment data](experiment-data/README.md) |
| Export completed measurements to the public dataset | [CSCloud data exporter](scripts/experiment-data/README.md) |
| Locate core code, tests, and experiments | [Repository layout](docs/repository-layout.md) |

The default proof backends accept authenticated **raw24 bundles**, including a
signed registry, device report, private CFG/path artifacts, and commitment openings.
Custom inputs also require an independently trusted authority key and the expected
verifier challenge. Each backend README defines its accepted formats and limits.
ZEKRA uses its own released inputs. See `make help` for component test commands.

## Common setup issues

| Symptom | Action |
| --- | --- |
| Docker cannot connect to its daemon | Start Docker and confirm `docker info` succeeds. |
| A submodule is missing or at a different revision | Run `git submodule update --init --recursive`; preserve any local dependency edits before restoring a clean checkout. |
| The output directory already exists | Choose a new `--output` path outside the repository. |
| A build or proof stops before the success message | Inspect the last stage log under `logs/`. For a killed process, check Docker's resource state before treating it as a circuit failure. |

## License and provenance

Original repository code and tooling use the [MIT License](LICENSE), unless a
component or file states otherwise. Dependency licenses remain with their sources.
See [source provenance](docs/source-provenance.md) and [`.gitmodules`](.gitmodules)
for imported components and pinned dependencies.
