# Repository layout

The top-level directories are component boundaries. Commands shared across
components live in `scripts/`; each component keeps its own build environment,
protocol documentation, licenses, and research evidence.

| Area | Maintained entry point | Responsibility |
| --- | --- | --- |
| Trace provider | [zkcfa-tracer/provider](../zkcfa-tracer/provider/README.md) | Static provisioning, QEMU tracing, normalization, signing, and bundle export. |
| Binius64 backend | [zkcfa-binius64/zkcfa64](../zkcfa-binius64/README.md) | The application circuit, prover, verifier, and reporting. |
| PLONK backend | [zkcfa-plonk/zkcfa](../zkcfa-plonk/README.md) | Poseidon commitments, the PLONK relation, proving/verifying, and authenticated reissuance. |
| ZEKRA baseline | [zekra/reproduce](../zekra/reproduce/README.md) | Isolated reproduction around the upstream artifact. |
| Shared orchestration | [scripts](../scripts/README.md) | Repository checks, CRC32 integration, and Embench-21 campaign helpers. |
| Public experiment data | [experiment-data](../experiment-data/README.md) | Reviewed statistics, samples, failure outcomes, and provenance for paper experiments. |

## Application code and upstream dependencies

`zkcfa-binius64/binius64`, `zkcfa-plonk/plonk`, and `zekra/ZEKRA` are Git
submodules. The adjacent application and wrapper directories are owned by this
repository. Preserve this separation when adding code: upstream files retain
their own version history and licenses.

The two application crates are independent Cargo projects, both named `zkcfa`.
Their dependency versions, lockfiles, and toolchains differ. The root Makefile
dispatches to them without creating a combined Cargo workspace or moving their
path dependencies. `test-binius` selects Rust 1.97.1, matching its pinned
dependency; `test-plonk` runs from the crate directory so its toolchain file is
honored. Both test targets use their checked-in lockfiles.

## Paper experiments

The current [Embench-21 workflow](../scripts/embench21/README.md) coordinates
prepared inputs, acquisition, signed bundles, and measurement. Backend-specific
methods and reproduction tools remain with the component that defines their
measurement semantics:

- [Binius64 results](../zkcfa-binius64/research/README.md).
- [PLONK comparison](../zkcfa-plonk/research/README.md).
- [ZEKRA reproduction and experiment tools](../zekra/README.md).
- [Tracer research navigation](../zkcfa-tracer/research/README.md).

Reviewed paper data is collected in `experiment-data/`, with the CSCloud release
in [experiment-data/cscloud](../experiment-data/cscloud/). These exports retain
statistics, per-run samples, failure outcomes, and source/provenance metadata.
The ignored `output/` tree holds local raw runs and private working artifacts.

The tracer research tree supplies the acquisition adapters, source overlays,
integration harness, and ZEKRA-compatible compression used by the experiments.
The Binius64 and ZEKRA scaling helpers share
`zkcfa-tracer/research/zekra_projection.py`; the maintained provider uses its
own stack-safe projection. Benchmark vendor snapshots retain the exact source
inputs and licenses needed for acquisition and comparison.

The membership and timestamped-stack controls are explicit research features;
the production relation retains membership and stack checks. Frozen measurement
records preserve the source revisions and parameters actually used. Earlier
implementations and superseded exploratory studies remain available in Git
history rather than the working tree.

## Local working files

`ppt/` holds local presentations and their `.ppt-build/` and `.chart-data-*`
working directories. `paper/` holds local manuscript snapshots. Both are
ignored and are not dependencies of published repository instructions.

The existing `output/`, `tmp/`, component input directories, and tracer work
directories are also ignored. Prefer a private campaign directory outside the
checkout for cross-backend experiments; the full CRC32 pipeline uses that
arrangement by default. The standalone upstream ZEKRA control uses the ignored
`zekra/output/` directory and checks that its source checkout is unchanged.
Generated bundles, execution paths, openings, and keys belong in the campaign
directory. Publish reviewed paper statistics, samples, and provenance in
`experiment-data/`; keep private inputs and complete working artifacts in the
ignored campaign directories.

## Checks and execution

Run `make check` from the repository root for lightweight structural checks.
Run component tests explicitly through `make test-provider`, `make test-binius`,
`make test-plonk`, or `make test-zekra` after installing their documented
dependencies. Full experiments are separate commands; neither layout checks nor component tests
stand in for a new 21-application measurement campaign.
