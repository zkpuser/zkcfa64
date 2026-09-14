# Paper experiments

These experiments exercise the maintained relations and preserve the measurements
and controls used by the paper. The release executable and signed bundle protocol
are described in the [component README](../README.md).

`scripts/` contains input generators, campaign runners, and result exporters;
`tests/` checks those tools without running proofs. `docs/` explains experiment
methods, `data/` contains published exports, and `results/` preserves a campaign's
inputs, raw measurements, and logs together.

Campaign metadata binds measurements to source paths and hashes. Reproduce or
audit a campaign with its recorded source revision. Each run records the scripts,
Cargo files, Rust modules, and experiment entry points used for the measurements.

Run the lightweight experiment tests from `zkcfa-binius64/`:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s research/tests -v
```

## Application and address-width comparisons

The [application campaign](../../scripts/embench21/README.md) provisions signed
inputs and records proof outcomes. The
[matched compressed-path comparison](../../scripts/embench21/MATCHED_COMPRESSED.md)
uses the same input bytes for Binius64 and PLONK and records the ZEKRA baseline.
Released ZEKRA inputs are available directly in the pinned
`zekra/ZEKRA/embench-iot-applications/` submodule.

[`RAW64_ADDRESS_RESULTS.md`](docs/RAW64_ADDRESS_RESULTS.md) compares raw24 with
the separately compiled full-width relation on fresh executions of the same
21 applications. See the [acquisition method](docs/RAW64_ADDRESS_ACQUISITION.md),
[measurements](data/raw64-address-comparison.csv), and [relation](../RAW64.md)
for the real 47-bit guest addresses and the experiment's evidence limits.

## Scaling and component controls

- [`scaling_inputs.py`](scripts/scaling_inputs.py) generates and audits
  the growing-CFG and fixed-CFG synthetic families. Complete, stack-safe, and
  ZEKRA-projected paths have separate row counts and capacities.
- [`run_scaling_binius.py`](scripts/run_scaling_binius.py) runs the
  production raw24 circuit through the [`scaling` example](../zkcfa64/examples/scaling.rs).
  Build it from `zkcfa64/` with
  `cargo build --locked --offline --release --features experiments --example scaling`.
  [`summarize_scaling.py`](scripts/summarize_scaling.py) verifies the
  input, source, and log identities before exporting the seven-scale control grid.
  Companion runners cover [PLONK](../../zkcfa-plonk/research/scripts/run_plonk_scaling.py)
  and [ZEKRA](../../zekra/reproduce/scaling/README.md).
- The [`construction_control` example](../zkcfa64/examples/construction_control.rs)
  compares BinMult, exact indexed selection, and weighted LogUp on the same
  Binius64 relation. It requires the `construction-control` build feature.
- The [timestamped-stack campaign](results/timestamped-stack/README.md)
  records the 21 shared synthetic fixtures and measured enabled/disabled
  constraint differences. Its [`stack_control` example](../zkcfa64/examples/stack_control.rs)
  requires the `stack-control` feature; the
  [cross-backend summary](../../scripts/stack-comparison/README.md) compares it
  with ZEKRA C6.

These controls use synthetic relation inputs. They do not establish acquisition
authenticity or replace the signed application campaign. Backend-native constraint
counts are different units and do not by themselves establish a proving-time ratio.

## Backend and private inputs

The [pinned ZK backend note](../docs/BACKEND_ZK.md) retains its protocol
suite, implementation invariants, validation evidence, and security limits.

Signed proof bundles come from [`zkcfa-tracer/provider`](../../zkcfa-tracer/provider/README.md).
Keep generated private inputs, commitment openings, and keys in the ignored
`zkcfa-binius64/input/` directory or a selected private run directory. Choose new
output directories when repeating experiments so original measurements remain intact.
