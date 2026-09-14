# Paper experiments

`scripts/` contains the PLONK campaign runners, `tests/` checks their report and
resource-accounting behavior, and `results/` preserves dated measurement exports.
Shared input preparation and cross-backend summaries remain in the repository's
[`scripts/embench21/`](../../scripts/embench21/README.md) directory.

The maintained PLONK experiments reuse the raw24 relation and Poseidon commitments:

- The [application runner](scripts/run_plonk_campaign.py) measures signed
  application bundles, setup, proof generation, and verification.
  The [shared campaign instructions](../../scripts/embench21/README.md#matched-plonkkzg-measurements)
  describe its paired inputs and resource limits.
- The [matched compressed-path comparison](../../scripts/embench21/MATCHED_COMPRESSED.md)
  uses byte-identical raw24 inputs for Binius64 and PLONK and preserves failed or
  resource-limited attempts alongside successful measurements.
- The [scaling example](../zkcfa/examples/scaling.rs) and
  [campaign runner](scripts/run_plonk_scaling.py) measure synthetic
  Complete paths, with circuit size, padded domain size, and separate timing phases.

From `zkcfa-plonk/`, build the explicit scaling experiment and run the lightweight
Python checks separately:

```sh
cargo build --release --locked --features experiments \
  --manifest-path zkcfa/Cargo.toml --example scaling
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s research/tests -v
```

These Python checks use synthetic reports and mock processes; they do not run
proofs or access provider keys. Campaigns continue to record supplied binary
identities and caller-supplied build metadata without inferring how a binary was built.

See the [component README](../README.md) for build commands and the research SRS
boundary. Generated bundles and local results remain in their selected output
directories; they are not inputs to the release executable unless explicitly supplied.
