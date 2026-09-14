# Embench-21 rerun helpers

These helpers acquire fresh QEMU inputs and run the 21-application Binius64 suite.
The paper's same-path Binius64/ZEKRA comparison is documented in
[MATCHED_COMPRESSED.md](MATCHED_COMPRESSED.md); the original released-application
SmartMemory diagnosis and repair checks are in [ZEKRA application instructions](../../zekra/reproduce/APPLICATIONS.md).

- `docker-compose.yml` pins Ubuntu 20.04 and 22.04 builder images and builds the maintained
  provider image from `zkcfa-tracer/provider/Dockerfile`.
- `prepare_current_inputs.py` runs inside the provider image, compiles the QEMU plugin, acquires one
  fresh complete trace per application, normalizes it, and emits digest-addressed input metadata.
- `run_binius_campaign.py` runs on the proof host after signed-bundle construction. It executes one
  serialized complete and shadow proof per application, records verification outcomes, captures
  peak resident set size, and emits `results.csv` plus `metadata.json`.
- [`run_plonk_campaign.py`](../../zkcfa-plonk/research/scripts/run_plonk_campaign.py) authenticates and reissues the same private raw24 artifacts to PLONK,
  then runs serialized preflights and KZG proofs with time and process-group RSS limits. It records
  failed, interrupted, and resource-skipped attempts separately from verified proofs.

## Prepared inputs

Run the commands below from the monorepo root with Docker Compose available. First prepare a
private campaign directory with this layout:

```text
campaign/
  vendor/manifest.json
  vendor/<indirect-policy files referenced by the manifest>
  bin/<application>                  # all 21 x86-64 ELF executables
  sysroots/ubuntu20/
  sysroots/ubuntu22/
```

The manifest must contain the ordered application list in `prepare_current_inputs.py`, with each
application's `elf_sha256`, `runtime_profile` (`ubuntu20` or `ubuntu22`), and any `indirect_policy`
path relative to `vendor/`. Supply the materialized recovery and functional-oracle vendor inputs
and binaries built with the matching toolchains; acquisition checks every ELF against its manifest
hash. Each sysroot must contain its matching `lib64/ld-linux-x86-64.so.2`,
`lib/x86_64-linux-gnu/libc.so.6`, and `lib/x86_64-linux-gnu/libm.so.6`, including any symlink targets.
The helpers do not build these binaries, materialize vendor overlays, or populate the sysroots.

## Acquire and sign in the provider container

Set `campaign_dir` to the absolute path of that prepared directory. The repository is mounted
read-only; generated files go into the campaign directory. `PYTHONPATH=/provider` is required
for the provider Python modules; `--provider` alone does not set the import path.

```sh
campaign_dir=/absolute/path/to/campaign
docker compose -f scripts/embench21/docker-compose.yml run --rm --build \
  -v "$PWD:/workspace:ro" -v "$campaign_dir:/campaign" \
  -e PYTHONPATH=/provider provider \
  python3 /workspace/scripts/embench21/prepare_current_inputs.py --campaign /campaign
```

This creates `inputs/<application>/` with the binary, complete trace and normalized artifacts,
plus `inputs.json` containing public digests. Then the existing evaluation harness creates one
complete and one shadow signed bundle per application, with disposable keys and fresh challenges:

```sh
docker compose -f scripts/embench21/docker-compose.yml run --rm \
  -v "$PWD:/workspace:ro" -v "$campaign_dir:/campaign" \
  -e PYTHONPATH=/provider provider \
  python3 /workspace/zkcfa-tracer/research/provider-integration/suite.py \
  --inputs /campaign/inputs --output /campaign/signed
```

The resulting `signed/bundles.json` and `signed/<application>/{complete,shadow}/` directories
are the inputs expected by `run_binius_campaign.py`.

## Measure on the macOS proof host

Build the native release executable as described in the
[Binius64 README](../../zkcfa-binius64/README.md#build-and-test), then supply its absolute path.
The proof helper uses macOS `/usr/bin/time -l` for peak RSS and requires `rustc` on `PATH` for
metadata. Run it on macOS, with the campaign directory accessible from that host:

```sh
python3 scripts/embench21/run_binius_campaign.py \
  --campaign "$campaign_dir" --binary /absolute/path/to/release-executable --threads 8
```

The helper runs all 42 proofs sequentially, once each: 21 complete followed by 21 shadow.
It preserves a failed command or unsuccessful verification as a failed result and continues the
remaining lanes. Per-run logs and `binius-results/results.csv` are saved as jobs finish;
`metadata.json` freezes the result hash after all 42 attempts finish.
These are single-run measurements, not repeated-run uncertainty estimates.

Acquisition, signing and proving require their respective `inputs/`, `signed/` and
`binius-results/` output directories to be absent; they do not resume a partial campaign.
Keep campaign directories private: working files include execution paths, openings, nonces and
signing keys. Share only reviewed aggregate measurements and public-digest metadata.

## Matched PLONK/KZG measurements

Build both maintained PLONK executables using the same selected toolchain and CPU flags as the
paired Binius build. Supply their paths to the runner; it records binary hashes and does not infer
build flags from the current shell. An optional `--build-metadata` JSON file can record the actual
build commands and toolchain. The runner needs macOS `/usr/bin/time -l` and permission to read
process-group RSS through `ps`.

```sh
python3 zkcfa-plonk/research/scripts/run_plonk_campaign.py \
  --campaign "$campaign_dir" \
  --reissue-binary /absolute/path/to/zkcfa-reissue \
  --prove-binary /absolute/path/to/zkcfa \
  --modes shadow --threads 8 \
  --max-proof-domain 8388608 --max-rss-gib 20 --proof-timeout-s 1800
```

The default mode is `shadow`, matching the paper's backend comparison. Use `--modes complete,shadow`
for both modes or `--applications crc32` for a small end-to-end check. Each lane uses fresh target
keys, openings, and a runner-supplied challenge through the authenticated reissuer. The runner
checks that all three private artifact files, capacities, path mode, endpoints, code measurement,
and scope survive reissuance; it also checks the proof's public commitments and shape against the
target signed statement and preflight. Signatures and native commitment opening are checked by
the Rust executables.

`--phase prepare` reissues and preflights without KZG setup/proving. `--phase prove` resumes those
same prepared bundles and requires identical binary hashes, source manifest, and thread count.
It does not rerun prior failures or successful proofs. Increasing `--max-proof-domain` permits a
previously domain-skipped lane to be attempted, without replacing any measured result.

The default proof-domain limit is `2^22`; the example raises it to `2^23` so that the large
stack-safe `picojpeg` lane can be attempted under the RSS/time limits. A domain skip is a scheduling
decision, not an observed memory failure. The preflight estimate is also only a guard; measured
gate/domain values come exclusively from executable reports. Do not run this campaign alongside
other proof benchmarks.

Results are updated after each lane under `plonk-results/`: `results.csv`, `metadata.json`,
`run-identity.json`, and per-phase logs. `verified=true` requires a genuine `zkcfa.raw.proof`
report; a `satisfied=true` preflight is never counted as a proof. The CSV separates preflight
authentication time from post-proof public authentication time. Peak memory footprint, when
available, is recorded separately from peak RSS. Both modes of a paired backend comparison must
be drawn from the same newly acquired inputs; historical proof timings are never imported.

Lightweight runner checks (no cryptographic proof generation):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s zkcfa-plonk/research/tests -p test_plonk_campaign.py -v
```

## Export reviewed paper measurements

Once all 42 primary attempts finish, the primary table and its summary can be frozen before
the backend campaigns complete:

```sh
python3 scripts/embench21/export_paper_data.py \
  --campaign "$campaign_dir" --primary-only --output /absolute/path/to/new-primary-export
```

The output contains the original primary CSV, `primary-table.tex`, `summary.json`, and a
`primary-constraint-audit.json` tying each successful row's AND/BMUL counts to its proof log hash.
The projection reduction uses **AND + BMUL**. The audit records reported IMUL values separately;
an omitted ZERO count remains unavailable. This metric is distinct from the scaling study's
AND + IMUL + BMUL + ZERO sum.

When both backend campaigns finish, create a separate full export:

```sh
python3 scripts/embench21/export_paper_data.py \
  --campaign "$campaign_dir" \
  --plonk-results "$campaign_dir/plonk-results/results.csv" \
  --zekra-results /absolute/path/to/new-zekra-campaign/results.csv \
  --output /absolute/path/to/new-full-export
```

The exporter checks completed CSV hashes and backend provenance, rehashes paired private
artifacts, and emits a combined backend CSV, both table fragments, and their summary. Ratios use
only applications with verified proofs on both matched backends. Failed proof phase values stay
empty; observed failure RSS/wall time and outcome remain available. ZEKRA is a separate legacy
statement and never enters matched ratios. Its proof size is the `reported_proof_bits` value in
the verified libsnark log; `ceiling_bytes_equivalent` is a unit equivalent, not a measured
serialized-file size. Table units are explicit in `summary.json`.
PLONK RSS and domain guards are marked `R` (configured resource limit), not OOM; timeout uses
`T`. `M` is reserved for ZEKRA outcomes with a matching Docker `OOMKilled` event and exit 137.
The generated caption lists only outcome types present in that export.

Exports never overwrite an existing directory, never substitute historical measurements, and
do not edit the manuscript. Lightweight aggregation checks:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/embench21/tests -p test_paper_export.py -v
```
