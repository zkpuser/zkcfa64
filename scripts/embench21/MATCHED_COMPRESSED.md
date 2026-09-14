# Shared compressed application measurements

This experiment gives Binius64 and repaired ZEKRA the same 21 captured, stack-safe
application paths from an explicitly selected signed campaign. Source bundles are
under `signed/<app>/shadow/bundle/private/` in that campaign. ZEKRA's released
application measurements use different paths and do not enter these timing
aggregates.

## Preserve the inputs

```sh
SOURCE_CAMPAIGN="/path/to/signed-campaign"
MATCHED_INPUTS="output/matched-compressed-inputs"
python3 scripts/embench21/prepare_matched_compressed.py \
  --source-campaign "$SOURCE_CAMPAIGN" \
  --output "$MATCHED_INPUTS"
```

Run these commands from the repository root, replacing the source path with an
existing campaign. Preparation requires a new output directory and the complete
signed bundles, static maps, and capture/projection evidence for all 21 applications.
It copies `translator`, `typed_cfg`,
and `recorded_path` byte-for-byte to `common/<app>/` and writes ZEKRA's five input
files separately to `zekra/<app>/`. It never recompresses the path, inserts returns,
changes call types, or completes an incomplete capture.

The raw24 address mapping is the one used by the evaluated Binius circuit:
`SCOPE_RETURN` maps to `0xffffff`; provider gateways `0xfffe0000 + id` map to
`0xff0000 + id`. Ordinary program addresses are unchanged. ZEKRA labels are ordered
using static successor sets, independent of EP visits. The prepared audits decode
the numeric labels and compare every operation and call continuation to the source.

ZEKRA requires untyped executable adjacency including returns. Its adjacency is
derived from JMP/CAL records and statically established return edges. Return blocks
come from the matching instruction map, with explicit external-call gateways;
callee JMP/CRT reachability determines allowed continuations. CRT declarations do
not become executable edges. No execution-path edge is used to augment the CFG.

The native relations retain their differences: ZEKRA checks untyped adjacency,
including RET transitions; the Binius relation checks typed edges and CRT binding
and requires a final empty stack. This is a shared-source input comparison, not a
claim that the circuits have identical acceptance sets.

`manifest.json` freezes the source files, public configuration, source capture and
projection evidence, capacities, label mapping, and each conversion audit. All 21
source paths pass typed membership, exact returns, and final-empty-stack checks.

## Measure serially

The runner requires the evaluated Binius scaling executable, its build metadata
JSON, and the repaired ZEKRA backend JAR. Supply their locations explicitly; they
are copied into each campaign's `frozen/` directory. The executable and JAR must
match `BINIUS_SHA` and `REPAIRED_JAR_SHA` in the runner. Selecting a path does not
relax these identity checks, and an arbitrary new build is not a substitute.
For a fresh source rerun, explicitly pass `--expected-binius-sha256` with the
newly built executable's SHA-256. Its build metadata must bind the same digest
in `binary.sha256` or `binaries.scaling.sha256`; record the actual compiler,
build command, flags, and source hashes alongside it. The expected binary and
build-metadata digests are frozen in the new plan and rechecked on resume.
The original JAR is read from the clean `zekra/ZEKRA` submodule. See the
[ZEKRA repair controls](../../zekra/reproduce/scaling/README.md) for the repair.

Run a separate smoke campaign first; its measurements do not enter the full run:

```sh
BINIUS_BINARY="/path/to/evaluated/scaling"
BINIUS_BUILD_METADATA="/path/to/evaluated/native-build.json"
REPAIRED_JAR="/path/to/repaired/xjsnark_backend.jar"
python3 scripts/embench21/run_matched_compressed.py \
  --inputs "$MATCHED_INPUTS" \
  --binius-binary "$BINIUS_BINARY" \
  --binius-build-metadata "$BINIUS_BUILD_METADATA" \
  --repaired-jar "$REPAIRED_JAR" \
  --output output/matched-compressed-smoke \
  --applications crc32
```

Then run the full campaign in a new directory:

```sh
python3 scripts/embench21/run_matched_compressed.py \
  --inputs "$MATCHED_INPUTS" \
  --binius-binary "$BINIUS_BINARY" \
  --binius-build-metadata "$BINIUS_BUILD_METADATA" \
  --repaired-jar "$REPAIRED_JAR" \
  --output output/matched-compressed
```

Add `--resume` to resume an interrupted campaign. The three artifact options can
be omitted on resume: only the campaign's frozen copies are used. Use the saved
`instrumentation/run_matched_compressed.py` if the working runner has changed.
The runner checks frozen inputs, binaries, intermediate artifacts, and prior logs;
it does not silently replace completed measurements. Docker access and macOS
process/RSS accounting must be available to the runner. The Docker server must be
ARM64 with at least eight CPUs and more than 18 GiB of memory; the compiler image
`zkcfa-zekra:paper-ubuntu22.04` must be amd64 and `zekra-native:local` must be ARM64.

Each application runs four Binius invocations followed by ZEKRA input formatting,
circuit compilation, and four native proof invocations. The first invocation of
each backend is an excluded warmup. Three verified measured runs are required for
a complete timing row. Proof workloads do not overlap. Threads and container CPUs
are fixed at eight; each stage has a 900-second limit. ZEKRA has an 18-GiB container
limit without additional swap; Binius has an 18-GiB sampled process-group guard.
The host guard and container limit are different resource mechanisms.

## Interpret the measurements

- The main time comparison is Binius `crypto_prove_ms` versus the libsnark prover
  phase. Binius witness filling/local checks are recorded separately.
- Binius setup covers construction and preprocessing. ZEKRA setup is libsnark key
  generation; formatter, compiler/witness, and native conversion are separate.
- Binius proof size is serialized bytes. ZEKRA's native output reports group-element
  bit accounting, not a measured serialized file size.
- Successful RSS is the largest peak from the three measured invocations, excluding
  warmup. Host and Linux accounting scopes remain explicit in the result records.
- Resource failures preserve their stage, logs, observed RSS, timeout and Docker
  OOM evidence. A failed application is not replaced by a shorter path.
- Inputs came from existing captured applications. These runs benchmark proof
  construction and verification, without fresh acquisition or signature timing.
  The frozen Binius research executable's original `synthetic=true` JSON field is
  retained verbatim; the campaign envelope records the actual input provenance.

The full run writes `plan.json`, per-attempt logs and phase records, per-backend
`result.json`, and aggregate `summary.json` / `results.csv`. Paper tables are not
automatically overwritten by the runner.
