# Experiment data

This directory contains the public measurement datasets used in the zkCFA64
paper. It is versioned with the implementation so that readers can inspect the
reported results without running the benchmarks.

## Available datasets

| Directory | Contents |
| --- | --- |
| [cscloud/](cscloud/README.md) | Final CSCloud measurements: 21-application comparisons, membership and stack controls, scaling, address-width experiments, online attestation, and ZEKRA reproduction. |

Each dataset includes CSV tables, JSON sample statistics, environment and artifact
identities, and a SHA-256 manifest. The CSCloud package contains 25 files totaling
about 2.05 MiB. Its files preserve the finalized paper data package byte for byte.

## Read the results

Open the CSV files for tabular analysis; use the corresponding JSON for sample
lists, units, timing scopes, and outcome details. The
[dataset README](cscloud/README.md) maps each file to its experiment.

Failures, timeouts, and unexecuted attempts are retained. Missing values are not
zero, and excluded warmups do not enter the formal timing statistics. Read the
recorded repetition counts and measurement scope before comparing backends.

## Verify the package

Run from the repository root with Python 3:

```sh
python3 - <<'PY'
import hashlib
import json
from pathlib import Path

base = Path("experiment-data/cscloud")
manifest = json.loads((base / "manifest.json").read_text())
expected = set(manifest["files_sha256"]) | {"manifest.json"}
assert {p.name for p in base.iterdir()} == expected, "Unexpected package contents"
for name, expected_hash in manifest["files_sha256"].items():
    actual_hash = hashlib.sha256((base / name).read_bytes()).hexdigest()
    assert actual_hash == expected_hash, f"Hash mismatch: {name}"
print(f"Verified {len(expected) - 1} payload files.")
PY
```

Expected output: `Verified 24 payload files.` This checks packaged file integrity;
it does not execute benchmarks or reverify proofs. Export paths recorded in the
manifest identify the original run archive, not files required in this checkout.

## Export updated results

Experiment runners write to their private campaign directories. After a complete
campaign, use the [CSCloud exporter](../scripts/experiment-data/README.md) to
validate and publish its selected results here:

```sh
python3 scripts/experiment-data/export_cscloud.py \
  --run-root /absolute/path/to/closed-run \
  --selection /absolute/path/to/selection.json \
  --replace
```

The default destination is `experiment-data/cscloud/`. Use `--check` instead of
`--replace` to validate without writing, or `--output` to create a separate
candidate package. The selection pins a specific completed run; see the exporter
README for the required inputs and the published campaign's selection record.

## Reproduce the measurements

Start with the [repository README](../README.md), then use the
[Embench-21 workflow](../scripts/embench21/README.md),
[matched comparison](../scripts/embench21/MATCHED_COMPRESSED.md), and component
research instructions for [Binius64](../zkcfa-binius64/research/README.md),
[PLONK](../zkcfa-plonk/research/README.md), and [ZEKRA](../zekra/README.md).
The recorded source revisions, inputs, toolchains, hardware, and resource limits
define the measurement environment; timings can vary on another system.

This directory contains public statistics and provenance. Full run archives stay
in private campaign directories: signing keys, commitment openings, raw traces,
proof transcripts, binaries, and large logs are not part of these datasets.
