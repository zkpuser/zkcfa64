# CSCloud data export

[export_cscloud.py](export_cscloud.py) packages a completed CSCloud experiment
campaign into the public dataset at `experiment-data/cscloud/`. It validates the
selected exports, removes private fields and machine paths, regenerates CSV from
JSON, and writes a SHA-256 manifest. It does not run experiments or edit the paper.

Requires Python 3.10+ and the completed local run archive. No Docker or prover
process is started by this command. Run the examples from the repository root.

## Export a completed campaign

First validate the selected data without writing anything:

```sh
python3 scripts/experiment-data/export_cscloud.py \
  --run-root /absolute/path/to/closed-run \
  --selection /absolute/path/to/selection.json \
  --check
```

Then export to the default `experiment-data/cscloud/` directory:

```sh
python3 scripts/experiment-data/export_cscloud.py \
  --run-root /absolute/path/to/closed-run \
  --selection /absolute/path/to/selection.json \
  --replace
```

Omit `--replace` when creating a new dataset directory. To review a candidate
separately, use `--output /absolute/path/to/new-public-package`. An existing target
is replaced only when it is a complete, intact public package with no extra files.
Validation or installation failure preserves the existing package.

The command exits with status `0` and prints a JSON summary: `status` is
`validated` for `--check` or `packaged` for an export, with 10 blocks and 25 files.
Rejected inputs return a nonzero exit status. The command never stages, commits,
or pushes files; review the resulting Git diff before committing an update.

## Accepted inputs

This tool accepts the full CSCloud campaign archive and its pinned selection
record. Arbitrary CSV files, a CRC32 smoke run, and partial application exports
are insufficient. The archive must contain:

- `run.json` with schema `zkcfa.final-reproduction.v1` and the fresh-measurement policy.
- Completed native-build and environment metadata, plus Binius64 and PLONK
  scaling metadata identifying the measured hardware, tools, and limits.
- Terminal `logs/<stage>.process.json` records bound to the selected exports.
- All 10 result blocks listed below, with the required application grids,
  repetitions, and explicit failure or unexecuted-attempt records.

The selection uses schema `zkcfa.paper-data.selection.v1`. Its `run_started_utc`
must match `run.json`; every block specifies an `exports/`-relative `directory`
and the `manifest_sha256` of that directory's manifest file. Parent traversal and
symlink evidence are rejected. Source manifests also bind the absolute run path,
so moving an archive does not automatically make it valid at the new location.

| Blocks | Manifest file |
| --- | --- |
| `modes`, `matched`, `backends`, `released`, `repaired`, `repair-control`, `raw64` | `manifest.json` |
| `controls`, `online` | `evidence.json` |
| `structural` | `structural-results.json` |

[cscloud-selection.json](cscloud-selection.json) records the exact exports used
by the published dataset. With that original archive available locally, check it
using:

```sh
python3 scripts/experiment-data/export_cscloud.py \
  --run-root output/final-reproduction \
  --selection scripts/experiment-data/cscloud-selection.json \
  --check
```

For a new campaign, create a separate selection JSON using this schema. Set its
run identity, explicitly select all 10 export directories, and record the SHA-256
of each selected manifest. The published selection's hashes identify its original
run and must not be reused as pins for new measurements.

## Output and validation scope

The [dataset README](../../experiment-data/cscloud/README.md) describes all 25
output files. JSON retains statistical samples and outcome details; CSV is
regenerated from that public JSON. Timeouts and resource failures remain outcomes,
missing runs are not zero, and warmups remain excluded from formal statistics.

The exporter checks pinned statistics, experiment coverage, terminal stage records,
and file integrity. The upstream experiment exporters are responsible for the
full raw-evidence checks; this packaging step does not reopen private proofs or
rerun verification. Each new manifest records the exporter version by SHA-256.

Raw traces, signing keys, commitment openings, proof transcripts, binaries, and
large logs remain in the private run archive. Generated packages contain public
statistics and provenance only.

Run the exporter tests without benchmarks:

```sh
make test-experiment-data
```
