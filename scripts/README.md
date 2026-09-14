# Shared repository tools

These entry points coordinate components from the monorepo root. Tools used
only by a provider or backend remain with that component.

| Entry point | Purpose | Requirements |
| --- | --- | --- |
| `make check` / `python3 scripts/check-repository.py` | Validate repository boundaries, maintained-document links, and Python/shell syntax without running experiments. | Git, Python 3, Bash. |
| [run-crc32-pipeline.sh](run-crc32-pipeline.sh) | Run provider acquisition, signing, Binius64, PLONK, and the isolated ZEKRA comparison. | Docker, initialized submodules; full options in `--help` and the [root README](../README.md#end-to-end-crc32-reproduction). |
| [embench21/](embench21/README.md) | Acquire and sign the prepared 21-application suite, then measure both Binius64 path modes. | Prepared vendor/binary/sysroot inputs, provider Docker image, and a macOS proof host. |
| [experiment-data/](experiment-data/README.md) | Validate and export a completed CSCloud campaign to the public dataset. | Python 3.10+, completed run archive, and pinned selection JSON. |

The [root Makefile](../Makefile) also exposes individual component test targets.
For a CRC32 command preview, run `make crc32 CRC32_ARGS="--dry-run"`.
`--quick` performs a reduced smoke run; it is not the full reproduction.

The repository checker uses Git-visible files, so ignored local artifacts cannot
satisfy links that would be broken in a clean checkout. It excludes third-party
submodules and vendored sources. It checks local
link destinations, not remote URLs or section anchors, and parses scripts
without executing them. Experiment-specific checks are documented beside their
runners.

Keep generated campaign directories private. This directory holds orchestration
source and usage instructions, not experiment outputs or signing keys.
