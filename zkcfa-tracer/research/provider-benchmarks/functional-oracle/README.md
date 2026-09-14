# Embench functional-oracle overlay

This is a second, independent overlay on top of the already materialized
boundary-recovery tree. It does not edit the immutable ZEKRA vendor snapshot or
the existing `recovery/` overlay.

ZEKRA reduced the workloads of `matmult-int`, `nbody`, `primecount`, and `slre`
without reducing their result oracles. The computation therefore completes, but
the common Embench `main` returns 1. The four patches keep the reduced workloads
and change only the stale oracle data:

| application | reduced workload result | repaired oracle |
|---|---:|---:|
| `matmult-int` | `[[19889638, 21314794], [16940158, 22958442]]` | same 2x2 matrix |
| `nbody` | `-0.16907516382852447` | same single energy sample |
| `primecount` | `30` | `30` |
| `slre` | `47` | `47` |

The materializer hash-gates the incoming recovery manifest and provenance, all
four incoming source files, all four patches, and all four resulting source
files. It rejects symlinks, stale `bin/` contents, malformed or partial ELF pins,
an existing output, and output paths inside either input tree. The output keeps
the first-layer `recovery-provenance.json` and adds
`functional-oracle-provenance.json` plus a copy of this overlay.

## ELF pins and reproducible bootstrap

The checked-in overlay contains final hashes produced by the pinned Ubuntu 20,
GCC 9.4.0, binutils 2.34 toolchain in `Dockerfile.bootstrap`:

| application | repaired ELF SHA-256 |
|---|---|
| `matmult-int` | `551a02c0ddb778645777c50176a3bc7063b60487113b8f31d2c0b0549a77960c` |
| `nbody` | `0d35c90e58c9057e15f074ef11efbfb29bf41ea13e4407badbd9c923e3ae5765` |
| `primecount` | `75e38d50790364b2ee54e5c0eb1ac70a8d3de55d7ea3a468f5a6da914f2ceca6` |
| `slre` | `18675b07c2da113870fa4149d11ec663bd15a205e3e9fe6dc52fa885d7fe02c1` |

Normal materialization produces a valid, fully pinned manifest:

```sh
python3 static/materialize_recovery.py \
  --vendor vendor/zekra-embench21 \
  --overlay vendor/zekra-embench21/recovery/overlay.json \
  --output /tmp/zekra-embench21-recovered

python3 static/materialize_functional_oracle.py \
  --recovered /tmp/zekra-embench21-recovered \
  --overlay functional-oracle/overlay.json \
  --output /tmp/zekra-embench21-functional
```

For a deliberate future re-bootstrap, replace all four functional ELF pins in a
working copy of `overlay.json` with the literal `BOOTSTRAP_REQUIRED` and pass
`--bootstrap-source-only`. That output is intentionally not a valid
`zkcfa.embench21-manifest.v1`: the normal hash-gated suite builder rejects the
sentinel. Compile with `Dockerfile.bootstrap` and the manifest's exact source
order, then pin all four new digests before normal use. Mixed pending/pinned
states and bootstrap mode against an already pinned overlay are rejected.

The final 21-app campaign must require `guest_exit_status == 0` for every app and
must feed the exact same newly pinned ELF into QEMU tracing and the compatibility
executor. Historical ZEKRA ELFs and paths remain a separate baseline.
