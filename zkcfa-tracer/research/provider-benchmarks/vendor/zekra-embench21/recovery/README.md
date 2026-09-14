# Embench boundary-recovery overlay

This directory defines an explicit, deterministic recovery variant for the two
ZEKRA Embench programs that crash before a complete `main` entry/return trace.
It does **not** edit or relabel the byte-identical ZEKRA snapshot.  The variant's
identity is the base ZEKRA revision plus `overlay.json` and its SHA-256 digest.

## Provenance and changes

The immutable base is ZEKRA revision
`01a0152bfd9812a0569dce19965e7e92df30015d`; its checked-in `manifest.json`
hash is
`e2fb14a493c2f5cdc276b1386cb90135be1b19eb2baf6f28173e95b3e3f71db6`.
The audited `overlay.json` hash is
`f5ec96bde01835a212d34a1c1c6d4fdb6350cdcafa21975efd70bbc74fced044`.
The recovery reference is the official Embench 1.0 tag at commit
`0466a18e4f6b47e19598d7c6ba72916d54b68f65`.  Every base source, patch,
recovered source, policy, and recovered ELF is independently hash-gated in
`overlay.json`; the upstream file hashes are provenance references and are not
fetched during a build.

The two minimal functional repairs are:

- `picojpeg`: restore the JPEG bytes that remain in the ZEKRA source but were
  commented out.  With only the first 48 bytes active, decode initialization
  fails and the unchanged verifier eventually calls `memcmp` on a null MCU
  buffer.  The recovery retains ZEKRA's `LOCAL_SCALE_FACTOR=1`; compared with
  official Embench 1.0, that scale factor is the only remaining source
  difference.
- `sglib-combined`: change the BEEBS heap from 2048 to the official 8192 bytes
  and restore the official array quicksort and `memcpy`.  On x86-64 the three
  100-node structures require 6400 bytes
  (`100 * (sizeof(dllist)=24 + sizeof(ilist)=16 + sizeof(rbtree)=24)`), so the
  old heap returns null during list construction.  The unchanged verifier also
  requires the sorted array.  The recovery retains ZEKRA's
  `LOCAL_SCALE_FACTOR=1` and aligned heap attribute.

The checked-in ZEKRA sources, manifest, and policies remain untouched.  The
materializer rejects a changed base manifest/source, changed patch or policy,
unexpected path, symlink, patch-context mismatch, recovered-source mismatch,
or existing output.  It writes `recovery-provenance.json` next to a separately
materialized manifest; the base `source_revision` field alone must never be
used as the composite variant identity.

## Reproduce

From `provider/`, materialize the source variant without compiling it:

```sh
python3 static/materialize_recovery.py \
  --vendor vendor/zekra-embench21 \
  --overlay vendor/zekra-embench21/recovery/overlay.json \
  --output /tmp/zekra-embench21-recovered
```

The provider Docker build materializes the same tree under the pinned Ubuntu
20/GCC 9 stage, rebuilds and hash-gates all 20 GCC-9 applications, and copies
the separately pinned Ubuntu 22 CRC32 into the recovery tree:

```sh
ZKCFA_TRACER_REVISION=<40-hex-tracer-revision> docker compose build provider
```

Run the full provider pipeline against the explicit recovered tree with:

```sh
ZKCFA_TRACER_REVISION=<40-hex-tracer-revision> docker compose run --rm \
  -v /absolute/host/output:/suite provider \
  python3 /provider/embench21_recovery_suite.py \
  --suite-root /suite --tracer-revision <40-hex-tracer-revision> \
  --accept-capacity-only
```

The recovery runner binds the base manifest, overlay, materialized manifest,
and recovery provenance in `provider-suite-summary.json` and
`recovery-suite.json`.  It also rehashes every raw handoff file and requires
complete root-return evidence before setting `raw_handoff_ready=true`.  The
explicit `--accept-capacity-only` option returns zero only when the sole failed
results are the three expected legacy-capacity failures and all three have a
complete raw handoff.  Their machine-readable result status remains `FAIL`;
the option does not turn them into legacy signed successes.  Without that
option, the expected three capacity failures make the command return one.  The
runner preserves the original 21-app baseline rather than overwriting it.

## Proof and attestation boundary

No trace boundary is shortened, synthesized, or marked complete after a
crash.  Recovery traces must still enter `main` from the external-root sentinel,
observe the real root return and captured continuation, exit with
`complete=1`, and pass runtime-code measurement.

The repaired programs produce complete raw `translator`, `typed_cfg`, and
`recorded_path` artifacts, but both exceed the old dense statement's
`EP_CAP <= 2^14` limit (`picojpeg`: 262144; `sglib-combined`: 32768).  A
capacity failure therefore is not a legacy dense signed bundle.  The legacy
provider signature also does not attest the recovery overlay or new raw proof
commitments.  Those work artifacts may be consumed by the separately audited
raw/full-edge proof lane only with that caveat; the old dense capacity gate is
intentionally unchanged.
