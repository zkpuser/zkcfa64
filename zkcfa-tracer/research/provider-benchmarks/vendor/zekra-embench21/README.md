# ZEKRA Embench-IoT source snapshot

This directory contains the 21 application source snapshot published by
ZEKRA at Git revision `01a0152bfd9812a0569dce19965e7e92df30015d`.
The batch provider compiles each application independently and never consumes
the released CFG or recorded path as proof evidence.

`manifest.json` pins the complete C-input list in its exact link order, one of
two digest-pinned build profiles, the matching runtime profile, the expected
ELF SHA-256 digest, and any independently authored indirect-target policy for
each application. ZEKRA's extractor used unsorted `os.listdir` order; making
that order explicit is necessary for byte-for-byte reproduction. Twenty
released artifacts reproduce under the pinned Ubuntu 20/GCC 9 profile and
CRC32 reproduces under the pinned Ubuntu 22/GCC 11 profile. The upstream Git
tree does not track these ELF files, so the hashes are reproduced from tracked
source, fixed compiler arguments, and explicit order rather than accepted as
unaudited binary inputs. `static/build_embench21.py` rejects omitted or extra C
inputs and every output whose digest differs from the manifest.
The static provider constructs `typed_cfg` only from that measured ELF and the
pre-provisioned policy; neither a QEMU trace nor a ZEKRA-generated input is a
static source.

`recovery/` contains a separate hash-bound overlay for `picojpeg` and
`sglib-combined`.  It recovers two upstream workload components needed for a
complete x86-64 run, but it is deliberately identified as base ZEKRA plus an
overlay rather than as the byte-identical ZEKRA snapshot.  See
`recovery/README.md` for the exact source/ELF hashes, build command, boundary
requirements, and legacy-attestation caveat.

Applications may call the profile-matched Ubuntu loader, libc, or libm through a
byte-bound PLT gateway.  Those external implementations and their effects are
measured but trusted and outside the CFA relation.  The V3 tracer requires
eager binding and read-only relocated PLT slots, rejects lazy resolver re-entry,
and accepts return only after it
has observed execution leave the primary ELF and resume at the exact signed
fallthrough. Scope-policy v2 binds V3 to this exact external-call model and to
the measured profile dependency manifest; it does not expose the private
per-call policy as a deterministic public digest. This is an explicit
experiment boundary, not whole-system CFA.

`source/LICENSE` is ZEKRA's MIT license.  The Embench source files carry their
upstream SPDX notices; most are GPL-3.0-or-later.  The complete corresponding
source needed by the 21 build recipes is retained here so that every generated
x86-64 executable remains reproducible and redistributable.  No released path,
CFG, nonce, or generated proof input is vendored.
