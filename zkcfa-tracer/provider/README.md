# ZKCFA raw24 provider

This directory is the maintained trace-to-proof handoff. Static provisioning
derives the raw24 translator and full-key typed CFG from a measured executable;
the QEMU plugin records one complete root-scoped execution; and the device
faithfully normalizes the trace and signs the resulting blinded EP commitment
against a fresh registry challenge. The device authenticates evidence; the worker
and proof circuit check CFG membership, CRT declarations, and exact returns.

The default `complete` path preserves every normalized QEMU row. The optional
`shadow` path is an explicitly signed, lossy projection that preserves shadow
stack state but not loop multiplicity.

An authority may explicitly select `--profile raw64-typed-channels` for the
experimental full-width address encoding. The default remains `raw24-full-key`.
The selected profile is signed and propagated through device reporting and
bundle export; the Binius verifier must be compiled for the matching profile.
See [the raw64 format and experiment](../../zkcfa-binius64/RAW64.md) for the
three-word records, reserved tokens, and measured scope.

## Source layout

- [`qemu/trace_scope.c`](qemu/trace_scope.c) is the QEMU tracing plugin.
- [`examples/crc32/crc32.c`](examples/crc32/crc32.c) and
  [`examples/crc32/start.S`](examples/crc32/start.S) form the freestanding
  AArch64 demonstration used by `make static` and `make demo`. This small
  example is separate from the Embench CRC32 workload measured in the paper.
- [`tests/fixtures/external_reentry_main.c`](tests/fixtures/external_reentry_main.c)
  and [`tests/fixtures/external_reentry_dso.c`](tests/fixtures/external_reentry_dso.c)
  are negative-test fixtures for detecting hidden primary-ELF re-entry during
  an external call. The existing
  [`static/qemu_external_reentry.py`](static/qemu_external_reentry.py) driver
  requires a compiled test binary and preload library, plus explicit QEMU,
  sysroot, and runtime-dependency inputs. These fixtures are not run
  automatically by `make test` or `make demo`.

## Reproduce trace acquisition

All commands in this README run from the maintained provider directory. From
the monorepo root, first enter it:

```sh
cd zkcfa-tracer/provider
```

The container pins QEMU and build dependencies:

```sh
make demo
```

The container demo runs the maintained unit tests, builds and traces the sample,
checks that trace acquisition fails closed on tampered runtime code, and repeats
the build to verify reproducibility. The corresponding in-container operations
are:

```sh
make test
make static
make -f Makefile.static OUT=build/static qemu-negative
make -f Makefile.static OUT=build/static reproducible
```

`make static` builds the sample executable, provisions its static policy,
captures a complete QEMU trace, and produces `translator`, `typed_cfg`,
`recorded_path`, and device-local `evidence.json`. The optional `make shadow`
target, which is not part of `make demo`, produces a device-local projection
from that complete bundle. None of these targets creates keys or combines
authority, device, and registry roles.

## Production role flow

Keys and challenges come from external role owners. Private PEM files must be
mode `0600`; outputs must not already exist.

The authority signs a trace-independent CFG commitment and a power-of-two EP
policy capacity. It does not read `recorded_path`:

```sh
PYTHONPATH=. python3 -m zkcfa_provider.protocol authority \
  --artifacts /authority/static \
  --policy-artifacts /authority/static \
  --binary /authority/application \
  --authority-private /authority/keys/authority-private.pem \
  --device-public /authority/enrolled/device.pem \
  --device-id device-1 \
  --registry-output /authority/out/registry.json \
  --opening-output /authority/private/enrollment.json \
  --ep-cap 65536 \
  --path-mode complete
```

The reference online registry serves that signed registry and maintains
one-time challenge state:

```sh
PYTHONPATH=. python3 -m zkcfa_provider.registry \
  --registry /authority/out/registry.json \
  --authority-public /trust/authority.pem \
  --state-db /registry/private/challenges.sqlite3
```

Issue `POST /raw/challenges` with `device_id` and `raw_registry_id`. Supply the
returned 32-hex-character `challenge_id` and 64-hex-character `nonce` directly
to the device. The device checks code identity, acquisition completeness, scope,
artifact consistency and encoding capacity, then signs the recorded evidence.
It does not check the EP against the CFG or compare returns with the call stack:

```sh
PYTHONPATH=. python3 -m zkcfa_provider.protocol device \
  --artifacts /device/run \
  --policy-artifacts /device/static \
  --binary /device/application \
  --trace /device/run/trace.log \
  --evidence /device/run/evidence.json \
  --registry /device/in/registry.json \
  --opening /device/private/enrollment.json \
  --authority-public /device/trust/authority.pem \
  --device-private /device/keys/device.pem \
  --device-id device-1 \
  --challenge-id "$CHALLENGE_ID" \
  --nonce "$NONCE" \
  --report-output /device/out/report.json \
  --worker-secret-output /device/private/worker.json
```

Submit `report.json` to `POST /raw/reports/verify`; the service atomically
consumes its challenge. This accepts report authenticity and freshness, not
control-flow compliance; a matching verified proof is still required. The
service with `--state-db` persists issuance, expiry, and atomic consumption in
SQLite across ordinary restarts. Its database and parent directory are trusted
registry state; rollback protection and durable storage remain deployment
requirements. Omitting `--state-db` selects the in-memory reference service,
which rejects old reports as unknown after a restart.

For challenge-first acquisition, `zkcfa_provider.online.capture_raw_online_report`
starts QEMU only after receiving a challenge and uses the already provisioned
capacity. It creates a new private capture directory and accepts no existing
trace as input. The plugin emits `capture_context`, a domain-separated SHA-256
identifier of the registry, device, challenge ID, and nonce. The signer checks
that context on its snapshotted trace before signing; no forward-edge or
call/return-policy checks are added. The low-level `device` command can require
this check with `--require-capture-context`.

The context is a session identifier, not a MAC: the QEMU launcher, plugin,
normalizer, raw buffers, and signer together emulate the protected Tracer.
A compromised producer that can replace the log and its context is outside this
emulation's trust boundary. Existing offline evaluation APIs remain available
and do not establish challenge-before-execution merely by signing an old log.

At the worker, export the fixed proof handoff. `--authority-public`
is an external trust input used to verify the envelopes and is not copied:

```sh
PYTHONPATH=. python3 -m zkcfa_provider.protocol bundle \
  --output /handoff/bundle \
  --artifacts /device/run \
  --authority-public /worker/trust/authority.pem \
  --registry /authority/out/registry.json \
  --report /device/out/report.json \
  --worker-secret /device/private/worker.json
```

The worker exporter verifies both signatures, checks all cross-bindings, and recomputes
`H_cfg_raw24` and `H_ep_raw24` from the four private opening words and fixed-name
proof inputs. Its strict preflight rejects noncompliant paths or infeasible
multiplicities before proving. The circuit independently enforces those checks
even if a worker skips preflight. A compliant input is exported atomically:

```text
bundle/
├── public/
│   ├── registry.json
│   └── report.json
└── private/
    ├── worker.json
    ├── translator
    ├── typed_cfg
    └── recorded_path
```

`evidence.json`, `projection.json`, and `source-evidence.json` stay in the
device-local audit directory. They are validated before the device signature
but are not proof inputs and are never exported.

## Verifier trust configuration

The verifier must never learn its authority key from the bundle. Configure the
independent trust-store path, its pre-established PEM digest, and the expected
freshness values:

```sh
ZKCFA_PROVIDER_BUNDLE=/handoff/bundle \
ZKCFA_AUTHORITY_PUBLIC=/verifier/trust/authority.pem \
ZKCFA_AUTHORITY_SHA256=<64-lowercase-hex-pinned-pem-digest> \
ZKCFA_EXPECTED_CHALLENGE_ID=<32-lowercase-hex> \
ZKCFA_EXPECTED_NONCE=<64-lowercase-hex> \
  zkcfa64
```

The signed circuit object contains only `schema=zkcfa.raw.circuit`,
`profile` (default `raw24-full-key`), `backend=binius64`, `edge_cap`, `ep_cap`,
`path_mode`, and `log_inv_rate`.
Encoding, independent 128-bit blinding, the public ABI, and the address
namespace are fixed by the compiled profile. For raw24, EP encoding and BinMult
multiplicity width are derived uniquely from `ep_cap`: capacities through
`2^14` use `inline14` with 12 multiplicity bits; larger capacities through
`2^24` use `shared24` and the required derived width.
The experimental `raw64-typed-channels` profile always uses `wide64` EP rows
and retains the same capacity-dependent multiplicity widths. It must be paired
with the verifier built using `--features raw64`.

For `inline14`, the signed capacity pair must also satisfy
`2 * (ep_cap - 1) <= edge_cap * (2^12 - 1)`. The left side is the exact
number of BinMult queries, including padded transitions; the right side is the
aggregate range of the fixed-width CFG multiplicity table. This rejects a
capacity pair that must overflow for every possible execution, such as
`edge_cap=8, ep_cap=2^14`. It does not claim that every trace fitting a valid
pair is feasible: a concrete trace that concentrates 4096 queries on one CFG
entry can be recorded and signed, but is rejected by worker preflight and cannot
satisfy that proof configuration. The device does not count CFG membership queries.

The authority may choose any feasible signed power-of-two capacity at least as
large as the eventual execution. Paper evaluation uses exact fitted values
`E=max(8,next_power_of_two(active JMP/CAL/CRT table keys))` and
`L=max(16,next_power_of_two(path rows))`; that fitted policy is an evaluation
choice, not a production trust requirement. The all-in-one fitted benchmark
evaluation harness is under `../research/provider-integration/`.

## Capture and compliance boundary

`load_raw_evidence` is the device serializer. It derives return hints by recording
call/pop events, without comparing actual return targets. An underflow retains
the observed return with hint zero; unclosed calls remain in the path. EP addresses
need not occur in the CFG namespace. `load_raw_statement` adds worker-side policy
and witness-feasibility checks.

Normalization records actual branch destinations, including block-interior
addresses. A nonbranch instruction that does not continue sequentially is recorded
as `discontinuity <actual-destination> <actual-source>` using reserved tag 3.
The device commits both addresses; this capture record is rejected by the existing
proof relation. It cannot be silently normalized into a legal block transfer.

Stack-safe projection records stack changes without validating return destinations.
It removes copies only when their preceding address and mechanical stack state
match a retained copy, and preserves discontinuities and underflow events. This
prevents compression from deleting the only occurrence of a violated policy edge.
The trusted QEMU root/external-call boundary and code-integrity checks still define
which execution interval the capture covers; they are not an internal CFA verdict.

See [the correction and validation record](docs/DEVICE_CAPTURE_BOUNDARY.md).
