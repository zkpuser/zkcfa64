# zkCFA on Binius64

Prove and verify an authenticated control-flow execution using Binius64.
The default executable uses raw24 addresses, a typed CFG, BinMult membership,
an exact call/return stack, and independently blinded CFG and path commitments.
An authority signs the program registry; a registered device signs each execution.

## Directory layout

| Path | Purpose |
| --- | --- |
| [`binius64/`](binius64/) | Pinned proof-system submodule; application changes belong outside this directory. |
| [`zkcfa64/`](zkcfa64/) | Rust application, lockfile, signed-bundle entry point, core relation, and module tests. |
| [`research/`](research/README.md), [`zkcfa64/examples/`](zkcfa64/examples/) | Experiment tools, optional Rust runners, fixed inputs, and measurement evidence. |
| [`RAW_PROTOCOL.md`](RAW_PROTOCOL.md), [`RAW24.md`](RAW24.md), [`docs/`](docs/) | Bundle protocol, relation encoding, and backend validation notes. |

## Build and test

Run every command below from the **repository root**. Use Rust **1.97.1**,
matching the pinned Binius64 toolchain; `--locked` preserves dependency versions.

```sh
git submodule update --init --recursive -- zkcfa-binius64/binius64
rustup toolchain install 1.97.1 --profile minimal
cargo +1.97.1 test --locked --no-default-features \
  --manifest-path zkcfa-binius64/zkcfa64/Cargo.toml --lib --bins
cargo +1.97.1 build --locked --release --no-default-features \
  --manifest-path zkcfa-binius64/zkcfa64/Cargo.toml
```

The test command checks raw24; ignored proof roundtrips and experiment features
are opt-in. Additional targets are listed in the repository [Makefile](../Makefile).

## Accepted inputs

Create a signed bundle with the sibling [provider pipeline](../zkcfa-tracer/provider/README.md).
The prove-then-verify command requires this exact structure:

```text
bundle/
  public/
    registry.json
    report.json
  private/
    worker.json
    translator
    typed_cfg
    recorded_path
```

Extra entries and symlinks are rejected. On Unix, use mode `0700` for `private/`
and `0600` for `worker.json`. The worker supplies two distinct, nonzero 128-bit
commitment openings. Keep generated bundles in `zkcfa-binius64/input/` (ignored)
or another private directory.

The three text artifacts must be ASCII, without comments or blank lines:

- `translator`: one unique node per line. Ordinary addresses use lowercase
  `0x`-prefixed hexadecimal in `0x1..0xfeffff`. `SCOPE_RETURN` and provider gateway
  tokens `0xfffe0000..0xfffefffe` map into the reserved raw24 suffix; numeric input
  cannot directly name that suffix. Zero is reserved for padding.
- `typed_cfg`: `SRC jmp DST`, `SRC cal DST`, or `SRC crt RETURN_SITE` per line.
  All nodes must occur in `translator`; duplicate source/destination pairs,
  including pairs with different types, and static `ret` records are rejected.
- `recorded_path`: header `initial_node=NODE final_node=NODE`, followed by
  `jump DST`, `call DST RETURN_SITE`, or `ret DST`. Jumps/calls require the matching
  typed edge; each call also requires its `crt` edge. Returns must match the latest
  outstanding call, the final stack must be empty, and the declared final node
  must match the last row. Every referenced node must occur in `translator`.

The signed circuit must select `backend=binius64`, `profile=raw24-full-key`, and
`path_mode=complete` (root-scope trace) or `shadow` (lossy stack-safe projection).
`edge_cap` is a power of two at least 8;
`ep_cap` is a power of two from 16 through `2^24`, counting the initial path row.
Both must cover the supplied instance; `1 <= log_inv_rate <= 16` is required.
For `ep_cap <= 2^14`, each BinMult multiplicity must fit 12 bits, including neutral
padding queries. Larger capacities use the derived `shared24` encoding and width.
The supplied artifacts/openings must reproduce the signed commitments and endpoints.

## Run a signed bundle

Supply the authority PEM and its SHA-256 pin from an independent trust store.
The verifier's expected challenge ID (32 lowercase hex digits) and nonce
(64 lowercase hex digits) must exactly match the device-signed report.
Replace the quoted placeholders below with those trusted values and bundle path.

```sh
ZKCFA_PROVIDER_BUNDLE='/absolute/path/to/bundle' \
ZKCFA_AUTHORITY_PUBLIC='/independent/trust-store/authority.pem' \
ZKCFA_AUTHORITY_SHA256='REPLACE_WITH_64_LOWERCASE_HEX_DIGITS' \
ZKCFA_EXPECTED_CHALLENGE_ID='REPLACE_WITH_32_LOWERCASE_HEX_DIGITS' \
ZKCFA_EXPECTED_NONCE='REPLACE_WITH_64_LOWERCASE_HEX_DIGITS' \
ZKCFA_JSON=1 \
cargo +1.97.1 run --locked --release --no-default-features \
  --manifest-path zkcfa-binius64/zkcfa64/Cargo.toml
```

Only the six `ZKCFA_*` variables shown above are accepted. The registry/report
must also agree on program measurement, scope, device, configuration, and allowed
endpoints. See [the signed bundle protocol](RAW_PROTOCOL.md) for schemas,
canonical signatures, trust boundaries, and the ten-word public ABI.

## Expected output

Success exits with status 0 after signature, input, constraint, and proof checks.
With `ZKCFA_JSON=1`, stdout includes a single-line report with
`"schema":"zkcfa.raw.proof"` and `"verified":true`, alongside diagnostic text;
stdout is **not** a JSON-only stream. Without that variable, the report is text.

The JSON contains `application`, `profile`, `path_mode`, `instance`, `capacity`,
`constraints`, `public_inputs`, and `proof_bytes` (serialized proof length in bytes).
`phases_ms` reports `setup`, `prove`, `public_preflight`, and `verify` in milliseconds.
Setup includes input loading/preprocessing; prove includes witness construction.
Instance counts are prover diagnostics. Proof bytes remain in memory; the command
does not export a proof file. Invalid input or failed verification exits nonzero
with an error diagnostic and no successful proof report.

Optional [raw64](RAW64.md) and [research experiments](research/README.md) have separate entry points.
See [BACKEND_ZK.md](docs/BACKEND_ZK.md) for backend security and validation limits.
