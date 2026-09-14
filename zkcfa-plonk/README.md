# PLONK backend for zkCFA

This component proves and verifies the paper's raw24 control-flow relation using
PLONK/KZG and Poseidon commitments. It checks typed CFG membership, call/return
matching, signed endpoints, and authority/device attestations for a recorded execution.

## Directory layout

| Path | Purpose |
| --- | --- |
| [`zkcfa/`](zkcfa/) | Maintained Rust application: signed proving, preflight, and bundle reissuance. |
| [`plonk/`](plonk/) | Pinned PLONK dependency, maintained as a Git submodule. |
| [`input/`](input/README.md) | Generated application bundles; its README specifies the exact file layout. |
| [`research/`](research/README.md) | Experiment runners, their tests, and preserved paper measurements. |

## Build and test

Run all commands below from the **repository root**. Requirements: Git, stable
Rust, and Python 3 for the research-tool tests.

```sh
git submodule update --init --recursive -- zkcfa-plonk/plonk
cargo +stable build --release --locked --manifest-path zkcfa-plonk/zkcfa/Cargo.toml
cargo +stable test --release --locked --manifest-path zkcfa-plonk/zkcfa/Cargo.toml --lib --bins
make test-plonk-research
```

Executables are written to `zkcfa-plonk/zkcfa/target/release/`.
Experiment runners require `--features experiments`.

## Accepted inputs

Both proving and preflight require a signed **PLONK raw24 bundle**, containing:

```text
bundle/public/registry.json
bundle/public/report.json
bundle/private/worker.json
bundle/private/{translator,typed_cfg,recorded_path}
```

The three tracer artifacts must use canonical ASCII raw24 syntax: `translator` lists
unique nodes; `typed_cfg` contains `src type dst` rows with `jmp`, `cal`, or `crt` types;
`recorded_path` declares its initial/final nodes, then records `jump`, `call`, or `ret` rows.
Addresses, CFG membership, balanced returns, capacities, and declared endpoints must agree.
Reserved gateway and scope-return tokens follow the [raw24 specification](RAW24.md).

The signed registry must select `backend=plonk`, profile `raw24-full-key`, and the
approved Poseidon parameters. Capacities must fit the instance and be powers of two:
`EDGE_CAP >= 8`, `16 <= EP_CAP <= 2^24`. Registry, device report, artifacts, and
openings must agree on commitments, measurement, scope, endpoints, and challenge.

Signed path mode is `complete` (uncompressed) or `shadow` (`shadow-safe` compression);
both require complete root entry/exit. Convert Binius64 bundles through
[authenticated reissuance](#authenticated-binius64-to-plonk-reissuance); editing their backend field invalidates the signatures.

The bundle accepts no extra files or symlinks. On Unix, use mode `0700` for `private/`
and `0600` for its four files. See the [input guide](input/README.md) and
[protocol specification](RAW24.md) for the full format and signed trust boundary.

## Run preflight or prove and verify

Supply an independently trusted authority PEM and SHA-256 pin, plus the verifier's
expected challenge and nonce. Replace the quoted placeholders: challenge IDs use
32 lowercase hex characters; nonces and SHA-256 pins use 64.

```sh
export ZKCFA_PROVIDER_BUNDLE="/absolute/plonk-run/bundle"
export ZKCFA_AUTHORITY_PUBLIC="/independent/trust-store/authority.pem"
export ZKCFA_AUTHORITY_SHA256="<trusted-authority-pem-sha256>"
export ZKCFA_EXPECTED_CHALLENGE_ID="<verifier-challenge-id>"
export ZKCFA_EXPECTED_NONCE="<verifier-nonce>"
export ZKCFA_JSON=1

# Authenticate, reopen commitments, and check the full circuit without proving.
cargo +stable run --release --locked --manifest-path zkcfa-plonk/zkcfa/Cargo.toml --bin zkcfa -- --preflight

# Generate a PLONK/KZG proof and independently verify its serialized bytes.
cargo +stable run --release --locked --manifest-path zkcfa-plonk/zkcfa/Cargo.toml --bin zkcfa
```

These five input variables and `ZKCFA_JSON` are the only accepted `ZKCFA_*` controls.
Unknown environment controls, unknown arguments, and repeated arguments are rejected.

## Expected output

Success returns exit code 0 and a final JSON record when `ZKCFA_JSON=1`, otherwise
a text report. Invalid input, authentication failure, or an unsatisfied relation
exits nonzero without a success report. Proofs remain in memory; the CLI does
not automatically write proof or report files.

| Mode | Report schema | Success indicator | Main results |
| --- | --- | --- | --- |
| Prove and verify | `zkcfa.raw.proof` | `verified: true` | Phase times in `phases_ms`, `proof_bytes`, commitments, and endpoints. |
| Preflight | `zkcfa.raw.preflight` | `satisfied: true` | Circuit checks and `public_preflight_ms`; no proof or `verified` field. |

Both reports include the application, path mode, capacities, PLONK gate count,
and padded domain size. Instance counts are marked `prover-diagnostic`.
Preflight success does not establish proof verification.

## Authenticated Binius64-to-PLONK reissuance

The reissuer authenticates the source bundle and enrollment, checks its SHA-256
commitments, and issues a PLONK statement with fresh keys and Poseidon openings.
The target verifier supplies a fresh challenge and nonce, both different from the source.

```sh
cargo +stable run --release --locked --manifest-path zkcfa-plonk/zkcfa/Cargo.toml --bin zkcfa-reissue -- \
  --source-bundle "/absolute/binius-run/bundle" \
  --source-authority-public "/independent/trust-store/source-authority.pem" \
  --source-authority-sha256 "<source-authority-pem-sha256>" \
  --source-challenge-id "<source-challenge-id>" \
  --source-nonce "<source-nonce>" \
  --source-enrollment "/absolute/binius-run/staging-private/enrollment.json" \
  --target-challenge-id "<target-verifier-challenge-id>" \
  --target-nonce "<target-verifier-nonce>" \
  --run-dir "/absolute/plonk-run"
```

The target directory must be new and its parent an existing non-symlink directory.
Output includes `bundle/`, `keys/{public,private}/`, `issuance/`, and
`protocol-result.json` with the next run's paths, key pin, challenge, and nonce.
Trust the target authority independently and keep private key material confidential.
Reissuance preserves the acquired execution; it does not rerun QEMU.

## Research and protocol details

See [RAW24.md](RAW24.md) for encodings, commitments, and verification, and the
[research guide](research/README.md) for campaigns and synthetic scaling. The research runner
creates a fresh KZG SRS and circuit keys per invocation; deployment requires authenticated,
reusable setup material bound to the approved circuit configuration.

License terms are recorded in [LICENSE](LICENSE), the [application manifest](zkcfa/Cargo.toml),
and the [PLONK dependency license](plonk/LICENSE).
