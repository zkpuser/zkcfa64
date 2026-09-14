# Signed raw bundle protocol

This document is the stable authority-to-device-to-prover contract for the
`raw24-full-key` profile. Verification fails closed on signatures, canonical
identities, the verifier challenge, circuit parameters, endpoint policy, scope
policy, and the proof's ten public words.

## Bundle and trust boundary

```text
bundle/
  public/
    registry.json
    report.json
  private/                         mode 0700 on Unix
    worker.json                    mode 0600 on Unix
    translator
    typed_cfg
    recorded_path
```

The full prover loader requires exactly `public/` and `private/` at the root and
the exact entries shown inside each. The bundle root and both subdirectories must
be real directories, not symlinks; every artifact must be a regular, non-symlink
file. The authority key is deliberately absent: the
verifier must receive an independently trusted Ed25519 PEM and its SHA-256 pin.
The public verifier loader reads only that external key, `registry.json`, and
`report.json`; it never opens `private/`.

The three raw artifacts and the four opening words are confidential prover
inputs. Trace evidence and shadow-projection records are device-local inputs to
attestation and are not transported in the proof bundle.

## Canonical signed envelopes

`registry.json` and `report.json` have exactly these envelope fields:

```json
{
  "algorithm": "Ed25519",
  "key_id": "<64 lowercase hex>",
  "payload": {},
  "signature": "<base64>"
}
```

The signature message is the object's domain followed by canonical JSON of its
payload.

| Object | Payload schema | Signature domain |
|---|---|---|
| Authority registry | `zkcfa.raw.registry` | `ZKCFA/raw/registry/signature\0` |
| Device report | `zkcfa.raw.report` | `ZKCFA/raw/report/signature\0` |

Canonical JSON sorts object keys lexicographically, emits no insignificant
whitespace, preserves array order, uses JSON's primitive spelling, and permits
only ASCII keys and strings. Every decoded protocol object rejects unknown
fields. A key ID is
`SHA-256("ZKCFA/key/id\0" || raw_ed25519_public_key)`.

## Authority registry

The authority payload contains exactly:

```text
schema, application, raw_registry_id, binary_measurement,
raw_config_id, h_cfg_raw24, circuit, allowed_endpoints,
devices, scope_policy
```

It binds the measured program, the independently blinded canonical CFG
commitment, all proof parameters, a strictly sorted duplicate-free endpoint
policy, registered device keys, and the complete root-scope policy.

The signed circuit object contains only two fixed selectors and four actual
parameters:

```json
{
  "backend": "binius64",
  "edge_cap": 8,
  "ep_cap": 16,
  "log_inv_rate": 1,
  "path_mode": "complete",
  "profile": "raw24-full-key",
  "schema": "zkcfa.raw.circuit"
}
```

`path_mode` is `complete` or `shadow`. `EDGE_CAP` is a power of two at least
eight. `EP_CAP` is a power of two from 16 through `2^24`. At materialization,
the signed capacities must also be at least the actual edge and path-row counts.
An authority may preselect larger capacities; evaluation tooling normally uses
the smallest fitting powers of two.

EP encoding and multiplicity width are derived, not separately signed:

- `EP_CAP <= 2^14`: `inline14`, 12 multiplicity bits;
- `EP_CAP > 2^14`: `shared24`, with
  `ceil(log2(2 * (EP_CAP - 1) + 1))` multiplicity bits.

The scope object has schema `zkcfa.raw.scope` and exactly these fields:

```text
schema, architecture, boundary_kind, root_symbol, caller_symbol,
scope_call_address, root_address, root_exit_blocks, scope_return_address,
sentinel, sentinel_address, require_complete_entry_exit,
position_independent, canonical_entry, canonical_start_code,
canonical_address_model, proof_path_compression, normalization,
external_call_model
```

`normalization` is `qemu-root-scope`; compression is `none` for `complete` and
`shadow-safe` for `shadow` (the legacy wire identifier for the stack-safe
projection); the external-call model is `none` or
`plt-exact-return`. Complete entry and exit are mandatory.

Canonical identities are:

```text
raw_config_id   = SHA-256("ZKCFA/raw/circuit/id\0" || canonical(circuit))
raw_registry_id = SHA-256("ZKCFA/raw/registry/id\0" ||
                         canonical(registry payload without raw_registry_id))
scope_digest    = SHA-256("ZKCFA/raw/scope/digest\0" || canonical(scope_policy))
```

For the circuit object above, `raw_config_id` is
`bdd2a50f0d5716899d7f06ebf01e0a6e84ee3d1873e7d10dce746fc6a2136dbc`.

## Device report

The enrolled device payload contains exactly:

```text
schema, device_id, challenge_id, nonce, raw_registry_id,
raw_config_id, binary_measurement, h_cfg_raw24, h_ep_raw24,
entry_raw, final_raw, scope_policy_digest,
runtime_code_match, boundary_policy_satisfied
```

The device signature directly binds both independently blinded commitments, the
authority identities, actual endpoints, scope policy, measured program, and the
verifier's challenge. The verifier requires the endpoint pair to appear in the
authority policy and both decision booleans to be true.

Before signing, a trusted device validates its local complete-QEMU boundary and
runtime-code evidence. For `shadow`, it also validates the stack-safe
projection against its complete source evidence. The proof consumer does not
reparse those unsigned device-local records; it relies on the enrolled device
signature and proves the path committed by `H_ep` under the signed path mode.

The verifier matches an out-of-band 128-bit challenge ID and 256-bit nonce. This
implementation does not maintain a replay database: expiry and atomic challenge
consumption belong to the challenge issuer.

## Confidential worker handoff

`worker.json` has schema `zkcfa.raw.worker` and exactly:

```text
schema, raw_registry_id, raw_config_id, h_cfg_raw24, h_ep_raw24,
ep_blind_low, ep_blind_high, cfg_blind_low, cfg_blind_high
```

Each opening word is canonical lowercase `0x` plus sixteen hexadecimal digits.
The EP and CFG openings are nonzero and distinct. The loader checks worker/public
identity equality, reconstructs the canonical EP and CFG buffers from the fixed
artifact names, and requires their SHA-256 digests to equal the signed
commitments.

Raw addresses are canonical lowercase `0x...` tokens; the only symbolic token is
`SCOPE_RETURN`. Comments, malformed rows, and interior blank lines are rejected.
Active path rows may use only JMP, CAL, and RET; the reserved tag is padding-only.

## Verification order and public ABI

Before proof verification, the public preflight:

1. pins and decodes the external authority key;
2. verifies the authority and device signatures under separate domains;
3. recomputes canonical key, config, registry, and scope identities;
4. checks all registry/report equality, measurement, endpoint, and challenge
   conditions;
5. checks that the instantiated backend, parameters, and path mode equal the
   signed circuit object;
6. reconstructs the complete Binius public vector from verifier-owned circuit
   constants, zero padding, and signed `H_ep`, `H_cfg`, entry, and final values;
7. verifies the opaque proof bytes against that reconstructed vector.

The circuit exposes exactly ten 64-bit words:

```text
H_ep[4] | H_cfg[4] | entry_raw | final_raw
```

`H_ep` and `H_cfg` are SHA-256 digests of canonical big-endian word buffers. The
prover does not supply public-vector constants or padding to the verifier. The
report records public-preflight time separately from proof-verification time.

## Release checks

The Rust suite contains positive composition and cross-language identifier
vectors plus fail-closed tests for stale challenge/nonce, wrong authority pin,
signature tampering and cross-domain replay, mismatched registry/configuration/
measurement/CFG, unauthorized endpoints and scope, noncanonical capacities,
unknown protocol fields, embedded trust material, unexpected private files,
artifact tampering, reserved active tags, and unrecognized environment controls.
