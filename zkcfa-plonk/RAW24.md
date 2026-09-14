# Raw24 Poseidon PLONK relation

The PLONK backend proves the raw24 full-key relation over a provider's `translator`, `typed_cfg`,
and complete or stack-safe `recorded_path`. It neither derives CFG edges from the trace nor
translates raw addresses into dense labels.

## Statement

For an authority/device-authenticated PLONK statement, the prover demonstrates that:

1. the private CFG is the canonical sorted raw24 full-key table committed by `H_cfg`;
2. the private execution path is the canonical raw24 buffer committed by `H_ep`;
3. every active non-return transition is a typed CFG edge;
4. every call site has a `(call-site, CRT, return-site)` declaration in the CFG;
5. calls and returns satisfy the corrected time-indexed CF2 shadow-stack relation;
6. the first and last active rows equal the signed endpoints; and
7. EP and CFG use distinct, nonzero 128-bit openings.

The public-input order is:

```text
H_ep_poseidon | H_cfg_poseidon | entry_raw | final_raw
```

Each commitment is one BLS12-381 scalar-field element. Signed JSON encodes it as a canonical
32-byte big-endian lowercase hexadecimal string; values at least as large as the field modulus
are rejected instead of reduced.

## Signed trust boundary

The authority registry binds:

- `backend=plonk`, profile and complete Poseidon configuration;
- CFG and EP capacities plus complete/shadow path mode;
- `H_cfg`, binary measurement, allowed endpoints and scope policy; and
- registered device verification keys.

The device report binds `H_ep`, the same registry/configuration and `H_cfg`, actual endpoints,
measurement, scope digest, device identity, and verifier-selected challenge ID and nonce. The
private worker handoff repeats the signed identifiers and contains only the independent EP/CFG
openings plus the three canonical tracer artifacts.

Historical source provenance may be signed into a registry, but it is not required by the zkCFA
relation. When present it is parsed strictly. Private signing keys and bundle issuance are provider
responsibilities and are not accepted by the proof executable.

## Raw encodings

An active CFG edge is packed as:

```text
key = (src << 26) | (edge_type << 24) | dst
```

Real keys form a strictly sorted prefix. Remaining table slots use unique padding keys
`2^63 | row`. The CFG commitment preimage is a ten-word header followed by `EDGE_CAP` keys; its
opening occupies header words 8 and 9.

For `EP_CAP <= 2^14`, an execution row uses `inline14`:

```text
word = tag | (dst << 2) | (aux << 26) | (hint << 50)
```

Larger capacities use `shared24`:

```text
payload = CAL ? aux : RET ? hint : 0
word = tag | (dst << 2) | (payload << 26)
```

The EP commitment preimage is a ten-word header followed by `EP_CAP` rows. Its header binds the
capacity, active length, address width, encoding, path mode and EP opening. Inactive rows are zero;
boolean-prefix constraints bind the active length and select the final endpoint.

Program addresses remain unchanged inside the raw 24-bit namespace. The provider's finite
external-gateway symbols occupy a reserved suffix, and `SCOPE_RETURN` maps injectively to
`0xffffff`. Numeric input cannot name the reserved token window directly.

## Poseidon commitment

The authority-approved profile fixes:

- the BLS12-381 scalar field;
- width 3, rate 2, `x^5`, 8 full and 55 partial rounds;
- capacity tag 3 and output coordinate `state[1]`;
- separate EP and CFG domains;
- three-u64 little-limb packing and exact source length; and
- a SHA-256 fingerprint of the generated round constants and MDS matrix.

Define:

```text
C(a, b) = PoseidonPerm([3, a, b])[1]
p[j]    = w[3j] + 2^64 w[3j+1] + 2^128 w[3j+2]
h[0]    = C(artifact_domain, N)
h[j+1]  = C(h[j], p[j])
```

Missing limbs in the final packed element are zero. Every source word is constrained below
`2^64`; the resulting 192-bit packing is injective in the scalar field. Including `N` separates
buffers that differ only by trailing zero words. EP and CFG use different domains and different
openings.

The PLONK fork's Poseidon constructor initially allocates its capacity tag as a witness. Every
active wrapper replaces it with a circuit-description constant before emitting a round, including
artifact commitments and the membership/shadow challenge derivations.

## Membership and CF2

The CFG is a private witness, not part of the verification key. Each EP slot contributes a typed
forward-edge query and a call-site CRT query. Inactive slots select deterministic table keys.
Range-constrained private multiplicities have fixed total cardinality, and two domain-separated
grand-product equalities compare the query multiset with the multiplicity-expanded CFG table.

There are `Q = 2 * (EP_CAP - 1)` queries. A single table key may receive all queries, so each
multiplicity uses `ceil(log2(Q + 1))` bits. This width is capacity-derived for both `inline14` and
`shared24`.

The CF2 argument contributes the tuple `(slot, call-row, return-site)` for each CALL and
`(slot, matching-call-row, destination)` for each RET. A masked grand-product equality, balanced
depth recurrence, and strict `matching-call-row < return-row` check enforce LIFO matching and make
same-depth return-site swaps fail. Its slot and hint widths are derived from signed `EP_CAP`.

Membership and CF2 challenges are derived in circuit from both Poseidon commitments using
domain-separated inputs.

## Verification flow

The verifier first authenticates the public authority/device envelopes. From their signed
capacities it builds a canonical valid shape witness whose values do not affect selectors or
permutation wiring, then generates the research SRS, proving key, PLONK verifier key, PC verifier
key, and public-input positions. It never reads the provider's private directory. The prover opens
the confidential handoff against that exact statement, recomputes both commitments and endpoints,
checks that the real witness synthesizes the verifier-derived shape, and uses the verifier-owned
proving material. Its only cryptographic output is serialized proof bytes; the public-input vector
returned by the proving library is discarded.

Verification strictly decodes the opaque proof with no trailing bytes, performs a fresh public-only
load, checks the authority pin and both signatures again, requires the complete public statement
to equal the initially authenticated statement, and reconstructs all four public inputs. The
verification receipt contains only public state and timings. Node, edge, and path-row counts in
experimental reports are prover diagnostics rather than additional public inputs.

The development runner has the verifier create a fresh universal KZG SRS and circuit keys per
invocation and releases the universal SRS after proving. Deployment should instead authenticate
and reuse the SRS identifier, PC verifier-key digest, PLONK verifier-key digest, approved circuit
configuration and transcript label.

## Input and measurements

The generated input layout and command are documented in [README.md](README.md) and
[input/README.md](input/README.md). The complete 21-application capacity, proving, verification
and proof-size evidence is in
[research/results/PLONK_BINIUS64_EMBENCH21.md](research/results/PLONK_BINIUS64_EMBENCH21.md).
