# Pinned salt-free Binius64 ZK backend

## Provenance

- pinned backend commit: `c56e2027591df056cee5bd741085e110d491f28e`;
- upstream base: `binius-zk/binius64` `c6e4dfb2d736c79979aebaf2e68897bee221031d`;
- protocol suite:
  `binius64/zk/affine-query-hiding-unsalted-terminal-per-relation-cross-segment/v6`;
- serialized prover/verifier setup version: 6.

The pinned upstream base uses unsalted Merkle leaves. This fork adds
the composed query-hiding and terminal-binding construction described below.

## Construction

The pinned ZK path is salt-free. Its privacy and binding mechanisms are algebraic:

- every ordinary witness-dependent ZK oracle reserves `q + 1` high novel-basis coefficients for
  query hiding;
- every wrapped inner oracle reserves two additional, independent terminal-claim keys, for `q + 3`
  total support;
- logical messages and transparent queries are even-lifted, leaving exactly the odd coordinates
  available to the high-novel support;
- Reed--Solomon evaluation uses the FRI-selected affine coset, including shorter oracles in a mixed
  batch;
- BaseFold retains its independent folding mask;
- the outer precommit, private, and mask oracles each receive their own `q + 1` support; and
- a real cross-segment constraint binds the shared precommit/private dummy.

Two relations on one wrapped inner oracle consume two different one-time pads. A third terminal
relation fails closed. Independent keys are required for each terminal relation in the
upstream LogUp flow.

The implementation has no Merkle salt field, salt RNG stream, salted leaf frame, or salt-aware compiler API.
This agrees with upstream's salt-free tree format, but it is not a claim that the other blindings can
be removed.

## Upstream evidence

[PR #1423](https://github.com/binius-zk/binius64/pull/1423) proposed salting only the initial FRI
codeword. On 2026-03-31, maintainer Jim Posen
[wrote](https://github.com/binius-zk/binius64/pull/1423#issuecomment-4165111804) that he believed he
had a proof that the additional salting was unnecessary. He
[closed the PR](https://github.com/binius-zk/binius64/pull/1423#issuecomment-4208066126) on
2026-04-08 because it was "very likely the protocol is ZK without the extra salts."

Upstream later made that implementation decision explicit in
[PR #2065](https://github.com/binius-zk/binius64/pull/2065) and commit
[`4b7dfd4d`](https://github.com/binius-zk/binius64/commit/4b7dfd4dda1744504241dcb2f304b024a0028c4d):
Merkle leaf salting was removed and ordinary `H(values)` leaves retained. The pinned upstream base
already contains this change.

Neither #1423 nor #2065 supplies the missing end-to-end fix for this repository's composed ZK path.
In particular, the pinned upstream base does not reserve query-hiding support for every production ZK
oracle or bind multiple terminal relations with independent keys.

## Fail-closed invariants

The port rejects incomplete or internally inconsistent configurations before producing or accepting
a proof:

- production BaseFold compilers require valid randomizable support for every ZK oracle;
- support must provide at least `q + 1` query-hiding coordinates, excluding terminal keys;
- raw oracle send rejects a spec that declares randomizable support;
- randomized send requires an RNG and fills only the declared support;
- prover and verifier validate spec count, order, message length, support layout, and terminal-key
  count;
- the Reed--Solomon encoder and BaseFold prover compiler validate both the linear subspace and the
  affine shift for every oracle length; and
- merge decoration rejects supported specs because it does not implement support-preserving
  randomization.

The port also fixes an upstream fused-NTT optimization that incorrectly selected its zero-
twiddle fast path from the block index alone. The fast path now depends on the actual twiddles, with
an affine block-zero regression test.

Version 6 is intentionally incompatible with the earlier unsalted version 5. Both prover and
verifier absorb the suite identifier before protocol interaction, and setup deserialization rejects
version 5.

## Validation

Recorded validation of the pinned backend and its application integration includes:

- `cargo check --locked --workspace --all-targets`;
- `binius-math`: 178 unit tests, plus 10 affine/high-novel integration tests (one large rank probe
  remains ignored);
- `binius-iop`: 119 unit tests (one reporting-only test ignored);
- `binius-iop-prover`: 96 unit and 2 integration tests;
- `binius-prover`: 80 unit and 20 integration tests, including zero-IMUL, BinMul, serialized v6,
  signature-of-knowledge, two relations on one oracle, and terminal-key tamper rejection;
- `binius-verifier`: 17 unit tests;
- `binius-spartan-prover`: 9 unit/integration tests;
- `binius-spartan-verifier`: 18 unit/integration tests;
- outer proof-size tracking agrees with real transcript bytes; the rate-3 standalone Spartan
  regression value is 95,520 bytes; and
- `zkcfa64`: 51 application tests in the integration validation snapshot.

## Security boundary

This is a concrete implementation fix with regression and rank evidence, not a new unconditional
zero-knowledge theorem.

1. The construction and upstream rationale are classical random-oracle evidence. No concrete QROM
   reduction or post-quantum security bound is claimed here.
2. The retained rank probes cover the high-novel evaluation map, while the protocol tests cover
   honest and adversarial transcript paths. A full simulator proof should still condition on every
   root, query opening, fold message, and terminal vector.
3. The two-key limit is an explicit protocol bound. Supporting more terminal relations requires a
   suite/version change and a corresponding support allocation, not silent key reuse.
4. The proof suite must remain part of the verifier policy. A v5 or salted-v4 setup is not
   interchangeable with v6.

Production deployment requires review of the full-transcript classical analysis. A concrete QROM
security level requires a supporting reduction.
