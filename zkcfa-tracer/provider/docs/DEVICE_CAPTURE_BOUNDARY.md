# Device capture and worker compliance

## Signing and verification roles

Device signing authenticates captured execution evidence. CFG/CRT membership,
exact returns, and concrete multiplicity counts are checked by the worker's
`load_raw_statement` path and proof circuit.

The authority approves and signs the independently provisioned CFG. The
device calls `load_raw_evidence`: it authenticates the captured EP and
mechanically derived call/pop hints, without deciding internal CFA compliance.
Actual return destinations are never repaired. Off-CFG addresses, wrong returns,
underflows and unmatched calls remain evidence. The worker's strict loader and
the proof circuit enforce membership, CRT and exact returns.

An unexpected nonbranch/REP/stop successor becomes `discontinuity dst src`,
serialized with reserved tag 3. Both actual addresses are committed. Existing
circuits reject this tag, so a discontinuity cannot disappear during block
normalization. Valid raw24/raw64 serialization and the proof relation are unchanged.

Report verification establishes signature authenticity, registry bindings and
freshness; it is not a CFA verdict. Acceptance also requires a valid proof for
the signed commitments. Signatures, code measurements, immutable input snapshots,
canonical formats, capacity bounds and complete scoped capture remain enforced.
The QEMU root-return and external-gateway/reentry checks delimit the supported
capture interval. Unknown code is not authenticated, and internal CFG/CRT/LIFO
verdicts remain with the worker.

## Evidence-preserving projection

The compressor preserves evidence of noncompliance by comparing the mechanical
stack state and preceding address at repetition boundaries. A distinct entry copy
is retained separately from the steady-state copy. It never removes discontinuity
markers, and underflows receive distinct stack states. This preserves a
representative of each distinct forward/CRT query and invalid return; stack
bookkeeping does not compare return destinations.

For example, reducing `B → A → A` to `B → A` would erase the sole `A → A`
transition. The projection retains it even if it is absent from the CFG.

## Validation

Recorded validation of the device/worker separation includes:

- Provider suite, including live pinned-QEMU REP capture: 67 passed, none skipped.
- Signing integration: 24 combinations of raw24/raw64 and complete/shadow cover
  valid execution, missing CAL, missing CRT, wrong returns, underflow and
  discontinuity. All reports authenticate; the 20 invalid combinations fail
  worker preflight, while the four valid combinations export correctly.
- Existing signature-tampering, challenge-replay, snapshot-race, evidence-substitution,
  code/scope binding and raw64 golden-vector regressions remain enabled.
- Rust default suite: 56 passed. Rust raw64 suite: 39 passed.
- Circuit tests exercise 54 negative scenarios, bypassing host policy checks
  and recomputing commitments. Stack cases use honest membership advice and pass
  with the stack argument disabled, then fail with it enabled.
- Four actual cryptographic roundtrips passed, one per address profile and mode.
  The same proofs reject a changed public EP digest. These are small synthetic
  proof fixtures; they are not a new 21-application timing campaign.
- The committed projection test checks 500 deterministic randomized repeated
  paths; an additional independent review checked 30,000 cases without finding
  a policy-violation-erasure counterexample.

Provider command (in the pinned provider image):

```sh
ZKCFA_RUN_PINNED_QEMU_REP=1 PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Rust commands (from `zkcfa-binius64/zkcfa64`):

```sh
cargo +1.97.1 test --locked
cargo +1.97.1 test --locked --features raw64
RAYON_NUM_THREADS=2 cargo +1.97.1 test --release --locked device_evidence_honest_cryptographic_proof_roundtrip -- --ignored --test-threads=1
RAYON_NUM_THREADS=2 cargo +1.97.1 test --release --locked --features raw64 device_evidence_honest_cryptographic_proof_roundtrip -- --ignored --test-threads=1
```

## Effect on archived paper inputs

Read-only regeneration of the archived campaign's `primary/inputs/<app>/`
found byte-identical complete EPs for all 21 applications. The corrected projection
changes 20 of the 21 shadow EPs. Counts below include the initial EP row.
New projections were compared in memory; archived inputs and results were not overwritten.

These are path-regeneration results, not rerun proving times. Shadow proof sizes,
capacities and timings measured with the previous projection remain associated
with that version. Complete statement bytes are unchanged; this does not establish
unchanged device-side latency.

| Application | Previous shadow rows | Corrected shadow rows |
| --- | ---: | ---: |
| aha-mont64 | 115 | 226 |
| crc32 | 23 | 26 |
| cubic | 401 | 401 |
| edn | 140 | 228 |
| huffbench | 1442 | 2803 |
| matmult-int | 37 | 38 |
| md5sum | 441 | 828 |
| minver | 224 | 300 |
| nbody | 80 | 110 |
| nettle-aes | 190 | 323 |
| nettle-sha256 | 59 | 68 |
| nsichneu | 653 | 657 |
| picojpeg | 29375 | 34334 |
| primecount | 1141 | 1449 |
| sglib-combined | 13971 | 18980 |
| slre | 651 | 718 |
| st | 58 | 69 |
| statemate | 106 | 108 |
| tarfind | 294 | 467 |
| ud | 228 | 304 |
| wikisort | 10730 | 6796 |

Machine-readable comparison: [capture-boundary-path-comparison.json](capture-boundary-path-comparison.json).
