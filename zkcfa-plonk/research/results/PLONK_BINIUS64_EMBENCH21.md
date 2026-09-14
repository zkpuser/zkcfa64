# PLONK/Poseidon and Binius64 on the 21-application suite

Both campaigns use byte-identical raw24 full-key artifacts for each application
and mode. Measurements use release binaries and eight Rayon threads on the same Apple Silicon
host; the result CSVs do not themselves encode host or thread metadata.

The compared statements have the same CFG/path semantics, capacities, raw endpoints, and active
rows, but not the same commitment bytes. Binius64 opens its signed SHA-256 raw buffers; PLONK opens
backend-specific Poseidon field commitments issued only after authenticating the source bundle.
Authority/device signatures are therefore not reinterpreted across backends.

## Observed outcomes

- Binius64 is the practical full-suite prover: all 21 applications in both modes produced proofs
  that verified (`42/42`). Complete/shadow median proving times are `257.837 ms` and `147.970 ms`.
- PLONK/Poseidon accepts all 42 signed instances and passes full circuit synthesis plus every gate
  check (`42/42`). Seven representative instances have completed actual KZG proof generation and
  fresh public-only verification; three were rerun on the final pretrimmed-verifier path. This
  report does not relabel the other 35 preflights as proofs.
- On the three final-path paired runs, PLONK proving takes `36.26x` to `157.28x` as long,
  verification is `6.04x` to `8.51x` faster, and its `1,930 B` proof gives a `260.63x` to
  `365.35x` proof-size reduction. The
  `2^22` wikisort verifier is `25.740 ms`; an earlier helper reported `1,224.229 ms` because it
  included an O(n) universal-parameter trim in the verification interval.
- Shadow compression is essential for PLONK scalability. Across all 21 applications it removes
  `81.265%` of PLONK constraints and `82.737%` of padded domain rows. It moves wikisort from
  `2^25` to `2^22` and picojpeg from `2^26` to `2^23`.
- The current PLONK command generates a fresh universal KZG SRS and compiles a key for every run.
  This is a benchmark/development path, not a deployable setup model. A deployed PLONK variant
  needs a verifier-controlled, authenticated reusable SRS/VK.

## What was actually validated

| Check | PLONK/Poseidon | Binius64 |
|---|---:|---:|
| Signed complete bundles accepted | 21/21 | 21/21 |
| Signed shadow bundles accepted | 21/21 | 21/21 |
| Commitments/endpoints reopened | 42/42 | 42/42 |
| Full relation synthesized and locally satisfied | 42/42 | 42/42 |
| Cryptographic proof generated and verified | 7/42 unique instances; 10 runs with ablations | 42/42 |

PLONK preflight is stronger than format parsing: it authenticates the bundle, recomputes both
Poseidon commitments, builds the capacity-selected circuit, assigns the complete witness, and
checks every gate. It is still not a KZG proof.

## Aggregate 21-application results

PLONK capacity and preflight results:

All 42 source rows are preserved in
[`PLONK_PREFLIGHT_EMBENCH21.csv`](PLONK_PREFLIGHT_EMBENCH21.csv).

| Metric | Complete | Shadow | Shadow reduction |
|---|---:|---:|---:|
| Active EP rows | 331,044 | 60,345 | 81.771% (`5.486x`) |
| Median active EP rows | 1,854 | 228 | 87.702% (`8.132x`) |
| PLONK constraints | 75,431,576 | 14,132,050 | 81.265% (`5.338x`) |
| Median constraints | 408,827 | 103,269 | 74.741% (`3.959x`) |
| Padded domain rows | 122,814,464 | 21,200,896 | 82.737% (`5.793x`) |
| Median domain | `2^19` | `2^17` | `4x` fewer rows |
| Preflight wall total | 337.84 s | 62.91 s | 81.379% (`5.370x`) |
| Median preflight wall | 2.03 s | 0.49 s | 75.862% (`4.143x`) |

Binius64 cryptographic proof results:

| Metric | Complete | Shadow | Shadow reduction |
|---|---:|---:|---:|
| Active EP rows | 331,044 | 60,345 | 81.771% (`5.486x`) |
| AND constraints | 49,544,954 | 8,624,771 | 82.592% (`5.744x`) |
| Reported setup total / median | 176.923 s / 472.036 ms | 20.390 s / 151.299 ms | 88.475% total |
| Prove total / median | 1,550.744 s / 257.837 ms | 33.973 s / 147.970 ms | 97.809% total |
| Verify total / median | 3.830 s / 97.250 ms | 2.063 s / 85.533 ms | 46.143% total |
| Proof bytes total / median | 12,984,096 / 570,288 | 11,833,920 / 525,536 | 8.858% total |

The complete proving total is dominated by picojpeg (`1,214.883 s`) and wikisort
(`306.980 s`). The cross-application median is a better measure of a typical Binius64 run.

PLONK gate counts and Binius64 AND counts are different arithmetizations. They must not be divided
to claim a backend constraint advantage. Binius64 also has BMUL constraints, but the proof result
CSV used here does not carry those counts, so this report does not invent a per-campaign BMUL row.

## Per-application comparison

PLONK columns are `active EP/capacity; constraints / evaluation domain` from exact full-circuit
preflight. Binius64 columns are `prove ms / verify ms / proof bytes` from a proof that verified.
`C` is complete and `S` is stack-safe.

| Application | PLONK C | PLONK S | Binius64 C | Binius64 S |
|---|---:|---:|---:|---:|
| aha-mont64 | 1,177/2,048; 336,229 / `2^19` | 115/128; 44,773 / `2^16` | 257.837 / 98.844 / 570,256 | 105.069 / 82.773 / 510,560 |
| crc32 | 3,092/4,096; 632,805 / `2^20` | 23/32; 18,607 / `2^15` | 556.770 / 99.439 / 625,440 | 89.710 / 68.004 / 503,008 |
| cubic | 401/512; 126,671 / `2^17` | 401/512; 126,671 / `2^17` | 149.081 / 82.153 / 525,568 | 147.970 / 82.691 / 525,568 |
| edn | 4,396/8,192; 1,288,399 / `2^21` | 140/256; 87,397 / `2^17` | 1,579.902 / 118.587 / 660,432 | 124.847 / 81.361 / 518,080 |
| huffbench | 7,668/8,192; 1,339,493 / `2^21` | 1,442/2,048; 409,701 / `2^19` | 1,593.127 / 123.411 / 660,432 | 537.966 / 99.768 / 625,408 |
| matmult-int | 38/64; 34,747 / `2^16` | 37/64; 34,747 / `2^16` | 101.118 / 78.827 / 510,528 | 98.289 / 77.393 / 510,528 |
| md5sum | 7,230/8,192; 1,288,399 / `2^21` | 441/512; 126,671 / `2^17` | 1,573.062 / 121.665 / 660,432 | 152.433 / 87.411 / 525,568 |
| minver | 352/512; 126,671 / `2^17` | 224/256; 87,397 / `2^17` | 148.504 / 79.415 / 525,568 | 114.505 / 85.533 / 518,080 |
| nbody | 114/128; 44,773 / `2^16` | 66/128; 44,773 / `2^16` | 106.749 / 81.389 / 510,560 | 100.990 / 69.470 / 510,560 |
| nettle-aes | 1,854/2,048; 360,655 / `2^19` | 190/256; 87,397 / `2^17` | 254.733 / 90.610 / 570,256 | 116.067 / 82.813 / 518,080 |
| nettle-sha256 | 116/128; 67,151 / `2^17` | 59/64; 56,613 / `2^16` | 119.017 / 82.353 / 518,016 | 122.094 / 82.739 / 510,560 |
| nsichneu | 661/1,024; 924,773 / `2^20` | 653/1,024; 924,773 / `2^20` | 549.966 / 93.731 / 625,472 | 553.688 / 109.240 / 625,472 |
| picojpeg | 137,169/262,144; 40,735,226 / `2^26` | 29,375/32,768; 5,430,372 / `2^23` | 1,214,883.006 / 1,230.389 / 914,368 | 19,872.433 / 199.697 / 757,232 |
| primecount | 1,898/2,048; 336,229 / `2^19` | 1,141/2,048; 336,229 / `2^19` | 253.991 / 88.178 / 570,256 | 248.551 / 95.176 / 570,256 |
| sglib-combined | 31,758/32,768; 5,217,998 / `2^23` | 13,971/16,384; 2,679,909 / `2^22` | 19,878.719 / 198.395 / 757,232 | 5,360.088 / 160.722 / 705,120 |
| slre | 2,337/4,096; 820,325 / `2^20` | 651/1,024; 349,285 / `2^19` | 553.643 / 109.286 / 625,472 | 243.409 / 90.250 / 570,288 |
| st | 1,147/2,048; 336,229 / `2^19` | 58/64; 34,747 / `2^16` | 253.658 / 90.503 / 570,256 | 97.934 / 75.349 / 510,528 |
| statemate | 232/256; 408,827 / `2^19` | 106/128; 381,413 / `2^19` | 249.469 / 97.250 / 570,288 | 242.565 / 102.815 / 570,288 |
| tarfind | 3,185/4,096; 645,371 / `2^20` | 294/512; 103,269 / `2^17` | 554.154 / 110.414 / 625,440 | 149.383 / 93.687 / 525,536 |
| ud | 413/512; 126,671 / `2^17` | 228/256; 87,397 / `2^17` | 147.641 / 90.774 / 525,568 | 118.528 / 80.120 / 518,080 |
| wikisort | 125,806/131,072; 20,233,934 / `2^25` | 10,730/16,384; 2,679,909 / `2^22` | 306,980.180 / 664.042 / 862,256 | 5,376.863 / 155.544 / 705,120 |

Five applications remain in the same PLONK constraint bucket after shadow compression: cubic,
matmult-int, nbody, nsichneu, and primecount. This is expected when the reduced trace stays in the
same capacity bucket or when the CFG side dominates the shape.

## Paired cryptographic proof measurements

All rows below use the same application, mode, byte-identical raw artifacts, endpoints, and
capacity at both backends. The ratio columns are `PLONK / Binius64` for proving and
`Binius64 / PLONK` for verifier speed and proof-size reduction. The PLONK and Binius64 signatures
and commitment values are intentionally backend-specific.

Full PLONK millisecond values, verifier-key path, and source precision are preserved in
[`PLONK_PROOF_SAMPLES.csv`](PLONK_PROOF_SAMPLES.csv); Binius64 denominators come from its
`results.csv`. Displayed seconds are rounded to three decimals. The two auxiliary matmult rows
retain rounded PLONK measurements; all three final-path rows retain full-millisecond results.

Final default implementation (`pretrimmed_vk`):

| Application / mode | Domain | PLONK setup | PLONK prove | PLONK verify | PLONK proof | Prove ratio | Verify speedup | Size reduction |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| crc32 / complete | `2^20` | 119.577 s | 87.568 s | 11.679 ms | 1,930 B | 157.279x | 8.514x | 324.062x |
| crc32 / shadow | `2^15` | 4.600 s | 3.253 s | 8.220 ms | 1,930 B | 36.263x | 8.273x | 260.626x |
| wikisort / shadow | `2^22` | 458.758 s | 403.962 s | 25.740 ms | 1,930 B | 75.130x | 6.043x | 365.347x |

Summing only these three final-path rows, PLONK proving takes `82.144x` the summed Binius64 proving
time, its verifier is `7.077x` faster, and its proof payload gives a `316.678x` size reduction.
This sum is dominated by wikisort and is not an application-average speedup.

Additional proof-generation scaling samples collected before the verifier-key handoff change are
still valid for setup/proving/proof size; their verifier values include inline trim and are not the
final verifier benchmark:

| Application / mode | Domain | Setup | Prove | Old verify | Proof | Prove ratio | Size reduction |
|---|---:|---:|---:|---:|---:|---:|---:|
| cubic / complete | `2^17` | 16.458 s | 11.907 s | 9.369 ms | 1,930 B | 79.872x | 272.315x |
| statemate / complete | `2^19` | 62.615 s | 45.542 s | 11.145 ms | 1,930 B | 182.556x | 295.486x |
| matmult-int / complete | `2^16` | 8.594 s | 6.127 s | 8.448 ms | 1,930 B | about 60.593x | 264.522x |
| matmult-int / shadow | `2^16` | 8.588 s | 6.099 s | 8.605 ms | 1,930 B | about 62.052x | 264.522x |

The seven unique PLONK instances (ten proof runs) all produced exactly `1,930 B` proofs, spanning
domains `2^15` to `2^22`. Relative to the full Binius64 result range, this sampled PLONK proof
size gives a `260.626x` to `473.766x` reduction. Proof size remains small because the PLONK proof contains a fixed set of
polynomial commitments and evaluations rather than one field element per trace row.

The verifier-key ablation is:

| Instance | Domain | Inline trim | Pretrimmed VK | Verifier speedup (inline / pretrimmed) |
|---|---:|---:|---:|---:|
| crc32 / complete | `2^20` | 13.136 ms | 11.679 ms | 1.125x |
| crc32 / shadow | `2^15` | 8.381 ms | 8.220 ms | 1.020x |
| wikisort / shadow | `2^22` | 1,224.229 ms | 25.740 ms | 47.561x |

The original generic helper called `PC::trim` inside the timed verifier path. SonicKZG 0.3
implemented that trim by copying `powers_of_g[..=supported_degree]`; wikisort therefore allocated
and copied 4,194,305 G1 affine points only to discard the committer key. The final runner derives
the PC verifier key during setup, checks that its degree matches the PLONK VK domain, releases the
universal SRS after proof generation, and gives the fresh verifier only the small PC VK. This is
semantically the same transcript/proof check, and all four public-input tamper runs still fail.

## Why complete PLONK does not yet count as a 21/21 proof campaign

The largest complete instances require domains `2^25` (wikisort) and `2^26` (picojpeg). The
current runner asks KZG setup for twice those degrees, `2^26` and `2^27`. Even a lower bound that
counts only one 48-byte compressed G1 power is 3 GiB and 6 GiB respectively; real setup, circuit,
witness, FFT, and commitment memory is substantially larger. Repeating that setup inside each
command is not a credible full-suite deployment strategy.

Deployment across the full Complete-path suite requires the following setup and
scalability measures:

1. provision and authenticate a reusable universal SRS;
2. cache/distribute capacity-specific verification keys;
3. retain the stack-safe path as the normal large-trace PLONK lane; and
4. segment or recursively aggregate very large complete paths if complete QEMU-row proofs are a
   PLONK requirement.

Binius64 proves all complete QEMU rows without this trusted universal setup. These
measurements support its use as the paper's primary backend for full-trace performance.

## Measurement boundaries

- PLONK `setup` starts after provider authentication, raw loading, commitment opening, and
  `probe_size`; it measures fresh KZG SRS generation plus circuit compilation.
- Binius64 `setup` starts before provider authentication/loading and includes circuit construction
  plus transparent prover/verifier setup. Reported setup ratios are therefore descriptive, not
  apples-to-apples backend setup ratios.
- Binius64 `prove` includes witness population, local constraint verification, and proof
  generation. PLONK `prove` includes construction of the prover circuit and `gen_proof`.
- Both backends time public authentication separately from cryptographic verification, making
  final-path `verify` the closest direct comparison. PLONK verifier-key trim is now in its reported
  setup rather than verification; the library still repeats this trim because circuit compilation
  does not return the PC VK it already derived.
- Results are one release run per row, not confidence intervals. Large ratios are robust enough to
  establish the engineering tradeoff, but they should not be presented as microbenchmark-quality
  estimates.

## Reproducibility record

- PLONK branch/commit: `optimized` at `a1580777dfa89d4f154483f5ef2a19b9ee8eb20d`, with the
  Poseidon/raw24 working-tree changes described in [`RAW24.md`](../../RAW24.md).
- Binius64 branch/commit: `optimized` at `f85e5efc5ac4775c06e08554755b72ac75e33636`.
- Rust: `rustc 1.97.1 (8bab26f4f 2026-07-14)`.
- PLONK preflight CSV SHA-256 (the checked-in copy is byte-identical to the campaign output):
  `a0dfb062b3cd13d2b4b8418c6a565f8957ecaf44608e5a650038ad26caf49c6c`.
- PLONK proof-sample CSV SHA-256:
  `c74264301022e337abaad53034798bc60df354c20ab3a754e63785a9c2005d69`.
- Binius64 result CSV SHA-256:
  `714288236164d3d35b27208925904dfb55a0db771daa848cf022554c050ccb66`.
- Binius64 summary SHA-256:
  `547e9efba1260653614c23e3c60d0f751c97f4274680b82399cb58fb1aa15b4f`.
- Direct comparison checked all `42 x 3 = 126` private `translator`, `typed_cfg`, and
  `recorded_path` files: `126/126` byte-identical. It also checked entry, final, binary
  measurement, and scope digest in all 42 public reports: `168/168` values identical.
- Release tests on the final minimal source tree: `44 passed`, `0 failed`, `1 ignored`
  provider-environment smoke test. Four real public-input tamper proof runs all failed
  verification as required; the release environment hook used for that campaign has since been
  removed from the proof binary.
