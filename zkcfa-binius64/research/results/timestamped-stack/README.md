# Timestamped stack constraint experiment

This experiment measures the compiled contribution of the production raw24 timestamped stack checker (`RawShadow`). It uses Binius64 backend revision `c56e2027591df056cee5bd741085e110d491f28e`. Exact source and binary hashes are recorded in `binius/metadata.json`.

## Measurement and controls

For every case, `stack_control` independently constructs the full production circuit and a research ablation that disables only the existing `RawShadow` call. Both circuits retain record decoding and validation, SHA-256 EP/CFG commitments, endpoint checks, and sealed BinMult CFG membership. The difference in compiled native constraints is the measured stack contribution, including stack challenge derivation and effects of normal compiler optimizations. Every circuit receives the same valid instance and passes the complete local constraint verifier and independently reconstructed public-statement check.

The circuit profile is raw24, Complete mode, InlineHint14, fixed `E_capacity=8`, fixed 15-bit stack pointer, and a maximum supported stack depth of 32,767. Every EP capacity is fully occupied. `L` includes the initial JMP record. A fixed three-node, five-edge recursive CFG supplies exactly `L/4` calls, `L/4` returns, and `L/2` JMP records, including the initial JMP. Different depths rearrange nesting while preserving the CFG, addresses, capacities, and transfer counts. Every call has the same continuation address, with the original call-row index retained in its return hint. The actual maximum depth is attained and all returns are balanced and exact.

The shared fixtures are provided as typed production inputs, `events.tsv`, and `events.json`. This supports the identical event sequence in a ZEKRA C6 comparison. ZEKRA can provision its stack array to the measured depth `D`; Binius64 keeps its production 15-bit pointer across all cases.

## Grids

- Length: `L=64,128,256,512,1024,2048,4096`, fixed actual depth `D=8`.
- Depth: `D=1,2,4,8,16,32,64,128,256`, fixed `L=1024`.
- Diagonal: `L=64,128,256,512,1024,2048,4096`, `D=L/4`.

There are 21 unique cases; overlapping points are measured once and assigned to each applicable family. Constraint counts are deterministic, so a single compilation per variant and case is sufficient. The raw build/check timing observations are single-run diagnostics, not a timing benchmark. Full cryptographic proof roundtrips additionally pass at `(L,D)=(64,8)` and `(1024,256)`.

## Measured counts

| L | AND | BMUL | ZERO | Total native constraints |
|---:|---:|---:|---:|---:|
| 64 | 917 | 380 | 512 | 1,809 |
| 128 | 1,109 | 764 | 832 | 2,705 |
| 256 | 1,493 | 1,532 | 1,472 | 4,497 |
| 512 | 2,261 | 3,068 | 2,752 | 8,081 |
| 1024 | 3,797 | 6,140 | 5,312 | 15,249 |
| 2048 | 6,869 | 12,284 | 10,432 | 29,585 |
| 4096 | 13,013 | 24,572 | 20,672 | 58,257 |

IMUL is zero in every measured stack difference. Across the measured grid, the compiler outputs exactly `AND=3L+725`, `BMUL=6L−4`, `ZERO=5L+192`, and total `14L+913`. These formulas summarize the compiler measurements; they are not used to generate the CSV. The four grand products account for `4(L−1)` BMULs, and the two token selections per row contribute another `2L` BMULs because the pinned frontend lowers `select` to a binary-field multiplication constraint (`binius64/crates/frontend/src/gates/select.rs`). At fixed `L=1024`, every depth from 1 to 256 has exactly 15,249 stack constraints. The diagonal cases have the same counts as the corresponding fixed-depth length cases.

The total sums heterogeneous native Binius64 constraint types. It is a compiled-size measure within this backend; it is not an R1CS-equivalent gate count and does not alone imply a proving-time ratio against a prime-field backend. For a cross-backend plot, preserve each backend's native unit or normalize to its own baseline to compare growth.

## Files

- `inputs/manifest.json`: case definitions, controlled parameters, input hashes, and validation outcomes.
- `inputs/Lxxxx-Dxxxx/events.tsv`: shared event sequence; columns are `row`, `kind`, `dst`, `aux`, `hint`, `depth_after`; kinds are `jmp`, `cal`, `ret`; addresses are decimal integers.
- `binius/measurements.csv`: all 21 measured cases, enabled/disabled counts, differences, and verification flags.
- `binius/raw/*.json`: complete per-case measurements, input hashes, and exact invocation.
- `binius/logs/*`: original process output and diagnostic logs.
- `binius/metadata.json`: toolchain, backend revision, exact source/binary hashes, and completion flags.

## Reproduce

From `zkcfa-binius64/zkcfa64`:

```sh
RUSTFLAGS='-C target-cpu=native' cargo build --locked --offline --release --features stack-control --example stack_control
```

From `zkcfa-binius64`, choose new output directories:

```sh
python3 research/scripts/stack_control_inputs.py --output /tmp/stack-inputs
python3 research/scripts/run_stack_control.py --inputs /tmp/stack-inputs --output /tmp/stack-binius
```

The scripts refuse to overwrite existing directories. The runner fixes `RAYON_NUM_THREADS=8`, verifies every input hash and witness, and validates depth invariance. A consistency assertion checks the observed BMUL difference against the implementation's grand products and selections after collecting the compiler statistics.

Only the `stack-control` research feature exposes the ablation. The signed production protocol retains stack checking by default.
