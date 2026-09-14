# ZEKRA C6 stack-constraint experiment

This experiment measures the **released C6 shadow-stack gadget**, parameterized
with path capacity `L` and shadow-stack capacity `D`. It compiles the actual
xJsnark circuit, evaluates each supplied witness, exports the arithmetic circuit
and witness, and reads the generated constraint count. It does not run Groth16
setup/proving or derive experimental data from an asymptotic formula.

The native unit is a **BN254 R1CS row**. Binius64's native 64-bit word-constraint
counts have a different meaning. A ratio between these units is not a speedup
or an equal-cost gate comparison. Within-backend length/depth trends are the
intended comparison.

## Reproduce

From the workspace root, first generate the shared inputs using the Binius
stack experiment's documented generator. The defaults below use the local,
already built `zkcfa-zekra:paper-ubuntu22.04` image; containers have networking
disabled. Use new output directories for repeated runs.

```sh
python3 zekra/reproduce/stack_constraints/run_stack_constraints.py \
  --inputs zkcfa-binius64/research/results/timestamped-stack/inputs \
  --output zekra/reproduce/results/timestamped-stack

python3 zekra/reproduce/stack_constraints/verify_arithmetic.py \
  zekra/reproduce/results/timestamped-stack
```

`--case CASE_ID` selects cases, and `--pointer-bits 15` fixes the C6 stack
pointer width for a sensitivity control. For example:

```sh
python3 zekra/reproduce/stack_constraints/run_stack_constraints.py \
  --inputs zkcfa-binius64/research/results/timestamped-stack/inputs \
  --output zekra/reproduce/results/timestamped-stack-fixed15 \
  --pointer-bits 15 --case L1024-D0001 --case L1024-D0008 \
  --case L1024-D0032 --case L1024-D0256
```

The compiler reports a deterministic circuit-size metric. Repeating a timing
measurement is unnecessary for that metric. Full Java process duration is kept
in the provenance record but is not a cryptographic proving-time measurement.

## Shared cases and scope

The shared manifest supplies 21 unique synthetic, fully occupied execution
paths. `L` includes the initial jump. Each has `L/4` calls, `L/4` returns, and
`L/2` jumps. The actual maximum depth equals `D`; fixed-length cases preserve
these operation counts and change only their nesting. The same three-node,
five-edge typed CFG remains valid for all cases.

- Length scan: `L = 64, 128, 256, 512, 1024, 2048, 4096`, `D = 8`.
- Depth scan: `L = 1024`, `D = 1, 2, 4, 8, 16, 32, 64, 128, 256`.
- Joint scan: the same seven lengths with `D = L/4`.

The C6-only circuit uses the supplied destinations and continuations directly
as its destination/return labels, an injective relabeling of the three nodes.
Translation, hashing, and forward-edge checks are outside this component.
The shared fixtures separately satisfy forward edges and exact return matching.

`events.tsv` is copied unchanged and checked against its manifest SHA-256.
Its values are assigned in the sample's `pre()` callback **after** circuit
construction. Calls, returns, and memory indices therefore remain witness
values rather than compile-time constants.

## Isolated source changes

The runner copies the released
`ZEKRA/zekra_java/components/zekra_c6/zekra_c6.java` into each case directory.
It changes only:

1. `EXECUTION_PATH_SIZE`, `SHADOWSTACK_DEPTH`, and stack-pointer width;
2. sample witness assignment (upstream's all-call dummy sample is unsuitable
   for a bounded stack);
3. enabling circuit export and printing the chosen SmartMemory state.

The `outsource`, `push`, and `pop` algorithms are retained. By default, the
pointer width is `D.bit_length()`, matching upstream `compile_circuit.py`.
The shared Binius implementation retains its fixed 15-bit stack-pointer range.

The jar uses the existing isolated native-field packing repair documented in
`../scaling/README.md`. Only the same four SmartMemory class entries change.
The original jar hash, repaired jar hash, source hashes, image ID, exact commands,
logs, circuit hashes, and witness hashes are recorded. The upstream submodule
is not modified.

## Verification and output

`measurement.json` preserves each compiler result and SmartMemory mode.
`constraints.csv` repeats a case only when it belongs to multiple scan families.
Every successful case must finish xJsnark's sample evaluation without an error.
A separate sample increments the first return destination and must fail its
return-equality assertion.

`verify_arithmetic.py` independently interprets each exported arithmetic circuit
using the saved input/witness file, checks its assertions and bit splits, and
recounts its R1CS rows. Its total must equal the Java compiler's total. The
result is saved as `arithmetic-verification.json`.

The released backend adaptively chooses SmartMemory implementations. Its mode
constants are `1 = network`, `2 = linear`, and `3 = sqrt`; the primary campaign
observes only linear and network modes. Thus a paper-level `L sqrt(D)` cost
description must not be presented as the observed growth law of these compiled
circuits. Any such curve should be identified as a theoretical reference.

## Measured primary results

All 21 primary witnesses satisfy their generated circuits. At `D=8`, increasing
`L` from 64 to 4096 increases the count from 5,225 to 339,881, with linear mode
selected throughout. At `L=1024`, increasing `D` from 1 to 256 increases the
count from 28,649 to 256,853. The compiler selects linear mode through `D=16`
and network mode from `D=32` in this scan. The joint scan's largest case,
`L=4096, D=1024`, produces 1,186,983 R1CS rows in network mode.

The four fixed-15-bit controls also satisfy their generated circuits:

| `L` | `D` | R1CS rows | SmartMemory mode |
| ---: | ---: | ---: | :--- |
| 1024 | 1 | 57,262 | linear |
| 1024 | 8 | 107,389 | linear |
| 1024 | 32 | 257,268 | network |
| 1024 | 256 | 281,387 | network |

Depth dependence persists with a fixed pointer width, so the primary depth
trend is not explained solely by changes to the pointer representation.
