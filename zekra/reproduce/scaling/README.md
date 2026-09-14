# ZEKRA scaling experiment

This adapter benchmarks **ZEKRA with a native-field SmartMemory packing repair** on
synthetic same-source CFA artifacts. It does not modify the upstream submodule and
does not represent these inputs as acquired QEMU traces or authenticated device
observations.

```sh
python3 zekra/reproduce/scaling/run_scaling.py \
  --input /absolute/path/to/fixture/complete \
  --output /absolute/path/to/new/result-directory \
  --levels 2 --warmups 1 --repetitions 3
```

The input directory supplies `translator`, `typed_cfg`, and `recorded_path`. Its
optional `static_returns.tsv` describes the fixture generator's predefined return
relation. The output directory must be new. `--prepare-only` audits and converts
inputs without Docker or circuit execution. Run the adapter's small semantic checks
with `python3 -m unittest discover -s zekra/reproduce/tests -p 'test_scaling.py'`.

For both generated families at 64/128/256/512/1024/2048/4096 source rows, run:

```sh
python3 zekra/reproduce/scripts/run_zekra_scaling.py \
  --inputs "$SCALING_INPUTS" --output "$NEW_CAMPAIGN" \
  --warmups 1 --repetitions 3
```

The campaign requires the shared generator's complete seven-point manifest and
checks each selected input against it. Add `--families growing-cfg` for only the
growing-CFG series. Cases run serially; each family has one excluded warmup at
source64, followed by three measured repetitions at every scale. The manifest
freezes this plan, the inputs, and execution-source hashes. Execution sources are
copied into the new campaign directory. The wrapper also preserves Docker events
for formal attempts, warmups, and compilation phases. An exit code of 137 alone
does not establish an out-of-memory failure.

After completion, the wrapper invokes `summarize_scaling.py` to export aggregate and
per-attempt CSV records. The exporter checks measurement and log hashes, excludes
warmups from medians, and retains missing timings as empty fields. Old six-point
campaigns without warmup fields remain readable; their existing observations are
not supplemented with inferred runs.

## Statement and conversion

All node addresses must be nonzero raw24 values. An ordinary raw address may be the
initial/final synthetic caller; the adapter does not invent a QEMU scope boundary.
The repository's `zekra_compress` function in
`zkcfa-tracer/research/zekra_projection.py` compresses the source EP. The adapter
loads this independent module and records its source hash and every compression
decision. Both the source and projected EP
must satisfy typed forward-edge checks, exact call/return stack matching, the same
endpoints, and the statically supplied return relation. A projection that fails is
rejected; it is never replaced silently with the stack-safe compressor.

ZEKRA also tests return transitions against its untyped adjacency table. The adapter
therefore erases the kinds from the supplied typed graph and adds a **static** return
relation. For a supplied generator sidecar, every edge must be reachable from a CAL
target by following JMP and nested calls' CRT continuations, with the return
destination equal to that call site's CRT. Without a sidecar, only terminal blocks
of that traversal are treated as returns. This procedure never reads an EP to learn
graph edges. Original CRT edges, including declared self-loops, remain explicit.

Labels retain the input translator order. The formatter reserves raw address zero
and label `ADJLIST_SIZE` for empty/dummy rows. The actual fixture nodes and the
synthetic caller remain distinct from those values. Adjacency/node capacity is the
next power of two with floor 8; projected transition capacity is the next power of
two with floor 16. Fixed stack depth is 15. Label and bucket widths cover the padded
capacities including the dummy label. The campaign fixes `ADJLIST_LEVELS=2` for all
cases and audits all static neighbors, including unvisited nodes, before compilation.
The constraint `(bucket_width+8)*levels < 254` is checked explicitly.

## Isolated repair and its scope

The upstream jar must have SHA-256
`d6966c45ad659627027d19b4d8389d58a452f82ca416f1057efcdd428fbb535b`.
In this jar, `SmartMemory.getElementSize` uses chunk-size logic even for a native
`FieldElement`, whose packed representation is one full-width field wire. The
observed native-field metadata are `[30]`; the historical failing suite showed
32-bit truncation in the associated memory path. These are related observations,
not interchangeable bit-width measurements.

`PatchNativeMemory.java` prepends one branch to that method: when `typeClass` is
`FieldElement` **and** its modulus equals the circuit's native field modulus, return
one limb with the native field's bit width (254). The same predicate selects a
254-bit data-write chunk at seven `setWireValue` calls in the three memory witness
callbacks (`SmartMemory$2`, `$3`, and `$4`); otherwise their original 32-bit chunk
argument remains. This second part prevents a full native-field wire from being
silently populated with only its low 32 bits. Every original type fallback remains.
JDK 11's bundled ASM performs the isolated bytecode rewrite; no network dependency
or replacement upstream checkout is needed. The runner checks that exactly these
four class entries change inside the jar. Other types and non-native fields are
outside this repair; their independent upstream chunk-count defect is not claimed
to be repaired.

`CheckNativeMemory.java` reports original and repaired metadata, checks the native
write width, and verifies unchanged unsigned/non-native field write-width fallbacks.
Original and repaired jar hashes, patch-source hashes, Java before
and after parameterization, arithmetic circuit, witness file, and native proving
binary hashes are saved.

A 128-node, 39-bit-adjacency acyclic control checks original and repaired jars on
the same input and circuit size. The original sample fails because the memory
operand is the witness modulo 2^32; the repaired sample satisfies the circuit and
proves/verifies successfully. The control is excluded from performance aggregates.
Run it in a new directory:

```sh
python3 zekra/reproduce/scaling/run_repair_control.py --output /absolute/new/repair-control --prepare-only
python3 zekra/reproduce/scaling/run_repair_control.py --output /absolute/new/repair-control
```

`native-memory-diagnostics.json` records the final repair's source and jar identities,
assertion operands and formal resource-failure evidence. Per-campaign logs and
measurements remain in their original output directories.

## Environment and recorded measurements

Formatting and xJsnark compilation use local image
`zkcfa-zekra:paper-ubuntu22.04` under amd64. Groth16 uses native arm64 image
`zekra-native:local` with ALT_BN128, `MULTICORE=ON`, `PERFORMANCE=ON`,
`-O3 -march=native`, and `USE_ASM=OFF`. The runner records image IDs, Docker
CPU/memory configuration, native architecture, build settings, linked libraries,
and source revisions. `OMP_NUM_THREADS=8` and `OMP_DYNAMIC=FALSE` are fixed for
every invocation; the native executable links `libgomp`.

The original Java source is copied to each result directory, parameterized there,
and compiled once for that case. Compilation must produce a satisfied sample, an
arithmetic circuit, and a witness. Return status alone is insufficient: upstream
formatter rejection and sample unsatisfaction can both return zero. The compiled
`Total constraints` must equal every Groth16 invocation's `QAP pre degree`.

Each invocation of the upstream native CLI performs setup, proving, and verification.
`--repetitions` counts measured invocations. The standalone adapter defaults to
zero warmups; `--warmups 1 --repetitions 5` explicitly requests one excluded warmup
and five measured invocations of a matched fixture. The campaign uses the
per-family source64 warmup policy described above. Successful measured repetitions
yield median setup/prove/verify phase times; full
process wall time is separate and includes translation and container overhead.
Log files, their hashes, individual timings, verification outcomes, constraint counts,
and QAP dimensions are retained in `measurement.json`. `warmup_runs` and `runs`
store excluded and measured invocations separately. A failed phase is recorded as
failed with its real status, never as a zero time. The adapter stops that case after
an unsuccessful proof, so planned and completed repetition counts must be reported
separately if such a failure occurs. Timeout/interruption removes only the named
container created by that invocation. A failed warmup stops that case before any
measured invocation.

Historical 15-level CRC32/Embench results are a different configuration and campaign.
This study's repaired-jar, two-level numbers must not be presented as an unmodified
upstream reproduction or silently pooled with those earlier results.
