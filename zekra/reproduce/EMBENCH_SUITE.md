# Released ZEKRA application diagnostic

`run-embench-suite.sh` evaluates ZEKRA's own saved inputs for all 21 bundled
applications and the CRC32 500/500 control. These are the original released
compressed statements, not the QEMU paths in the paper's shared-path comparison.

Use the [isolated campaign wrapper](APPLICATIONS.md) from the
workspace root. It snapshots upstream source, fixes resource limits and records
container outcomes before removal. The wrapper uses the amd64 compiler image
and the native ARM64 Groth16 image; no extraction or new path compression occurs.

## SmartMemory failure

The original jar produces nine unsatisfied application samples after all three
Poseidon digests match. For each affected sample, its native-field adjacency
witness and memory value satisfy:

```text
memory = witness mod 2^32
```

The Java witness uses the full packed adjacency entry, but the SmartMemory path
populates the circuit wire with only its low 32 bits. Thus a valid input can fail
when a visited node's adjacency encoding exceeds 32 bits. For example, a recorded
failure has `witness=17599719342600` and `memory=3238330888`.

The [input audit](scripts/audit_zekra_released_inputs.py) checks
raw/numeric path agreement, executed return matching and the visited adjacency
widths against the original results. Its nine affected applications are md5sum,
minver, nettle-aes, nettle-sha256, picojpeg, primecount, sglib-combined, st and
wikisort. CRC32's visited entries fit within 32 bits and its 500/500 control
reproduces 336,230 constraints and successful verification.

This is a completeness defect: it prevents proofs for some valid paths. The
[repair runner](APPLICATIONS.md#repaired-released-application-statements)
checks the corrected jar on the same inputs and parameters. The
[synthetic repair control](scaling/README.md#isolated-repair-and-its-scope) tests
original and repaired jars on an identical circuit with a wide adjacency entry.

## Outcome accounting

Keep unsatisfied samples separate from timeout, compilation, native proof and
container-memory failures. A sample that satisfies the circuit can still exhaust
the host's resource allowance during native conversion or proving; this does not
establish a platform-independent limit. The isolated wrapper saves the inspected
OOM state, logs and phase outcomes. The RSS runner additionally retains peak
resident memory, including explicitly marked sampled lower bounds for interrupted
collectors. Current shared-path performance is reported by the separate
[matched compressed campaign](../../scripts/embench21/MATCHED_COMPRESSED.md).
