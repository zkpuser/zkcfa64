# ZEKRA application measurements and repair checks

The paper's same-path application comparison is documented in
[MATCHED_COMPRESSED.md](../../scripts/embench21/MATCHED_COMPRESSED.md). The original and repaired released
application runs below support the SmartMemory failure diagnosis; their timings
must not be substituted for the shared-path comparison.

`run_zekra_campaign.py` prepares a fresh upstream source snapshot, then runs the
selected applications and the published CRC32 500/500 control serially. By default
it selects all 21 applications. It uses the
original xJsnark jar, adjacency depth 15, raw24 addresses, and ZEKRA's own saved
compressed inputs. These are descriptive prior-work results; they are a different
statement from newly acquired complete/stack-safe QEMU inputs.

## Three-application smoke check

To check the pipeline before a full campaign, choose a new output directory and
prepare cubic, matmult-int, and aha-mont64. The CRC32 500/500 control is included
automatically. Run these commands from the workspace root:

```sh
smoke_dir=/absolute/new/zekra-apps3
python3 zekra/reproduce/scripts/run_zekra_campaign.py \
  --output "$smoke_dir" --prepare-only \
  --applications cubic,matmult-int,aha-mont64 --keep-artifacts
python3 zekra/reproduce/scripts/run_zekra_campaign.py \
  --output "$smoke_dir" --threads 8 --cpus 8 --require-proofs
```

Preparation freezes the selection and artifact-retention setting. Execution reads
those settings from the saved plan; `--require-proofs` fails unless every selected
application proves and verifies. `--keep-artifacts` retains generated arithmetic
circuits and witness inputs for inspection.

In `summary.json`, `selection_complete` means the CSV contains exactly the selected
applications. `coverage_complete` additionally requires all 21 applications, so it
remains false for this smoke check even if every selected proof verifies.
Neither coverage flag is itself a proof-success flag. A subset CSV cannot serve
as the baseline for the existing full-suite input audit, repaired-application
runner, or RSS runner below; those tools require all 21 applications.

## Full released suite

Omit `--applications` during preparation to select all 21 applications:

```sh
original_dir=/absolute/new/zekra21
python3 zekra/reproduce/scripts/run_zekra_campaign.py --output "$original_dir" --prepare-only
python3 zekra/reproduce/scripts/run_zekra_campaign.py --output "$original_dir" --threads 8 --cpus 8
```

Preparation checks a clean upstream checkout, pins image IDs, and freezes source
hashes. The output directory must be absent for preparation. Execution uses only
that snapshot; `compile_circuit.py` never writes to the shared submodule. Each
Docker invocation has its own name, no network, fixed OpenMP settings and a CPU
limit. The proxy records Docker's inspected OOM state before removing its own
container, plus circuit/witness hashes before the historical shell wrapper removes
large intermediates. Run the command once per prepared directory.

`results.csv` preserves the original wrapper's column names. `summary.json`
contains coverage, log hashes, and validation issues. A validated full-suite run requires
the CRC32 control to verify with 336,230 constraints, all 21 apps to have explicit
outcomes, every reported proof to verify, and compiled R1CS counts to equal native
QAP pre degrees. Exit 137 alone is insufficient for a validated host-memory result:
the exact container must have `OOMKilled=true`. Unsatisfied samples remain failures.

The recorded original-jar baseline contains nine unsatisfied applications and one
resource-limited application. Full-suite coverage therefore does not promise 21
verified proofs. These outcomes support the SmartMemory diagnosis and separate
repair experiments documented below.

The native arm64 image and binary identity/build flags are recorded separately
from the amd64 formatter/compiler image.

Use that completed original campaign for the input audit and repaired runs below.
Pass its CSV and snapshot explicitly; these tools do not select private manuscript
data or an old local campaign by default. From the repository root:

```sh
python3 zekra/reproduce/scripts/audit_zekra_released_inputs.py \
  --legacy-results "$original_dir/results.csv" \
  --input-root "$original_dir/snapshot/zekra/ZEKRA/embench-iot-applications" \
  --output /absolute/new/zekra-input-audit
```

This audit writes `audit.json`, `summary.csv`, and its explanation to the new
output directory. It reads the original input files and outcomes without running
a compiler or prover. For an archive without Git metadata, `zekra_revision` is
`null`; the input hashes still identify the audited bytes. The original campaign's
`preparation.json` separately records the revision used to create that archive.

The synthetic scaling experiment has a separate runner in
[`scaling/`](scaling/README.md), with a repaired
native-field memory jar, two fixed adjacency levels, and audited static returns.
Never merge its results into the original-jar legacy table as the same experiment.

## Repaired released application statements

`run_zekra_repaired_apps.py` applies that same four-class SmartMemory repair to a
fresh isolated source snapshot, while retaining the released application's five
input files and every parameter from the supplied original `results.csv`. It does
not use the synthetic input converter, re-project paths, or insert returns.

```sh
python3 zekra/reproduce/scripts/run_zekra_repaired_apps.py \
  --baseline "$original_dir/results.csv" \
  --historical-inputs "$original_dir/snapshot/zekra/ZEKRA/embench-iot-applications" \
  --output /absolute/new/repaired-zekra21
```

The runner first checks the CRC32 control, then measures minver, nettle-aes and
md5sum with one excluded warmup and three formal native runs each. Other cases
have one primary run. Containers have eight CPUs, eight OpenMP threads, an 18-GiB
memory cap, and a 900-second phase timeout. It preserves logs, inspected OOM state,
input/formatter hashes, all native attempts, and comparison CSV/JSON records.
The output directory must be new; `--prepare-only` freezes the plan without
executing circuits. Historical results remain unchanged and are not claimed to
be input-matched to the QEMU application statements.

The recorded repaired campaign verified all nine formerly unsatisfied
applications and all 11 prior successes. Huffbench remained resource-limited
at the 18-GiB cgroup cap; the original campaign used an approximately
22.94-GiB VM allowance. The campaign outputs and independent input/result
audit identify the inputs and outcomes for each application.

## Full application rerun with resident-memory measurements

`run_zekra_rss_apps.py` creates a separate snapshot for all 21 released application
statements and the CRC32 control. It retains the five original input files,
parameters from the supplied original `results.csv`, and the same four-class
SmartMemory repair. Historical campaigns and the original runner remain unchanged.
The output directory must be new for the initial invocation:

```sh
python3 zekra/reproduce/scripts/run_zekra_rss_apps.py \
  --baseline "$original_dir/results.csv" \
  --historical-inputs "$original_dir/snapshot/zekra/ZEKRA/embench-iot-applications" \
  --output /absolute/new/zekra-rss21 --memory-gib 18 --timeout 900
```

Cases and stages run serially, with eight CPUs, eight OpenMP threads,
`OMP_DYNAMIC=FALSE`, an 18-GiB memory limit with no additional swap allowance,
and a 900-second workload timeout per stage. Every case that reaches native proof
generation has one excluded warmup followed by three measured native runs, stopping
after its first failure. Reported setup, proving, and strong-IC verification times
are medians of verified measured runs, parsed from libsnark's phase timings.
Successful cases require all three measured proofs to verify and their QAP pre
degrees to match the compiled R1CS constraint count.

The same RSS collector and stage runner are used by the shared-path campaign.
Successful native RSS is the **maximum peak RSS across the three measured runs**;
the warmup is excluded and the median peak is also retained. The Linux collector
uses `wait4().ru_maxrss × 1024` to store bytes. This measures a process's resident
high-water mark, including the maximum reported by its reaped descendants, rather
than simultaneous aggregate process-tree memory. Native RSS covers the native
worker's conversion, setup, proving, and verification. Formatter and compiler/witness
RSS are recorded separately, as is a full-pipeline maximum across those stages and
the measured native runs. Historical virtual-memory/vsize values are not RSS and
must not be substituted for these measurements.

A failed native attempt retains its measured peak even if it was the warmup; it
is labeled as a failed attempt, not a three-run statistic. If OOM kills the
collector before `wait4` finishes, surviving sampled `/proc` resident high-water
marks provide an explicitly marked lower bound. Sampled summed process-group RSS
is a separate field. Container OOM state, exit status, and timeout evidence remain
available; OOM attempts are not repeated three times.

Resume the saved plan without overwriting completed stages:

```sh
python3 zekra/reproduce/scripts/run_zekra_rss_apps.py \
  --baseline "$original_dir/results.csv" \
  --historical-inputs "$original_dir/snapshot/zekra/ZEKRA/embench-iot-applications" \
  --output /absolute/new/zekra-rss21 --resume
```

`plan.json` records inputs, image IDs, code hashes, limits, and measurement scope;
`instrumentation/` preserves the runner and collector. Each stage attempt has
`attempts/<stage>/<attempt>/{pending.json,output.log,rss.json,phase.json}` beneath
its case or patch directory. Per-case `result.json`, campaign `events.jsonl`,
`summary.json`, and `results.csv` retain proof checks, timing samples, RSS, and
artifact hashes. Interrupted attempts are preserved, and completed stages are
reused. Resume checks the recorded code hashes; if the working runner has changed,
invoke the saved `instrumentation/run_zekra_rss_apps.py` with the same output path
and `--resume`.
