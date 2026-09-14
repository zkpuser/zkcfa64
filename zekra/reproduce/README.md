# Upstream CRC32 reproduction

Run from the workspace root with Python 3, Git, and Docker. Build the two images
once using the [environment instructions](../README.md#build-the-environments).

```sh
make reproduce-zekra
# Explicit, new output directory:
bash zekra/reproduce/run-crc32-paper22.sh --output zekra/output/crc32-run1
```

The Python entry point is `run_crc32.py`; the shell entry point delegates to it.
The default output is a new UTC-stamped directory under `zekra/output/`.
An existing output directory or any path inside the upstream checkout is rejected,
including paths redirected there by a symlink. Use `--prepare-only` to create and
inspect the source snapshot without running Docker. Image construction is explicit;
the runner uses the installed image IDs and does not rebuild or pull images.

## Source isolation

The runner requires the clean upstream commit
`01a0152bfd9812a0569dce19965e7e92df30015d`, then extracts `git archive` into
`<output>/work/ZEKRA/`. Only this snapshot is mounted writable. The extractor's
source-order shim is frozen in `<output>/harness/` and mounted read-only; the
upstream Python, Java, and jar files receive no repair patch.

Before and after the run, `source-before.json` and `source-after.json` record the
upstream commit, Git status, and hashes of every source file, including ignored
files and symlink targets. A changed inventory makes the run fail. The runner
creates uniquely named containers, disables their network, records their exit
and OOM states, and removes only its own containers after each stage.

## Asserted result

The amd64 Ubuntu 22.04 compiler environment runs extraction, formatting, and
xJsnark compilation. The native Groth16 image runs setup, proving, and strong-IC
verification with eight OpenMP threads by default.

| Check | Expected value |
| --- | --- |
| CFG nodes / edges | 88 / 106 |
| Path transitions before / after compression | 3090 / 24 |
| Extracted path valid | True |
| Poseidon hashes | All three values published in upstream `ZEKRA/README.md` |
| Adjacency / path capacity | 500 / 500 |
| Adjacency levels / stack depth | 15 / 15 |
| Label / bucket / address bit width | 10 / 7 / 24 |
| R1CS constraints | 336230 |
| Groth16 verification | PASS |

A missing expected value or a failing process produces a nonzero exit and a
failed `summary.json`. The default per-stage timeout is 1800 seconds; adjust it
with `--stage-timeout`. `--threads`, `--compiler-image`, and `--prover-image` are
also explicit options. The prover image must match the Docker server architecture.

## Retained outputs

- `summary.json`: assertions, native setup/prove/verify times, image IDs and
  architectures, thread count, Docker resources, commands, exit states, and hashes.
- `00-compiler-environment.log` through `05-groth16.log`: complete stage output.
- `work/ZEKRA/zekra.arith` and `work/ZEKRA/zekra_Sample_Run1.in`: arithmetic circuit
  and witness/input text consumed by libsnark.
- `work/ZEKRA/embench-iot-applications/crc32/`: extracted and formatted inputs.
- `source.tar`, `harness/`, and the source inventories: provenance needed to
  identify the exact source and reproduction tools used.

The upstream CLI generates the keys and proof and verifies them in the same
process; it does not export a standalone serialized proof. Keep the circuit,
input, and log to rerun and inspect the result. Native phase timings exclude
extraction, formatting, compilation, and container startup. A single reproduction
run establishes correctness; it is not a repeated performance campaign.

For other experiments see [applications](APPLICATIONS.md),
[scaling](scaling/README.md), and [stack constraints](stack_constraints/README.md).
Run the host-only harness checks with `make test-zekra`.
