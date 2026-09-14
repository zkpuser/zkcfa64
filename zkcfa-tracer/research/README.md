# Research and reproduction

This directory contains the evaluation helpers and pinned benchmark inputs used
for paper comparisons and reproducibility. It is not part of the deployable
provider; none of these modules is imported by `provider/`.

## Current evaluation helpers

Start with the [Embench-21 rerun helpers](../../scripts/embench21/README.md) for
the current acquisition, signing, and Binius64 measurement workflow.

- [`provider-integration/`](provider-integration/README.md): the fitted-capacity
  evaluation harness that creates
  disposable keys, exercises all protocol roles, checks replay rejection, and
  records benchmark metadata. Production callers use the role-separated CLI in
  [`provider/`](../provider/README.md) with externally managed keys and challenges.
- [`provider-benchmarks/`](provider-benchmarks/README.md): pinned Embench source
  and overlay materializers, acquisition adapters, and campaign import checks.
  Use the explicit provider/input arguments documented there.
- [`zekra_projection.py`](zekra_projection.py): the ZEKRA consecutive-sequence
  compression baseline shared by the Binius64 and ZEKRA scaling measurements.
  It preserves the measured compression algorithm and is separate from the
  maintained provider's stack-safe projection.
- `atomic_publish.py`: shared support for research artifact publication.

Run experiment scripts and tests from the directory documented by their local
README. The compression regression checks run from this directory:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -m unittest discover -s tests -v
```

## Local outputs

- `generated-results/` and `local-work/`: ignored local outputs, build products,
  and tool checkouts. They are not provider inputs or source-controlled files.
