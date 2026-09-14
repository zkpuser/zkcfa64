# Provider integration harness

This directory contains the evaluation-only all-in-one runner. It creates
disposable authority/device keys, selects exact fitted capacities, issues and
consumes one in-memory challenge, checks replay rejection, and records timing
and byte counts. Those conveniences deliberately combine trust roles and are
not a production deployment interface.

Run the commands below from the monorepo root (`zkcfa64/`), after installing
the dependencies declared in `zkcfa-tracer/provider/pyproject.toml`:

```sh
PYTHONPATH=zkcfa-tracer/provider python3 zkcfa-tracer/research/provider-integration/bundle.py \
  --run-dir /tmp/zkcfa-run \
  --artifacts /path/to/device-artifacts \
  --policy-artifacts /path/to/static-policy \
  --binary /path/to/application \
  --trace /path/to/trace.log \
  --path-mode complete
```

For `--path-mode shadow`, first run the maintained shadow projection tool and
also pass `--complete-source-artifacts` and `--source-trace`. The generated
`protocol-result.json` is benchmark metadata, not verifier input.

`suite.py` applies the same fitted evaluation policy to all 21 maintained paper
inputs, signs both complete and shadow modes, and writes a `bundles.json`
manifest containing the external authority-key path and pin, challenge, nonce,
timings, and byte counts for each run:

```sh
PYTHONPATH=zkcfa-tracer/provider python3 zkcfa-tracer/research/provider-integration/suite.py \
  --inputs /path/to/final-inputs \
  --output /tmp/zkcfa-signed-suite
```

The generated keys are disposable experiment keys. Production deployments use
the role-separated provider commands and externally managed keys and challenge
state described in the [provider README](../../provider/README.md).
