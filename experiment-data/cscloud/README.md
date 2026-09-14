# Paper reproduction data

This package contains the measured statistics used in the CSCloud paper, together with environment, input, binary and source identities. Reproduction inputs, dependencies and execution instructions are provided by the repository.

- `modes.json/csv`: the two authenticated raw24 modes for all 21 applications.
- `controls.json/csv`: membership comparisons, matched512, backend-fork cost and public-authentication metrics.
- `online.json/csv`: five fresh online measurements after one excluded warmup.
- `structural.json`, `scaling.csv`, `scaling-attempts.csv`, `stack.csv`: the seven-point scaling grid, real failure accounting and stack counts.
- `matched.json/csv` and `backends.json/csv`: matched application comparisons, with the actual PLONK picojpeg supplement retaining the original unexecuted scheduling record.
- `released.json/csv`, `repaired.json/csv`, `repair-control.json/csv`: original ZEKRA results and the separately identified repair diagnostics.
- `raw64.json/csv`: paired address-width results, including actual failures and unequal repetition schedules.
- `identities.json`: environment and artifact SHA256 identities; paths beginning `repo/` are repository-relative and `run/` are relative to the reproduction run.
- `manifest.json`: exact selected export identities and SHA256 for every packaged file except the manifest itself.

Read each JSON definition/timing scope before comparing values. Missing/unexecuted observations are not zero. Partial successes and failures are preserved. Warmups and preflights do not enter formal timing medians. Scaling min–max error bars require three verified formal samples. Stack-count observations are not repeated timing benchmarks. RSS and macOS footprint are distinct. ZEKRA proof-bit accounting is not a serialized-byte measurement.

CSV files are regenerated from the public JSON rather than copied from working directories. Nested CSV cells contain JSON. Control CSVs contain flattened median/minimum/maximum records; complete sample lists remain in JSON. Statistical values are unchanged. Operational command fields and private-material fields are omitted; known local paths are made relative and other machine paths are redacted.

No private signing keys, commitment openings, raw acquisition traces, proof transcripts, binaries, source contents or large logs are included. Artifact hashes identify those inputs without copying their contents. Source versions may differ between explicitly attributed frozen stages.

Reproduction entry points and dependencies are documented in the repository root README and the component READMEs. Use the recorded source revisions, input manifests and toolchain/image identities. The measured hardware and resource limits are part of the reported experiment. This package is assembled only after all required statistical exports close; a terminal resource failure is retained as a scientific result.

