# Benchmark inputs and acquisition adapters

This directory supplies the pinned source tree, recovery and functional-oracle
overlays, build helpers, and acquisition adapters used by the paper's
21-application evaluation. The maintained campaign workflow is documented in
[Embench-21 rerun helpers](../../../scripts/embench21/README.md).

`vendor/zekra-embench21/` binds the source, build manifest, and recovery overlay.
The scripts under `static/` materialize the overlays and rebuild the pinned
ELFs; see the [functional-oracle instructions](functional-oracle/README.md).
These inputs are required before the current campaign's acquisition step.

The acquisition adapters require `--provider` to identify a maintained provider
tree as well as the pinned input directories shown by their `--help` output.
`capture_recovered.py` performs the pinned QEMU acquisition
used to recover a complete root-return interval for `picojpeg` and
`sglib-combined`. It requires the materialized recovery provenance and
emits `same-elf-zekra-handoff/<application>/`: each handoff contains the exact
executable as `main`, original QEMU trace, normalized path, static bindings,
complete boundary evidence, a machine-readable manifest, and `SHA256SUMS`.
The manifest sets `zekra_input.recompile=false`; ZEKRA must load those exact
bytes instead of invoking its legacy compile-at-startup step.
`prepare_final_suite.py` then re-provisions and re-normalizes all 21 captured
traces with the selected maintained provider, rejecting any path-content
change. Signing the resulting inputs is handled by
`../provider-integration/suite.py`.

`import_compat_qemu_campaign.py` is the fail-closed bridge from a published
compat/QEMU campaign to the legacy complete-path proof-input layout. Its trust
roots are deliberately supplied outside the campaign: the original suite, a
local provider source tree, the exact expected QEMU commit, and the caller-known
SHA-256 of the campaign root `SHA256SUMS`. For every application the importer
copies the provider implementation once, re-runs that trusted `normalize.py`
over private copies of the checksum-bound raw trace, plugin map, typed CFG, and
translator, and requires both the regenerated `recorded_path` and the complete
canonical trace evidence to match the published artifacts exactly.
The trusted provider source-set identity (including `static/__init__.py`) is
written into the imported provenance.

For the recorded source-aware campaign, pass
`--expected-campaign-sha256s-sha256` with value
`83ce23a2673994ffde83a19e4ee0fa59720d247861244231c9c94ef2044de82e`; the
default exact QEMU revision is
`667e1fff878326c35c7f5146072e60a63a9a41c8`. Override either only from an
independently authenticated value.

This replay closes the raw-trace-to-recorded-path and raw-trace-to-evidence
derivations; it does not prove that an otherwise untrusted raw trace came from
QEMU or that the static inputs came from a fresh trusted provision run. A
campaign without an authenticated root checksum still requires a trusted
provision/QEMU rerun or equivalent external attestation before it can be treated
as proof input.

Run the adapter and overlay checks from this directory. They create their
fixtures in temporary directories and do not launch a full proof campaign:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python3 -m unittest discover -s tests -v
```
