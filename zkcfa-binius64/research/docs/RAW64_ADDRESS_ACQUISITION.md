# Real high-address acquisition experiment

The `raw64_addresses.py` harness tests the maintained provider on real x86-64
PIE executions whose program counters occupy the usual 47-bit Linux user
address range. It retains the actual high address bits in the proof inputs.
The experiment does not rewrite an already captured low-address trace.

## Paired acquisition

Each application is executed twice under the same QEMU binary and runtime
libraries, using the identical ELF and application input:

| Lane | Provisioned PIE base | Actual runtime base | Proof address treatment |
| --- | --- | --- | --- |
| `low` | `0x400000` | `0x555555556000` | Existing raw24 normalization |
| `wide` | `0x555555556000` | `0x555555556000` | Full runtime PC retained; measured `runtime_bias=0` |

The original provider plugin measures the runtime mapping before execution.
It checks the instruction bytes against the independently provisioned ELF
map and validates entry, continuity, and root return. The wide lane requires
`runtime_bias=0` and a program counter requiring at least 47 bits; otherwise the
harness fails. Thus the logged canonical PC is also the actual guest virtual
PC in every accepted wide capture. No modified plugin is needed.

Indirect target policies are translated to the selected ELF namespace before
static provisioning. Their application and exact ELF digest remain bound.
Complete and stack-safe projection inputs are then derived using the same
maintained provider paths. The projection retains its weaker semantic scope.

`audit` compares the two independently captured instruction sequences,
translator nodes, typed CFG edges, complete paths, and stack-safe paths after
subtracting the known base difference **in memory for this audit only**. The
proof inputs and original traces remain untouched. It also verifies identical
ELF digests. This controls program and path differences while comparing the
complete raw24 and raw64 constructions. The measured difference includes the
larger serialization, three membership channels, and explicit CFG checks.

## Reproduction

The input is an existing fresh provider campaign with `inputs.json`,
`inputs/<app>/<app>`, `inputs/<app>/artifacts`, optional per-application
`indirect-policy.json`, and `sysroots/<profile>/runtime-dependencies.json` plus
its measured libraries. The harness checks the ELF and runtime manifest hashes
from that campaign. The recorded experiment reused a complete 21-application input
campaign and independently provisioned and executed all 42 application/address pairs.
Source identities and measurement timestamps are retained in the campaign metadata.

Use a provider image with Python dependencies, GCC, GLib development headers,
and QEMU's source/build tree. Mount the repository and source campaign at the
same absolute paths they have on the host, and mount the source read only.
This preserves usable host paths in protocol results. For example, inside the
provider environment:

```sh
python3 zkcfa-binius64/research/scripts/raw64_addresses.py prepare \
  --source /absolute/path/to/source-campaign \
  --output /absolute/path/to/zkcfa-binius64/build/raw64-addresses \
  --provider /absolute/path/to/zkcfa-tracer/provider

python3 zkcfa-binius64/research/scripts/raw64_addresses.py audit \
  --output /absolute/path/to/zkcfa-binius64/build/raw64-addresses \
  --provider /absolute/path/to/zkcfa-tracer/provider

python3 zkcfa-binius64/research/scripts/raw64_addresses.py sign \
  --output /absolute/path/to/zkcfa-binius64/build/raw64-addresses \
  --provider /absolute/path/to/zkcfa-tracer/provider \
  --integration /absolute/path/to/zkcfa-tracer/research/provider-integration
```

`--applications crc32` selects a smoke test. Completed acquisition lanes are
resumeable after their recorded hashes are checked. Incomplete lanes fail
closed rather than silently overwriting their logs. `--high-base` allows a
different observed mapping; the zero-bias requirement still applies.

`sign` selects `raw24-full-key` for `low` and `raw64-typed-channels` for `wide`.
It creates 84 independently signed complete/shadow bundles for all 21 apps.
The output layout is:

```text
captures.json
pair-audit.json
bundles.json
inputs/{low,wide}/<app>/{artifacts,shadow,trace.log,capture.json,...}
signed/{low,wide}/<app>/{complete,shadow}/protocol-result.json
signed/{low,wide}/<app>/{complete,shadow}/bundle/
```

Proof and verification measurements are run separately, serially, using the
same host-native build settings. Capture time in `capture.json` is a QEMU
acquisition measurement and must not be reported as proof or device hardware
latency. Generated traces, keys, and bundles belong in an ignored build/input
directory; they are not public research fixtures.

## Scope of the evidence

The recorded capture audit passed for all 21 applications and all 42 complete
and stack-safe path pairs. Every wide trace retained 47-bit runtime addresses
with zero normalization bias. CRC32, for example, executed at
`0x555555557060`–`0x555555557349`, with 14,398 recorded instructions and
3,091 complete path records (22 after stack-safe projection).

This validates one concrete general-purpose Linux user-space address layout
and full-width serialization of its addresses. It does not establish coverage
of all x86-64 canonical mappings, 57-bit page-table configurations, kernels,
shared-library control-flow, address-space randomization across multiple
layouts, or native hardware collection. Full 64-bit encoding boundary tests
are separate from real execution evidence. The provider's reserved scope and
external gateway tokens remain special typed nodes rather than executable
program addresses.
