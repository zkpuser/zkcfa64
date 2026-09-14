# Full-width address experiment

`RUSTFLAGS='-C target-cpu=native' cargo build --release --features raw64 --manifest-path zkcfa64/Cargo.toml`
compiles the independent `raw64-typed-channels` relation. A build without this
feature retains the existing `raw24-full-key` relation. Each binary accepts only
its compiled, authority-signed profile; the feature is not a verifier option
that an untrusted prover can choose.

The experimental relation retains all 64 address bits. Real execution in the
accompanying campaign uses x86-64 userspace PCs occupying 47 bits, while synthetic
circuit tests also cover 56-bit values and high-half addresses with bit 63 set.
Those synthetic tests are not claims of 57-bit paging or kernel tracing.

## Canonical bytes

Words are unsigned 64-bit integers, serialized big-endian for SHA-256. Address
zero denotes inactive evidence. The inherited provider gateway token range
`0xfffe0000..0xfffefffe` maps to `0xffffffffffff0000..0xfffffffffffffffe`;
`SCOPE_RETURN` maps to `0xffffffffffffffff`. These are reserved protocol tokens,
not ordinary numeric program addresses. Numeric input cannot directly name the
top 65,536 values. All other accepted addresses keep their full value.
An actual program PC in the legacy gateway input range cannot be represented
as an ordinary address under this compatibility profile.

Each CFG edge is three words `[source, type, destination]`. Real edges are sorted
lexicographically by that tuple; types are JMP=0, CAL=1, CRT=3. Trailing padding
at table index `j` is `[0, 0, j+1]`. A zero source separates padding from real
edges without taking a bit away from any real address. The circuit checks real
endpoint nonzeroness, allowed types, and the exact padding tuples.

Each execution-path row is three words `[tag, destination, payload]`. Tags are
JMP=0, CAL=1, RET=2. A call's payload is its full return address; a return's
payload is its matching-call row number; a jump's payload is zero. Every word of
an inactive row is zero. Call-row numbers remain 24 bits and stack depth remains
15 bits. Address width does not increase those separate bounds.

The ten-word headers retain the raw24 field positions. CFG magic is `CFG-W64V`,
EP magic is `EP-W64V1`, address width is 64, and EP header word 6 is 24 (matching
call-row width). Path mode and independent nonzero 128-bit commitment openings
remain authenticated in their existing header positions. The EP layout label
is `wide64`. For a capacity `C`, either artifact uses `10+3C` words instead of
`10+C` words in raw24.

The public ABI remains ten words: four per SHA-256 digest, entry, and final
address. The signed profile and configuration identity bind the wider layout.
The protocol JSON fields `h_cfg_raw24` and `h_ep_raw24` retain their historical
names for envelope compatibility; their contents are profile-specific digests,
not raw24 encodings. Human/JSON proof reports call them `H_cfg_raw64` and
`H_ep_raw64` for this profile.

## Membership and exact returns

A full typed edge contains 130 bits, so it cannot be injected into a 128-bit
field by concatenation. The implementation uses three independently
domain-separated BinMult channels, one for each allowed static edge type.
Within each channel the address pair maps injectively into GF(2^128), with
`low=destination` and `high=source`. A row outside that channel contributes
the multiplicative identity. All channels use the same committed multiplicity
vector; challenges bind the EP, CFG, multiplicity seal, and channel identity.
Unused seal bits are zero. This avoids truncation and avoids introducing a
tuple-compression collision assumption. As in raw24, polynomial evaluation
soundness and Fiat-Shamir assumptions still apply.

The return-stack token also spans two words: the low word is the complete
return address; the high word holds the active marker at bit 63, the 15-bit stack
position at bits 24..38, and the 24-bit call timestamp at bits 0..23. The other
high-word bits are zero. Two field challenges check push/pop equality, with
depth range checks, earlier-call checks, and an empty final stack.

This is a distinct construction, not merely a changed address constant. Besides
larger commitment buffers, it performs three membership-channel checks and adds
explicit CFG row checks. Performance comparisons therefore measure this concrete
implementation, not an isolated cost of enabling address high bits.

Power-of-two commitment capacities can also amplify a modest increase in
circuit size. In the picojpeg shadow case, the logged value vector grows from
3,432,339 to 8,603,741 words, while the padded commitment capacity grows from
4,194,304 to 16,777,216 words. Consequently, proving and memory costs need not
scale linearly with the number of constraints. These are the observed circuit
shapes; they do not by themselves isolate the causes of a measured time ratio.

## Reproduction

The provider authority and fitted experimental bundle harness accept
`--profile raw64-typed-channels`; their default remains raw24. The same source
artifacts, trusted acquisition checks, signature checks, endpoint policy, and
private/public handoff separation apply to both profiles. Complete and shadow
remain different signed statements. Backend zero-knowledge and worker
confidentiality assumptions are inherited without strengthening them.

The real-address acquisition harness is
`research/scripts/raw64_addresses.py`. The serial measurement harness
is `research/scripts/run_raw64_comparison.py`; it alternates the two
profiles, excludes warmups, and records all repetitions and raw logs. Repetitions
reuse each signed evidence statement for offline performance measurements;
they do not represent multiple acceptances by the one-time online registry.
Both compared binaries must use the same `-C target-cpu=native` setting, as
recommended by Binius64. On AArch64 this enables the SIMD/AES field-arithmetic
implementation instead of the portable fallback. Build the raw24 binary without
`--features raw64` and preserve separate executable copies before comparing.

From this component's directory, prepare the two executable copies before
starting the measurement process:

```sh
mkdir -p zkcfa64/target/raw64-experiment
RUSTFLAGS='-C target-cpu=native' cargo build --release --manifest-path zkcfa64/Cargo.toml
cp zkcfa64/target/release/zkcfa zkcfa64/target/raw64-experiment/zkcfa-raw24
RUSTFLAGS='-C target-cpu=native' cargo build --release --features raw64 --manifest-path zkcfa64/Cargo.toml
cp zkcfa64/target/release/zkcfa zkcfa64/target/raw64-experiment/zkcfa-raw64
```

Run both Rust profiles' tests and provider tests before measuring. The raw64
tests include digest-refreshed wire mutations, so rejection is checked inside
the circuit rather than relying only on the honest witness constructor.

For the 21-application campaign, the measurement plan uses three repetitions
per profile and path mode, except that complete paths with `EP_CAP >= 65536`
(picojpeg and wikisort) use one because of their memory and runtime costs:

```sh
python3 research/scripts/run_raw64_comparison.py \
  --raw24-root build/raw64-addresses/signed/low \
  --raw64-root build/raw64-addresses/signed/wide \
  --raw24-binary zkcfa64/target/raw64-experiment/zkcfa-raw24 \
  --raw64-binary zkcfa64/target/raw64-experiment/zkcfa-raw64 \
  --output build/raw64-addresses/measurements \
  --repeats 3 --large-case-repeats 1 --large-ep-cap 65536
```

Run from this component's directory. On macOS, `/usr/bin/time -l` must be able
to read process resource statistics. `--resume` reuses journaled attempts only
after checking the executable hashes, signed input bindings, and original
logs. It preserves failed attempts and does not silently retry or remove them.
An interrupted, unjournaled log is retained under its original name. A file
named `STOP_AFTER_CASE` in the output directory requests a pause after a paired
case; remove that file before resuming. Do not change the inputs or binaries
within one measurement directory.

The recorded phase times and peak RSS describe this host and concrete circuit.
The large cases have only one sample; none of the timing comparisons is a
statistical-significance claim. Peak RSS is resident memory, not total virtual
allocation, and memory pressure or swapping can affect the large-case times.
The report also retains macOS's separate peak memory footprint metric and the
process duration from `time -l`; the original Python controller duration is
preserved as a distinct metric. See [the results](research/docs/RAW64_ADDRESS_RESULTS.md)
for the resource-limited case and its system-log evidence.
