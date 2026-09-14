# Raw24 relation

The release relation proves that a committed execution path is a typed walk in a
committed CFG, has authorized call-return sites, satisfies exact LIFO returns, and
starts and ends at the public raw endpoints. It uses raw 24-bit addresses directly.

## CFG encoding

Each real edge is one 50-bit key:

```text
src[24] | type[2] | dst[24]
```

The canonical table is sorted and padded to the signed `EDGE_CAP`, a power of two
at least eight and no smaller than the real edge count. Evaluation runs normally
choose the smallest fitting capacity, while production enrollment may reserve a
larger table. Padding keys set bit 63 and include their table index, so they are
outside the real-key space and pairwise distinct. BinMult proves all forward-edge
and call-return-site queries against this table.

The committed CFG buffer is:

```text
CFG-FLAT | EDGE_CAP | real_edges | 24 | 0 | 0 | 0 | 0 |
cfg_blind_low | cfg_blind_high | EDGE_CAP keys
```

The two final header words are a confidential, nonzero 128-bit opening. They are
independent of the execution-path opening.

## Execution-path encoding

Every row contains a 2-bit operation tag and a 24-bit destination. `inline14` is
canonical when `EP_CAP <= 2^14`; it additionally carries a 24-bit CAL return
address and a 14-bit matching-CAL row on RET. `shared24` is canonical for larger
capacities and reuses the mutually exclusive CAL/RET payload as either the raw
return address or the 24-bit matching-CAL row.

The EP header is ten words. Its first word is `EPINLINE` or `EPSHARED`; words four
and five hold the private opening; word seven is `COMPLETE` or `SHADOWED`. Thus
path semantics are part of `H_ep` and cannot be changed after signing.

## Public ABI

The circuit exposes exactly ten 64-bit words:

```text
H_ep[4] | H_cfg[4] | entry_raw | final_raw
```

`H_ep` and `H_cfg` are SHA-256 digests of the canonical big-endian word buffers.
The verifier combines those signed values and endpoints with its own compiled
constants and zero padding to reconstruct the full Binius public segment; it
does not accept that segment from the prover. The openings, ordinary artifact
hashes, trace rows, and CFG edges remain private.

## Path statements

For `complete`, the device attests that its local evidence describes a complete,
code-matched root-scope QEMU path. For `shadow`, the device additionally validates
a stack-safe projection against the complete source path. Those evidence records
remain device-local; the proof bundle carries the signed decision and the path
opening, not device-local evidence files.

The stack-safe projection is explicitly lossy: it preserves the exact shadow stack
but does not preserve loop multiplicity, data flow, memory effects, outputs, or
transitions removed before proving. This weaker statement is selected in the
signed circuit object and domain-separated inside `H_ep`.

The raw namespace reserves zero, maps the provider's finite external-gateway
range injectively into `0xff0000..0xfffffe`, and maps `SCOPE_RETURN` to `0xffffff`.
Numeric inputs may not name the reserved suffix directly.
