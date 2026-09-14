# Security boundary

The public verifier trusts one pinned Ed25519 authority key. The signed registry
binds the blinded `H_cfg_raw24`, the full proof-shaping circuit configuration,
the executable measurement, allowed endpoint pairs, authorized device keys, and
the QEMU scope policy. The signed device report directly binds both
`H_cfg_raw24` and `H_ep_raw24`, the registry/configuration identities, measured
binary, actual endpoints, scope-policy digest, and fresh challenge and nonce.

The authority registry, the authority-signed confidential enrollment opening,
and the device report use distinct NUL-terminated signature domains. Registry,
circuit, scope, and key identifiers also use distinct hash domains. Signed JSON
is canonical, ASCII-only, compact JSON with sorted keys.

`public/` contains only `registry.json` and `report.json`. The authority public
key is never copied into the bundle: a verifier must obtain it from an external
trust store and pin the SHA-256 of that PEM. Otherwise a bundle could bootstrap
its own trust anchor. `private/worker.json` contains only statement identities
and the independent CFG/EP openings. The worker loads `translator`, `typed_cfg`,
and `recorded_path` from fixed paths. `H_cfg_raw24` commits to the canonical
typed-edge table and `H_ep_raw24` commits to the canonical path rows; `translator`
is the static CFG parsing namespace. Recorded EP destinations and continuations
may lie outside that namespace: otherwise off-CFG behavior could not be signed.
At device-signing time its exact file hash must match the static manifest whose
hash is bound by the authority-signed confidential enrollment opening. Neither
proof commitment nor the later exported worker bundle binds otherwise unused
translator rows. Consequently, adding an unused translator node does not change
the proof relation, while changing a committed edge or path row changes its
commitment. Publishing the worker data would expose
confidential openings.

All key, evidence, and bundle inputs must be regular non-symlink files. Private
keys and worker data must not be group- or world-accessible. Outputs are created
without overwrite and bundles are renamed into place atomically. Public files
are mode `0644` below a `0755` directory; private files are mode `0600` below a
`0700` directory.

Before constructing a device statement, the signer reads every mutable static,
trace, evidence, and projection input exactly once into a private read-only
snapshot. Statement construction and evidence regeneration use only that
snapshot, so one pathname cannot supply different bytes to the commitment and
the evidence check.

The default statement covers every normalized QEMU row. The optional shadow
statement is lossy: it removes repeated copies with matching preceding addresses
and mechanically recorded stack states while preserving policy violations.
It does not preserve loop multiplicity. Its circuit path mode and signed scope
policy make that distinction explicit.

Normalization records actual raw targets without testing direct/indirect target
allowlists, CFG/CRT membership, or return matching. It never rounds a transfer
into a basic-block leader. Unexpected nonbranch/REP/stop successors are retained
as `discontinuity dst src` records, committed using reserved EP tag 3, which the
proof relation rejects. No such marker can be erased by projection. Unknown code
or an incomplete root/external-call capture still fails acquisition: the current
trace format cannot authenticate an interval outside its measured scope.

Return hints record the latest observed call row without comparing the return
destination. Underflow uses hint zero and leaves the actual return in the EP.
The projector likewise performs mechanical push/pop bookkeeping; it does not
check return targets. Distinct underflow states prevent erasing these events.
Removing repeated copies requires matching stack and predecessor-address states;
the initial copy is retained separately if its incoming state differs.

QEMU trace evidence, and the optional projection/source-evidence reports, remain
inside the device's audit directory. The device recomputes and validates them
before signing `H_ep_raw24`, the actual endpoints, runtime-code match, boundary
success, scope digest, and the circuit path mode. Neither the worker nor the
public verifier trusts or consumes device-local evidence files. Regeneration
checks evidence fidelity, not control-flow compliance. A signed report can contain
off-CFG transfers or invalid returns. `verify_report(...)["accepted"]` means only
authenticity and freshness; control-flow acceptance also requires the proof.

Worker-side `load_raw_statement` checks membership, CRT, returns, stack balance
and concrete multiplicity limits before proving. These are convenience checks
for an honest worker. The proof circuit independently rejects violations even
if preflight is bypassed. `load_raw_evidence`, used by the device signer, performs
only canonical serialization, capacity and commitment-parameter checks.

The confidential enrollment retains one artifact digest:
`static_manifest_sha256` makes the device use the exact authority-provisioned
static policy. That manifest itself binds the executable, translator, typed CFG,
plugin map, runtime dependencies, and external/indirect-call policy. Publishing
this digest would create a policy-enumeration oracle, so it stays between the
authority and device. Device-local complete evidence retains hashes of the
selected `recorded_path` and `typed_cfg`; the shadow projection additionally
hashes its full/compressed paths, translator, typed CFG, and source evidence.
Those values make the device's regeneration check refer to one exact local input
set, but they are neither signed public fields nor worker inputs. Public
`binary_measurement`, `h_cfg_raw24`, `h_ep_raw24`, registry/config IDs, and the
scope digest are statement bindings rather than device-local artifact hashes.

The optional SQLite registry persists issuance and atomically consumes challenges
across ordinary service restarts. Its database is trusted state and does not
protect against an administrator rolling storage back. The default in-memory
registry rejects old reports as unknown after restart. Production issuance must
protect issued/expired/consumed state and durable storage transactionally;
an offline verifier cannot by itself provide replay protection.
