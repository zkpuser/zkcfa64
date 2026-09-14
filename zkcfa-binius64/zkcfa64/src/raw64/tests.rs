//! Full-width relation unit and adversarial circuit tests.

use super::*;

const TEST_EP_BLIND: Blinding =
    Blinding::from_words_const(0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210);
const TEST_CFG_BLIND: Blinding =
    Blinding::from_words_const(0x1123_4567_89AB_CDEF, 0xEEDC_BA98_7654_3210);
const ENTRY: u64 = 0x8000_0000_0040_1000;
const CALLEE: u64 = 0x4000_0000_0040_1100;
const RETURN: u64 = 0xF000_0000_0060_1060;

fn params() -> RawParams {
    RawParams {
        edge_cap: 8,
        ep_cap: 8,
        ep_encoding: RawEpEncoding::Wide64,
        path_mode: RawPathMode::CompleteQemu,
    }
}

fn fixture() -> RawInstance {
    RawInstance {
        node_count: 3,
        edges: vec![
            RawEdge {
                src: ENTRY,
                etype: ET_CAL,
                dst: CALLEE,
            },
            RawEdge {
                src: ENTRY,
                etype: ET_CRT,
                dst: RETURN,
            },
        ],
        steps: vec![
            RawStep {
                tag: TAG_JMP,
                dst: ENTRY,
                aux: 0,
                hint: 0,
            },
            RawStep {
                tag: TAG_CAL,
                dst: CALLEE,
                aux: RETURN,
                hint: 0,
            },
            RawStep {
                tag: TAG_RET,
                dst: RETURN,
                aux: 0,
                hint: 1,
            },
        ],
        ep_blind: TEST_EP_BLIND,
        cfg_blind: TEST_CFG_BLIND,
    }
}

fn nested_fixture() -> RawInstance {
    let mut inst = fixture();
    let inner = 0x6000_0000_0040_1200;
    let inner_return = 0xD000_0000_0060_1070;
    inst.edges.extend([
        RawEdge {
            src: CALLEE,
            etype: ET_CAL,
            dst: inner,
        },
        RawEdge {
            src: CALLEE,
            etype: ET_CRT,
            dst: inner_return,
        },
    ]);
    inst.edges.sort_unstable_by_key(|edge| edge.key());
    inst.steps = vec![
        inst.steps[0],
        inst.steps[1],
        RawStep {
            tag: TAG_CAL,
            dst: inner,
            aux: inner_return,
            hint: 0,
        },
        RawStep {
            tag: TAG_RET,
            dst: inner_return,
            aux: 0,
            hint: 2,
        },
        RawStep {
            tag: TAG_RET,
            dst: RETURN,
            aux: 0,
            hint: 1,
        },
    ];
    inst.node_count = 5;
    inst
}

fn build_with_shadow(p: RawParams, shadow: bool) -> (Circuit, RawCfgWalk) {
    let builder = CircuitBuilder::new();
    let walk = RawCfgWalk::build_with_shadow(&builder, p, shadow);
    (builder.build(), walk)
}

fn accepts(circuit: &Circuit, mut filler: WitnessFiller) -> bool {
    circuit.populate_wire_witness(&mut filler).is_ok()
        && circuit
            .constraint_system()
            .verify(&filler.into_value_vec())
            .is_ok()
}

/// Mutate witness cells after constructing honest multiplicities, then refresh
/// signed digest inputs and endpoints. No forged instance passes host validation
/// or the honest query constructor: failures therefore originate in the circuit.
fn altered_witness_accepts(
    circuit: &Circuit,
    walk: &RawCfgWalk,
    inst: &RawInstance,
    ep_changes: &[(usize, usize, u64)],
    cfg_changes: &[(usize, usize, u64)],
) -> bool {
    let mut filler = circuit.new_witness_filler();
    walk.populate_unchecked(&mut filler, inst).unwrap();
    let mut ep = inst.ep_buf(walk.params);
    let mut cfg = inst.cfg_buf(walk.params);
    for &(row, part, value) in ep_changes {
        ep[RAW_EP_HEADER_WORDS + RAW_ROW_WORDS * row + part] = value;
        filler[walk.steps[row][part]] = Word(value);
    }
    for &(row, part, value) in cfg_changes {
        cfg[RAW_CFG_HEADER_WORDS + RAW_ROW_WORDS * row + part] = value;
        filler[walk.table[row][part]] = Word(value);
    }
    for (i, value) in digest_words(&buf_digest(&ep)).into_iter().enumerate() {
        filler[walk.ep_digest[i]] = Word(value);
    }
    for (i, value) in digest_words(&buf_digest(&cfg)).into_iter().enumerate() {
        filler[walk.cfg_digest[i]] = Word(value);
    }
    // Remove endpoint mismatch as an accidental explanation for rejection.
    filler[walk.entry] = Word(ep[RAW_EP_HEADER_WORDS + 1]);
    filler[walk.final_node] =
        Word(ep[RAW_EP_HEADER_WORDS + RAW_ROW_WORDS * (inst.steps.len() - 1) + 1]);
    accepts(circuit, filler)
}

#[test]
fn device_signed_nonmembers_and_discontinuities_fail_raw64_constraints() {
    for path_mode in [RawPathMode::CompleteQemu, RawPathMode::ShadowSafe] {
        let p = RawParams {
            path_mode,
            ..params()
        };
        let (circuit, walk) = build_with_shadow(p, false);
        let inst = fixture();
        assert!(altered_witness_accepts(&circuit, &walk, &inst, &[], &[]));
        for changes in [
            vec![(1, 1, CALLEE ^ (1 << 40))],
            vec![(1, 2, RETURN ^ (1 << 56))],
            // An acquisition discontinuity is committed as tag 3 with observed
            // destination and source. Both zero and nonzero payloads must fail.
            vec![(1, 0, 3), (1, 1, CALLEE), (1, 2, 0)],
            vec![(1, 0, 3), (1, 1, CALLEE), (1, 2, ENTRY)],
        ] {
            assert!(
                !altered_witness_accepts(&circuit, &walk, &inst, &changes, &[]),
                "invalid signed EP accepted by raw64/{path_mode:?}: {changes:x?}"
            );
        }
    }
}

#[test]
fn device_signed_stack_violations_fail_raw64_constraints_with_valid_membership() {
    let honest = fixture();
    let mut wrong_return = honest.clone();
    wrong_return.steps[2].dst = RETURN ^ (1 << 56);
    let mut wrong_hint = honest.clone();
    wrong_hint.steps[2].hint = 0;
    let mut unmatched_call = honest.clone();
    unmatched_call.steps.truncate(2);
    let mut underflow = honest.clone();
    underflow.steps = vec![
        honest.steps[0],
        RawStep {
            hint: 0,
            ..honest.steps[2]
        },
    ];
    let mut balanced_underflow = underflow.clone();
    balanced_underflow.steps.push(honest.steps[1]);
    balanced_underflow.edges.extend([
        RawEdge {
            src: RETURN,
            etype: ET_CAL,
            dst: CALLEE,
        },
        RawEdge {
            src: RETURN,
            etype: ET_CRT,
            dst: RETURN,
        },
    ]);
    balanced_underflow
        .edges
        .sort_unstable_by_key(|edge| edge.key());
    let cases = [
        ("wrong return", wrong_return),
        ("wrong timestamp", wrong_hint),
        ("unmatched call", unmatched_call),
        ("empty-stack return", underflow),
        ("balanced underflow", balanced_underflow),
    ];
    for path_mode in [RawPathMode::CompleteQemu, RawPathMode::ShadowSafe] {
        let p = RawParams {
            path_mode,
            ..params()
        };
        let (without, without_walk) = build_with_shadow(p, false);
        let (with, with_walk) = build_raw_circuit(p);
        assert!(altered_witness_accepts(
            &with,
            &with_walk,
            &honest,
            &[],
            &[]
        ));
        for (name, invalid) in &cases {
            assert!(
                altered_witness_accepts(&without, &without_walk, invalid, &[], &[]),
                "{name} must have honest membership advice and fresh digest/endpoints"
            );
            assert!(
                !altered_witness_accepts(&with, &with_walk, invalid, &[], &[]),
                "{name} accepted by raw64/{path_mode:?}"
            );
        }
    }
}

#[test]
#[ignore = "cryptographic roundtrip; run explicitly with --ignored"]
fn device_evidence_honest_cryptographic_proof_roundtrip() {
    use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
    use binius_transcript::{ProverTranscript, VerifierTranscript};
    use binius_verifier::{config::StdChallenger, hash::StdHashSuite, zk_config::ZKVerifier};

    for path_mode in [RawPathMode::CompleteQemu, RawPathMode::ShadowSafe] {
        let p = RawParams {
            ep_cap: 16,
            path_mode,
            ..params()
        };
        let inst = fixture();
        let (circuit, walk) = build_raw_circuit(p);
        let mut filler = circuit.new_witness_filler();
        walk.populate(&mut filler, &inst).unwrap();
        circuit.populate_wire_witness(&mut filler).unwrap();
        let witness = filler.into_value_vec();
        circuit.constraint_system().verify(&witness).unwrap();
        let verifier =
            ZKVerifier::<StdHashSuite>::setup(circuit.constraint_system().clone(), 1).unwrap();
        let prover = ZKProver::<OptimalPackedB128, StdHashSuite>::setup(&verifier).unwrap();
        let mut transcript = ProverTranscript::new(StdChallenger::default());
        prover
            .prove(&witness, rand::rng(), &mut transcript)
            .unwrap();
        let proof = transcript.finalize();
        assert!(!proof.is_empty());
        let inout = canonical_inout_words(inst.public_values(p));
        let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof.clone());
        verifier.verify(&inout, &mut transcript).unwrap();
        transcript.finalize().unwrap();

        let mut altered_inout = inout;
        altered_inout[RAW_OFF_EP_DIGEST] = Word(altered_inout[RAW_OFF_EP_DIGEST].0 ^ 1);
        let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof);
        assert!(verifier.verify(&altered_inout, &mut transcript).is_err());
    }
}

#[test]
fn raw64_buffers_preserve_all_address_bits_and_canonical_padding() {
    let inst = fixture();
    let p = params();
    assert_eq!(inst.edges[0].key(), [ENTRY, ET_CAL, CALLEE]);
    assert_eq!(
        inst.steps[1].words(p.ep_encoding),
        [TAG_CAL, CALLEE, RETURN]
    );
    assert_eq!(inst.steps[2].words(p.ep_encoding), [TAG_RET, RETURN, 1]);
    let cfg = inst.cfg_buf(p);
    let ep = inst.ep_buf(p);
    assert_eq!(cfg.len(), 10 + 3 * p.edge_cap);
    assert_eq!(ep.len(), 10 + 3 * p.ep_cap);
    assert_eq!(cfg[0], u64::from_be_bytes(*b"CFG-W64V"));
    assert_eq!(ep[0], u64::from_be_bytes(*b"EP-W64V1"));
    assert_eq!(cfg[3], 64);
    assert_eq!(ep[3], 64);
    assert_eq!(ep[6], 24);
    assert_eq!(&cfg[16..19], &[0, 0, 3]);
    assert_eq!(&ep[19..], &[0; 15]);
}

#[test]
fn raw64_provider_golden_digests_match_rust_typed_bundle_and_circuit() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "zkcfa-raw64-golden-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
        dir.join("translator"),
        concat!("SCOPE_RETURN\n0x555555554000\n0x555555554008\n0x555555554004\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("typed_cfg"),
        concat!(
            "SCOPE_RETURN cal 0x555555554000\n",
            "SCOPE_RETURN crt SCOPE_RETURN\n",
            "0x555555554000 cal 0x555555554008\n",
            "0x555555554000 crt 0x555555554004\n",
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("recorded_path"),
        concat!(
            "initial_node=SCOPE_RETURN final_node=SCOPE_RETURN\n",
            "call 0x555555554000 SCOPE_RETURN\n",
            "call 0x555555554008 0x555555554004\n",
            "ret 0x555555554004\n",
            "ret SCOPE_RETURN\n",
        ),
    )
    .unwrap();
    let result = RawInstance::from_typed_bundle_with_openings(
        dir.to_str().unwrap(),
        Blinding::from_words_const(3, 4),
        Blinding::from_words_const(1, 2),
    );
    std::fs::remove_dir_all(&dir).unwrap();
    let inst = result.unwrap();
    let p = RawParams {
        ep_cap: 16,
        ..params()
    };
    inst.validate(p).unwrap();
    let values = inst.public_values(p);
    assert_eq!(
        hex::encode(values.h_cfg),
        "90f834f0b364ee65a66e72c3c811f262ea5d9c8c7a1a48d44870f2b6eaf2c0c3"
    );
    assert_eq!(
        hex::encode(values.h_ep),
        "0f8568daa0d4f4d3fc76a53075626aded6a806f28ef4850b5310778039ea42b8"
    );
    let (circuit, walk) = build_raw_circuit(p);
    assert!(altered_witness_accepts(&circuit, &walk, &inst, &[], &[]));
}

#[test]
fn raw64_namespace_keeps_high_addresses_and_reserves_explicit_tokens() {
    assert_eq!(parse_raw_addr_token("0x8000000000401000").unwrap(), ENTRY);
    assert!(parse_raw_addr_token("0xffffffffffff0000").is_err());
    assert!(parse_raw_addr_token("0xffffffffffffffff").is_err());
    assert!(parse_raw_addr_token("0x0").is_err());
    assert_eq!(parse_raw_addr_token("SCOPE_RETURN").unwrap(), u64::MAX);
    assert_eq!(
        parse_raw_addr_token("0xfffe0000").unwrap(),
        RAW_GATEWAY_BASE
    );
    assert_eq!(parse_raw_addr_token("0xfffefffe").unwrap(), u64::MAX - 1);
    assert_eq!(
        parse_raw_addr_token("0x1000000401000").unwrap(),
        0x1000000401000
    );
    assert_ne!(parse_raw_addr_token("0x1000000401000").unwrap(), ENTRY);
}

#[test]
fn raw64_hint_capacity_and_multiplicity_policy_are_independent_of_addresses() {
    let mut p = params();
    assert_eq!(p.ep_encoding.label(), "wide64");
    p.ep_cap = 1 << 14;
    assert_eq!(p.mult_bits(), 12);
    p.ep_cap = 1 << 15;
    assert_eq!(p.mult_bits(), 16);
    p.ep_cap = 1 << 17;
    assert_eq!(p.mult_bits(), 18);
    assert!(RawEpEncoding::for_ep_cap(1 << 24).is_ok());
    assert!(RawEpEncoding::for_ep_cap((1 << 24) + 1).is_err());
}

#[test]
fn raw64_honest_high_bit_circuit_and_ten_word_public_abi() {
    let inst = fixture();
    let p = params();
    inst.validate(p).unwrap();
    let (circuit, walk) = build_raw_circuit(p);
    assert_eq!(circuit.constraint_system().n_inout, 10);
    let mut filler = circuit.new_witness_filler();
    walk.populate(&mut filler, &inst).unwrap();
    circuit.populate_wire_witness(&mut filler).unwrap();
    let values = filler.into_value_vec();
    circuit.constraint_system().verify(&values).unwrap();
    assert_eq!(
        canonical_inout_words(inst.public_values(p)).as_slice(),
        values.inout()
    );
    assert_eq!(
        canonical_public_words(circuit.constraint_system(), inst.public_values(p)).unwrap(),
        values.public()
    );
}

#[test]
fn raw64_synthetic_56_bit_and_upper_half_addresses_satisfy_constraints() {
    // These are synthetic circuit witnesses, not claims of QEMU execution
    // with a 57-bit userspace configuration or kernel attestation.
    let (circuit, walk) = build_raw_circuit(params());
    for prefix in [0x00FF_0000_0000_0000, 0xFFFF_8000_0000_0000] {
        let mut inst = fixture();
        let replace = |address: u64| prefix | (address & 0xFF_FFFF);
        for edge in &mut inst.edges {
            edge.src = replace(edge.src);
            edge.dst = replace(edge.dst);
        }
        for step in &mut inst.steps {
            step.dst = replace(step.dst);
            if step.tag == TAG_CAL {
                step.aux = replace(step.aux);
            }
        }
        inst.validate(params()).unwrap();
        assert!(
            altered_witness_accepts(&circuit, &walk, &inst, &[], &[]),
            "synthetic full-width prefix {prefix:#x} was truncated or rejected"
        );
    }
}

#[test]
fn raw64_high_address_aliases_fail_typed_membership_without_shadow() {
    let inst = fixture();
    let (circuit, walk) = build_with_shadow(params(), false);
    assert!(altered_witness_accepts(&circuit, &walk, &inst, &[], &[]));
    // Same low 24 bits, distinct high bits: test src, dst and CRT return site
    // independently. Bit63 is tested as well as a bit above the old width.
    for (row, part, original, bit) in [(0, 1, ENTRY, 63), (1, 1, CALLEE, 40), (1, 2, RETURN, 63)] {
        let alias = original ^ (1 << bit);
        assert_eq!(alias & 0xFF_FFFF, original & 0xFF_FFFF);
        assert_ne!(alias, original);
        assert!(
            !altered_witness_accepts(&circuit, &walk, &inst, &[(row, part, alias)], &[]),
            "high-bit alias accepted at {row}/{part}"
        );
    }
}

#[test]
fn raw64_type_changes_fail_even_with_the_same_complete_address_pair() {
    let inst = fixture();
    let (circuit, walk) = build_with_shadow(params(), false);
    assert!(!altered_witness_accepts(
        &circuit,
        &walk,
        &inst,
        &[(1, 0, TAG_JMP), (1, 2, 0)],
        &[]
    ));
    // Unsupported types must not silently vanish from all three GP channels.
    assert!(!altered_witness_accepts(
        &circuit,
        &walk,
        &inst,
        &[],
        &[(0, 1, 2)]
    ));
    assert!(!altered_witness_accepts(
        &circuit,
        &walk,
        &inst,
        &[(1, 0, 1 << 32)],
        &[]
    ));
}

#[test]
fn raw64_shadow_rejects_full_width_return_alias_and_wrong_timestamp() {
    let inst = fixture();
    let (circuit, walk) = build_raw_circuit(params());
    assert!(!altered_witness_accepts(
        &circuit,
        &walk,
        &inst,
        &[(2, 1, RETURN ^ (1 << 56))],
        &[]
    ));
    assert!(!altered_witness_accepts(
        &circuit,
        &walk,
        &inst,
        &[(2, 2, 0)],
        &[]
    ));
    assert!(!altered_witness_accepts(
        &circuit,
        &walk,
        &inst,
        &[(2, 2, 2)],
        &[]
    ));
    assert!(!altered_witness_accepts(
        &circuit,
        &walk,
        &inst,
        &[(2, 2, 1 << 24)],
        &[]
    ));
}

#[test]
fn raw64_nested_return_swap_is_rejected_only_when_exact_stack_is_enabled() {
    let inst = nested_fixture();
    inst.validate(params()).unwrap();
    let changes = [
        (3, 1, inst.steps[4].dst),
        (3, 2, inst.steps[4].hint as u64),
        (4, 1, inst.steps[3].dst),
        (4, 2, inst.steps[3].hint as u64),
    ];
    let (without, walk_without) = build_with_shadow(params(), false);
    assert!(
        altered_witness_accepts(&without, &walk_without, &inst, &changes, &[]),
        "forward-edge membership should allow this counterexample by itself"
    );
    let (with, walk_with) = build_raw_circuit(params());
    assert!(altered_witness_accepts(&with, &walk_with, &inst, &[], &[]));
    assert!(!altered_witness_accepts(
        &with,
        &walk_with,
        &inst,
        &changes,
        &[]
    ));
}

#[test]
fn raw64_padding_and_inactive_rows_are_constrained_after_digest_refresh() {
    let inst = fixture();
    let (circuit, walk) = build_raw_circuit(params());
    // Padding is used neutrally in both products. Changing both neutral uses
    // does not create a membership mismatch; canonical padding must reject it.
    for (part, value) in [(0, ENTRY), (1, ET_CAL), (2, 99)] {
        assert!(!altered_witness_accepts(
            &circuit,
            &walk,
            &inst,
            &[],
            &[(7, part, value)]
        ));
    }
    for part in 0..RAW_ROW_WORDS {
        assert!(!altered_witness_accepts(
            &circuit,
            &walk,
            &inst,
            &[(7, part, 1)],
            &[]
        ));
    }
    assert!(
        !altered_witness_accepts(&circuit, &walk, &inst, &[(0, 2, 1)], &[]),
        "JMP payload must be zero"
    );
    assert!(
        !altered_witness_accepts(&circuit, &walk, &inst, &[(0, 1, 0)], &[]),
        "active address zero must be rejected"
    );
}

#[test]
fn raw64_path_modes_and_independent_openings_remain_digest_bound() {
    let inst = fixture();
    let p = params();
    let projected = RawParams {
        path_mode: RawPathMode::ShadowSafe,
        ..p
    };
    assert_ne!(
        buf_digest(&inst.ep_buf(p)),
        buf_digest(&inst.ep_buf(projected))
    );
    assert_eq!(
        buf_digest(&inst.cfg_buf(p)),
        buf_digest(&inst.cfg_buf(projected))
    );
    let mut fresh = inst.clone();
    fresh.ep_blind = Blinding::from_words_const(7, 11);
    assert_ne!(buf_digest(&inst.ep_buf(p)), buf_digest(&fresh.ep_buf(p)));
    assert_eq!(buf_digest(&inst.cfg_buf(p)), buf_digest(&fresh.cfg_buf(p)));
    let (circuit, walk) = build_raw_circuit(p);
    let mut filler = circuit.new_witness_filler();
    walk.populate_unchecked(&mut filler, &fresh).unwrap();
    for (i, value) in digest_words(&buf_digest(&inst.ep_buf(p)))
        .into_iter()
        .enumerate()
    {
        filler[walk.ep_digest[i]] = Word(value);
    }
    assert!(!accepts(&circuit, filler));
}
