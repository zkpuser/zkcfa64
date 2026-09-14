//! Raw24 unit and adversarial circuit tests.

use super::*;

#[cfg(test)]
fn constraints_accept(circuit: &Circuit, walk: &RawCfgWalk, inst: &RawInstance) -> bool {
    let mut filler = circuit.new_witness_filler();
    if walk.populate_unchecked(&mut filler, inst).is_err() {
        return false;
    }
    if circuit.populate_wire_witness(&mut filler).is_err() {
        return false;
    }
    circuit
        .constraint_system()
        .verify(&filler.into_value_vec())
        .is_ok()
}

/// Start from a complete honest witness (including a valid BinMult multiplicity column), then
/// replace one digest-bound raw EP word at the wire level.  This reaches the circuit even when
/// the honest multiplicity constructor cannot construct a witness for the forged non-edge.
#[cfg(test)]
fn circuit_rejects_forged_step(
    circuit: &Circuit,
    walk: &RawCfgWalk,
    honest: &RawInstance,
    forged: &RawInstance,
    row: usize,
    refresh_digest: bool,
) -> Result<bool> {
    let mut filler = circuit.new_witness_filler();
    walk.populate_unchecked(&mut filler, honest)?;
    let forged_ep = forged.ep_buf(walk.params);
    filler[walk.steps[row]] = Word(forged_ep[RAW_EP_HEADER_WORDS + row]);
    if refresh_digest {
        let forged_digest = buf_digest(&forged_ep);
        for (i, word) in digest_words(&forged_digest).into_iter().enumerate() {
            filler[walk.ep_digest[i]] = Word(word);
        }
    }
    if circuit.populate_wire_witness(&mut filler).is_err() {
        return Ok(true);
    }
    Ok(circuit
        .constraint_system()
        .verify(&filler.into_value_vec())
        .is_err())
}

const TEST_EP_BLIND: Blinding =
    Blinding::from_words_const(0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210);
const TEST_CFG_BLIND: Blinding =
    Blinding::from_words_const(0x1123_4567_89AB_CDEF, 0xEEDC_BA98_7654_3210);

fn fixture() -> RawInstance {
    RawInstance {
        node_count: 3,
        edges: vec![
            RawEdge {
                src: 0x401000,
                dst: 0x401100,
                etype: 1,
            },
            RawEdge {
                src: 0x401000,
                dst: 0x601060,
                etype: ET_CRT,
            },
        ],
        steps: vec![
            RawStep {
                dst: 0x401000,
                tag: TAG_JMP,
                aux: 0,
                hint: 0,
            },
            RawStep {
                dst: 0x401100,
                tag: TAG_CAL,
                aux: 0x601060,
                hint: 0,
            },
            RawStep {
                dst: 0x601060,
                tag: TAG_RET,
                aux: 0,
                hint: 1,
            },
        ],
        ep_blind: TEST_EP_BLIND,
        cfg_blind: TEST_CFG_BLIND,
    }
}

fn params() -> RawParams {
    RawParams {
        edge_cap: 8,
        ep_cap: 8,
        ep_encoding: RawEpEncoding::InlineHint14,
        path_mode: RawPathMode::CompleteQemu,
    }
}

fn shared_params() -> RawParams {
    RawParams {
        edge_cap: 8,
        ep_cap: 8,
        ep_encoding: RawEpEncoding::SharedPayload24,
        path_mode: RawPathMode::CompleteQemu,
    }
}

/// Exercise the circuit using newly committed EP words and endpoints, rather than
/// relying on rejection by the loader, an old digest, or the host CFA validator.
fn changed_ep_accepts(
    circuit: &Circuit,
    walk: &RawCfgWalk,
    inst: &RawInstance,
    changes: &[(usize, u64)],
) -> bool {
    let mut filler = circuit.new_witness_filler();
    walk.populate_unchecked(&mut filler, inst).unwrap();
    let mut ep = inst.ep_buf(walk.params);
    for &(row, word) in changes {
        ep[RAW_EP_HEADER_WORDS + row] = word;
        filler[walk.steps[row]] = Word(word);
    }
    for (i, word) in digest_words(&buf_digest(&ep)).into_iter().enumerate() {
        filler[walk.ep_digest[i]] = Word(word);
    }
    filler[walk.entry] = Word((ep[RAW_EP_HEADER_WORDS] >> 2) & (RAW_ADDR_LIMIT - 1));
    filler[walk.final_node] =
        Word((ep[RAW_EP_HEADER_WORDS + inst.steps.len() - 1] >> 2) & (RAW_ADDR_LIMIT - 1));
    circuit.populate_wire_witness(&mut filler).is_ok()
        && circuit
            .constraint_system()
            .verify(&filler.into_value_vec())
            .is_ok()
}

#[test]
#[cfg(feature = "construction-control")]
fn indexed_control_rejects_bad_indices_and_nonmembers_without_host_validation() {
    let builder = CircuitBuilder::new();
    let table: Vec<Wire> = (0..8).map(|_| builder.add_witness()).collect();
    let query = builder.add_witness();
    let membership = RawIndexedMembership::build(&builder, &table, &[query]);
    let circuit = builder.build();
    let accepts = |query_value: u64, index: u64| {
        let mut filler = circuit.new_witness_filler();
        for (i, &wire) in table.iter().enumerate() {
            filler[wire] = Word(0x1000 + i as u64);
        }
        filler[query] = Word(query_value);
        filler[membership.indices[0]] = Word(index);
        circuit.populate_wire_witness(&mut filler).is_ok()
            && circuit
                .constraint_system()
                .verify(&filler.into_value_vec())
                .is_ok()
    };
    for index in 0..8 {
        assert!(accepts(0x1000 + index, index));
        assert!(!accepts(0x1000 + index, (index + 1) % 8));
        assert!(!accepts(0x1000 + index, index + 8));
        assert!(!accepts(0x2000, index));
    }
    assert!(!accepts(0x1007, u64::MAX));
}

#[test]
#[cfg(feature = "construction-control")]
fn indexed_control_keeps_fresh_digest_and_return_constraints() {
    for encoding in [RawEpEncoding::InlineHint14, RawEpEncoding::SharedPayload24] {
        for path_mode in [RawPathMode::CompleteQemu, RawPathMode::ShadowSafe] {
            let p = RawParams {
                ep_encoding: encoding,
                path_mode,
                ..params()
            };
            let (circuit, walk) = build_raw_membership_control(p, RawMembershipKind::Indexed);
            let honest = fixture();
            assert!(changed_ep_accepts(&circuit, &walk, &honest, &[]));
            let bad_forward = RawStep {
                dst: 0x401200,
                ..honest.steps[1]
            }
            .word(encoding);
            let bad_crt = RawStep {
                aux: 0x601080,
                ..honest.steps[1]
            }
            .word(encoding);
            // Freshly rehash each malformed EP. No loader, preflight, or host CFA
            // validator is used for these altered records.
            for word in [
                bad_forward,
                bad_crt,
                TAG_RESERVED | (honest.steps[1].dst << 2),
            ] {
                assert!(!changed_ep_accepts(&circuit, &walk, &honest, &[(1, word)]));
            }
            for bad_return in [
                RawStep {
                    dst: 0x601080,
                    ..honest.steps[2]
                },
                RawStep {
                    hint: 0,
                    ..honest.steps[2]
                },
            ] {
                assert!(!changed_ep_accepts(
                    &circuit,
                    &walk,
                    &honest,
                    &[(2, bad_return.word(encoding))]
                ));
            }
            // A stale digest must not authenticate a changed transfer either.
            let mut forged = honest.clone();
            forged.steps[1].dst = 0x401200;
            assert!(
                circuit_rejects_forged_step(&circuit, &walk, &honest, &forged, 1, false).unwrap()
            );
        }
    }
}

#[cfg(feature = "construction-control")]
mod logup_tests {
    use super::*;

    struct Harness {
        circuit: Circuit,
        membership: RawLogUpMembership,
        table: Vec<Wire>,
        queries: Vec<Wire>,
        ep_digest: [Wire; 4],
        cfg_digest: [Wire; 4],
    }

    impl Harness {
        fn new(table_len: usize, queries_len: usize) -> Self {
            let builder = CircuitBuilder::new();
            let table: Vec<Wire> = (0..table_len).map(|_| builder.add_witness()).collect();
            let queries: Vec<Wire> = (0..queries_len).map(|_| builder.add_witness()).collect();
            let ep_digest = core::array::from_fn(|_| builder.add_inout());
            let cfg_digest = core::array::from_fn(|_| builder.add_inout());
            let mask32 = builder.add_constant(Word::MASK_32);
            bind_raw_digest(&builder, "test-queries", &queries, ep_digest, mask32);
            bind_raw_digest(&builder, "test-table", &table, cfg_digest, mask32);
            let membership =
                RawLogUpMembership::build(&builder, &table, &queries, ep_digest, cfg_digest);
            Self {
                circuit: builder.build(),
                membership,
                table,
                queries,
                ep_digest,
                cfg_digest,
            }
        }

        fn source(table: &[u64], queries: &[u64]) -> Vec<u64> {
            RawLogUpMembership::host_source(
                table.len(),
                queries.len(),
                RawPublicValues {
                    h_ep: buf_digest(queries),
                    h_cfg: buf_digest(table),
                    entry: 0,
                    final_node: 0,
                },
            )
        }

        fn alpha(table: &[u64], queries: &[u64]) -> Ghash128b {
            RawLogUpMembership::host_challenge(RawLogUpMembership::host_hash(
                DOM_LG_ALPHA,
                &Self::source(table, queries),
            ))
        }

        fn beta(table: &[u64], queries: &[u64], coefficients: &[Ghash128b]) -> Ghash128b {
            let mut source = Self::source(table, queries);
            let alpha = u128::from(Self::alpha(table, queries));
            let mut sealed = source[..2].to_vec();
            for &coefficient in coefficients {
                let bits = u128::from(coefficient);
                sealed.extend([bits as u64, (bits >> 64) as u64]);
            }
            source.extend([alpha as u64, (alpha >> 64) as u64]);
            source.extend(digest_words(&RawLogUpMembership::host_hash(
                DOM_LG_SEAL,
                &sealed,
            )));
            RawLogUpMembership::host_challenge(RawLogUpMembership::host_hash(DOM_LG_BETA, &source))
        }

        fn filler(
            &self,
            table: &[u64],
            queries: &[u64],
            coefficients: &[Ghash128b],
        ) -> WitnessFiller<'_> {
            let mut filler = self.circuit.new_witness_filler();
            for (&wire, &value) in self.table.iter().zip(table) {
                filler[wire] = Word(value);
            }
            for (&wire, &value) in self.queries.iter().zip(queries) {
                filler[wire] = Word(value);
            }
            for (&wire, value) in self
                .ep_digest
                .iter()
                .zip(digest_words(&buf_digest(queries)))
            {
                filler[wire] = Word(value);
            }
            for (&wire, value) in self.cfg_digest.iter().zip(digest_words(&buf_digest(table))) {
                filler[wire] = Word(value);
            }
            for (&wire, &coefficient) in self.membership.weighted_table.iter().zip(coefficients) {
                let bits = u128::from(coefficient);
                filler[wire.lo] = Word(bits as u64);
                filler[wire.hi] = Word((bits >> 64) as u64);
            }
            filler
        }

        fn accepts(&self, table: &[u64], queries: &[u64], coefficients: &[Ghash128b]) -> bool {
            let mut filler = self.filler(table, queries, coefficients);
            self.circuit.populate_wire_witness(&mut filler).is_ok()
                && self
                    .circuit
                    .constraint_system()
                    .verify(&filler.into_value_vec())
                    .is_ok()
        }
    }

    #[test]
    fn logup_preserves_even_multiplicities_and_rejects_off_table_queries() {
        let harness = Harness::new(4, 8);
        // Duplicate table entries are safe; honest advice uses the first occurrence.
        let table = [0x1000, 0x2000, 0x2000, 0x3000];
        let honest = [
            0x1000, 0x1000, 0x2000, 0x2000, 0x2000, 0x2000, 0x3000, 0x3000,
        ];
        let alpha = Harness::alpha(&table, &honest);
        let coefficients = RawLogUpMembership::coefficients(&table, &honest, alpha).unwrap();
        assert!(harness.accepts(&table, &honest, &coefficients));
        assert_ne!(
            coefficients[0],
            Ghash128b::ZERO,
            "two equal queries must not disappear"
        );
        for bad_count in [2, 4, 8] {
            let mut queries = honest;
            queries[..bad_count].fill(0x4000);
            let alpha = Harness::alpha(&table, &queries);
            let mut forged = vec![Ghash128b::ZERO; table.len()];
            let mut weight = Ghash128b::ONE;
            for &query in &queries {
                if let Some(j) = table.iter().position(|&key| key == query) {
                    forged[j] += weight;
                }
                weight *= alpha;
            }
            // The invalid values reach the actual circuit; no host loader or CFA
            // validator rejects them before this assertion.
            assert!(
                !harness.accepts(&table, &queries, &forged),
                "accepted {bad_count} equal off-table queries"
            );
        }
        let mut forged = coefficients;
        forged[1] += Ghash128b::ONE;
        assert!(!harness.accepts(&table, &honest, &forged));
    }

    #[test]
    fn logup_seal_blocks_post_challenge_weighted_column_choice() {
        let harness = Harness::new(2, 4);
        let table = [11, 12];
        let queries = [99, 99, 99, 99];
        let alpha = Harness::alpha(&table, &queries);
        let beta_old = Harness::beta(&table, &queries, &[Ghash128b::ZERO; 2]);
        let mut sum = Ghash128b::ZERO;
        let mut weight = Ghash128b::ONE;
        for &query in &queries {
            sum += weight * (beta_old + Ghash128b::from(query as u128)).invert_or_zero();
            weight *= alpha;
        }
        // An unsealed lookup can always be forged by selecting one coefficient
        // after beta, even for four repeated invalid queries.
        let forged = [
            (beta_old + Ghash128b::from(table[0] as u128)) * sum,
            Ghash128b::ZERO,
        ];
        assert_eq!(
            sum,
            forged[0] * (beta_old + Ghash128b::from(table[0] as u128)).invert_or_zero()
        );
        let unsealed_builder = CircuitBuilder::new();
        let constant = |value: Ghash128b| {
            let bits = u128::from(value);
            G {
                lo: unsealed_builder.add_constant_64(bits as u64),
                hi: unsealed_builder.add_constant_64((bits >> 64) as u64),
            }
        };
        RawLogUpMembership::check_identity(
            &unsealed_builder,
            &table.map(|key| unsealed_builder.add_constant_64(key)),
            &queries.map(|key| unsealed_builder.add_constant_64(key)),
            &forged.map(constant),
            constant(alpha),
            constant(beta_old),
        );
        let unsealed = unsealed_builder.build();
        let mut unsealed_filler = unsealed.new_witness_filler();
        unsealed
            .populate_wire_witness(&mut unsealed_filler)
            .unwrap();
        assert!(
            unsealed
                .constraint_system()
                .verify(unsealed_filler.value_vec())
                .is_ok()
        );
        let beta_new = Harness::beta(&table, &queries, &forged);
        assert_ne!(beta_new, beta_old);
        assert!(!harness.accepts(&table, &queries, &forged));
    }

    #[test]
    fn logup_rejects_zero_denominators_and_forged_inverse_advice() {
        let builder = CircuitBuilder::new();
        let query = builder.add_witness();
        let coefficient = G {
            lo: builder.add_witness(),
            hi: builder.add_witness(),
        };
        let zero = builder.add_constant_64(0);
        let alpha = G {
            lo: builder.add_constant_64(2),
            hi: zero,
        };
        let beta = G {
            lo: builder.add_witness(),
            hi: builder.add_witness(),
        };
        let inverses = RawLogUpMembership::check_identity(
            &builder,
            &[query],
            &[query],
            &[coefficient],
            alpha,
            beta,
        );
        let circuit = builder.build();
        for (beta_lo, beta_hi, should_accept) in [(13, 1, true), (17, 0, false)] {
            let mut filler = circuit.new_witness_filler();
            filler[query] = Word(17);
            filler[coefficient.lo] = Word(1);
            filler[coefficient.hi] = Word(0);
            filler[beta.lo] = Word(beta_lo);
            filler[beta.hi] = Word(beta_hi);
            let populated = circuit.populate_wire_witness(&mut filler).is_ok();
            let accepted = populated
                && circuit
                    .constraint_system()
                    .verify(filler.value_vec())
                    .is_ok();
            assert_eq!(accepted, should_accept);
            if should_accept {
                // Mutate the actual constrained inverse after hint execution.
                let old = filler[inverses[0].lo].as_u64();
                filler[inverses[0].lo] = Word(old ^ 1);
                assert!(
                    circuit
                        .constraint_system()
                        .verify(filler.value_vec())
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn logup_preserves_fresh_commitments_and_exact_return_checks() {
        fn accepts_with_nonmember_weights_omitted(
            circuit: &Circuit,
            walk: &RawCfgWalk,
            instance: &RawInstance,
        ) -> bool {
            let mut filler = circuit.new_witness_filler();
            // Continue past the advice constructor's nonmembership error after it
            // fills record and digest wires; forge only the advice in this test.
            if let Err(error) = walk.populate_unchecked(&mut filler, instance) {
                assert!(error.to_string().starts_with("LogUp query "));
            }
            let table = instance.cfg_table(walk.params);
            let queries = RawBinMult::host_queries(instance, walk.params, &table);
            let source = RawLogUpMembership::host_source(
                table.len(),
                queries.len(),
                instance.public_values(walk.params),
            );
            let alpha = RawLogUpMembership::host_challenge(RawLogUpMembership::host_hash(
                DOM_LG_ALPHA,
                &source,
            ));
            let mut coefficients = vec![Ghash128b::ZERO; table.len()];
            let mut weight = Ghash128b::ONE;
            for query in queries {
                if let Some(j) = table.iter().position(|&key| key == query) {
                    coefficients[j] += weight;
                }
                weight *= alpha;
            }
            let RawMembership::LogUp(membership) = &walk.membership else {
                panic!("expected LogUp relation")
            };
            for (&wire, value) in membership.weighted_table.iter().zip(coefficients) {
                let bits = u128::from(value);
                filler[wire.lo] = Word(bits as u64);
                filler[wire.hi] = Word((bits >> 64) as u64);
            }
            circuit.populate_wire_witness(&mut filler).is_ok()
                && circuit
                    .constraint_system()
                    .verify(filler.value_vec())
                    .is_ok()
        }
        let honest = fixture();
        for encoding in [RawEpEncoding::InlineHint14, RawEpEncoding::SharedPayload24] {
            for path_mode in [RawPathMode::CompleteQemu, RawPathMode::ShadowSafe] {
                let p = RawParams {
                    ep_encoding: encoding,
                    path_mode,
                    ..params()
                };
                let (circuit, walk) = build_raw_membership_control(p, RawMembershipKind::LogUp);
                assert!(constraints_accept(&circuit, &walk, &honest));
                assert!(accepts_with_nonmember_weights_omitted(
                    &circuit, &walk, &honest
                ));
                for step in [
                    RawStep {
                        dst: 0x401200,
                        ..honest.steps[1]
                    },
                    RawStep {
                        aux: 0x601080,
                        ..honest.steps[1]
                    },
                    RawStep {
                        tag: TAG_RESERVED,
                        aux: 0,
                        hint: 0,
                        ..honest.steps[1]
                    },
                ] {
                    let mut invalid = honest.clone();
                    invalid.steps[1] = step;
                    assert!(!accepts_with_nonmember_weights_omitted(
                        &circuit, &walk, &invalid
                    ));
                }
                let builder = CircuitBuilder::new();
                let no_stack_walk =
                    RawCfgWalk::build_with_membership(&builder, p, false, RawMembershipKind::LogUp);
                let no_stack = builder.build();
                let mut wrong_return = honest.clone();
                wrong_return.steps[2].dst = 0x601080;
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
                for invalid in [wrong_return, wrong_hint, unmatched_call, underflow] {
                    // Populate from the invalid EP itself: alpha and weighted-table
                    // advice are fresh and honest for its still-valid memberships.
                    assert!(constraints_accept(&no_stack, &no_stack_walk, &invalid));
                    assert!(!constraints_accept(&circuit, &walk, &invalid));
                }
                let mut filler = circuit.new_witness_filler();
                walk.populate_unchecked(&mut filler, &honest).unwrap();
                filler[walk.steps[1]] = Word(
                    RawStep {
                        dst: 0x401200,
                        ..honest.steps[1]
                    }
                    .word(encoding),
                );
                assert!(
                    circuit.populate_wire_witness(&mut filler).is_err()
                        || circuit
                            .constraint_system()
                            .verify(&filler.into_value_vec())
                            .is_err()
                );
            }
        }
    }
}

#[test]
fn device_signed_nonmembers_and_discontinuities_fail_raw_constraints() {
    for encoding in [RawEpEncoding::InlineHint14, RawEpEncoding::SharedPayload24] {
        for path_mode in [RawPathMode::CompleteQemu, RawPathMode::ShadowSafe] {
            let p = RawParams {
                ep_encoding: encoding,
                path_mode,
                ..params()
            };
            let builder = CircuitBuilder::new();
            let walk = RawCfgWalk::build_with_shadow(&builder, p, false);
            let circuit = builder.build();
            let inst = fixture();
            assert!(changed_ep_accepts(&circuit, &walk, &inst, &[]));
            let bad_forward = RawStep {
                dst: 0x401200,
                ..inst.steps[1]
            }
            .word(encoding);
            let bad_crt = RawStep {
                aux: 0x601080,
                ..inst.steps[1]
            }
            .word(encoding);
            // Tag 3 carries an authenticated acquisition discontinuity. It must never
            // satisfy the CFA relation, including when its source payload is absent.
            for word in [
                bad_forward,
                bad_crt,
                TAG_RESERVED | (inst.steps[1].dst << 2),
                TAG_RESERVED | (inst.steps[1].dst << 2) | (inst.steps[0].dst << RAW_EDGE_SHIFT),
            ] {
                assert!(
                    !changed_ep_accepts(&circuit, &walk, &inst, &[(1, word)]),
                    "invalid signed EP word {word:#x} accepted by {encoding:?}/{path_mode:?}"
                );
            }
        }
    }
}

#[test]
fn device_signed_stack_violations_fail_raw_constraints_with_valid_membership() {
    let honest = fixture();
    let mut wrong_return = honest.clone();
    wrong_return.steps[2].dst = 0x601080;
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
    // A subsequent call restores final depth to zero. The intermediate underflow
    // must still be rejected, even with a valid forward edge and CRT declaration.
    let mut balanced_underflow = underflow.clone();
    balanced_underflow.steps.push(honest.steps[1]);
    balanced_underflow.edges.extend([
        RawEdge {
            src: honest.steps[2].dst,
            dst: honest.steps[1].dst,
            etype: ET_CAL,
        },
        RawEdge {
            src: honest.steps[2].dst,
            dst: honest.steps[1].aux,
            etype: ET_CRT,
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
    for encoding in [RawEpEncoding::InlineHint14, RawEpEncoding::SharedPayload24] {
        for path_mode in [RawPathMode::CompleteQemu, RawPathMode::ShadowSafe] {
            let p = RawParams {
                ep_encoding: encoding,
                path_mode,
                ..params()
            };
            let builder = CircuitBuilder::new();
            let without_walk = RawCfgWalk::build_with_shadow(&builder, p, false);
            let without = builder.build();
            let (with, with_walk) = build_raw_circuit(p);
            assert!(changed_ep_accepts(&with, &with_walk, &honest, &[]));
            for (name, invalid) in &cases {
                assert!(
                    changed_ep_accepts(&without, &without_walk, invalid, &[]),
                    "{name} must have honest membership advice and fresh digest/endpoints"
                );
                assert!(
                    !changed_ep_accepts(&with, &with_walk, invalid, &[]),
                    "{name} accepted by {encoding:?}/{path_mode:?}"
                );
            }
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

/// Replace one EP word and refresh H_ep while retaining the rest of an honest witness. This
/// bypasses the canonical host encoder so tests can reach malformed bit patterns directly.
fn circuit_rejects_raw_word(
    p: RawParams,
    inst: &RawInstance,
    row: usize,
    word: u64,
) -> Result<bool> {
    let (circuit, walk) = build_raw_circuit(p);
    let mut filler = circuit.new_witness_filler();
    walk.populate_unchecked(&mut filler, inst)?;
    let mut ep_buf = inst.ep_buf(p);
    ep_buf[RAW_EP_HEADER_WORDS + row] = word;
    filler[walk.steps[row]] = Word(word);
    let digest = buf_digest(&ep_buf);
    for (i, value) in digest_words(&digest).into_iter().enumerate() {
        filler[walk.ep_digest[i]] = Word(value);
    }
    if circuit.populate_wire_witness(&mut filler).is_err() {
        return Ok(true);
    }
    Ok(circuit
        .constraint_system()
        .verify(&filler.into_value_vec())
        .is_err())
}

#[test]
fn raw_low_50_bits_preserve_the_full_edge_tuple() {
    let step = RawStep {
        dst: 0x401100,
        tag: TAG_CAL,
        aux: 0x601060,
        hint: 0,
    };
    let expected = TAG_CAL | (0x401100 << 2) | (0x601060 << 26);
    assert_eq!(step.word(RawEpEncoding::InlineHint14), expected);
}

#[test]
#[should_panic(expected = "raw step destination is not canonical")]
fn raw_encoder_rejects_bit_24_instead_of_aliasing_aux() {
    let _ = RawStep {
        dst: 0x0100_0005,
        tag: TAG_CAL,
        aux: 0,
        hint: 0,
    }
    .word(RawEpEncoding::InlineHint14);
}

#[test]
fn shared_payload_reuses_mutually_exclusive_fields_without_truncation() {
    let ret = RawStep {
        dst: 0x401100,
        tag: TAG_RET,
        aux: 0,
        hint: 125_801,
    };
    let word = ret.word(RawEpEncoding::SharedPayload24);
    assert_eq!(
        word,
        TAG_RET | (0x401100 << 2) | (125_801u64 << RAW_EDGE_SHIFT)
    );
    assert_eq!(
        word >> RAW_HINT_SHIFT,
        0,
        "shared encoding high reserved bits must be zero"
    );
    assert_eq!((word >> RAW_EDGE_SHIFT) & (RAW_ADDR_LIMIT - 1), 125_801);
    assert_eq!(
        RawEpEncoding::for_ep_cap(1 << 14).unwrap(),
        RawEpEncoding::InlineHint14
    );
    assert_eq!(
        RawEpEncoding::for_ep_cap(1 << 17).unwrap(),
        RawEpEncoding::SharedPayload24
    );
    assert!(RawEpEncoding::for_ep_cap((1 << 24) + 1).is_err());
}

#[test]
fn wikisort_capacity_has_a_worst_case_safe_multiplicity_width() {
    let p = RawParams {
        edge_cap: 512,
        ep_cap: 131_072,
        ep_encoding: RawEpEncoding::for_ep_cap(131_072).unwrap(),
        path_mode: RawPathMode::CompleteQemu,
    };
    let max_query_count = 2 * (p.ep_cap - 1);
    assert_eq!(p.mult_bits(), 18);
    assert!(max_query_count < (1usize << p.mult_bits()));
    assert!(max_query_count >= (1usize << (p.mult_bits() - 1)));
}

#[test]
fn ep_encoding_and_multiplicity_are_derived_at_the_inline_boundary() {
    let inline = RawParams {
        edge_cap: 8,
        ep_cap: 1 << 14,
        ep_encoding: RawEpEncoding::for_ep_cap(1 << 14).unwrap(),
        path_mode: RawPathMode::CompleteQemu,
    };
    assert_eq!(inline.ep_encoding, RawEpEncoding::InlineHint14);
    assert_eq!(inline.mult_bits(), 12);

    let shared = RawParams {
        ep_cap: 1 << 15,
        ep_encoding: RawEpEncoding::for_ep_cap(1 << 15).unwrap(),
        ..inline
    };
    assert_eq!(shared.ep_encoding, RawEpEncoding::SharedPayload24);
    assert_eq!(shared.mult_bits(), 16);
}

#[test]
fn inline_buffer_binds_complete_path_mode() {
    let inst = fixture();
    let buf = inst.ep_buf(params());
    assert_eq!(buf[0], MAGIC_RAW_EP_INLINE);
    assert_eq!(buf[6], 0);
    assert_eq!(
        buf[RAW_EP_PATH_MODE],
        RawPathMode::CompleteQemu.header_word()
    );
    assert_eq!(
        buf[RAW_EP_HEADER_WORDS + 2],
        TAG_RET | (0x601060 << 2) | (1 << RAW_HINT_SHIFT)
    );
    assert_eq!(params().mult_bits(), INLINE_MULT_BITS);
}

#[test]
fn path_mode_is_domain_separated_inside_h_ep() {
    let inst = fixture();
    let complete = params();
    let projected = RawParams {
        path_mode: RawPathMode::ShadowSafe,
        ..complete
    };
    assert_ne!(
        buf_digest(&inst.ep_buf(complete)),
        buf_digest(&inst.ep_buf(projected))
    );
    assert_eq!(
        buf_digest(&inst.cfg_buf(complete)),
        buf_digest(&inst.cfg_buf(projected)),
        "path semantics belong to H_ep and must not perturb the static CFG commitment"
    );
}

#[test]
fn semantic_path_mode_labels_and_domains_are_stable() {
    assert_eq!(
        RawPathMode::from_signed_label("complete").unwrap(),
        RawPathMode::CompleteQemu
    );
    assert_eq!(
        RawPathMode::from_signed_label("shadow").unwrap(),
        RawPathMode::ShadowSafe
    );
    assert!(RawPathMode::from_signed_label("compressed").is_err());
    assert_eq!(
        RawPathMode::CompleteQemu.header_word(),
        u64::from_be_bytes(*b"COMPLETE")
    );
    assert_eq!(
        RawPathMode::ShadowSafe.header_word(),
        u64::from_be_bytes(*b"SHADOWED")
    );
}

#[test]
fn cfg_header_carries_the_private_opening() {
    let inst = fixture();
    let p = params();
    let buf = inst.cfg_buf(p);
    assert_eq!(buf.len(), RAW_CFG_HEADER_WORDS + p.edge_cap);
    assert_eq!(buf[0], MAGIC_RAW_CFG);
    assert_eq!(buf[1], p.edge_cap as u64);
    assert_eq!(buf[2], inst.edges.len() as u64);
    assert_eq!(buf[3], RAW_ADDR_BITS as u64);
    assert_eq!(&buf[4..8], &[0; 4]);
    assert_eq!(
        [buf[RAW_CFG_BLIND_LO], buf[RAW_CFG_BLIND_HI]],
        TEST_CFG_BLIND.words()
    );
    assert_eq!(buf[RAW_CFG_HEADER_WORDS], inst.edges[0].key());
}

#[test]
fn raw_artifact_openings_move_only_their_own_commitments() {
    let p = params();
    let original = fixture();
    let original_ep = buf_digest(&original.ep_buf(p));
    let original_cfg = buf_digest(&original.cfg_buf(p));

    let mut fresh_ep = original.clone();
    fresh_ep.ep_blind = Blinding::from_words_const(0x3131, 0x4141);
    assert_ne!(buf_digest(&fresh_ep.ep_buf(p)), original_ep);
    assert_eq!(buf_digest(&fresh_ep.cfg_buf(p)), original_cfg);

    let mut fresh_cfg = original;
    fresh_cfg.cfg_blind = Blinding::from_words_const(0x5151, 0x6161);
    assert_eq!(buf_digest(&fresh_cfg.ep_buf(p)), original_ep);
    assert_ne!(buf_digest(&fresh_cfg.cfg_buf(p)), original_cfg);
}

#[test]
fn raw_host_validation_rejects_reused_artifact_openings() {
    let mut inst = fixture();
    inst.cfg_blind = inst.ep_blind;
    let err = inst.validate(params()).unwrap_err().to_string();
    assert!(err.contains("reuse the same blinding value"), "{err}");
}

#[test]
fn reserved_tag_is_rejected_by_host_and_circuit() {
    let mut forged = fixture();
    forged.steps[0].tag = TAG_RESERVED;
    let error = forged.validate(params()).unwrap_err().to_string();
    assert!(error.contains("reserved padding tag"), "{error}");

    let honest = fixture();
    let malformed = RawStep {
        tag: TAG_RESERVED,
        ..honest.steps[0]
    }
    .word(RawEpEncoding::InlineHint14);
    assert!(circuit_rejects_raw_word(params(), &honest, 0, malformed).unwrap());
}

#[test]
fn signed_capacities_may_be_preselected_but_cannot_be_too_small() {
    let raw = fixture();
    let fitted = RawParams {
        edge_cap: 8,
        ep_cap: 16,
        ep_encoding: RawEpEncoding::InlineHint14,
        path_mode: RawPathMode::CompleteQemu,
    };
    validate_capacity_bounds(&raw, fitted).unwrap();
    validate_capacity_bounds(
        &raw,
        RawParams {
            edge_cap: 16,
            ep_cap: 32,
            ..fitted
        },
    )
    .unwrap();
    let error = validate_capacity_bounds(
        &raw,
        RawParams {
            edge_cap: 2,
            ..fitted
        },
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("EDGE_CAP=2"), "{error}");
    let error = validate_capacity_bounds(
        &raw,
        RawParams {
            ep_cap: 2,
            ..fitted
        },
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("EP_CAP=2"), "{error}");
}

#[test]
fn changed_ep_opening_does_not_match_signed_h_ep() {
    let p = params();
    let baseline = fixture();
    let signed_digest = buf_digest(&baseline.ep_buf(p));
    let mut fresh = baseline;
    fresh.ep_blind = Blinding::from_words_const(0x6262, 0x7272);
    assert_ne!(signed_digest, buf_digest(&fresh.ep_buf(p)));

    let (circuit, walk) = build_raw_circuit(p);
    let mut filler = circuit.new_witness_filler();
    walk.populate_unchecked(&mut filler, &fresh).unwrap();
    for (i, word) in digest_words(&signed_digest).into_iter().enumerate() {
        filler[walk.ep_digest[i]] = Word(word);
    }
    let accepted = circuit.populate_wire_witness(&mut filler).is_ok()
        && circuit
            .constraint_system()
            .verify(&filler.into_value_vec())
            .is_ok();
    assert!(
        !accepted,
        "a changed raw EP opening matched the signed H_ep"
    );
}

#[test]
fn changed_cfg_opening_does_not_match_signed_h_cfg() {
    let p = params();
    let baseline = fixture();
    let signed_digest = buf_digest(&baseline.cfg_buf(p));
    let mut fresh = baseline;
    fresh.cfg_blind = Blinding::from_words_const(0x7171, 0x8181);
    assert_ne!(signed_digest, buf_digest(&fresh.cfg_buf(p)));

    let (circuit, walk) = build_raw_circuit(p);
    let mut filler = circuit.new_witness_filler();
    walk.populate_unchecked(&mut filler, &fresh).unwrap();
    for (i, word) in digest_words(&signed_digest).into_iter().enumerate() {
        filler[walk.cfg_digest[i]] = Word(word);
    }
    let accepted = circuit.populate_wire_witness(&mut filler).is_ok()
        && circuit
            .constraint_system()
            .verify(&filler.into_value_vec())
            .is_ok();
    assert!(
        !accepted,
        "a changed raw CFG opening matched the signed H_cfg"
    );
}

#[test]
fn raw_openings_are_private_and_public_abi_stays_ten_words() {
    let inst = fixture();
    let (circuit, walk) = build_raw_circuit(params());
    assert_eq!(circuit.constraint_system().n_inout, RAW_N_PUBLIC);
    assert_eq!(RAW_N_PUBLIC, 10);
    let mut filler = circuit.new_witness_filler();
    walk.populate_unchecked(&mut filler, &inst).unwrap();
    circuit.populate_wire_witness(&mut filler).unwrap();
    let public: Vec<u64> = filler
        .into_value_vec()
        .public()
        .iter()
        .map(|word| word.0)
        .collect();
    for opening_word in inst
        .ep_blind
        .words()
        .into_iter()
        .chain(inst.cfg_blind.words())
    {
        assert!(
            !public.contains(&opening_word),
            "raw opening reached the public segment"
        );
    }
}

#[test]
fn verifier_rebuilds_the_entire_public_segment() {
    let inst = fixture();
    let p = params();
    let (circuit, walk) = build_raw_circuit(p);
    let mut filler = circuit.new_witness_filler();
    walk.populate(&mut filler, &inst).unwrap();
    circuit.populate_wire_witness(&mut filler).unwrap();
    let witness_public = filler.into_value_vec().public().to_vec();
    let cs = circuit.constraint_system();
    let rebuilt = canonical_public_words(cs, inst.public_values(p)).unwrap();

    assert_eq!(rebuilt, witness_public);
    assert_eq!(&rebuilt[..cs.n_const()], &cs.constants);
    assert!(
        rebuilt[cs.n_const()..cs.offset_inout()]
            .iter()
            .all(|word| *word == Word::ZERO)
    );
    assert!(
        rebuilt[cs.offset_inout() + cs.n_inout..]
            .iter()
            .all(|word| *word == Word::ZERO)
    );
}

#[test]
fn verifier_statement_is_exactly_ten_inout_words_even_with_many_constants() {
    let inst = fixture();
    let p = params();
    let (circuit, walk) = build_raw_circuit(p);
    let mut filler = circuit.new_witness_filler();
    walk.populate(&mut filler, &inst).unwrap();
    circuit.populate_wire_witness(&mut filler).unwrap();
    let witness = filler.into_value_vec();
    let cs = circuit.constraint_system();
    let inout = canonical_inout_words(inst.public_values(p));

    assert!(cs.n_const() > RAW_N_PUBLIC);
    assert_eq!(cs.n_inout, RAW_N_PUBLIC);
    assert_eq!(inout.len(), RAW_N_PUBLIC);
    assert_eq!(inout.as_slice(), witness.inout());
    assert!(witness.public().len() > inout.len());
}

#[test]
fn shared_payload_is_constrained_by_the_exact_shadow_stack() {
    let inst = fixture();
    inst.validate(shared_params()).unwrap();
    let (circuit, walk) = build_raw_circuit(shared_params());
    assert!(constraints_accept(&circuit, &walk, &inst));
    let mut forged = inst.clone();
    forged.steps[2].hint = 0;
    assert!(circuit_rejects_forged_step(&circuit, &walk, &inst, &forged, 2, true).unwrap());
}

#[test]
fn shared_payload_rejects_nonzero_reserved_high_bits() {
    let inst = fixture();
    let honest = inst.steps[2].word(RawEpEncoding::SharedPayload24);
    assert!(circuit_rejects_raw_word(shared_params(), &inst, 2, honest | (1 << 63)).unwrap());
}

#[test]
fn shared_payload_rejects_payload_on_jmp_and_reserved_tag() {
    let inst = fixture();
    for tag in [TAG_JMP, TAG_RESERVED] {
        let malformed = tag | (inst.steps[0].dst << 2) | (7 << RAW_EDGE_SHIFT);
        assert!(
            circuit_rejects_raw_word(shared_params(), &inst, 0, malformed).unwrap(),
            "tag {tag} accepted a nonzero shared payload"
        );
    }
}

#[test]
fn shared_payload_rejects_forward_return_hint() {
    let inst = fixture();
    let forward = RawStep {
        hint: 2,
        ..inst.steps[2]
    }
    .word(RawEpEncoding::SharedPayload24);
    assert!(circuit_rejects_raw_word(shared_params(), &inst, 2, forward).unwrap());
}

#[test]
fn honest_raw_relation_satisfies_constraints() {
    let inst = fixture();
    inst.validate(params()).unwrap();
    let (circuit, walk) = build_raw_circuit(params());
    assert!(constraints_accept(&circuit, &walk, &inst));
}

#[test]
fn same_low_16_address_is_not_aliased() {
    let inst = fixture();
    let (circuit, walk) = build_raw_circuit(params());
    let mut forged = inst;
    forged.steps[1].dst = 0x601100;
    assert_ne!(0x401100, 0x601100);
    assert_eq!(0x401100u64 & 0xFFFF, 0x601100u64 & 0xFFFF);
    assert!(circuit_rejects_forged_step(&circuit, &walk, &fixture(), &forged, 1, true).unwrap());
}

#[test]
fn wrong_return_hint_is_rejected_by_the_raw_shadow_argument() {
    let inst = fixture();
    let (circuit, walk) = build_raw_circuit(params());
    let mut forged = inst;
    forged.steps[2].hint = 0;
    assert!(circuit_rejects_forged_step(&circuit, &walk, &fixture(), &forged, 2, true).unwrap());
}

#[test]
fn cal_to_jmp_is_rejected_by_typed_membership_without_shadow() {
    let inst = fixture();
    let builder = CircuitBuilder::new();
    let walk = RawCfgWalk::build_with_shadow(&builder, params(), false);
    let circuit = builder.build();
    let mut forged = inst;
    forged.steps[1].tag = TAG_JMP;
    forged.steps[1].aux = 0;
    assert!(circuit_rejects_forged_step(&circuit, &walk, &fixture(), &forged, 1, true).unwrap());
}

#[test]
fn raw_24_profile_fails_closed_on_scope_sentinel() {
    let mut inst = fixture();
    inst.steps[0].dst = 0xFFFF_0000;
    assert!(inst.validate(params()).is_err());
}

#[test]
fn provider_symbol_tokens_are_injective_and_disjoint() {
    let mut tokens = HashSet::new();
    for id in 0..0xFFFFu64 {
        let external = format!("{:#x}", PROVIDER_GATEWAY_BASE + id);
        let token = parse_raw_addr_token(&external).unwrap();
        assert_eq!(token, RAW_GATEWAY_BASE + id);
        assert!(tokens.insert(token));
    }
    let scope = parse_raw_addr_token("SCOPE_RETURN").unwrap();
    assert_eq!(scope, RAW_SCOPE_SENTINEL);
    assert!(tokens.insert(scope));
    assert_eq!(tokens.len(), 0x1_0000);
    assert_eq!(
        parse_raw_addr_token("0xfffefffe").unwrap(),
        RAW_SCOPE_SENTINEL - 1
    );
    assert!(parse_raw_addr_token("0xfffeffff").is_err());
    assert!(parse_raw_addr_token("0").is_err());
    assert!(parse_raw_addr_token("401000").is_err());
    assert!(parse_raw_addr_token("0X401000").is_err());
    assert!(parse_raw_addr_token("0xABCDEF").is_err());
    assert!(parse_raw_addr_token("0xff0000").is_err());
    assert!(parse_raw_addr_token("0xffffff").is_err());
}

#[test]
fn typed_bundle_uses_static_registry_and_needs_no_ret_table_rows() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("zkcfa-raw-typed-{}-{unique}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(
        dir.join("translator"),
        "SCOPE_RETURN\n0x401000\n0x401010\n0xfffe0000\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("typed_cfg"),
        concat!(
            "SCOPE_RETURN cal 0x401000\n",
            "SCOPE_RETURN crt SCOPE_RETURN\n",
            "0x401000 cal 0xfffe0000\n",
            "0x401000 crt 0x401010\n",
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("recorded_path"),
        concat!(
            "initial_node=SCOPE_RETURN final_node=SCOPE_RETURN\n",
            "call 0x401000 SCOPE_RETURN\n",
            "call 0xfffe0000 0x401010\n",
            "ret 0x401010\n",
            "ret SCOPE_RETURN\n",
        ),
    )
    .unwrap();

    let inst = RawInstance::from_typed_bundle_with_openings(
        dir.to_str().unwrap(),
        TEST_EP_BLIND,
        TEST_CFG_BLIND,
    )
    .unwrap();
    let canonical_cfg = std::fs::read_to_string(dir.join("typed_cfg")).unwrap();
    std::fs::write(
        dir.join("typed_cfg"),
        canonical_cfg.replacen('\n', "\n\n", 1),
    )
    .unwrap();
    let err = RawInstance::from_typed_bundle_with_openings(
        dir.to_str().unwrap(),
        TEST_EP_BLIND,
        TEST_CFG_BLIND,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("typed_cfg line 2"), "{err}");

    std::fs::write(dir.join("typed_cfg"), canonical_cfg.replace(' ', "\u{a0}")).unwrap();
    let err = RawInstance::from_typed_bundle_with_openings(
        dir.to_str().unwrap(),
        TEST_EP_BLIND,
        TEST_CFG_BLIND,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("typed_cfg must be ASCII"), "{err}");

    std::fs::write(dir.join("typed_cfg"), "SCOPE_RETURN ret 0x401000\n").unwrap();
    let err = RawInstance::from_typed_bundle_with_openings(
        dir.to_str().unwrap(),
        TEST_EP_BLIND,
        TEST_CFG_BLIND,
    )
    .unwrap_err()
    .to_string();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(err.contains("contains RET"), "{err}");
    assert_eq!(inst.node_count, 4);
    assert_eq!(inst.edges.len(), 4);
    assert!(
        inst.edges
            .iter()
            .all(|edge| edge.etype != crate::raw_format::ET_RET)
    );
    inst.validate(params()).unwrap();
    let (circuit, walk) = build_raw_circuit(params());
    assert!(constraints_accept(&circuit, &walk, &inst));
}
