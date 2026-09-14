//! Feature-gated indexed and weighted LogUp controls on the production relation.

use super::*;

/// Exact per-query table selection for the controlled construction experiment.
///
/// An index is private advice, constrained below the public table capacity. The complete
/// multiplexer tree and equality check prove that every query is an entry of the same
/// digest-bound table. Unlike the collective BinMult alternative, this costs O(Q*M) gates.
/// It introduces no probabilistic membership check or new Fiat--Shamir challenge.
#[cfg(feature = "construction-control")]
pub(super) struct RawIndexedMembership {
    pub(super) indices: Vec<Wire>,
}

#[cfg(feature = "construction-control")]
impl RawIndexedMembership {
    pub(super) fn build(b: &CircuitBuilder, table: &[Wire], queries: &[Wire]) -> Self {
        assert!(table.len().is_power_of_two());
        let bound = b.add_constant_64(table.len() as u64);
        let indices = queries
            .iter()
            .enumerate()
            .map(|(i, &query)| {
                let sb = b.subcircuit(format!("raw/indexed/q[{i}]"));
                let index = sb.add_witness();
                sb.assert_true("index_in_range", sb.icmp_ult(index, bound));
                let selected =
                    binius_circuits::multiplexer::single_wire_multiplex(&sb, table, index);
                sb.assert_eq("typed_membership", query, selected);
                index
            })
            .collect();
        Self { indices }
    }

    pub(super) fn populate(
        &self,
        w: &mut WitnessFiller,
        inst: &RawInstance,
        p: RawParams,
    ) -> Result<()> {
        let table = inst.cfg_table(p);
        let mut first = std::collections::HashMap::new();
        for (j, &key) in table.iter().enumerate() {
            first.entry(key).or_insert(j);
        }
        for (&wire, query) in self
            .indices
            .iter()
            .zip(RawBinMult::host_queries(inst, p, &table))
        {
            let &index = first
                .get(&query)
                .ok_or_else(|| anyhow::anyhow!("indexed membership query {query:#x} is absent"))?;
            w[wire] = Word(index as u64);
        }
        Ok(())
    }
}

/// Weighted binary-field LogUp (Eagen--Haböck, ePrint 2024/2067, Protocol 1).
///
/// The weight of query occurrence i is alpha^i, not its integer multiplicity embedded
/// in characteristic two. Alpha follows the digest-bound source. The complete weighted
/// table column is SHA-256 sealed before beta, preventing post-challenge coefficient
/// selection. Every reciprocal is constrained, including denominators with zero weight.
/// This research gadget does not change the signed production relation.
#[cfg(feature = "construction-control")]
pub(super) struct RawLogUpMembership {
    pub(super) weighted_table: Vec<G>,
}

#[cfg(feature = "construction-control")]
pub(super) const DOM_LG_ALPHA: &[u8; 16] = b"ZKCFA/RAW/LALPH\0";
#[cfg(feature = "construction-control")]
pub(super) const DOM_LG_SEAL: &[u8; 16] = b"ZKCFA/RAW/LSEAL\0";
#[cfg(feature = "construction-control")]
pub(super) const DOM_LG_BETA: &[u8; 16] = b"ZKCFA/RAW/LBETA\0";

/// Batch inversion is witness generation only. Zero inputs receive zero advice;
/// the circuit's denominator * reciprocal = 1 equations then fail closed.
#[cfg(feature = "construction-control")]
pub(super) struct RawLogUpInverseHint;

#[cfg(feature = "construction-control")]
impl Hint for RawLogUpInverseHint {
    const NAME: &'static str = "zkcfa.research.logup.ghash_batch_inverse.v1";

    fn shape(&self, dimensions: &[usize]) -> (usize, usize) {
        assert_eq!(dimensions.len(), 1);
        (2 * dimensions[0], 2 * dimensions[0])
    }

    fn execute(&self, dimensions: &[usize], inputs: &[Word], outputs: &mut [Word]) {
        let n = dimensions[0];
        let values: Vec<Ghash128b> = inputs
            .chunks_exact(2)
            .map(|w| Ghash128b::from(w[0].as_u64() as u128 | ((w[1].as_u64() as u128) << 64)))
            .collect();
        let mut prefixes = Vec::with_capacity(n);
        let mut product = Ghash128b::ONE;
        for &value in &values {
            prefixes.push(product);
            if value != Ghash128b::ZERO {
                product *= value;
            }
        }
        let mut reciprocal = product.invert_or_zero();
        for i in (0..n).rev() {
            let value = values[i];
            let inverse = if value == Ghash128b::ZERO {
                Ghash128b::ZERO
            } else {
                let inverse = reciprocal * prefixes[i];
                reciprocal *= value;
                inverse
            };
            let bits = u128::from(inverse);
            outputs[2 * i] = Word(bits as u64);
            outputs[2 * i + 1] = Word((bits >> 64) as u64);
        }
    }
}

#[cfg(feature = "construction-control")]
impl RawLogUpMembership {
    pub(super) fn hash_words(b: &CircuitBuilder, domain: &[u8; 16], words: &[Wire]) -> [Wire; 4] {
        let mask32 = b.add_constant(Word::MASK_32);
        let mut message = dom_words(b, domain);
        for &word in words {
            message.extend_from_slice(&split_be(b, word, mask32));
        }
        let bytes = message.len() * 4;
        pack4(b, sha256_fixed(b, &message, bytes))
    }

    pub(super) fn challenge(b: &CircuitBuilder, digest: [Wire; 4]) -> G {
        // The same GHASH polynomial-basis convention as BinMult: each SHA-256
        // big-endian 32-bit chunk is a successive little-endian polynomial limb.
        let swap = |word| b.bxor(b.shl(word, 32), b.shr(word, 32));
        G {
            lo: swap(digest[0]),
            hi: swap(digest[1]),
        }
    }

    pub(super) fn source_words(
        b: &CircuitBuilder,
        table_len: usize,
        queries_len: usize,
        ep_digest: [Wire; 4],
        cfg_digest: [Wire; 4],
    ) -> Vec<Wire> {
        let mut words = vec![
            b.add_constant_64(table_len as u64),
            b.add_constant_64(queries_len as u64),
        ];
        words.extend(ep_digest);
        words.extend(cfg_digest);
        words
    }

    pub(super) fn build(
        b: &CircuitBuilder,
        table: &[Wire],
        queries: &[Wire],
        ep_digest: [Wire; 4],
        cfg_digest: [Wire; 4],
    ) -> Self {
        assert!(!table.is_empty() && !queries.is_empty());
        let weighted_table: Vec<G> = table
            .iter()
            .map(|_| G {
                lo: b.add_witness(),
                hi: b.add_witness(),
            })
            .collect();
        let source = Self::source_words(b, table.len(), queries.len(), ep_digest, cfg_digest);
        let alpha = {
            let sb = b.subcircuit("raw/logup/alpha");
            Self::challenge(&sb, Self::hash_words(&sb, DOM_LG_ALPHA, &source))
        };
        let seal = {
            let sb = b.subcircuit("raw/logup/seal");
            let mut words = source[..2].to_vec();
            for value in &weighted_table {
                words.extend([value.lo, value.hi]);
            }
            Self::hash_words(&sb, DOM_LG_SEAL, &words)
        };
        let beta = {
            let sb = b.subcircuit("raw/logup/beta");
            let mut words = source;
            words.extend([alpha.lo, alpha.hi]);
            words.extend(seal);
            Self::challenge(&sb, Self::hash_words(&sb, DOM_LG_BETA, &words))
        };
        Self::check_identity(b, table, queries, &weighted_table, alpha, beta);
        Self { weighted_table }
    }

    /// The rational identity itself. Keeping it separate permits denominator-zero
    /// and adaptive-coefficient tests with explicit challenges, without host validation.
    pub(super) fn check_identity(
        b: &CircuitBuilder,
        table: &[Wire],
        queries: &[Wire],
        weighted_table: &[G],
        alpha: G,
        beta: G,
    ) -> Vec<G> {
        assert_eq!(table.len(), weighted_table.len());
        let zero = b.add_constant_64(0);
        let one = b.add_constant_64(1);
        let denominators: Vec<G> = queries
            .iter()
            .chain(table)
            .map(|&key| G {
                lo: b.bxor(beta.lo, key),
                hi: beta.hi,
            })
            .collect();
        let inputs: Vec<Wire> = denominators
            .iter()
            .flat_map(|den| [den.lo, den.hi])
            .collect();
        let hint = b.call_hint(RawLogUpInverseHint, &[denominators.len()], &inputs);
        let inverses: Vec<G> = hint
            .chunks_exact(2)
            .map(|pair| G {
                lo: pair[0],
                hi: pair[1],
            })
            .collect();
        for (i, (&den, &inverse)) in denominators.iter().zip(&inverses).enumerate() {
            let sb = b.subcircuit(format!("raw/logup/inverse[{i}]"));
            let product = gmul(&sb, den, inverse);
            sb.assert_eq("denominator_nonzero_lo", product.lo, one);
            sb.assert_eq("denominator_nonzero_hi", product.hi, zero);
        }
        let mut lhs = G { lo: zero, hi: zero };
        let mut weight = G { lo: one, hi: zero };
        for (i, &inverse) in inverses[..queries.len()].iter().enumerate() {
            let sb = b.subcircuit(format!("raw/logup/query[{i}]"));
            let term = gmul(&sb, weight, inverse);
            lhs = G {
                lo: sb.bxor(lhs.lo, term.lo),
                hi: sb.bxor(lhs.hi, term.hi),
            };
            if i + 1 < queries.len() {
                weight = gmul(&sb, weight, alpha);
            }
        }
        let mut rhs = G { lo: zero, hi: zero };
        for (j, (&coefficient, &inverse)) in weighted_table
            .iter()
            .zip(&inverses[queries.len()..])
            .enumerate()
        {
            let sb = b.subcircuit(format!("raw/logup/table[{j}]"));
            let term = gmul(&sb, coefficient, inverse);
            rhs = G {
                lo: sb.bxor(rhs.lo, term.lo),
                hi: sb.bxor(rhs.hi, term.hi),
            };
        }
        b.assert_eq("raw/logup/log_derivative_lo", lhs.lo, rhs.lo);
        b.assert_eq("raw/logup/log_derivative_hi", lhs.hi, rhs.hi);
        inverses
    }

    pub(super) fn host_hash(domain: &[u8; 16], words: &[u64]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(domain);
        for word in words {
            hash.update(word.to_be_bytes());
        }
        hash.finalize().into()
    }

    pub(super) fn host_challenge(digest: [u8; 32]) -> Ghash128b {
        let limbs: Vec<u32> = digest[..16]
            .chunks_exact(4)
            .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()))
            .collect();
        Ghash128b::from(limbs.iter().enumerate().fold(0u128, |bits, (i, &limb)| {
            bits | ((limb as u128) << (32 * i))
        }))
    }

    pub(super) fn host_source(
        table_len: usize,
        queries_len: usize,
        values: RawPublicValues,
    ) -> Vec<u64> {
        let mut words = vec![table_len as u64, queries_len as u64];
        words.extend(digest_words(&values.h_ep));
        words.extend(digest_words(&values.h_cfg));
        words
    }

    pub(super) fn coefficients(
        table: &[u64],
        queries: &[u64],
        alpha: Ghash128b,
    ) -> Result<Vec<Ghash128b>> {
        let mut first = std::collections::HashMap::new();
        for (j, &key) in table.iter().enumerate() {
            first.entry(key).or_insert(j);
        }
        let mut coefficients = vec![Ghash128b::ZERO; table.len()];
        let mut weight = Ghash128b::ONE;
        for &query in queries {
            let &j = first
                .get(&query)
                .ok_or_else(|| anyhow::anyhow!("LogUp query {query:#x} is absent"))?;
            coefficients[j] += weight;
            weight *= alpha;
        }
        Ok(coefficients)
    }

    pub(super) fn populate(
        &self,
        w: &mut WitnessFiller,
        inst: &RawInstance,
        p: RawParams,
    ) -> Result<()> {
        let table = inst.cfg_table(p);
        let queries = RawBinMult::host_queries(inst, p, &table);
        let source = Self::host_source(table.len(), queries.len(), inst.public_values(p));
        let alpha = Self::host_challenge(Self::host_hash(DOM_LG_ALPHA, &source));
        for (&wire, coefficient) in self
            .weighted_table
            .iter()
            .zip(Self::coefficients(&table, &queries, alpha)?)
        {
            let bits = u128::from(coefficient);
            w[wire.lo] = Word(bits as u64);
            w[wire.hi] = Word((bits >> 64) as u64);
        }
        Ok(())
    }
}

/// Research-only builder; never used by the signed production protocol.
#[cfg(feature = "construction-control")]
pub(crate) fn build_raw_membership_control(
    params: RawParams,
    membership_kind: RawMembershipKind,
) -> (Circuit, RawCfgWalk) {
    let builder = CircuitBuilder::new();
    let walk = RawCfgWalk::build_with_membership(&builder, params, true, membership_kind);
    (builder.build(), walk)
}
