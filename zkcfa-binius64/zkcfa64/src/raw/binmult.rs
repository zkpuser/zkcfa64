//! Production sealed binary-multiplicity membership.

use super::*;

pub(super) struct RawBinMult {
    pub(super) mpack: Vec<Wire>,
    pub(super) n_tab: usize,
}

impl RawBinMult {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn query_wires(
        b: &CircuitBuilder,
        p: RawParams,
        table: &[Wire],
        dsts: &[Wire],
        etypes: &[Wire],
        auxs: &[Wire],
        is_cals: &[Wire],
        is_rets: &[Wire],
        inactive: &[Wire],
    ) -> Vec<Wire> {
        let mut queries = Vec::with_capacity(2 * (p.ep_cap - 1));
        for t in 1..p.ep_cap {
            let sb = b.subcircuit(format!("raw/bm/q[{t}]"));
            let neutral0 = table[(2 * (t - 1)) % p.edge_cap];
            let neutral1 = table[(2 * (t - 1) + 1) % p.edge_cap];
            let edge = sb.bxor_multi(&[
                sb.shl(dsts[t - 1], RAW_EDGE_SHIFT),
                sb.shl(etypes[t], RAW_ADDR_BITS),
                dsts[t],
            ]);
            let skip_edge_membership = sb.bor(inactive[t], is_rets[t]);
            queries.push(sb.select(skip_edge_membership, neutral0, edge));
            let call_site = sb.bxor_multi(&[
                sb.shl(dsts[t - 1], RAW_EDGE_SHIFT),
                sb.add_constant_64(ET_CRT << RAW_ADDR_BITS),
                auxs[t],
            ]);
            queries.push(sb.select(is_cals[t], call_site, neutral1));
        }
        queries
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn build(
        b: &CircuitBuilder,
        p: RawParams,
        table: &[Wire],
        dsts: &[Wire],
        etypes: &[Wire],
        auxs: &[Wire],
        is_cals: &[Wire],
        is_rets: &[Wire],
        inactive: &[Wire],
        ep_digest: [Wire; 4],
        cfg_digest: [Wire; 4],
    ) -> Self {
        let mask32 = b.add_constant(Word::MASK_32);
        let zero = b.add_constant_64(0);
        let one_g = G {
            lo: b.add_constant_64(1),
            hi: zero,
        };
        let n_tab = p.edge_cap;
        let queries =
            Self::query_wires(b, p, table, dsts, etypes, auxs, is_cals, is_rets, inactive);

        let mult_bits = p.mult_bits();
        let seal_words = (n_tab * mult_bits).div_ceil(64);
        let mpack: Vec<Wire> = (0..seal_words).map(|_| b.add_witness()).collect();
        let used_tail_bits = (n_tab * mult_bits) % 64;
        if used_tail_bits != 0 {
            let unused_mask = !((1u64 << used_tail_bits) - 1);
            let sb = b.subcircuit("raw/bm/canonical-tail");
            let mask = sb.add_constant_64(unused_mask);
            sb.assert_zero(
                "unused_multiplicity_bits",
                sb.band(*mpack.last().expect("non-empty multiplicity seal"), mask),
            );
        }
        let mdig = {
            let sb = b.subcircuit("raw/bm/seal");
            let mut msg = dom_words(&sb, DOM_M);
            for &word in &mpack {
                msg.extend_from_slice(&split_be(&sb, word, mask32));
            }
            let len = msg.len() * 4;
            pack4(&sb, sha256_fixed(&sb, &msg, len))
        };

        let h = {
            let sb = b.subcircuit("raw/bm/challenge");
            let mut msg = dom_words(&sb, DOM_BM_CH);
            for digest in [ep_digest, cfg_digest, mdig] {
                for &word in &digest {
                    msg.extend_from_slice(&split_be(&sb, word, mask32));
                }
            }
            let len = msg.len() * 4;
            sha256_fixed(&sb, &msg, len)
        };
        let challenge = G {
            lo: b.bxor(h[0], b.shl(h[1], 32)),
            hi: b.bxor(h[2], b.shl(h[3], 32)),
        };
        let den = |sb: &CircuitBuilder, key: Wire| G {
            lo: sb.bxor(key, challenge.lo),
            hi: challenge.hi,
        };

        let mut lhs = den(b, queries[0]);
        for (i, &query) in queries.iter().enumerate().skip(1) {
            let sb = b.subcircuit(format!("raw/bm/lhs[{i}]"));
            lhs = gmul(&sb, lhs, den(&sb, query));
        }

        let mut rhs = one_g;
        for (j, &key) in table.iter().enumerate() {
            let sb = b.subcircuit(format!("raw/bm/rhs[{j}]"));
            let mut power = den(&sb, key);
            let mut acc = one_g;
            for bit in 0..mult_bits {
                let idx = j * mult_bits + bit;
                let mb = sb.shl(mpack[idx / 64], 63 - (idx % 64) as u32);
                acc = gmul(&sb, acc, gsel(&sb, mb, power, one_g));
                if bit + 1 < mult_bits {
                    power = gmul(&sb, power, power);
                }
            }
            rhs = gmul(&sb, rhs, acc);
        }
        b.assert_eq("raw/bm/gp_lo", lhs.lo, rhs.lo);
        b.assert_eq("raw/bm/gp_hi", lhs.hi, rhs.hi);

        Self { mpack, n_tab }
    }

    pub(super) fn host_queries(inst: &RawInstance, p: RawParams, table: &[u64]) -> Vec<u64> {
        let mut out = Vec::with_capacity(2 * (p.ep_cap - 1));
        for t in 1..p.ep_cap {
            let neutral0 = table[(2 * (t - 1)) % table.len()];
            let neutral1 = table[(2 * (t - 1) + 1) % table.len()];
            match (inst.steps.get(t - 1), inst.steps.get(t)) {
                (Some(prev), Some(step)) => {
                    out.push(if step.tag == TAG_RET {
                        neutral0
                    } else {
                        RawEdge {
                            src: prev.dst,
                            dst: step.dst,
                            etype: etype_of_tag(step.tag),
                        }
                        .key()
                    });
                    out.push(if step.tag == TAG_CAL {
                        RawEdge {
                            src: prev.dst,
                            dst: step.aux,
                            etype: ET_CRT,
                        }
                        .key()
                    } else {
                        neutral1
                    });
                }
                _ => {
                    out.push(neutral0);
                    out.push(neutral1);
                }
            }
        }
        out
    }

    pub(super) fn host_multiplicities(
        inst: &RawInstance,
        p: RawParams,
        table: &[u64],
    ) -> Result<Vec<u64>> {
        let queries = Self::host_queries(inst, p, table);
        let mut first = std::collections::HashMap::new();
        for (j, &key) in table.iter().enumerate() {
            first.entry(key).or_insert(j);
        }
        let mut mult = vec![0u64; table.len()];
        for query in queries {
            let Some(&j) = first.get(&query) else {
                bail!("raw membership query {query:#x} is not in the typed CFG table");
            };
            mult[j] += 1;
        }
        Ok(mult)
    }

    pub(super) fn preflight(inst: &RawInstance, p: RawParams) -> Result<(usize, u64)> {
        let table = inst.cfg_table(p);
        let mult = Self::host_multiplicities(inst, p, &table)?;
        let (j, count) = mult
            .iter()
            .copied()
            .enumerate()
            .max_by_key(|(_, count)| *count)
            .ok_or_else(|| anyhow::anyhow!("raw CFG multiplicity table is empty"))?;
        let mult_bits = p.mult_bits();
        ensure!(
            count < 1 << mult_bits,
            "raw CFG entry {j} is reused {count} times, exceeding MULT_BITS={mult_bits}"
        );
        Ok((j, count))
    }

    pub(super) fn populate(
        &self,
        w: &mut WitnessFiller,
        inst: &RawInstance,
        p: RawParams,
    ) -> Result<()> {
        let table = inst.cfg_table(p);
        let mult = Self::host_multiplicities(inst, p, &table)?;
        debug_assert_eq!(mult.len(), self.n_tab);
        let mult_bits = p.mult_bits();
        if let Some((j, count)) = mult
            .iter()
            .enumerate()
            .find(|(_, count)| **count >= 1 << mult_bits)
        {
            bail!("raw CFG entry {j} is reused {count} times, exceeding MULT_BITS={mult_bits}");
        }
        let mut words = vec![0u64; self.mpack.len()];
        for (j, &count) in mult.iter().enumerate() {
            for bit in 0..mult_bits {
                if (count >> bit) & 1 == 1 {
                    let idx = j * mult_bits + bit;
                    words[idx / 64] |= 1 << (idx % 64);
                }
            }
        }
        for (wire, word) in self.mpack.iter().zip(words) {
            w[*wire] = Word(word);
        }
        Ok(())
    }
}
