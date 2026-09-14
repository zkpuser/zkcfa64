//! Raw24 circuit assembly, witness population, and production entry point.

use super::*;

#[derive(Clone, Copy)]
pub(super) struct RawRecordWires {
    pub(super) dst: Wire,
    pub(super) aux: Wire,
    pub(super) hint: Wire,
    pub(super) etype: Wire,
    pub(super) is_cal: Wire,
    pub(super) is_ret: Wire,
    pub(super) inactive: Wire,
}

#[derive(Clone, Copy)]
pub(crate) enum RawMembershipKind {
    BinMult,
    #[cfg(feature = "construction-control")]
    Indexed,
    #[cfg(feature = "construction-control")]
    LogUp,
}

pub(super) enum RawMembership {
    BinMult(RawBinMult),
    #[cfg(feature = "construction-control")]
    Indexed(RawIndexedMembership),
    #[cfg(feature = "construction-control")]
    LogUp(RawLogUpMembership),
}

impl RawMembership {
    pub(super) fn populate(
        &self,
        w: &mut WitnessFiller,
        inst: &RawInstance,
        p: RawParams,
    ) -> Result<()> {
        match self {
            Self::BinMult(membership) => membership.populate(w, inst, p),
            #[cfg(feature = "construction-control")]
            Self::Indexed(membership) => membership.populate(w, inst, p),
            #[cfg(feature = "construction-control")]
            Self::LogUp(membership) => membership.populate(w, inst, p),
        }
    }
}

pub(crate) struct RawCfgWalk {
    pub(super) params: RawParams,
    pub(super) ep_digest: [Wire; 4],
    pub(super) cfg_digest: [Wire; 4],
    pub(super) entry: Wire,
    pub(super) final_node: Wire,
    pub(super) n_edges: Wire,
    pub(super) ep_len: Wire,
    pub(super) table: Vec<Wire>,
    pub(super) steps: Vec<Wire>,
    pub(super) ep_blind_lo: Wire,
    pub(super) ep_blind_hi: Wire,
    pub(super) cfg_blind_lo: Wire,
    pub(super) cfg_blind_hi: Wire,
    pub(super) membership: RawMembership,
}

impl RawCfgWalk {
    pub(super) fn build(b: &CircuitBuilder, params: RawParams) -> Self {
        Self::build_with_shadow(b, params, true)
    }

    pub(super) fn build_with_shadow(
        b: &CircuitBuilder,
        params: RawParams,
        include_shadow: bool,
    ) -> Self {
        Self::build_with_membership(b, params, include_shadow, RawMembershipKind::BinMult)
    }

    pub(super) fn build_with_membership(
        b: &CircuitBuilder,
        params: RawParams,
        include_shadow: bool,
        membership_kind: RawMembershipKind,
    ) -> Self {
        let mask32 = b.add_constant(Word::MASK_32);
        let zero = b.add_constant_64(0);
        let one = b.add_constant_64(1);

        let ep_digest = core::array::from_fn(|_| b.add_inout());
        let cfg_digest = core::array::from_fn(|_| b.add_inout());
        let entry = b.add_inout();
        let final_node = b.add_inout();

        let n_edges = b.add_witness();
        let ep_len = b.add_witness();
        let table: Vec<Wire> = (0..params.edge_cap).map(|_| b.add_witness()).collect();
        let steps: Vec<Wire> = (0..params.ep_cap).map(|_| b.add_witness()).collect();
        let ep_blind_lo = b.add_witness();
        let ep_blind_hi = b.add_witness();
        let cfg_blind_lo = b.add_witness();
        let cfg_blind_hi = b.add_witness();

        let mut cfg_buf = vec![
            b.add_constant_64(MAGIC_RAW_CFG),
            b.add_constant_64(params.edge_cap as u64),
            n_edges,
            b.add_constant_64(RAW_ADDR_BITS as u64),
            zero,
            zero,
            zero,
            zero,
            cfg_blind_lo,
            cfg_blind_hi,
        ];
        cfg_buf.extend_from_slice(&table);
        let mut ep_buf = vec![
            b.add_constant_64(params.ep_encoding.magic()),
            b.add_constant_64(params.ep_cap as u64),
            ep_len,
            b.add_constant_64(RAW_ADDR_BITS as u64),
            ep_blind_lo,
            ep_blind_hi,
            b.add_constant_64(if params.ep_encoding == RawEpEncoding::SharedPayload24 {
                SHARED_HINT_BITS as u64
            } else {
                0
            }),
            b.add_constant_64(params.path_mode.header_word()),
            zero,
            zero,
        ];
        ep_buf.extend_from_slice(&steps);

        {
            let sb = b.subcircuit("raw/header");
            sb.assert_true("n_edges_ge1", sb.icmp_uge(n_edges, one));
            sb.assert_true(
                "n_edges_le_cap",
                sb.icmp_ule(n_edges, sb.add_constant_64(params.edge_cap as u64)),
            );
            sb.assert_true("ep_len_ge1", sb.icmp_uge(ep_len, one));
            sb.assert_true(
                "ep_len_le_cap",
                sb.icmp_ule(ep_len, sb.add_constant_64(params.ep_cap as u64)),
            );
        }

        bind_raw_digest(b, "ep", &ep_buf, ep_digest, mask32);
        bind_raw_digest(b, "cfg", &cfg_buf, cfg_digest, mask32);

        let cal_tag = b.add_constant_64(TAG_CAL);
        let ret_tag = b.add_constant_64(TAG_RET);
        let reserved_tag = b.add_constant_64(TAG_RESERVED);
        let mut records = Vec::with_capacity(params.ep_cap);
        for (t, &word) in steps.iter().enumerate() {
            let sb = b.subcircuit(format!("raw/rec[{t}]"));
            let tag = sb.shr(sb.shl(word, 62), 62);
            let dst = sb.shr(sb.shl(word, 38), 40);
            let aux_field = sb.shr(sb.shl(word, 14), 40);
            let hint_field = match params.ep_encoding {
                RawEpEncoding::InlineHint14 => sb.shr(word, RAW_HINT_SHIFT),
                RawEpEncoding::SharedPayload24 => aux_field,
            };
            let active = sb.icmp_ult(sb.add_constant_64(t as u64), ep_len);
            let inactive = sb.bnot(active);
            sb.assert_eq_cond("padding_zero", word, zero, inactive);
            sb.assert_true(
                "active_dst_nonzero",
                sb.bor(sb.icmp_ne(dst, zero), inactive),
            );

            let is_cal = sb.icmp_eq(tag, cal_tag);
            let is_ret = sb.icmp_eq(tag, ret_tag);
            let is_reserved = sb.icmp_eq(tag, reserved_tag);
            sb.assert_true(
                "active_tag_not_reserved",
                sb.bor(inactive, sb.bnot(is_reserved)),
            );
            let aux = sb.select(is_cal, aux_field, zero);
            let hint = sb.select(is_ret, hint_field, zero);
            match params.ep_encoding {
                RawEpEncoding::InlineHint14 => {
                    sb.assert_eq("aux_only_on_cal", aux_field, aux);
                    sb.assert_eq("hint_only_on_ret", hint_field, hint);
                }
                RawEpEncoding::SharedPayload24 => {
                    sb.assert_zero("reserved_high_zero", sb.shr(word, RAW_HINT_SHIFT));
                    sb.assert_eq("payload_only_on_cal_or_ret", aux_field, sb.bxor(aux, hint));
                }
            }
            sb.assert_true(
                "cal_aux_nonzero",
                sb.bor(sb.bnot(is_cal), sb.icmp_ne(aux, zero)),
            );
            let recomposed = match params.ep_encoding {
                RawEpEncoding::InlineHint14 => sb.bxor_multi(&[
                    tag,
                    sb.shl(dst, 2),
                    sb.shl(aux_field, RAW_EDGE_SHIFT),
                    sb.shl(hint_field, RAW_HINT_SHIFT),
                ]),
                RawEpEncoding::SharedPayload24 => {
                    sb.bxor_multi(&[tag, sb.shl(dst, 2), sb.shl(aux_field, RAW_EDGE_SHIFT)])
                }
            };
            sb.assert_eq("canonical_word", word, recomposed);
            let etype = sb.select(is_reserved, zero, tag);
            records.push(RawRecordWires {
                dst,
                aux,
                hint,
                etype,
                is_cal,
                is_ret,
                inactive,
            });
        }
        b.assert_zero("raw/t0_not_call", b.shr(records[0].is_cal, 63));

        let dsts: Vec<Wire> = records.iter().map(|r| r.dst).collect();
        let sb = b.subcircuit("raw/endpoints");
        sb.assert_eq("entry", dsts[0], entry);
        let (last_index, _) = sb.isub_bin_bout(ep_len, one, zero);
        let last = binius_circuits::multiplexer::single_wire_multiplex(&sb, &dsts, last_index);
        sb.assert_eq("final", last, final_node);

        let etypes: Vec<Wire> = records.iter().map(|r| r.etype).collect();
        let auxs: Vec<Wire> = records.iter().map(|r| r.aux).collect();
        let is_cals: Vec<Wire> = records.iter().map(|r| r.is_cal).collect();
        let is_rets: Vec<Wire> = records.iter().map(|r| r.is_ret).collect();
        let inactive: Vec<Wire> = records.iter().map(|r| r.inactive).collect();
        let membership = match membership_kind {
            RawMembershipKind::BinMult => RawMembership::BinMult(RawBinMult::build(
                b, params, &table, &dsts, &etypes, &auxs, &is_cals, &is_rets, &inactive, ep_digest,
                cfg_digest,
            )),
            #[cfg(feature = "construction-control")]
            RawMembershipKind::Indexed => {
                let queries = RawBinMult::query_wires(
                    b, params, &table, &dsts, &etypes, &auxs, &is_cals, &is_rets, &inactive,
                );
                RawMembership::Indexed(RawIndexedMembership::build(b, &table, &queries))
            }
            #[cfg(feature = "construction-control")]
            RawMembershipKind::LogUp => {
                let queries = RawBinMult::query_wires(
                    b, params, &table, &dsts, &etypes, &auxs, &is_cals, &is_rets, &inactive,
                );
                RawMembership::LogUp(RawLogUpMembership::build(
                    b, &table, &queries, ep_digest, cfg_digest,
                ))
            }
        };

        if include_shadow {
            let _ = RawShadow::build(b, params, &records, ep_digest, cfg_digest);
        }

        Self {
            params,
            ep_digest,
            cfg_digest,
            entry,
            final_node,
            n_edges,
            ep_len,
            table,
            steps,
            ep_blind_lo,
            ep_blind_hi,
            cfg_blind_lo,
            cfg_blind_hi,
            membership,
        }
    }

    pub(crate) fn populate(
        &self,
        w: &mut WitnessFiller,
        inst: &RawInstance,
    ) -> Result<([u8; 32], [u8; 32])> {
        inst.validate(self.params)?;
        self.populate_unchecked(w, inst)
    }

    pub(super) fn populate_unchecked(
        &self,
        w: &mut WitnessFiller,
        inst: &RawInstance,
    ) -> Result<([u8; 32], [u8; 32])> {
        let cfg_buf = inst.cfg_buf(self.params);
        let ep_buf = inst.ep_buf(self.params);
        let cfg_digest = buf_digest(&cfg_buf);
        let ep_digest = buf_digest(&ep_buf);
        for (i, word) in digest_words(&ep_digest).into_iter().enumerate() {
            w[self.ep_digest[i]] = Word(word);
        }
        for (i, word) in digest_words(&cfg_digest).into_iter().enumerate() {
            w[self.cfg_digest[i]] = Word(word);
        }
        w[self.entry] = Word(inst.entry());
        w[self.final_node] = Word(inst.final_node());
        w[self.n_edges] = Word(inst.edges.len() as u64);
        w[self.ep_len] = Word(inst.steps.len() as u64);
        for (i, &wire) in self.table.iter().enumerate() {
            w[wire] = Word(cfg_buf[RAW_CFG_HEADER_WORDS + i]);
        }
        for (i, &wire) in self.steps.iter().enumerate() {
            w[wire] = Word(ep_buf[RAW_EP_HEADER_WORDS + i]);
        }
        let [lo, hi] = inst.ep_blind.words();
        w[self.ep_blind_lo] = Word(lo);
        w[self.ep_blind_hi] = Word(hi);
        let [lo, hi] = inst.cfg_blind.words();
        w[self.cfg_blind_lo] = Word(lo);
        w[self.cfg_blind_hi] = Word(hi);
        self.membership.populate(w, inst, self.params)?;
        Ok((ep_digest, cfg_digest))
    }
}

pub(crate) fn build_raw_circuit(params: RawParams) -> (Circuit, RawCfgWalk) {
    let builder = CircuitBuilder::new();
    let walk = RawCfgWalk::build(&builder, params);
    (builder.build(), walk)
}

/// Research-only ablation for measuring the compiled contribution of `RawShadow`.
/// Both branches retain the production record, commitment, and BinMult membership checks.
#[cfg(feature = "stack-control")]
pub(crate) fn build_raw_stack_control(
    params: RawParams,
    include_shadow: bool,
) -> (Circuit, RawCfgWalk) {
    let builder = CircuitBuilder::new();
    let walk = RawCfgWalk::build_with_shadow(&builder, params, include_shadow);
    (builder.build(), walk)
}
