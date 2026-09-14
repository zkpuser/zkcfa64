//! Production timestamped exact-return stack checker.

use super::*;

pub(super) struct RawShadow;

impl RawShadow {
    pub(super) fn build(
        b: &CircuitBuilder,
        p: RawParams,
        records: &[RawRecordWires],
        ep_digest: [Wire; 4],
        cfg_digest: [Wire; 4],
    ) -> Self {
        const SP_BITS: u32 = 15;
        // Inline encoding uses 1|15|14|24|10. Shared encoding reuses the mutually exclusive
        // CAL/RET payload to provide the collision-free 1|15|24|24 layout for long traces.
        let (time_shift, value_shift) = match p.ep_encoding {
            RawEpEncoding::InlineHint14 => (34, 10),
            RawEpEncoding::SharedPayload24 => (24, 0),
        };
        let mask32 = b.add_constant(Word::MASK_32);
        let zero = b.add_constant_64(0);
        let real = b.add_constant_64(1 << 63);

        let mut pushes = Vec::with_capacity(p.ep_cap);
        let mut pops = Vec::with_capacity(p.ep_cap);
        let mut depth = zero;
        for (t, record) in records.iter().enumerate() {
            let sb = b.subcircuit(format!("raw/ss/row[{t}]"));
            let is_cal = sb.shr(record.is_cal, 63);
            let is_ret = sb.shr(record.is_ret, 63);
            let (slot, _) = sb.isub_bin_bout(depth, is_ret, zero);
            let (next_depth, _) = sb.iadd_cin_cout(slot, is_cal, zero);
            sb.assert_zero("depth_range", sb.shr(next_depth, SP_BITS));
            sb.assert_zero("slot_range", sb.shr(slot, SP_BITS));

            let push = sb.bxor_multi(&[
                real,
                sb.shl(slot, 48),
                sb.add_constant_64((t as u64) << time_shift),
                sb.shl(record.aux, value_shift),
            ]);
            let pop = sb.bxor_multi(&[
                real,
                sb.shl(slot, 48),
                sb.shl(record.hint, time_shift),
                sb.shl(record.dst, value_shift),
            ]);
            if t >= 1 {
                sb.assert_true(
                    "hint_lt_time",
                    sb.icmp_ult(record.hint, sb.add_constant_64(t as u64)),
                );
            }
            pushes.push(sb.select(record.is_cal, push, zero));
            pops.push(sb.select(record.is_ret, pop, zero));
            depth = next_depth;
        }
        b.assert_zero("raw/ss/balanced", depth);

        let h = {
            let sb = b.subcircuit("raw/ss/challenge");
            let mut msg = dom_words(&sb, DOM_SS_CH);
            for digest in [ep_digest, cfg_digest] {
                for &word in &digest {
                    msg.extend_from_slice(&split_be(&sb, word, mask32));
                }
            }
            let len = msg.len() * 4;
            sha256_fixed(&sb, &msg, len)
        };

        for k in 0..2 {
            let sb = b.subcircuit(format!("raw/ss/gp[{k}]"));
            let challenge = G {
                lo: sb.bxor(h[4 * k], sb.shl(h[4 * k + 1], 32)),
                hi: sb.bxor(h[4 * k + 2], sb.shl(h[4 * k + 3], 32)),
            };
            let den = |key: Wire| G {
                lo: sb.bxor(key, challenge.lo),
                hi: challenge.hi,
            };
            let mut push_product = den(pushes[0]);
            let mut pop_product = den(pops[0]);
            for t in 1..p.ep_cap {
                push_product = gmul(&sb, push_product, den(pushes[t]));
                pop_product = gmul(&sb, pop_product, den(pops[t]));
            }
            sb.assert_eq("push_pop_lo", push_product.lo, pop_product.lo);
            sb.assert_eq("push_pop_hi", push_product.hi, pop_product.hi);
        }
        Self
    }
}
