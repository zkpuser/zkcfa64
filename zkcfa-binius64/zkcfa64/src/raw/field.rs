//! Binary-field and SHA-256 circuit helpers shared by the raw24 gadgets.

use super::*;

#[derive(Clone, Copy)]
pub(super) struct G {
    pub(super) lo: Wire,
    pub(super) hi: Wire,
}

pub(super) fn gmul(b: &CircuitBuilder, x: G, y: G) -> G {
    let (lo, hi) = b.bmul(x.lo, x.hi, y.lo, y.hi);
    G { lo, hi }
}

pub(super) fn gsel(b: &CircuitBuilder, c: Wire, t: G, f: G) -> G {
    G {
        lo: b.select(c, t.lo, f.lo),
        hi: b.select(c, t.hi, f.hi),
    }
}

pub(super) fn split_be(b: &CircuitBuilder, w: Wire, mask32: Wire) -> [Wire; 2] {
    [b.shr(w, 32), b.band(w, mask32)]
}

pub(super) fn dom_words(b: &CircuitBuilder, dom: &[u8; 16]) -> Vec<Wire> {
    dom.chunks(4)
        .map(|c| b.add_constant_64(u32::from_be_bytes(c.try_into().unwrap()) as u64))
        .collect()
}

pub(super) fn pack4(b: &CircuitBuilder, d8: [Wire; 8]) -> [Wire; 4] {
    core::array::from_fn(|i| b.bxor(b.shl(d8[2 * i], 32), d8[2 * i + 1]))
}

pub(super) fn bind_raw_digest(
    b: &CircuitBuilder,
    name: &str,
    buf: &[Wire],
    public: [Wire; 4],
    mask32: Wire,
) {
    let sb = b.subcircuit(format!("raw/sha/{name}"));
    let mut msg = Vec::with_capacity(buf.len() * 2);
    for &word in buf {
        msg.extend_from_slice(&split_be(&sb, word, mask32));
    }
    let digest = sha256_fixed(&sb, &msg, buf.len() * 8);
    sb.assert_eq_v(name, pack4(&sb, digest), public);
}
