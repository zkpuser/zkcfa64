//! Raw24 domains, records, capacities, and signed profile parameters.

use super::*;

pub(super) const RAW_ADDR_BITS: u32 = 24;
pub(super) const RAW_ADDR_LIMIT: u64 = 1 << RAW_ADDR_BITS;
/// Canonical raw-24 encoding of the tracer's symbolic `SCOPE_RETURN` node.
///
/// The token is not a program address.  It occupies a suite-wide reserved value so the
/// provider's explicit entry/exit and call-return edges remain proof-visible without truncation.
pub(super) const RAW_SCOPE_SENTINEL: u64 = RAW_ADDR_LIMIT - 1;
/// Reserved raw-24 window for the provider's finite `0xfffe0000 + id` external gateways.
///
/// At most 65,535 provider gateways occupy `0xff0000..=0xfffffe`; `0xffffff` remains
/// exclusively reserved for `SCOPE_RETURN`.
pub(super) const RAW_GATEWAY_BASE: u64 = RAW_ADDR_LIMIT - 0x1_0000;
pub(super) const PROVIDER_GATEWAY_BASE: u64 = 0xFFFE_0000;
pub(super) const PROVIDER_GATEWAY_LIMIT: u64 = PROVIDER_GATEWAY_BASE + 0xFFFF;
pub(super) const INLINE_HINT_BITS: u32 = 14;
pub(super) const INLINE_HINT_LIMIT: usize = 1 << INLINE_HINT_BITS;
pub(super) const SHARED_HINT_BITS: u32 = 24;
pub(super) const SHARED_HINT_LIMIT: usize = 1 << SHARED_HINT_BITS;
pub(super) const RAW_EDGE_SHIFT: u32 = RAW_ADDR_BITS + 2;
pub(super) const RAW_HINT_SHIFT: u32 = 2 + 2 * RAW_ADDR_BITS;

/// Fixed semantic domains inside the blinded commitment preimages.
pub(super) const MAGIC_RAW_CFG: u64 = 0x4346_472D_464C_4154; // `CFG-FLAT`
pub(super) const MAGIC_RAW_EP_INLINE: u64 = 0x4550_494E_4C49_4E45; // `EPINLINE`
pub(super) const MAGIC_RAW_EP_SHARED: u64 = 0x4550_5348_4152_4544; // `EPSHARED`
pub(super) const RAW_CFG_HEADER_WORDS: usize = 10;
pub(super) const RAW_EP_HEADER_WORDS: usize = 10;
pub(super) const RAW_CFG_BLIND_LO: usize = 8;
pub(super) const RAW_CFG_BLIND_HI: usize = 9;
pub(super) const RAW_EP_PATH_MODE: usize = 7;

/// Padding entries are outside the 50-bit raw-edge key space and unique by slot.
pub(super) const PAD_KEY: u64 = 1 << 63;

pub(super) const INLINE_MULT_BITS: usize = 12;
pub(super) const DOM_M: &[u8; 16] = b"ZKCFA/RAW/MSEAL\0";
pub(super) const DOM_BM_CH: &[u8; 16] = b"ZKCFA/RAW/BMULT\0";
pub(super) const DOM_SS_CH: &[u8; 16] = b"ZKCFA/RAW/STACK\0";

pub(super) const RAW_OFF_EP_DIGEST: usize = 0;
pub(super) const RAW_OFF_CFG_DIGEST: usize = 4;
pub(super) const RAW_OFF_ENTRY: usize = 8;
pub(super) const RAW_OFF_FINAL: usize = 9;
pub(crate) const RAW_N_PUBLIC: usize = 10;

/// The ten relation-level public inputs, independent of the Binius public-vector layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RawPublicValues {
    pub(crate) h_ep: [u8; 32],
    pub(crate) h_cfg: [u8; 32],
    pub(crate) entry: u64,
    pub(crate) final_node: u64,
}

/// The path statement is a circuit parameter and a word in the canonical EP header.  Complete
/// QEMU rows and the optional lossy projection therefore cannot share an `H_ep`, even when their
/// active rows happen to be byte-for-byte equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RawPathMode {
    CompleteQemu,
    ShadowSafe,
}

impl RawPathMode {
    pub(super) const fn header_word(self) -> u64 {
        match self {
            Self::CompleteQemu => 0x434F_4D50_4C45_5445, // `COMPLETE`
            Self::ShadowSafe => 0x5348_4144_4F57_4544,   // `SHADOWED`
        }
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::CompleteQemu => "complete",
            Self::ShadowSafe => "shadow",
        }
    }

    pub(super) const fn statement(self) -> &'static str {
        match self {
            Self::CompleteQemu => "complete configured root-scope QEMU path",
            Self::ShadowSafe => "lossy stack-safe projected path",
        }
    }

    pub(super) fn from_signed_label(value: &str) -> Result<Self> {
        match value {
            "complete" => Ok(Self::CompleteQemu),
            "shadow" => Ok(Self::ShadowSafe),
            other => bail!("signed raw registry has unsupported path_mode {other:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RawEpEncoding {
    InlineHint14,
    SharedPayload24,
}

impl RawEpEncoding {
    pub(super) fn for_ep_cap(ep_cap: usize) -> Result<Self> {
        if ep_cap <= INLINE_HINT_LIMIT {
            Ok(Self::InlineHint14)
        } else if ep_cap <= SHARED_HINT_LIMIT {
            Ok(Self::SharedPayload24)
        } else {
            bail!("EP_CAP={ep_cap} exceeds the {SHARED_HINT_BITS}-bit RET hint");
        }
    }

    pub(super) const fn magic(self) -> u64 {
        match self {
            Self::InlineHint14 => MAGIC_RAW_EP_INLINE,
            Self::SharedPayload24 => MAGIC_RAW_EP_SHARED,
        }
    }

    pub(super) const fn hint_bits(self) -> u32 {
        match self {
            Self::InlineHint14 => INLINE_HINT_BITS,
            Self::SharedPayload24 => SHARED_HINT_BITS,
        }
    }

    pub(super) const fn hint_limit(self) -> usize {
        1 << self.hint_bits()
    }

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::InlineHint14 => "inline14",
            Self::SharedPayload24 => "shared24",
        }
    }
}

/// Parse one provider address/symbol into the canonical raw-24 proof namespace.
///
/// Program addresses are kept verbatim.  The provider's symbolic scope-return node and its
/// finite external-gateway namespace are mapped into a disjoint reserved suffix.  Numeric input
/// is never allowed to name that suffix directly, which keeps the mapping injective.
pub(super) fn parse_raw_addr_token(token: &str) -> Result<u64> {
    if token == "SCOPE_RETURN" {
        return Ok(RAW_SCOPE_SENTINEL);
    }
    let stripped = token
        .strip_prefix("0x")
        .filter(|digits| {
            !digits.is_empty()
                && digits
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
        .ok_or_else(|| {
            anyhow::anyhow!("bad raw address {token:?}: expected lowercase 0x-prefixed hexadecimal")
        })?;
    let value = u64::from_str_radix(stripped, 16)
        .map_err(|e| anyhow::anyhow!("bad raw address {token:?}: {e}"))?;
    if (PROVIDER_GATEWAY_BASE..PROVIDER_GATEWAY_LIMIT).contains(&value) {
        return Ok(RAW_GATEWAY_BASE + (value - PROVIDER_GATEWAY_BASE));
    }
    if value == 0 {
        bail!("raw address zero is reserved for inactive rows");
    }
    if value >= RAW_GATEWAY_BASE {
        bail!(
            "numeric address {value:#x} is outside raw-24 or collides with its reserved token window"
        );
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct RawEdge {
    pub(super) src: u64,
    pub(super) dst: u64,
    pub(super) etype: u64,
}

impl RawEdge {
    pub(super) fn key(self) -> u64 {
        assert!(
            self.src != 0 && self.src < RAW_ADDR_LIMIT,
            "raw edge source is not canonical"
        );
        assert!(
            self.dst != 0 && self.dst < RAW_ADDR_LIMIT,
            "raw edge destination is not canonical"
        );
        assert!(self.etype <= ET_CRT, "raw edge type is not canonical");
        (self.src << RAW_EDGE_SHIFT) | (self.etype << RAW_ADDR_BITS) | self.dst
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RawStep {
    pub(super) dst: u64,
    pub(super) tag: u64,
    pub(super) aux: u64,
    pub(super) hint: u32,
}

impl RawStep {
    pub(super) fn word(self, encoding: RawEpEncoding) -> u64 {
        assert!(
            self.dst != 0 && self.dst < RAW_ADDR_LIMIT,
            "raw step destination is not canonical"
        );
        assert!(self.tag <= TAG_RESERVED, "raw step tag is not canonical");
        assert!(
            self.aux < RAW_ADDR_LIMIT,
            "raw step auxiliary address is not canonical"
        );
        assert!(
            (self.hint as usize) < encoding.hint_limit(),
            "raw step hint is not canonical for {encoding:?}"
        );
        assert!(
            self.tag == TAG_CAL || self.aux == 0,
            "raw auxiliary address is only legal on CAL"
        );
        assert!(
            self.tag == TAG_RET || self.hint == 0,
            "raw hint is only legal on RET"
        );
        match encoding {
            RawEpEncoding::InlineHint14 => {
                (self.tag & 3)
                    | (self.dst << 2)
                    | (self.aux << RAW_EDGE_SHIFT)
                    | ((self.hint as u64) << RAW_HINT_SHIFT)
            }
            RawEpEncoding::SharedPayload24 => {
                let payload = if self.tag == TAG_CAL {
                    self.aux
                } else if self.tag == TAG_RET {
                    self.hint as u64
                } else {
                    0
                };
                (self.tag & 3) | (self.dst << 2) | (payload << RAW_EDGE_SHIFT)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RawParams {
    pub(super) edge_cap: usize,
    pub(super) ep_cap: usize,
    pub(super) ep_encoding: RawEpEncoding,
    pub(super) path_mode: RawPathMode,
}

impl RawParams {
    pub(crate) fn edge_cap(self) -> usize {
        self.edge_cap
    }

    pub(crate) fn ep_cap(self) -> usize {
        self.ep_cap
    }

    pub(crate) fn ep_encoding_label(self) -> &'static str {
        self.ep_encoding.label()
    }

    pub(crate) fn path_mode_label(self) -> &'static str {
        self.path_mode.label()
    }

    pub(crate) fn path_statement(self) -> &'static str {
        self.path_mode.statement()
    }

    pub(crate) fn mult_bits(self) -> usize {
        match self.ep_encoding {
            RawEpEncoding::InlineHint14 => INLINE_MULT_BITS,
            RawEpEncoding::SharedPayload24 => {
                let max_multiplicity = 2 * self.ep_cap.saturating_sub(1);
                (usize::BITS - max_multiplicity.leading_zeros()) as usize
            }
        }
    }
}

pub(crate) fn signed_raw_params(
    signed: &crate::attestation::RawCircuitConfig,
) -> Result<RawParams> {
    Ok(RawParams {
        edge_cap: signed.edge_cap,
        ep_cap: signed.ep_cap,
        ep_encoding: RawEpEncoding::for_ep_cap(signed.ep_cap)?,
        path_mode: RawPathMode::from_signed_label(&signed.path_mode)?,
    })
}
