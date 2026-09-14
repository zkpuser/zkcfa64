//! Full-width raw64 zkCFA experiment: typed-channel, lossless binary-field keys.
//!
//! The public commitments bind a typed full-key CFG and either a complete QEMU path or the
//! explicitly selected stack-safe projection. EP and CFG use independent secret openings.

use std::{collections::HashSet, path::Path};

use anyhow::{Result, bail, ensure};
use binius_circuits::sha256::sha256_fixed;
use binius_core::{InoutSegment, constraint_system::ConstraintSystem, word::Word};
use binius_frontend::{Circuit, CircuitBuilder, Wire, WitnessFiller};

use crate::raw_format::{
    Blinding, ET_CAL, ET_CRT, ET_JMP, TAG_CAL, TAG_JMP, TAG_RESERVED, TAG_RET, buf_digest,
    digest_words, etype_of_tag,
};

const RAW_ADDR_BITS: u32 = 64;
/// Zero denotes padding; the top 65,536 values are explicit provider tokens.
const RAW_SCOPE_SENTINEL: u64 = u64::MAX;
const RAW_GATEWAY_BASE: u64 = u64::MAX - 0xFFFF;
const PROVIDER_GATEWAY_BASE: u64 = 0xFFFE_0000;
const PROVIDER_GATEWAY_LIMIT: u64 = PROVIDER_GATEWAY_BASE + 0xFFFF;
const INLINE_HINT_LIMIT: usize = 1 << 14;
const SHARED_HINT_BITS: u32 = 24;
const SHARED_HINT_LIMIT: usize = 1 << SHARED_HINT_BITS;
const RAW_ROW_WORDS: usize = 3;

/// Fixed semantic domains inside the blinded commitment preimages.
const MAGIC_RAW_CFG: u64 = u64::from_be_bytes(*b"CFG-W64V");
const MAGIC_RAW_EP_WIDE: u64 = u64::from_be_bytes(*b"EP-W64V1");
const RAW_CFG_HEADER_WORDS: usize = 10;
const RAW_EP_HEADER_WORDS: usize = 10;
const RAW_CFG_BLIND_LO: usize = 8;
const RAW_CFG_BLIND_HI: usize = 9;
const RAW_EP_PATH_MODE: usize = 7;

const INLINE_MULT_BITS: usize = 12;
const DOM_M: &[u8; 16] = b"ZKCFA/W64/MSEAL\0";
const DOM_BM_CH: &[u8; 16] = b"ZKCFA/W64/BMULT\0";
const DOM_SS_CH: &[u8; 16] = b"ZKCFA/W64/STACK\0";

const RAW_OFF_EP_DIGEST: usize = 0;
const RAW_OFF_CFG_DIGEST: usize = 4;
const RAW_OFF_ENTRY: usize = 8;
const RAW_OFF_FINAL: usize = 9;
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
    const fn header_word(self) -> u64 {
        match self {
            Self::CompleteQemu => 0x434F_4D50_4C45_5445, // `COMPLETE`
            Self::ShadowSafe => 0x5348_4144_4F57_4544,   // `SHADOWED`
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::CompleteQemu => "complete",
            Self::ShadowSafe => "shadow",
        }
    }

    const fn statement(self) -> &'static str {
        match self {
            Self::CompleteQemu => "complete configured root-scope QEMU path",
            Self::ShadowSafe => "lossy stack-safe projected path",
        }
    }

    fn from_signed_label(value: &str) -> Result<Self> {
        match value {
            "complete" => Ok(Self::CompleteQemu),
            "shadow" => Ok(Self::ShadowSafe),
            other => bail!("signed raw registry has unsupported path_mode {other:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RawEpEncoding {
    Wide64,
}

impl RawEpEncoding {
    fn for_ep_cap(ep_cap: usize) -> Result<Self> {
        ensure!(
            ep_cap <= SHARED_HINT_LIMIT,
            "EP_CAP={ep_cap} exceeds the {SHARED_HINT_BITS}-bit RET hint"
        );
        Ok(Self::Wide64)
    }

    const fn magic(self) -> u64 {
        MAGIC_RAW_EP_WIDE
    }
    const fn hint_bits(self) -> u32 {
        SHARED_HINT_BITS
    }
    const fn hint_limit(self) -> usize {
        SHARED_HINT_LIMIT
    }
    const fn label(self) -> &'static str {
        "wide64"
    }
}

/// Parse one provider address/symbol into the canonical raw-64 proof namespace.
///
/// Program addresses are kept verbatim.  The provider's symbolic scope-return node and its
/// finite external-gateway namespace are mapped into a disjoint reserved suffix.  Numeric input
/// is never allowed to name that suffix directly, which keeps the mapping injective.
fn parse_raw_addr_token(token: &str) -> Result<u64> {
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
        bail!("numeric address {value:#x} is inside the reserved raw-64 token window");
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct RawEdge {
    src: u64,
    dst: u64,
    etype: u64,
}

impl RawEdge {
    fn key(self) -> [u64; RAW_ROW_WORDS] {
        assert!(self.src != 0, "raw edge source is not canonical");
        assert!(self.dst != 0, "raw edge destination is not canonical");
        assert!(
            matches!(self.etype, ET_JMP | ET_CAL | ET_CRT),
            "raw edge type is not canonical"
        );
        [self.src, self.etype, self.dst]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RawStep {
    dst: u64,
    tag: u64,
    aux: u64,
    hint: u32,
}

impl RawStep {
    fn words(self, encoding: RawEpEncoding) -> [u64; RAW_ROW_WORDS] {
        assert!(self.dst != 0, "raw step destination is not canonical");
        assert!(self.tag <= TAG_RESERVED, "raw step tag is not canonical");
        assert!(
            (self.hint as usize) < encoding.hint_limit(),
            "raw step hint is not canonical"
        );
        assert!(
            self.tag == TAG_CAL || self.aux == 0,
            "raw auxiliary address is only legal on CAL"
        );
        assert!(
            self.tag == TAG_RET || self.hint == 0,
            "raw hint is only legal on RET"
        );
        let payload = match self.tag {
            TAG_CAL => self.aux,
            TAG_RET => self.hint as u64,
            _ => 0,
        };
        [self.tag, self.dst, payload]
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RawInstance {
    node_count: usize,
    edges: Vec<RawEdge>,
    steps: Vec<RawStep>,
    /// Per-report secret opening for the raw execution-path commitment.
    ep_blind: Blinding,
    /// Independently provisioned secret opening for the raw CFG commitment.
    cfg_blind: Blinding,
}

impl RawInstance {
    /// Load the independently typed provider artifacts with their signed commitment openings.
    pub(crate) fn from_typed_bundle_with_openings(
        dir: &str,
        ep_blind: Blinding,
        cfg_blind: Blinding,
    ) -> Result<Self> {
        ensure!(
            ep_blind != cfg_blind,
            "raw H_ep and H_cfg reuse the same blinding value"
        );
        let translator_path = Path::new(dir).join("translator");
        let translator_text = std::fs::read_to_string(&translator_path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", translator_path.display()))?;
        ensure!(translator_text.is_ascii(), "translator must be ASCII");
        let mut nodes = HashSet::new();
        for (line_no, line) in translator_text.lines().enumerate() {
            let fields: Vec<_> = line.split_whitespace().collect();
            ensure!(
                fields.len() == 1 && !line.contains('#'),
                "translator line {} must contain one raw node",
                line_no + 1
            );
            let node = parse_raw_addr_token(fields[0])?;
            ensure!(
                nodes.insert(node),
                "translator line {} repeats raw node {node:#x}",
                line_no + 1
            );
        }
        ensure!(!nodes.is_empty(), "translator contains no raw nodes");

        let typed_path = Path::new(dir).join("typed_cfg");
        let cfg_text = std::fs::read_to_string(&typed_path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", typed_path.display()))?;
        ensure!(cfg_text.is_ascii(), "typed_cfg must be ASCII");
        let mut edges = Vec::new();
        for (line_no, line) in cfg_text.lines().enumerate() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 3 || line.contains('#') {
                bail!("typed_cfg line {} must contain src type dst", line_no + 1);
            }
            let src = parse_raw_addr_token(fields[0])?;
            let dst = parse_raw_addr_token(fields[2])?;
            ensure!(
                nodes.contains(&src) && nodes.contains(&dst),
                "typed_cfg line {} names a node outside translator",
                line_no + 1
            );
            let etype = match fields[1] {
                "jmp" => ET_JMP,
                "cal" => ET_CAL,
                "ret" => bail!(
                    "typed_cfg line {} contains RET; raw canonical tables contain only \
                     JMP/CAL/CRT because CRT plus the exact shadow stack authorizes returns",
                    line_no + 1
                ),
                "crt" => ET_CRT,
                other => bail!(
                    "typed_cfg line {} has unknown edge type {other:?}",
                    line_no + 1
                ),
            };
            edges.push(RawEdge { src, dst, etype });
        }
        let recorded_path = Path::new(dir).join("recorded_path");
        let path_text = std::fs::read_to_string(&recorded_path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", recorded_path.display()))?;
        ensure!(path_text.is_ascii(), "recorded_path must be ASCII");
        let mut lines = path_text.lines();
        let header = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("recorded_path is empty"))?;
        let header_fields: Vec<_> = header.split_whitespace().collect();
        ensure!(
            header_fields.len() == 2,
            "recorded_path header must contain exactly initial_node and final_node"
        );
        let mut entry = None;
        let mut declared_final = None;
        for field in header_fields {
            if let Some(value) = field.strip_prefix("initial_node=") {
                ensure!(entry.is_none(), "recorded_path header repeats initial_node");
                entry = Some(parse_raw_addr_token(value)?);
            } else if let Some(value) = field.strip_prefix("final_node=") {
                ensure!(
                    declared_final.is_none(),
                    "recorded_path header repeats final_node"
                );
                declared_final = Some(parse_raw_addr_token(value)?);
            } else {
                bail!("recorded_path header has unknown field {field:?}");
            }
        }
        let entry =
            entry.ok_or_else(|| anyhow::anyhow!("recorded_path header lacks initial_node"))?;
        let declared_final = declared_final
            .ok_or_else(|| anyhow::anyhow!("recorded_path header lacks final_node"))?;
        ensure!(
            nodes.contains(&entry) && nodes.contains(&declared_final),
            "recorded_path endpoints are outside translator"
        );
        let mut steps = vec![RawStep {
            dst: entry,
            tag: TAG_JMP,
            aux: 0,
            hint: 0,
        }];
        for (offset, line) in lines.enumerate() {
            let fields: Vec<_> = line.split_whitespace().collect();
            let line_no = offset + 2;
            if fields.len() < 2 || line.contains('#') {
                bail!("recorded_path line {line_no} is malformed");
            }
            let dst = parse_raw_addr_token(fields[1])?;
            let (tag, aux) = match fields[0] {
                "jump" if fields.len() == 2 => (TAG_JMP, 0),
                "ret" if fields.len() == 2 => (TAG_RET, 0),
                "call" if fields.len() == 3 => (TAG_CAL, parse_raw_addr_token(fields[2])?),
                other => bail!("recorded_path line {line_no} has malformed operation {other:?}"),
            };
            ensure!(
                nodes.contains(&dst),
                "recorded_path line {line_no} names a destination outside translator"
            );
            ensure!(
                tag != TAG_CAL || nodes.contains(&aux),
                "recorded_path line {line_no} names a call return site outside translator"
            );
            steps.push(RawStep {
                dst,
                tag,
                aux,
                hint: 0,
            });
        }
        ensure!(
            steps.last().map(|step| step.dst) == Some(declared_final),
            "recorded_path final row disagrees with final_node"
        );

        // Bind every RET to its matching CAL row before the path reaches the circuit.
        let mut stack = Vec::new();
        for t in 1..steps.len() {
            match steps[t].tag {
                TAG_CAL => stack.push(t),
                TAG_RET => {
                    let call = stack.pop().ok_or_else(|| {
                        anyhow::anyhow!("recorded_path row {t} returns on an empty stack")
                    })?;
                    ensure!(
                        steps[call].aux == steps[t].dst,
                        "recorded_path row {t} returns to {:#x}, expected {:#x}",
                        steps[t].dst,
                        steps[call].aux
                    );
                    steps[t].hint = u32::try_from(call)
                        .map_err(|_| anyhow::anyhow!("matching CAL row {call} exceeds u32"))?;
                }
                _ => {}
            }
        }
        ensure!(
            stack.is_empty(),
            "recorded_path leaves {} call(s) unmatched",
            stack.len()
        );

        edges.sort_unstable_by_key(|edge| edge.key());

        Ok(Self {
            node_count: nodes.len(),
            edges,
            steps,
            ep_blind,
            cfg_blind,
        })
    }

    pub(crate) fn entry(&self) -> u64 {
        self.steps[0].dst
    }

    pub(crate) fn final_node(&self) -> u64 {
        self.steps[self.steps.len() - 1].dst
    }

    pub(crate) const fn node_count(&self) -> usize {
        self.node_count
    }

    pub(crate) fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub(crate) fn step_count(&self) -> usize {
        self.steps.len()
    }

    pub(crate) fn public_values(&self, params: RawParams) -> RawPublicValues {
        RawPublicValues {
            h_ep: buf_digest(&self.ep_buf(params)),
            h_cfg: buf_digest(&self.cfg_buf(params)),
            entry: self.entry(),
            final_node: self.final_node(),
        }
    }

    pub(crate) fn buffer_word_counts(&self, params: RawParams) -> (usize, usize) {
        (self.ep_buf(params).len(), self.cfg_buf(params).len())
    }

    fn validate(&self, p: RawParams) -> Result<()> {
        if self.ep_blind == self.cfg_blind {
            bail!("raw H_ep and H_cfg reuse the same blinding value");
        }
        if self.edges.is_empty() {
            bail!("raw CFG has no edges");
        }
        if self.edges.len() > p.edge_cap {
            bail!(
                "{} raw edges exceed EDGE_CAP={}",
                self.edges.len(),
                p.edge_cap
            );
        }
        if self.steps.is_empty() {
            bail!("raw EP is empty");
        }
        if self.steps.len() > p.ep_cap {
            bail!(
                "{} raw EP rows exceed EP_CAP={}",
                self.steps.len(),
                p.ep_cap
            );
        }
        if p.ep_cap > p.ep_encoding.hint_limit() {
            bail!(
                "EP_CAP={} exceeds the {}-bit RET hint selected by {:?}",
                p.ep_cap,
                p.ep_encoding.hint_bits(),
                p.ep_encoding
            );
        }
        if p.ep_cap < 2 {
            bail!("EP_CAP must include the entry row and at least one transition");
        }

        let check_addr = |what: &str, a: u64| -> Result<()> {
            if a == 0 {
                bail!("{what}: address zero is reserved for inactive rows");
            }
            Ok(())
        };

        let mut endpoints = HashSet::new();
        for (j, e) in self.edges.iter().enumerate() {
            check_addr(&format!("edge {j} source"), e.src)?;
            check_addr(&format!("edge {j} destination"), e.dst)?;
            if !matches!(e.etype, ET_JMP | ET_CAL | ET_CRT) {
                bail!("edge {j} has invalid type {}", e.etype);
            }
            if !endpoints.insert((e.src, e.dst)) {
                bail!(
                    "raw CFG repeats endpoint pair {:#x}->{:#x}; type aliases are forbidden",
                    e.src,
                    e.dst
                );
            }
        }

        for (t, s) in self.steps.iter().enumerate() {
            check_addr(&format!("step {t} destination"), s.dst)?;
            if s.tag > TAG_RESERVED {
                bail!("step {t} has invalid tag {}", s.tag);
            }
            if s.tag == TAG_RESERVED {
                bail!("step {t} uses the reserved padding tag in an active row");
            }
            if s.tag == TAG_CAL {
                check_addr(&format!("step {t} call return site"), s.aux)?;
            } else if s.aux != 0 {
                bail!("step {t} is not CAL but carries raw aux {:#x}", s.aux);
            }
            if s.tag == TAG_RET {
                if s.hint as usize >= t {
                    bail!("step {t}: RET hint {} does not precede the return", s.hint);
                }
            } else if s.hint != 0 {
                bail!("step {t} is not RET but carries hint {}", s.hint);
            }
        }
        if self.steps[0].tag == TAG_CAL {
            bail!("entry row cannot be a CAL");
        }

        self.check_walk()?;
        self.check_call_sites()?;
        self.check_shadow_stack()?;
        Ok(())
    }

    fn edge_set(&self) -> HashSet<[u64; RAW_ROW_WORDS]> {
        self.edges.iter().map(|e| e.key()).collect()
    }

    fn check_walk(&self) -> Result<()> {
        let edges = self.edge_set();
        for t in 1..self.steps.len() {
            let s = self.steps[t];
            // Returns are authorized by the call-site CRT declaration and the exact LIFO shadow
            // stack.  Static/provider CFG registries intentionally do not enumerate RET targets.
            if s.tag == TAG_RET {
                continue;
            }
            let want = RawEdge {
                src: self.steps[t - 1].dst,
                dst: s.dst,
                etype: etype_of_tag(s.tag),
            };
            if !edges.contains(&want.key()) {
                bail!(
                    "raw step {t}: {:#x}->{:#x} (type {}) is not a CFG edge",
                    want.src,
                    want.dst,
                    want.etype
                );
            }
        }
        Ok(())
    }

    fn check_call_sites(&self) -> Result<()> {
        let edges = self.edge_set();
        for t in 1..self.steps.len() {
            let s = self.steps[t];
            if s.tag != TAG_CAL {
                continue;
            }
            let want = RawEdge {
                src: self.steps[t - 1].dst,
                dst: s.aux,
                etype: ET_CRT,
            };
            if !edges.contains(&want.key()) {
                bail!(
                    "raw step {t}: call site {:#x} does not declare return site {:#x}",
                    want.src,
                    want.dst
                );
            }
        }
        Ok(())
    }

    fn check_shadow_stack(&self) -> Result<()> {
        let mut stack = Vec::new();
        for (t, s) in self.steps.iter().enumerate() {
            match s.tag {
                TAG_CAL => stack.push(s.aux),
                TAG_RET => match stack.pop() {
                    None => bail!("raw step {t}: RET on an empty shadow stack"),
                    Some(want) if want != s.dst => bail!(
                        "raw step {t}: returns to {:#x}, top of shadow stack is {want:#x}",
                        s.dst
                    ),
                    _ => {}
                },
                _ => {}
            }
        }
        if !stack.is_empty() {
            bail!("raw EP is unbalanced: {} call(s) remain", stack.len());
        }
        Ok(())
    }

    fn cfg_table(&self, p: RawParams) -> Vec<[u64; RAW_ROW_WORDS]> {
        let mut table = Vec::with_capacity(p.edge_cap);
        table.extend(self.edges.iter().map(|e| e.key()));
        for j in self.edges.len()..p.edge_cap {
            table.push([0, ET_JMP, j as u64 + 1]);
        }
        table
    }

    fn cfg_buf(&self, p: RawParams) -> Vec<u64> {
        let mut out = vec![0u64; RAW_CFG_HEADER_WORDS];
        out[0] = MAGIC_RAW_CFG;
        out[1] = p.edge_cap as u64;
        out[2] = self.edges.len() as u64;
        out[3] = RAW_ADDR_BITS as u64;
        let [lo, hi] = self.cfg_blind.words();
        out[RAW_CFG_BLIND_LO] = lo;
        out[RAW_CFG_BLIND_HI] = hi;
        out.extend(self.cfg_table(p).into_iter().flatten());
        out
    }

    fn ep_buf(&self, p: RawParams) -> Vec<u64> {
        let mut out = vec![0u64; RAW_EP_HEADER_WORDS + RAW_ROW_WORDS * p.ep_cap];
        out[0] = p.ep_encoding.magic();
        out[1] = p.ep_cap as u64;
        out[2] = self.steps.len() as u64;
        out[3] = RAW_ADDR_BITS as u64;
        let [lo, hi] = self.ep_blind.words();
        out[4] = lo;
        out[5] = hi;
        out[6] = SHARED_HINT_BITS as u64;
        out[RAW_EP_PATH_MODE] = p.path_mode.header_word();
        for (t, step) in self.steps.iter().enumerate() {
            let start = RAW_EP_HEADER_WORDS + RAW_ROW_WORDS * t;
            out[start..start + RAW_ROW_WORDS].copy_from_slice(&step.words(p.ep_encoding));
        }
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RawParams {
    edge_cap: usize,
    ep_cap: usize,
    ep_encoding: RawEpEncoding,
    path_mode: RawPathMode,
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
        if self.ep_cap <= INLINE_HINT_LIMIT {
            INLINE_MULT_BITS
        } else {
            // Enough to count every query in the largest possible multiplicity.
            let max_queries = 2 * (self.ep_cap - 1);
            usize::BITS as usize - max_queries.leading_zeros() as usize
        }
    }
}

#[derive(Clone, Copy)]
struct RawRecordWires {
    dst: Wire,
    aux: Wire,
    hint: Wire,
    etype: Wire,
    is_cal: Wire,
    is_ret: Wire,
    inactive: Wire,
}

#[derive(Clone, Copy)]
struct G {
    lo: Wire,
    hi: Wire,
}

fn gmul(b: &CircuitBuilder, x: G, y: G) -> G {
    let (lo, hi) = b.bmul(x.lo, x.hi, y.lo, y.hi);
    G { lo, hi }
}

fn gsel(b: &CircuitBuilder, c: Wire, t: G, f: G) -> G {
    G {
        lo: b.select(c, t.lo, f.lo),
        hi: b.select(c, t.hi, f.hi),
    }
}

fn split_be(b: &CircuitBuilder, w: Wire, mask32: Wire) -> [Wire; 2] {
    [b.shr(w, 32), b.band(w, mask32)]
}

fn dom_words(b: &CircuitBuilder, dom: &[u8; 16]) -> Vec<Wire> {
    dom.chunks(4)
        .map(|c| b.add_constant_64(u32::from_be_bytes(c.try_into().unwrap()) as u64))
        .collect()
}

fn pack4(b: &CircuitBuilder, d8: [Wire; 8]) -> [Wire; 4] {
    core::array::from_fn(|i| b.bxor(b.shl(d8[2 * i], 32), d8[2 * i + 1]))
}

fn bind_raw_digest(b: &CircuitBuilder, name: &str, buf: &[Wire], public: [Wire; 4], mask32: Wire) {
    let sb = b.subcircuit(format!("raw/sha/{name}"));
    let mut msg = Vec::with_capacity(buf.len() * 2);
    for &word in buf {
        msg.extend_from_slice(&split_be(&sb, word, mask32));
    }
    let digest = sha256_fixed(&sb, &msg, buf.len() * 8);
    sb.assert_eq_v(name, pack4(&sb, digest), public);
}

struct RawBinMult {
    mpack: Vec<Wire>,
    n_tab: usize,
}

impl RawBinMult {
    #[allow(clippy::too_many_arguments)]
    fn build(
        b: &CircuitBuilder,
        p: RawParams,
        table: &[[Wire; RAW_ROW_WORDS]],
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
        let n_q = 2 * (p.ep_cap - 1);

        let mut queries = Vec::with_capacity(n_q);
        for t in 1..p.ep_cap {
            let sb = b.subcircuit(format!("raw/bm/q[{t}]"));
            let neutral0 = table[(2 * (t - 1)) % n_tab];
            let neutral1 = table[(2 * (t - 1) + 1) % n_tab];
            let edge = [dsts[t - 1], etypes[t], dsts[t]];
            let skip_edge_membership = sb.bor(inactive[t], is_rets[t]);
            queries.push(core::array::from_fn(|i| {
                sb.select(skip_edge_membership, neutral0[i], edge[i])
            }));
            let call_site = [dsts[t - 1], sb.add_constant_64(ET_CRT), auxs[t]];
            queries.push(core::array::from_fn(|i| {
                sb.select(is_cals[t], call_site[i], neutral1[i])
            }));
        }

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

        // A 130-bit typed edge must never be truncated into GF(2^128).
        // Each type gets its own transcript-separated channel; within that channel
        // the complete pair (src,dst) injects as hi=src, lo=dst. The same sealed
        // multiplicity vector is used in all channels, preserving typed equality.
        for channel in [ET_JMP, ET_CAL, ET_CRT] {
            let h = {
                let sb = b.subcircuit(format!("raw64/bm/challenge/{channel}"));
                let mut msg = dom_words(&sb, DOM_BM_CH);
                msg.push(sb.add_constant_64(channel)); // canonical 32-bit channel word
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
            let channel_word = b.add_constant_64(channel);
            let factor = |sb: &CircuitBuilder, key: [Wire; RAW_ROW_WORDS]| {
                let denominator = G {
                    lo: sb.bxor(key[2], challenge.lo),
                    hi: sb.bxor(key[0], challenge.hi),
                };
                gsel(sb, sb.icmp_eq(key[1], channel_word), denominator, one_g)
            };
            let mut lhs = factor(b, queries[0]);
            for (i, &query) in queries.iter().enumerate().skip(1) {
                let sb = b.subcircuit(format!("raw64/bm/{channel}/lhs[{i}]"));
                lhs = gmul(&sb, lhs, factor(&sb, query));
            }
            let mut rhs = one_g;
            for (j, &key) in table.iter().enumerate() {
                let sb = b.subcircuit(format!("raw64/bm/{channel}/rhs[{j}]"));
                let mut power = factor(&sb, key);
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
            b.assert_eq(format!("raw64/bm/{channel}/gp_lo"), lhs.lo, rhs.lo);
            b.assert_eq(format!("raw64/bm/{channel}/gp_hi"), lhs.hi, rhs.hi);
        }

        Self { mpack, n_tab }
    }

    fn host_queries(
        inst: &RawInstance,
        p: RawParams,
        table: &[[u64; RAW_ROW_WORDS]],
    ) -> Vec<[u64; RAW_ROW_WORDS]> {
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

    fn host_multiplicities(
        inst: &RawInstance,
        p: RawParams,
        table: &[[u64; RAW_ROW_WORDS]],
    ) -> Result<Vec<u64>> {
        let queries = Self::host_queries(inst, p, table);
        let mut first = std::collections::HashMap::new();
        for (j, &key) in table.iter().enumerate() {
            first.entry(key).or_insert(j);
        }
        let mut mult = vec![0u64; table.len()];
        for query in queries {
            let Some(&j) = first.get(&query) else {
                bail!("raw membership query {query:x?} is not in the typed CFG table");
            };
            mult[j] += 1;
        }
        Ok(mult)
    }

    fn preflight(inst: &RawInstance, p: RawParams) -> Result<(usize, u64)> {
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

    fn populate(&self, w: &mut WitnessFiller, inst: &RawInstance, p: RawParams) -> Result<()> {
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

struct RawShadow;

impl RawShadow {
    fn build(
        b: &CircuitBuilder,
        p: RawParams,
        records: &[RawRecordWires],
        ep_digest: [Wire; 4],
        cfg_digest: [Wire; 4],
    ) -> Self {
        const SP_BITS: u32 = 15;
        // Lossless 128-bit tuple: lo=address[64], hi=active[1] at bit63,
        // depth[15] at bits24..38, timestamp[24] at bits0..23. Unused bits are zero.
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

            let push = G {
                lo: record.aux,
                hi: sb.bxor_multi(&[real, sb.shl(slot, 24), sb.add_constant_64(t as u64)]),
            };
            let pop = G {
                lo: record.dst,
                hi: sb.bxor_multi(&[real, sb.shl(slot, 24), record.hint]),
            };
            if t >= 1 {
                sb.assert_true(
                    "hint_lt_time",
                    sb.icmp_ult(record.hint, sb.add_constant_64(t as u64)),
                );
            }
            pushes.push(gsel(&sb, record.is_cal, push, G { lo: zero, hi: zero }));
            pops.push(gsel(&sb, record.is_ret, pop, G { lo: zero, hi: zero }));
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
            let den = |key: G| G {
                lo: sb.bxor(key.lo, challenge.lo),
                hi: sb.bxor(key.hi, challenge.hi),
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

pub(crate) struct RawCfgWalk {
    params: RawParams,
    ep_digest: [Wire; 4],
    cfg_digest: [Wire; 4],
    entry: Wire,
    final_node: Wire,
    n_edges: Wire,
    ep_len: Wire,
    table: Vec<[Wire; RAW_ROW_WORDS]>,
    steps: Vec<[Wire; RAW_ROW_WORDS]>,
    ep_blind_lo: Wire,
    ep_blind_hi: Wire,
    cfg_blind_lo: Wire,
    cfg_blind_hi: Wire,
    binmult: RawBinMult,
}

impl RawCfgWalk {
    fn build(b: &CircuitBuilder, params: RawParams) -> Self {
        Self::build_with_shadow(b, params, true)
    }

    fn build_with_shadow(b: &CircuitBuilder, params: RawParams, include_shadow: bool) -> Self {
        let mask32 = b.add_constant(Word::MASK_32);
        let zero = b.add_constant_64(0);
        let one = b.add_constant_64(1);

        let ep_digest = core::array::from_fn(|_| b.add_inout());
        let cfg_digest = core::array::from_fn(|_| b.add_inout());
        let entry = b.add_inout();
        let final_node = b.add_inout();

        let n_edges = b.add_witness();
        let ep_len = b.add_witness();
        let table: Vec<[Wire; RAW_ROW_WORDS]> = (0..params.edge_cap)
            .map(|_| core::array::from_fn(|_| b.add_witness()))
            .collect();
        let steps: Vec<[Wire; RAW_ROW_WORDS]> = (0..params.ep_cap)
            .map(|_| core::array::from_fn(|_| b.add_witness()))
            .collect();
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
        cfg_buf.extend(table.iter().flatten().copied());
        let mut ep_buf = vec![
            b.add_constant_64(params.ep_encoding.magic()),
            b.add_constant_64(params.ep_cap as u64),
            ep_len,
            b.add_constant_64(RAW_ADDR_BITS as u64),
            ep_blind_lo,
            ep_blind_hi,
            b.add_constant_64(SHARED_HINT_BITS as u64),
            b.add_constant_64(params.path_mode.header_word()),
            zero,
            zero,
        ];
        ep_buf.extend(steps.iter().flatten().copied());

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

        // Canonical table padding cannot alias a real edge: real src and dst are
        // nonzero; padding is the unique tuple [0, JMP, index+1]. All types are
        // checked here so no unsupported type can disappear from all GP channels.
        let cal_tag = b.add_constant_64(TAG_CAL);
        let ret_tag = b.add_constant_64(TAG_RET);
        let crt_type = b.add_constant_64(ET_CRT);
        for (j, &[src, etype, dst]) in table.iter().enumerate() {
            let sb = b.subcircuit(format!("raw64/cfg[{j}]"));
            let active = sb.icmp_ult(sb.add_constant_64(j as u64), n_edges);
            let inactive = sb.bnot(active);
            sb.assert_true(
                "active_src_nonzero",
                sb.bor(inactive, sb.icmp_ne(src, zero)),
            );
            sb.assert_true(
                "active_dst_nonzero",
                sb.bor(inactive, sb.icmp_ne(dst, zero)),
            );
            let allowed = sb.bor(
                sb.icmp_eq(etype, zero),
                sb.bor(sb.icmp_eq(etype, cal_tag), sb.icmp_eq(etype, crt_type)),
            );
            sb.assert_true("typed_channel", allowed);
            sb.assert_eq_cond("padding_src", src, zero, inactive);
            sb.assert_eq_cond("padding_type", etype, zero, inactive);
            sb.assert_eq_cond(
                "padding_index",
                dst,
                sb.add_constant_64(j as u64 + 1),
                inactive,
            );
        }
        let mut records = Vec::with_capacity(params.ep_cap);
        for (t, &[tag, dst, payload]) in steps.iter().enumerate() {
            let sb = b.subcircuit(format!("raw64/rec[{t}]"));
            let active = sb.icmp_ult(sb.add_constant_64(t as u64), ep_len);
            let inactive = sb.bnot(active);
            for (name, word) in [("tag", tag), ("dst", dst), ("payload", payload)] {
                sb.assert_eq_cond(format!("padding_zero/{name}"), word, zero, inactive);
            }
            sb.assert_true(
                "active_dst_nonzero",
                sb.bor(inactive, sb.icmp_ne(dst, zero)),
            );
            sb.assert_true("active_tag_valid", sb.icmp_ule(tag, ret_tag));
            let is_cal = sb.icmp_eq(tag, cal_tag);
            let is_ret = sb.icmp_eq(tag, ret_tag);
            let aux = sb.select(is_cal, payload, zero);
            let hint = sb.select(is_ret, payload, zero);
            sb.assert_eq("payload_only_cal_ret", payload, sb.bxor(aux, hint));
            sb.assert_zero("hint_24_bits", sb.shr(hint, SHARED_HINT_BITS));
            sb.assert_true(
                "cal_aux_nonzero",
                sb.bor(sb.bnot(is_cal), sb.icmp_ne(aux, zero)),
            );
            records.push(RawRecordWires {
                dst,
                aux,
                hint,
                etype: tag,
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
        let binmult = RawBinMult::build(
            b, params, &table, &dsts, &etypes, &auxs, &is_cals, &is_rets, &inactive, ep_digest,
            cfg_digest,
        );

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
            binmult,
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

    fn populate_unchecked(
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
        for (i, row) in self.table.iter().enumerate() {
            for (part, &wire) in row.iter().enumerate() {
                w[wire] = Word(cfg_buf[RAW_CFG_HEADER_WORDS + RAW_ROW_WORDS * i + part]);
            }
        }
        for (i, row) in self.steps.iter().enumerate() {
            for (part, &wire) in row.iter().enumerate() {
                w[wire] = Word(ep_buf[RAW_EP_HEADER_WORDS + RAW_ROW_WORDS * i + part]);
            }
        }
        let [lo, hi] = inst.ep_blind.words();
        w[self.ep_blind_lo] = Word(lo);
        w[self.ep_blind_hi] = Word(hi);
        let [lo, hi] = inst.cfg_blind.words();
        w[self.cfg_blind_lo] = Word(lo);
        w[self.cfg_blind_hi] = Word(hi);
        self.binmult.populate(w, inst, self.params)?;
        Ok((ep_digest, cfg_digest))
    }
}

pub(crate) fn build_raw_circuit(params: RawParams) -> (Circuit, RawCfgWalk) {
    let builder = CircuitBuilder::new();
    let walk = RawCfgWalk::build(&builder, params);
    (builder.build(), walk)
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

pub(crate) fn validate_capacity_bounds(raw: &RawInstance, params: RawParams) -> Result<()> {
    let minimum_edge_cap = raw.edges.len().max(8);
    let minimum_ep_cap = raw.steps.len().max(16);
    ensure!(
        params.edge_cap >= minimum_edge_cap,
        "signed EDGE_CAP={} is smaller than required capacity {minimum_edge_cap}",
        params.edge_cap
    );
    ensure!(
        params.ep_cap >= minimum_ep_cap,
        "signed EP_CAP={} is smaller than required capacity {minimum_ep_cap}",
        params.ep_cap
    );
    Ok(())
}

pub(crate) fn validate_raw_instance(raw: &RawInstance, params: RawParams) -> Result<()> {
    raw.validate(params)
}

pub(crate) fn preflight_raw_instance(raw: &RawInstance, params: RawParams) -> Result<(usize, u64)> {
    RawBinMult::preflight(raw, params)
}

/// Encode the authenticated raw statement as the ten inout words accepted by the verifier API.
///
/// Circuit constants are deliberately absent: current Binius64 verifiers obtain them from the
/// constraint system and reject callers that restate the complete public segment.
pub(crate) fn canonical_inout_words(values: RawPublicValues) -> [Word; RAW_N_PUBLIC] {
    let mut inout = [Word::ZERO; RAW_N_PUBLIC];
    for (i, word) in digest_words(&values.h_ep).into_iter().enumerate() {
        inout[RAW_OFF_EP_DIGEST + i] = Word(word);
    }
    for (i, word) in digest_words(&values.h_cfg).into_iter().enumerate() {
        inout[RAW_OFF_CFG_DIGEST + i] = Word(word);
    }
    inout[RAW_OFF_ENTRY] = Word(values.entry);
    inout[RAW_OFF_FINAL] = Word(values.final_node);
    inout
}

/// Rebuild the complete Binius public segment for prover-side witness consistency checks.
///
/// This vector contains verifier-owned circuit constants in addition to the ten statement words;
/// it must not be passed to the current Binius64 verifier API.
pub(crate) fn canonical_public_words(
    cs: &ConstraintSystem,
    values: RawPublicValues,
) -> Result<Vec<Word>> {
    ensure!(
        cs.n_inout == RAW_N_PUBLIC,
        "compiled raw public ABI has {} inout words, expected {RAW_N_PUBLIC}",
        cs.n_inout
    );
    let mut public = vec![Word::ZERO; cs.n_public_words(InoutSegment::Public)];
    public[..cs.n_const()].copy_from_slice(&cs.constants);
    let base = cs.offset_inout();
    public[base..base + RAW_N_PUBLIC].copy_from_slice(&canonical_inout_words(values));
    Ok(public)
}

#[cfg(test)]
#[path = "raw64/tests.rs"]
mod tests;
