//! Canonical raw24/CF2 encoding shared by the PLONK and Binius64 relations.
//!
//! The loader accepts only the provider's independently generated `translator`,
//! `typed_cfg`, and `recorded_path` artifacts.  In particular, execution-path rows
//! never add or retype CFG edges.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use ark_ff::PrimeField;

use crate::poseidon::{hash_words, CFG_DOMAIN, EP_DOMAIN};

pub const RAW_ADDR_BITS: u32 = 24;
pub const RAW_ADDR_LIMIT: u64 = 1 << RAW_ADDR_BITS;
pub const RAW_SCOPE_SENTINEL: u64 = RAW_ADDR_LIMIT - 1;
pub const RAW_GATEWAY_BASE: u64 = RAW_ADDR_LIMIT - 0x1_0000;
pub const PROVIDER_GATEWAY_BASE: u64 = 0xfffe_0000;
pub const PROVIDER_GATEWAY_LIMIT: u64 = PROVIDER_GATEWAY_BASE + 0xffff;

pub const ET_JMP: u64 = 0;
pub const ET_CAL: u64 = 1;
pub const ET_RET: u64 = 2;
pub const ET_CRT: u64 = 3;

pub const TAG_JMP: u64 = 0;
pub const TAG_CAL: u64 = 1;
pub const TAG_RET: u64 = 2;
pub const TAG_RESERVED: u64 = 3;

pub const MAGIC_RAW_CFG: u64 = 0x4346_472d_464c_4154; // `CFG-FLAT`
pub const MAGIC_RAW_EP_INLINE: u64 = 0x4550_494e_4c49_4e45; // `EPINLINE`
pub const MAGIC_RAW_EP_SHARED: u64 = 0x4550_5348_4152_4544; // `EPSHARED`
pub const RAW_CFG_HEADER_WORDS: usize = 10;
pub const RAW_EP_HEADER_WORDS: usize = 10;
pub const PAD_KEY: u64 = 1 << 63;

const INLINE_HINT_BITS: u32 = 14;
const SHARED_HINT_BITS: u32 = 24;
const INLINE_HINT_LIMIT: usize = 1 << INLINE_HINT_BITS;
const SHARED_HINT_LIMIT: usize = 1 << SHARED_HINT_BITS;
const RAW_EDGE_SHIFT: u32 = RAW_ADDR_BITS + 2;
const RAW_HINT_SHIFT: u32 = 2 + 2 * RAW_ADDR_BITS;

pub type RawResult<T> = Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathMode {
    Complete,
    Shadow,
}

impl PathMode {
    pub const fn header_word(self) -> u64 {
        match self {
            Self::Complete => 0x434f_4d50_4c45_5445, // `COMPLETE`
            Self::Shadow => 0x5348_4144_4f57_4544,   // `SHADOWED`
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Shadow => "shadow",
        }
    }

    pub fn from_label(label: &str) -> RawResult<Self> {
        match label {
            "complete" => Ok(Self::Complete),
            "shadow" => Ok(Self::Shadow),
            other => Err(format!("unsupported raw path_mode {other:?}")),
        }
    }
}

impl TryFrom<&str> for PathMode {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_label(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawEncoding {
    Inline14,
    Shared24,
}

impl RawEncoding {
    pub fn for_ep_cap(ep_cap: usize) -> RawResult<Self> {
        if ep_cap <= INLINE_HINT_LIMIT {
            Ok(Self::Inline14)
        } else if ep_cap <= SHARED_HINT_LIMIT {
            Ok(Self::Shared24)
        } else {
            Err(format!(
                "EP_CAP={ep_cap} exceeds the {SHARED_HINT_BITS}-bit RET hint"
            ))
        }
    }

    pub const fn magic(self) -> u64 {
        match self {
            Self::Inline14 => MAGIC_RAW_EP_INLINE,
            Self::Shared24 => MAGIC_RAW_EP_SHARED,
        }
    }

    pub const fn hint_bits(self) -> u32 {
        match self {
            Self::Inline14 => INLINE_HINT_BITS,
            Self::Shared24 => SHARED_HINT_BITS,
        }
    }

    pub const fn hint_limit(self) -> usize {
        1 << self.hint_bits()
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Inline14 => "inline14",
            Self::Shared24 => "shared24",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawParams {
    pub edge_cap: usize,
    pub ep_cap: usize,
    pub path_mode: PathMode,
}

impl RawParams {
    pub fn encoding(self) -> RawResult<RawEncoding> {
        RawEncoding::for_ep_cap(self.ep_cap)
    }

    pub fn mult_bits(self) -> RawResult<usize> {
        self.encoding()?;
        let maximum = self.membership_query_count()?;
        // A single CFG key can receive every query (for example, a one-entry
        // table used by all neutral padding queries), so the inclusive range
        // is 0..=maximum. bit_length(maximum) = ceil(log2(maximum + 1)).
        Ok(bit_length(maximum))
    }

    pub fn membership_query_count(self) -> RawResult<usize> {
        if self.ep_cap < 2 {
            return Err("EP_CAP must include the entry row and at least one transition".to_owned());
        }
        let transitions = self
            .ep_cap
            .checked_sub(1)
            .ok_or_else(|| "EP_CAP underflows the membership-query bound".to_owned())?;
        2usize
            .checked_mul(transitions)
            .ok_or_else(|| "EP_CAP overflows the membership-query bound".to_owned())
    }

    /// Width for the shadow gadget's `slot` range check.
    ///
    /// A balanced trace of capacity `n` has one mandatory entry row. The
    /// largest slot observable by a CALL, RET, or neutral row is therefore
    /// `floor(n / 2) - 1`: odd capacities attain it at the deepest CALL/RET,
    /// and even capacities attain it with a neutral row at maximum depth.
    /// This PLONK backend's range gate accepts only even widths, so return the
    /// smallest positive even width covering that exact maximum.
    pub fn shadow_slot_bits(self) -> RawResult<usize> {
        if self.ep_cap < 2 {
            return Err("EP_CAP must include the entry row and at least one transition".to_owned());
        }
        self.encoding()?;
        let maximum_slot = self.ep_cap / 2 - 1;
        let logical_bits = bit_length(maximum_slot).max(1);
        Ok((logical_bits + 1) & !1)
    }

    fn validate(self) -> RawResult<RawEncoding> {
        if self.edge_cap == 0 {
            return Err("EDGE_CAP must be nonzero".to_owned());
        }
        if self.edge_cap > RAW_ADDR_LIMIT as usize {
            return Err("EDGE_CAP exceeds the reviewed raw24 capacity bound".to_owned());
        }
        if self.ep_cap < 2 {
            return Err("EP_CAP must include the entry row and at least one transition".to_owned());
        }
        self.encoding()
    }
}

fn bit_length(maximum: usize) -> usize {
    (usize::BITS - maximum.leading_zeros()) as usize
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RawOpenings {
    pub ep: [u64; 2],
    pub cfg: [u64; 2],
}

impl RawOpenings {
    fn validate(self) -> RawResult<()> {
        if self.ep == [0, 0] {
            return Err("raw H_ep opening must be nonzero".to_owned());
        }
        if self.cfg == [0, 0] {
            return Err("raw H_cfg opening must be nonzero".to_owned());
        }
        if self.ep == self.cfg {
            return Err("raw H_ep and H_cfg reuse the same blinding value".to_owned());
        }
        Ok(())
    }
}

impl core::fmt::Debug for RawOpenings {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RawOpenings(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RawEdge {
    pub src: u64,
    pub dst: u64,
    pub etype: u64,
}

impl RawEdge {
    pub fn key(self) -> u64 {
        assert!(canonical_addr(self.src), "raw edge source is not canonical");
        assert!(
            canonical_addr(self.dst),
            "raw edge destination is not canonical"
        );
        assert!(
            matches!(self.etype, ET_JMP | ET_CAL | ET_CRT),
            "raw edge type is not canonical"
        );
        (self.src << RAW_EDGE_SHIFT) | (self.etype << RAW_ADDR_BITS) | self.dst
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawStep {
    pub dst: u64,
    pub tag: u64,
    pub aux: u64,
    pub hint: u32,
}

impl RawStep {
    pub fn word(self, encoding: RawEncoding) -> u64 {
        assert!(
            canonical_addr(self.dst),
            "raw step destination is not canonical"
        );
        assert!(self.tag <= TAG_RESERVED, "raw step tag is not canonical");
        assert!(
            self.aux < RAW_ADDR_LIMIT,
            "raw step auxiliary address is not canonical"
        );
        assert!(
            (self.hint as usize) < encoding.hint_limit(),
            "raw step hint is not canonical for this encoding"
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
            RawEncoding::Inline14 => {
                (self.tag & 3)
                    | (self.dst << 2)
                    | (self.aux << RAW_EDGE_SHIFT)
                    | ((self.hint as u64) << RAW_HINT_SHIFT)
            }
            RawEncoding::Shared24 => {
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

#[derive(Clone, Debug)]
pub struct RawInstance {
    pub params: RawParams,
    pub encoding: RawEncoding,
    pub node_count: usize,
    pub edges: Vec<RawEdge>,
    pub steps: Vec<RawStep>,
    pub openings: RawOpenings,
}

impl RawInstance {
    pub fn load(
        private_dir: impl AsRef<Path>,
        params: RawParams,
        openings: RawOpenings,
    ) -> RawResult<Self> {
        load(private_dir, params, openings)
    }

    pub fn entry(&self) -> u64 {
        self.steps[0].dst
    }

    pub fn final_node(&self) -> u64 {
        self.steps[self.steps.len() - 1].dst
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn ep_len(&self) -> usize {
        self.steps.len()
    }

    pub fn validate(&self) -> RawResult<()> {
        let encoding = self.params.validate()?;
        if encoding != self.encoding {
            return Err("raw EP encoding is not the encoding derived from EP_CAP".to_owned());
        }
        self.openings.validate()?;
        if self.node_count == 0 {
            return Err("translator contains no raw nodes".to_owned());
        }
        if self.edges.is_empty() {
            return Err("raw CFG has no edges".to_owned());
        }
        if self.edges.len() > self.params.edge_cap {
            return Err(format!(
                "{} raw edges exceed EDGE_CAP={}",
                self.edges.len(),
                self.params.edge_cap
            ));
        }
        if self.steps.is_empty() {
            return Err("raw EP is empty".to_owned());
        }
        if self.steps.len() > self.params.ep_cap {
            return Err(format!(
                "{} raw EP rows exceed EP_CAP={}",
                self.steps.len(),
                self.params.ep_cap
            ));
        }

        let mut endpoints = HashSet::new();
        let mut previous_key = None;
        for (row, edge) in self.edges.iter().copied().enumerate() {
            check_addr(&format!("edge {row} source"), edge.src)?;
            check_addr(&format!("edge {row} destination"), edge.dst)?;
            if !matches!(edge.etype, ET_JMP | ET_CAL | ET_CRT) {
                return Err(format!(
                    "edge {row} has invalid or noncanonical type {}",
                    edge.etype
                ));
            }
            if !endpoints.insert((edge.src, edge.dst)) {
                return Err(format!(
                    "raw CFG repeats endpoint pair {:#x}->{:#x}; type aliases are forbidden",
                    edge.src, edge.dst
                ));
            }
            let key = edge.key();
            if previous_key.is_some_and(|previous| previous >= key) {
                return Err("raw CFG table is not in strictly increasing full-key order".to_owned());
            }
            previous_key = Some(key);
        }

        for (row, step) in self.steps.iter().copied().enumerate() {
            check_addr(&format!("step {row} destination"), step.dst)?;
            if step.tag > TAG_RET {
                return Err(format!("step {row} has invalid active tag {}", step.tag));
            }
            if step.tag == TAG_CAL {
                check_addr(&format!("step {row} call return site"), step.aux)?;
            } else if step.aux != 0 {
                return Err(format!(
                    "step {row} is not CAL but carries raw aux {:#x}",
                    step.aux
                ));
            }
            if step.tag == TAG_RET {
                if step.hint as usize >= row {
                    return Err(format!(
                        "step {row}: RET hint {} does not precede the return",
                        step.hint
                    ));
                }
            } else if step.hint != 0 {
                return Err(format!(
                    "step {row} is not RET but carries hint {}",
                    step.hint
                ));
            }
        }
        if self.steps[0].tag != TAG_JMP || self.steps[0].aux != 0 || self.steps[0].hint != 0 {
            return Err("entry row must be the canonical JMP header row".to_owned());
        }

        let edge_keys: HashSet<u64> = self.edges.iter().map(|edge| edge.key()).collect();
        let mut stack: Vec<(usize, u64)> = Vec::new();
        for row in 1..self.steps.len() {
            let previous = self.steps[row - 1];
            let step = self.steps[row];
            if step.tag != TAG_RET {
                let edge = RawEdge {
                    src: previous.dst,
                    dst: step.dst,
                    etype: etype_of_tag(step.tag),
                };
                if !edge_keys.contains(&edge.key()) {
                    return Err(format!(
                        "raw step {row}: {:#x}->{:#x} (type {}) is not a static CFG edge",
                        edge.src, edge.dst, edge.etype
                    ));
                }
            }

            match step.tag {
                TAG_CAL => {
                    let crt = RawEdge {
                        src: previous.dst,
                        dst: step.aux,
                        etype: ET_CRT,
                    };
                    if !edge_keys.contains(&crt.key()) {
                        return Err(format!(
                            "raw step {row}: call site {:#x} does not declare return site {:#x}",
                            crt.src, crt.dst
                        ));
                    }
                    stack.push((row, step.aux));
                }
                TAG_RET => {
                    let (call_row, return_site) = stack
                        .pop()
                        .ok_or_else(|| format!("raw step {row}: RET on an empty shadow stack"))?;
                    if return_site != step.dst {
                        return Err(format!(
                            "raw step {row}: returns to {:#x}, top of shadow stack is {return_site:#x}",
                            step.dst
                        ));
                    }
                    if step.hint as usize != call_row {
                        return Err(format!(
                            "raw step {row}: RET hint {} does not name matching CAL row {call_row}",
                            step.hint
                        ));
                    }
                }
                _ => {}
            }
        }
        if !stack.is_empty() {
            return Err(format!(
                "raw EP is unbalanced: {} call(s) remain",
                stack.len()
            ));
        }
        Ok(())
    }

    pub fn cfg_table(&self) -> Vec<u64> {
        let mut table = Vec::with_capacity(self.params.edge_cap);
        table.extend(self.edges.iter().copied().map(RawEdge::key));
        for row in self.edges.len()..self.params.edge_cap {
            table.push(PAD_KEY | row as u64);
        }
        table
    }

    pub fn cfg_words(&self) -> Vec<u64> {
        let mut words = vec![0; RAW_CFG_HEADER_WORDS];
        words[0] = MAGIC_RAW_CFG;
        words[1] = self.params.edge_cap as u64;
        words[2] = self.edges.len() as u64;
        words[3] = RAW_ADDR_BITS as u64;
        words[8] = self.openings.cfg[0];
        words[9] = self.openings.cfg[1];
        words.extend(self.cfg_table());
        words
    }

    pub fn ep_words(&self) -> Vec<u64> {
        let mut words = vec![0; RAW_EP_HEADER_WORDS + self.params.ep_cap];
        words[0] = self.encoding.magic();
        words[1] = self.params.ep_cap as u64;
        words[2] = self.steps.len() as u64;
        words[3] = RAW_ADDR_BITS as u64;
        words[4] = self.openings.ep[0];
        words[5] = self.openings.ep[1];
        if self.encoding == RawEncoding::Shared24 {
            words[6] = SHARED_HINT_BITS as u64;
        }
        words[7] = self.params.path_mode.header_word();
        for (row, step) in self.steps.iter().copied().enumerate() {
            words[RAW_EP_HEADER_WORDS + row] = step.word(self.encoding);
        }
        words
    }

    pub fn h_cfg_poseidon<F: PrimeField>(&self) -> RawResult<F> {
        hash_words(CFG_DOMAIN, &self.cfg_words())
    }

    pub fn h_ep_poseidon<F: PrimeField>(&self) -> RawResult<F> {
        hash_words(EP_DOMAIN, &self.ep_words())
    }
}

pub fn load(
    private_dir: impl AsRef<Path>,
    params: RawParams,
    openings: RawOpenings,
) -> RawResult<RawInstance> {
    let private_dir = private_dir.as_ref();
    let translator = read_ascii(private_dir.join("translator"), "translator")?;
    let typed_cfg = read_ascii(private_dir.join("typed_cfg"), "typed_cfg")?;
    let recorded_path = read_ascii(private_dir.join("recorded_path"), "recorded_path")?;
    parse_artifacts(&translator, &typed_cfg, &recorded_path, params, openings)
}

fn read_ascii(path: PathBuf, artifact: &str) -> RawResult<String> {
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    if !text.is_ascii() {
        return Err(format!("{artifact} must be ASCII"));
    }
    Ok(text)
}

fn parse_artifacts(
    translator: &str,
    typed_cfg: &str,
    recorded_path: &str,
    params: RawParams,
    openings: RawOpenings,
) -> RawResult<RawInstance> {
    let encoding = params.validate()?;
    openings.validate()?;
    let nodes = parse_translator(translator)?;
    let edges = parse_typed_cfg(typed_cfg, &nodes)?;
    let steps = parse_recorded_path(recorded_path, &nodes)?;
    let instance = RawInstance {
        params,
        encoding,
        node_count: nodes.len(),
        edges,
        steps,
        openings,
    };
    instance.validate()?;
    Ok(instance)
}

fn parse_translator(text: &str) -> RawResult<HashSet<u64>> {
    if !text.is_ascii() {
        return Err("translator must be ASCII".to_owned());
    }
    let mut nodes = HashSet::new();
    for (offset, line) in text.lines().enumerate() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 1 || line.contains('#') {
            return Err(format!(
                "translator line {} must contain one raw node",
                offset + 1
            ));
        }
        let node = parse_raw_addr(fields[0])?;
        if !nodes.insert(node) {
            return Err(format!(
                "translator line {} repeats raw node {node:#x}",
                offset + 1
            ));
        }
    }
    if nodes.is_empty() {
        return Err("translator contains no raw nodes".to_owned());
    }
    Ok(nodes)
}

fn parse_typed_cfg(text: &str, nodes: &HashSet<u64>) -> RawResult<Vec<RawEdge>> {
    if !text.is_ascii() {
        return Err("typed_cfg must be ASCII".to_owned());
    }
    let mut edges = Vec::new();
    let mut endpoints = HashSet::new();
    for (offset, line) in text.lines().enumerate() {
        let line_no = offset + 1;
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 3 || line.contains('#') {
            return Err(format!(
                "typed_cfg line {line_no} must contain src type dst"
            ));
        }
        let src = parse_raw_addr(fields[0])?;
        let dst = parse_raw_addr(fields[2])?;
        if !nodes.contains(&src) || !nodes.contains(&dst) {
            return Err(format!(
                "typed_cfg line {line_no} names a node outside translator"
            ));
        }
        let etype = match fields[1] {
            "jmp" => ET_JMP,
            "cal" => ET_CAL,
            "crt" => ET_CRT,
            "ret" => {
                return Err(format!(
                    "typed_cfg line {line_no} contains RET; canonical raw tables contain only JMP/CAL/CRT"
                ))
            }
            other => {
                return Err(format!(
                    "typed_cfg line {line_no} has unknown edge type {other:?}"
                ))
            }
        };
        if !endpoints.insert((src, dst)) {
            return Err(format!(
                "typed_cfg line {line_no} repeats endpoint pair {src:#x}->{dst:#x}; type aliases are forbidden"
            ));
        }
        edges.push(RawEdge { src, dst, etype });
    }
    if edges.is_empty() {
        return Err("typed_cfg contains no raw edges".to_owned());
    }
    edges.sort_unstable_by_key(|edge| edge.key());
    Ok(edges)
}

fn parse_recorded_path(text: &str, nodes: &HashSet<u64>) -> RawResult<Vec<RawStep>> {
    if !text.is_ascii() {
        return Err("recorded_path must be ASCII".to_owned());
    }
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| "recorded_path is empty".to_owned())?;
    let header_fields: Vec<_> = header.split_whitespace().collect();
    if header_fields.len() != 2 || header.contains('#') {
        return Err(
            "recorded_path header must contain exactly initial_node and final_node".to_owned(),
        );
    }
    let mut entry = None;
    let mut declared_final = None;
    for field in header_fields {
        if let Some(value) = field.strip_prefix("initial_node=") {
            if entry.is_some() {
                return Err("recorded_path header repeats initial_node".to_owned());
            }
            entry = Some(parse_raw_addr(value)?);
        } else if let Some(value) = field.strip_prefix("final_node=") {
            if declared_final.is_some() {
                return Err("recorded_path header repeats final_node".to_owned());
            }
            declared_final = Some(parse_raw_addr(value)?);
        } else {
            return Err(format!("recorded_path header has unknown field {field:?}"));
        }
    }
    let entry = entry.ok_or_else(|| "recorded_path header lacks initial_node".to_owned())?;
    let declared_final =
        declared_final.ok_or_else(|| "recorded_path header lacks final_node".to_owned())?;
    if !nodes.contains(&entry) || !nodes.contains(&declared_final) {
        return Err("recorded_path endpoints are outside translator".to_owned());
    }

    let mut steps = vec![RawStep {
        dst: entry,
        tag: TAG_JMP,
        aux: 0,
        hint: 0,
    }];
    for (offset, line) in lines.enumerate() {
        let line_no = offset + 2;
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 2 || line.contains('#') {
            return Err(format!("recorded_path line {line_no} is malformed"));
        }
        let dst = parse_raw_addr(fields[1])?;
        let (tag, aux) = match fields[0] {
            "jump" if fields.len() == 2 => (TAG_JMP, 0),
            "ret" if fields.len() == 2 => (TAG_RET, 0),
            "call" if fields.len() == 3 => (TAG_CAL, parse_raw_addr(fields[2])?),
            other => {
                return Err(format!(
                    "recorded_path line {line_no} has malformed operation {other:?}"
                ))
            }
        };
        if !nodes.contains(&dst) {
            return Err(format!(
                "recorded_path line {line_no} names a destination outside translator"
            ));
        }
        if tag == TAG_CAL && !nodes.contains(&aux) {
            return Err(format!(
                "recorded_path line {line_no} names a call return site outside translator"
            ));
        }
        steps.push(RawStep {
            dst,
            tag,
            aux,
            hint: 0,
        });
    }
    if steps.last().map(|step| step.dst) != Some(declared_final) {
        return Err("recorded_path final row disagrees with final_node".to_owned());
    }

    let mut stack = Vec::new();
    for row in 1..steps.len() {
        match steps[row].tag {
            TAG_CAL => stack.push(row),
            TAG_RET => {
                let call_row = stack
                    .pop()
                    .ok_or_else(|| format!("recorded_path row {row} returns on an empty stack"))?;
                if steps[call_row].aux != steps[row].dst {
                    return Err(format!(
                        "recorded_path row {row} returns to {:#x}, expected {:#x}",
                        steps[row].dst, steps[call_row].aux
                    ));
                }
                steps[row].hint = u32::try_from(call_row)
                    .map_err(|_| format!("matching CAL row {call_row} exceeds u32"))?;
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err(format!(
            "recorded_path leaves {} call(s) unmatched",
            stack.len()
        ));
    }
    Ok(steps)
}

pub fn parse_raw_addr(token: &str) -> RawResult<u64> {
    if token == "SCOPE_RETURN" {
        return Ok(RAW_SCOPE_SENTINEL);
    }
    let digits = token
        .strip_prefix("0x")
        .filter(|digits| {
            !digits.is_empty()
                && digits
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
        .ok_or_else(|| {
            format!("bad raw address {token:?}: expected lowercase 0x-prefixed hexadecimal")
        })?;
    let value = u64::from_str_radix(digits, 16)
        .map_err(|error| format!("bad raw address {token:?}: {error}"))?;
    if (PROVIDER_GATEWAY_BASE..PROVIDER_GATEWAY_LIMIT).contains(&value) {
        return Ok(RAW_GATEWAY_BASE + (value - PROVIDER_GATEWAY_BASE));
    }
    if value == 0 {
        return Err("raw address zero is reserved for inactive rows".to_owned());
    }
    if value >= RAW_GATEWAY_BASE {
        return Err(format!(
            "numeric address {value:#x} is outside raw24 or collides with its reserved token window"
        ));
    }
    Ok(value)
}

const fn canonical_addr(address: u64) -> bool {
    address != 0 && address < RAW_ADDR_LIMIT
}

fn check_addr(label: &str, address: u64) -> RawResult<()> {
    if !canonical_addr(address) {
        if address == 0 {
            Err(format!(
                "{label}: address zero is reserved for inactive rows"
            ))
        } else {
            Err(format!(
                "{label}: address {address:#x} exceeds the raw-{RAW_ADDR_BITS} profile"
            ))
        }
    } else {
        Ok(())
    }
}

const fn etype_of_tag(tag: u64) -> u64 {
    match tag {
        TAG_JMP => ET_JMP,
        TAG_CAL => ET_CAL,
        TAG_RET => ET_RET,
        TAG_RESERVED => ET_CRT,
        _ => tag,
    }
}

#[cfg(test)]
mod tests;
