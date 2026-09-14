//! Typed input loading, canonical artifact buffers, and host validation.

use super::*;

#[derive(Clone, Debug)]
pub(crate) struct RawInstance {
    pub(super) node_count: usize,
    pub(super) edges: Vec<RawEdge>,
    pub(super) steps: Vec<RawStep>,
    /// Per-report secret opening for the raw execution-path commitment.
    pub(super) ep_blind: Blinding,
    /// Independently provisioned secret opening for the raw CFG commitment.
    pub(super) cfg_blind: Blinding,
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

    pub(super) fn validate(&self, p: RawParams) -> Result<()> {
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
            if a >= RAW_ADDR_LIMIT {
                bail!("{what}: address {a:#x} exceeds the raw-{RAW_ADDR_BITS} profile");
            }
            Ok(())
        };

        let mut endpoints = HashSet::new();
        for (j, e) in self.edges.iter().enumerate() {
            check_addr(&format!("edge {j} source"), e.src)?;
            check_addr(&format!("edge {j} destination"), e.dst)?;
            if e.etype > ET_CRT {
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

    pub(super) fn edge_set(&self) -> HashSet<u64> {
        self.edges.iter().map(|e| e.key()).collect()
    }

    pub(super) fn check_walk(&self) -> Result<()> {
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

    pub(super) fn check_call_sites(&self) -> Result<()> {
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

    pub(super) fn check_shadow_stack(&self) -> Result<()> {
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

    pub(super) fn cfg_table(&self, p: RawParams) -> Vec<u64> {
        let mut table = Vec::with_capacity(p.edge_cap);
        table.extend(self.edges.iter().map(|e| e.key()));
        for j in self.edges.len()..p.edge_cap {
            table.push(PAD_KEY | j as u64);
        }
        table
    }

    pub(super) fn cfg_buf(&self, p: RawParams) -> Vec<u64> {
        let mut out = vec![0u64; RAW_CFG_HEADER_WORDS];
        out[0] = MAGIC_RAW_CFG;
        out[1] = p.edge_cap as u64;
        out[2] = self.edges.len() as u64;
        out[3] = RAW_ADDR_BITS as u64;
        let [lo, hi] = self.cfg_blind.words();
        out[RAW_CFG_BLIND_LO] = lo;
        out[RAW_CFG_BLIND_HI] = hi;
        out.extend(self.cfg_table(p));
        out
    }

    pub(super) fn ep_buf(&self, p: RawParams) -> Vec<u64> {
        let mut out = vec![0u64; RAW_EP_HEADER_WORDS + p.ep_cap];
        out[0] = p.ep_encoding.magic();
        out[1] = p.ep_cap as u64;
        out[2] = self.steps.len() as u64;
        out[3] = RAW_ADDR_BITS as u64;
        let [lo, hi] = self.ep_blind.words();
        out[4] = lo;
        out[5] = hi;
        if p.ep_encoding == RawEpEncoding::SharedPayload24 {
            out[6] = SHARED_HINT_BITS as u64;
        }
        out[RAW_EP_PATH_MODE] = p.path_mode.header_word();
        for (t, step) in self.steps.iter().enumerate() {
            out[RAW_EP_HEADER_WORDS + t] = step.word(p.ep_encoding);
        }
        out
    }
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
