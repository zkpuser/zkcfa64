//! Stable human-readable and JSON output for the PLONK raw24 relation.

use serde::Serialize;

pub(crate) const PROOF_SCHEMA: &str = "zkcfa.raw.proof";
pub(crate) const PREFLIGHT_SCHEMA: &str = "zkcfa.raw.preflight";
pub(crate) const PROVER_DIAGNOSTIC: &str = "prover-diagnostic";

#[derive(Clone, Debug, Serialize)]
pub(crate) struct InstanceSize {
    pub(crate) nodes: usize,
    pub(crate) edges: usize,
    pub(crate) steps: usize,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Capacity {
    pub(crate) edge_cap: usize,
    pub(crate) ep_cap: usize,
    pub(crate) ep_encoding: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PlonkConstraints {
    pub(crate) plonk_gates: usize,
    pub(crate) padded_domain: usize,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PhaseTimes {
    pub(crate) setup: f64,
    pub(crate) prove: f64,
    pub(crate) public_preflight: f64,
    pub(crate) verify: f64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PublicInputs {
    #[serde(rename = "H_ep")]
    pub(crate) h_ep: String,
    #[serde(rename = "H_cfg")]
    pub(crate) h_cfg: String,
    pub(crate) entry: String,
    pub(crate) final_node: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ProofReport {
    pub(crate) schema: &'static str,
    pub(crate) relation: &'static str,
    pub(crate) backend: &'static str,
    pub(crate) application: String,
    pub(crate) profile: &'static str,
    pub(crate) path_mode: String,
    pub(crate) instance: InstanceSize,
    pub(crate) instance_source: &'static str,
    pub(crate) capacity: Capacity,
    pub(crate) constraints: PlonkConstraints,
    pub(crate) phases_ms: PhaseTimes,
    pub(crate) proof_bytes: usize,
    pub(crate) public_inputs: PublicInputs,
    pub(crate) verified: bool,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PreflightReport {
    pub(crate) schema: &'static str,
    pub(crate) relation: &'static str,
    pub(crate) backend: &'static str,
    pub(crate) application: String,
    pub(crate) profile: &'static str,
    pub(crate) path_mode: String,
    pub(crate) instance: InstanceSize,
    pub(crate) instance_source: &'static str,
    pub(crate) capacity: Capacity,
    pub(crate) constraints: PlonkConstraints,
    pub(crate) public_preflight_ms: f64,
    pub(crate) satisfied: bool,
}

pub(crate) fn json_requested() -> bool {
    std::env::var_os("ZKCFA_JSON").is_some()
}

impl ProofReport {
    pub(crate) fn emit(&self) -> anyhow::Result<()> {
        if json_requested() {
            println!("{}", serde_json::to_string(self)?);
            return Ok(());
        }
        println!("zkCFA proof: {}", self.relation);
        println!("  backend          {}", self.backend);
        println!("  application      {}", self.application);
        println!("  profile          {}", self.profile);
        println!("  path mode        {}", self.path_mode);
        println!(
            "  prover diagnostic {} nodes, {} edges, {} rows",
            self.instance.nodes, self.instance.edges, self.instance.steps
        );
        println!(
            "  capacity         EDGE_CAP={} EP_CAP={} EP_ENCODING={}",
            self.capacity.edge_cap, self.capacity.ep_cap, self.capacity.ep_encoding
        );
        println!(
            "  constraints      PLONK={} DOMAIN={}",
            self.constraints.plonk_gates, self.constraints.padded_domain
        );
        println!("  setup            {:.3} ms", self.phases_ms.setup);
        println!("  prove            {:.3} ms", self.phases_ms.prove);
        println!(
            "  public preflight {:.3} ms",
            self.phases_ms.public_preflight
        );
        println!("  verify           {:.3} ms", self.phases_ms.verify);
        println!("  proof            {} B", self.proof_bytes);
        println!("  public H_ep      {}", self.public_inputs.h_ep);
        println!("  public H_cfg     {}", self.public_inputs.h_cfg);
        println!("  public entry     {}", self.public_inputs.entry);
        println!("  public final     {}", self.public_inputs.final_node);
        println!("  verified         {}", self.verified);
        Ok(())
    }
}

impl PreflightReport {
    pub(crate) fn emit(&self) -> anyhow::Result<()> {
        if json_requested() {
            println!("{}", serde_json::to_string(self)?);
            return Ok(());
        }
        println!("zkCFA preflight: {}", self.relation);
        println!("  backend          {}", self.backend);
        println!("  application      {}", self.application);
        println!("  path mode        {}", self.path_mode);
        println!(
            "  prover diagnostic {} nodes, {} edges, {} rows",
            self.instance.nodes, self.instance.edges, self.instance.steps
        );
        println!(
            "  capacity         EDGE_CAP={} EP_CAP={} EP_ENCODING={}",
            self.capacity.edge_cap, self.capacity.ep_cap, self.capacity.ep_encoding
        );
        println!(
            "  constraints      PLONK={} DOMAIN={}",
            self.constraints.plonk_gates, self.constraints.padded_domain
        );
        println!("  public preflight {:.3} ms", self.public_preflight_ms);
        println!("  satisfied        {}", self.satisfied);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ProofReport {
        ProofReport {
            schema: PROOF_SCHEMA,
            relation: "zkcfa/raw-cfa",
            backend: "plonk",
            application: "fixture".to_owned(),
            profile: "raw24-full-key",
            path_mode: "complete".to_owned(),
            instance: InstanceSize {
                nodes: 3,
                edges: 4,
                steps: 5,
            },
            instance_source: PROVER_DIAGNOSTIC,
            capacity: Capacity {
                edge_cap: 8,
                ep_cap: 16,
                ep_encoding: "inline14".to_owned(),
            },
            constraints: PlonkConstraints {
                plonk_gates: 123,
                padded_domain: 256,
            },
            phases_ms: PhaseTimes {
                setup: 1.0,
                prove: 2.0,
                public_preflight: 0.25,
                verify: 3.0,
            },
            proof_bytes: 1_930,
            public_inputs: PublicInputs {
                h_ep: "01".repeat(32),
                h_cfg: "02".repeat(32),
                entry: "0x401000".to_owned(),
                final_node: "0x401010".to_owned(),
            },
            verified: true,
        }
    }

    #[test]
    fn json_schema_is_backend_specific_and_stable() {
        let value = serde_json::to_value(sample()).unwrap();
        assert_eq!(value["schema"], PROOF_SCHEMA);
        assert_eq!(value["backend"], "plonk");
        assert_eq!(value["constraints"]["plonk_gates"], 123);
        assert_eq!(value["constraints"]["padded_domain"], 256);
        assert_eq!(value["instance_source"], PROVER_DIAGNOSTIC);
        assert!(value["constraints"].get("and").is_none());
        assert_eq!(value["verified"], true);
    }

    #[test]
    fn preflight_has_a_distinct_non_proof_schema() {
        let report = PreflightReport {
            schema: PREFLIGHT_SCHEMA,
            relation: "zkcfa/raw-cfa",
            backend: "plonk",
            application: "fixture".to_owned(),
            profile: "raw24-full-key",
            path_mode: "shadow".to_owned(),
            instance: InstanceSize {
                nodes: 1,
                edges: 1,
                steps: 1,
            },
            instance_source: PROVER_DIAGNOSTIC,
            capacity: Capacity {
                edge_cap: 1,
                ep_cap: 2,
                ep_encoding: "inline14".to_owned(),
            },
            constraints: PlonkConstraints {
                plonk_gates: 10,
                padded_domain: 16,
            },
            public_preflight_ms: 0.1,
            satisfied: true,
        };
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["schema"], PREFLIGHT_SCHEMA);
        assert_eq!(value["instance_source"], PROVER_DIAGNOSTIC);
        assert!(value.get("proof_bytes").is_none());
        assert!(value.get("verified").is_none());
        assert_eq!(value["satisfied"], true);
    }
}
