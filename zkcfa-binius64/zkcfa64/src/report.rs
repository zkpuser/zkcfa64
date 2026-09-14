//! Stable human-readable and JSON output for one raw zkCFA proof.

use std::fmt::Write as _;

pub const REPORT_SCHEMA: &str = "zkcfa.raw.proof";

#[derive(Clone, Debug)]
pub struct PublicInput {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Default)]
pub struct Phases {
    pub setup_ms: f64,
    pub prove_ms: f64,
    pub public_preflight_ms: f64,
    pub verify_ms: f64,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub relation: String,
    pub backend: String,
    pub application: String,
    pub profile: String,
    pub path_mode: String,
    pub nodes: usize,
    pub edges: usize,
    pub steps: usize,
    pub edge_cap: usize,
    pub ep_cap: usize,
    pub ep_encoding: String,
    pub multiplicity_bits: usize,
    pub and_constraints: u64,
    pub imul_constraints: u64,
    pub bmul_constraints: u64,
    pub phases: Phases,
    pub proof_bytes: usize,
    pub public_inputs: Vec<PublicInput>,
    pub verified: bool,
}

impl Report {
    pub fn render(&self) -> String {
        let mut output = String::new();
        let _ = writeln!(output, "zkCFA proof: {}", self.relation);
        let _ = writeln!(output, "  backend          {}", self.backend);
        let _ = writeln!(output, "  application      {}", self.application);
        let _ = writeln!(output, "  profile          {}", self.profile);
        let _ = writeln!(output, "  path mode        {}", self.path_mode);
        let _ = writeln!(
            output,
            "  instance         {} nodes, {} edges, {} rows",
            self.nodes, self.edges, self.steps
        );
        let _ = writeln!(
            output,
            "  capacity         EDGE_CAP={} EP_CAP={} EP_ENCODING={} MULT_BITS={}",
            self.edge_cap, self.ep_cap, self.ep_encoding, self.multiplicity_bits
        );
        let _ = writeln!(
            output,
            "  constraints      AND={} IMUL={} BMUL={}",
            self.and_constraints, self.imul_constraints, self.bmul_constraints
        );
        let _ = writeln!(output, "  setup            {:.3} ms", self.phases.setup_ms);
        let _ = writeln!(output, "  prove            {:.3} ms", self.phases.prove_ms);
        let _ = writeln!(
            output,
            "  public preflight {:.3} ms",
            self.phases.public_preflight_ms
        );
        let _ = writeln!(output, "  verify           {:.3} ms", self.phases.verify_ms);
        let _ = writeln!(output, "  proof            {} B", self.proof_bytes);
        for input in &self.public_inputs {
            let _ = writeln!(output, "  public {:<8} {}", input.name, input.value);
        }
        let _ = writeln!(
            output,
            "  verified         {}",
            if self.verified { "true" } else { "false" }
        );
        output
    }

    pub fn to_json(&self) -> String {
        let mut output = String::new();
        let _ = write!(output, "{{\"schema\":{}", json_string(REPORT_SCHEMA));
        let _ = write!(output, ",\"relation\":{}", json_string(&self.relation));
        let _ = write!(output, ",\"backend\":{}", json_string(&self.backend));
        let _ = write!(
            output,
            ",\"application\":{}",
            json_string(&self.application)
        );
        let _ = write!(output, ",\"profile\":{}", json_string(&self.profile));
        let _ = write!(output, ",\"path_mode\":{}", json_string(&self.path_mode));
        let _ = write!(
            output,
            ",\"instance\":{{\"nodes\":{},\"edges\":{},\"steps\":{}}}",
            self.nodes, self.edges, self.steps
        );
        let _ = write!(
            output,
            ",\"capacity\":{{\"edge_cap\":{},\"ep_cap\":{},\"ep_encoding\":{},\"multiplicity_bits\":{}}}",
            self.edge_cap,
            self.ep_cap,
            json_string(&self.ep_encoding),
            self.multiplicity_bits
        );
        let _ = write!(
            output,
            ",\"constraints\":{{\"and\":{},\"imul\":{},\"bmul\":{}}}",
            self.and_constraints, self.imul_constraints, self.bmul_constraints
        );
        let _ = write!(
            output,
            ",\"phases_ms\":{{\"setup\":{:.3},\"prove\":{:.3},\"public_preflight\":{:.3},\"verify\":{:.3}}}",
            self.phases.setup_ms,
            self.phases.prove_ms,
            self.phases.public_preflight_ms,
            self.phases.verify_ms
        );
        let _ = write!(output, ",\"proof_bytes\":{}", self.proof_bytes);
        let _ = write!(output, ",\"public_inputs\":{{");
        for (index, input) in self.public_inputs.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            let _ = write!(
                output,
                "{}:{}",
                json_string(&input.name),
                json_string(&input.value)
            );
        }
        let _ = write!(output, "}},\"verified\":{}}}", self.verified);
        output
    }

    pub fn emit(&self) {
        if std::env::var_os("ZKCFA_JSON").is_some() {
            println!("{}", self.to_json());
        } else {
            print!("{}", self.render());
        }
    }
}

fn json_string(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\t' => output.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Report {
        Report {
            relation: "zkcfa/raw-cfa".into(),
            backend: "binius64".into(),
            application: "fixture".into(),
            profile: "raw24-full-key".into(),
            path_mode: "complete".into(),
            nodes: 3,
            edges: 4,
            steps: 5,
            edge_cap: 8,
            ep_cap: 16,
            ep_encoding: "inline14".into(),
            multiplicity_bits: 12,
            and_constraints: 100,
            imul_constraints: 0,
            bmul_constraints: 20,
            phases: Phases {
                setup_ms: 1.0,
                prove_ms: 2.0,
                public_preflight_ms: 0.25,
                verify_ms: 3.0,
            },
            proof_bytes: 1234,
            public_inputs: vec![PublicInput {
                name: "H_cfg_raw24".into(),
                value: "ab12".into(),
            }],
            verified: true,
        }
    }

    #[test]
    fn json_has_the_stable_release_shape() {
        let json = sample().to_json();
        for expected in [
            "\"schema\":\"zkcfa.raw.proof\"",
            "\"relation\":\"zkcfa/raw-cfa\"",
            "\"public_preflight\":0.250",
            "\"verified\":true",
        ] {
            assert!(json.contains(expected), "missing {expected} in {json}");
        }
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let keys: std::collections::BTreeSet<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let expected = [
            "application",
            "backend",
            "capacity",
            "constraints",
            "instance",
            "path_mode",
            "phases_ms",
            "profile",
            "proof_bytes",
            "public_inputs",
            "relation",
            "schema",
            "verified",
        ]
        .into_iter()
        .collect();
        assert_eq!(keys, expected);
    }

    #[test]
    fn human_report_is_compact_and_stable() {
        let report = sample().render();
        for expected in [
            "zkCFA proof: zkcfa/raw-cfa",
            "path mode        complete",
            "constraints      AND=100 IMUL=0 BMUL=20",
            "public preflight 0.250 ms",
            "verified         true",
        ] {
            assert!(report.contains(expected), "missing {expected} in {report}");
        }
    }
}
