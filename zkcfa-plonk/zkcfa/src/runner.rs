//! Thin orchestration and reporting for the split PLONK prover/verifier pipeline.

use std::time::Instant;

use anyhow::{Context, Result};

use crate::{
    attestation::provider_config_from_env,
    prover::{PreparedProver, ProverDiagnostics},
    report::{
        Capacity, InstanceSize, PhaseTimes, PlonkConstraints, PreflightReport, ProofReport,
        PublicInputs as ReportPublicInputs, PREFLIGHT_SCHEMA, PROOF_SCHEMA, PROVER_DIAGNOSTIC,
    },
    verifier::VerifierContext,
};

/// Authenticate public state, prepare the private witness, and run preflight or prove-and-verify.
pub(crate) fn run(preflight: bool) -> Result<()> {
    let json_output = crate::report::json_requested();
    if !json_output {
        println!("\n=== Authenticated raw24 PLONK ===\n");
    }

    // Parse mutable process inputs once. The verifier authenticates public state before the prover
    // is allowed to open private artifacts, and both sides use this exact trust/challenge config.
    let config = provider_config_from_env().context("load verifier configuration")?;
    let verifier =
        VerifierContext::prepare(config.clone()).context("prepare public-only verifier context")?;
    let prepared = PreparedProver::prepare(&config, verifier.statement(), verifier.shape())
        .context("prepare confidential prover witness")?;
    let diagnostics = prepared.diagnostics().clone();
    let shape = verifier.shape().clone();

    if !json_output {
        print_preparation(verifier.statement(), &shape, &diagnostics);
    }

    if preflight {
        let (statement, public_auth_time) = verifier.reauthenticate()?;
        return PreflightReport {
            schema: PREFLIGHT_SCHEMA,
            relation: "zkcfa/raw-cfa",
            backend: "plonk",
            application: statement.application,
            profile: "raw24-full-key",
            path_mode: statement.circuit.path_mode,
            instance: InstanceSize {
                nodes: diagnostics.nodes,
                edges: diagnostics.edges,
                steps: diagnostics.steps,
            },
            instance_source: PROVER_DIAGNOSTIC,
            capacity: Capacity {
                edge_cap: shape.params.edge_cap,
                ep_cap: shape.params.ep_cap,
                ep_encoding: shape.encoding.to_owned(),
            },
            constraints: PlonkConstraints {
                plonk_gates: shape.constraints,
                padded_domain: shape.padded_size,
            },
            public_preflight_ms: milliseconds(public_auth_time),
            satisfied: true,
        }
        .emit();
    }

    // Setup is verifier-owned: only the universal parameters and proving key cross to the prover.
    let setup_start = Instant::now();
    let (verifier, proving_material) = verifier.setup()?;
    let setup_time = setup_start.elapsed();
    let output = prepared.prove(proving_material)?;
    let proof_bytes = output.proof.len();
    let receipt = verifier.verify(&output.proof)?;

    ProofReport {
        schema: PROOF_SCHEMA,
        relation: "zkcfa/raw-cfa",
        backend: "plonk",
        application: receipt.statement.application,
        profile: "raw24-full-key",
        path_mode: receipt.statement.circuit.path_mode,
        // These instance sizes are experimental prover diagnostics. The four-field public ABI does
        // not expose them; successful verification authenticates the commitments and endpoints.
        instance: InstanceSize {
            nodes: output.diagnostics.nodes,
            edges: output.diagnostics.edges,
            steps: output.diagnostics.steps,
        },
        instance_source: PROVER_DIAGNOSTIC,
        capacity: Capacity {
            edge_cap: receipt.statement.circuit.edge_cap,
            ep_cap: receipt.statement.circuit.ep_cap,
            ep_encoding: shape.encoding.to_owned(),
        },
        constraints: PlonkConstraints {
            plonk_gates: shape.constraints,
            padded_domain: shape.padded_size,
        },
        phases_ms: PhaseTimes {
            setup: milliseconds(setup_time),
            prove: milliseconds(output.prove_time),
            public_preflight: milliseconds(receipt.public_auth_time),
            verify: milliseconds(receipt.verify_time),
        },
        proof_bytes,
        public_inputs: ReportPublicInputs {
            h_ep: hex::encode(receipt.statement.h_ep),
            h_cfg: hex::encode(receipt.statement.h_cfg),
            entry: format!("0x{:06x}", receipt.statement.entry_raw),
            final_node: format!("0x{:06x}", receipt.statement.final_raw),
        },
        verified: true,
    }
    .emit()
}

fn print_preparation(
    statement: &crate::attestation::PublicStatement,
    shape: &crate::verifier::RelationShape,
    diagnostics: &ProverDiagnostics,
) {
    println!("[Input] application: {}", statement.application);
    println!(
        "[Attestation] device={} challenge={} measurement={} scope={}",
        statement.device_id,
        statement.challenge.challenge_id,
        hex::encode(statement.binary_measurement),
        hex::encode(statement.scope_policy_digest),
    );
    println!(
        "[Input] path={} encoding={} EP={}/{} CFG={}/{}",
        shape.params.path_mode.label(),
        shape.encoding,
        diagnostics.steps,
        shape.params.ep_cap,
        diagnostics.edges,
        shape.params.edge_cap
    );
    println!(
        "[Circuit] constraints={} bound={} padded={} SRS max-degree={}",
        shape.constraints, shape.raw_bound, shape.padded_size, shape.maximum_degree
    );
}

fn milliseconds(duration: std::time::Duration) -> f64 {
    let value = duration.as_secs_f64() * 1e3;
    (value * 1e3).round() / 1e3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_milliseconds_are_rounded_to_three_decimals() {
        assert_eq!(
            milliseconds(std::time::Duration::from_nanos(1_234_567)),
            1.235
        );
    }
}
