//! Thin prove-then-verify orchestration and reporting.

use std::time::Instant;

use anyhow::{Result, ensure};
use binius_core::InoutSegment;

use crate::{
    attestation::{ADDR_BITS, BACKEND, PROFILE, raw_provider_config_from_env},
    prover::PreparedProver,
    raw::RAW_N_PUBLIC,
    report::{Phases, PublicInput, Report},
    verifier::VerifierContext,
};

const ALLOWED_ENV: &[&str] = &[
    "ZKCFA_PROVIDER_BUNDLE",
    "ZKCFA_AUTHORITY_PUBLIC",
    "ZKCFA_AUTHORITY_SHA256",
    "ZKCFA_EXPECTED_CHALLENGE_ID",
    "ZKCFA_EXPECTED_NONCE",
    "ZKCFA_JSON",
];

fn unsupported_release_env(names: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut unsupported: Vec<String> = names
        .into_iter()
        .filter(|name| name.starts_with("ZKCFA_") && !ALLOWED_ENV.contains(&name.as_str()))
        .collect();
    unsupported.sort();
    unsupported
}

fn validate_release_env() -> Result<()> {
    let unsupported = unsupported_release_env(
        std::env::vars_os().filter_map(|(name, _)| name.into_string().ok()),
    );
    ensure!(
        unsupported.is_empty(),
        "unsupported zkCFA release controls: {}",
        unsupported.join(", ")
    );
    Ok(())
}

pub(crate) fn run() -> Result<()> {
    validate_release_env()?;
    println!("=== zkCFA {PROFILE}: typed CFG, BinMult, independent blinding ===\n");

    let total_start = Instant::now();
    let setup_start = Instant::now();
    let config = raw_provider_config_from_env()?;

    // Public-only setup owns the circuit parameters and verifier key before private loading.
    let verifier = VerifierContext::prepare(&config)?;
    let prepared_prover = PreparedProver::prepare(&config, &verifier)?;
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1e3;

    let statement = verifier.statement();
    let params = verifier.params();
    let metrics = prepared_prover.metrics();
    let stat = verifier.stat();
    let cs = verifier.circuit().constraint_system();

    println!(
        "Signed handoff: authority+device Ed25519 verified; registry={} config={} scope={} device={} challenge={}; private load {:.3} ms",
        hex::encode(statement.raw_registry_id),
        hex::encode(statement.raw_config_id),
        hex::encode(statement.scope_policy_digest),
        statement.device_id,
        statement.challenge.label(),
        metrics.private_load_ms,
    );
    println!(
        "Raw preflight: EP encoding={} MULT_BITS={} max CFG multiplicity={} at table entry {}",
        params.ep_encoding_label(),
        params.mult_bits(),
        metrics.max_multiplicity,
        metrics.max_multiplicity_entry,
    );
    println!(
        "Raw circuit: AND={} IMUL={} BMUL={} committed={} witness={}",
        stat.n_and_constraints,
        stat.n_imul_constraints,
        stat.n_bmul_constraints,
        stat.committed_allocated,
        stat.n_witness,
    );
    println!(
        "Raw sizes: value_vec={} (public {} + hidden {}), const={} inout={} private={}",
        cs.value_vec_len(),
        cs.n_public_words(InoutSegment::Public),
        cs.n_hidden_words(InoutSegment::Public),
        cs.n_const(),
        cs.n_inout,
        cs.n_private,
    );
    println!(
        "Raw params: profile={PROFILE} backend={BACKEND} ADDR_BITS={ADDR_BITS} EDGE_CAP={} EP_CAP={} EP_ENCODING={} MULT_BITS={} path_mode={} public_words={RAW_N_PUBLIC}",
        params.edge_cap(),
        params.ep_cap(),
        params.ep_encoding_label(),
        params.mult_bits(),
        params.path_mode_label(),
    );
    println!(
        "Raw instance: {} nodes, {} typed edges, {} EP rows; entry={:#x}, final={:#x}; path={}",
        metrics.nodes,
        metrics.edges,
        metrics.steps,
        metrics.entry,
        metrics.final_node,
        params.path_statement(),
    );
    println!(
        "Raw canonical buffers: EP={} words, CFG={} words",
        metrics.ep_buffer_words, metrics.cfg_buffer_words,
    );

    let proved = prepared_prover.prove(&verifier)?;
    let receipt = verifier.verify(&config, &proved.proof)?;
    println!(
        "Verifier preflight: ✓ public signatures, challenge, configuration, scope, endpoints, canonical constants/padding, and 10-word ABI; private handoff not read; challenge={} time={:.3} ms",
        receipt.statement.challenge.label(),
        receipt.public_preflight_ms,
    );
    println!("Verifier: ✓ raw proof verified from verifier-rebuilt public inputs");

    Report {
        relation: "zkcfa/raw-cfa".into(),
        backend: BACKEND.into(),
        application: receipt.statement.application,
        profile: PROFILE.into(),
        path_mode: params.path_mode_label().into(),
        nodes: proved.metrics.nodes,
        edges: proved.metrics.edges,
        steps: proved.metrics.steps,
        edge_cap: params.edge_cap(),
        ep_cap: params.ep_cap(),
        ep_encoding: params.ep_encoding_label().into(),
        multiplicity_bits: params.mult_bits(),
        and_constraints: stat.n_and_constraints as u64,
        imul_constraints: stat.n_imul_constraints as u64,
        bmul_constraints: stat.n_bmul_constraints as u64,
        phases: Phases {
            setup_ms,
            prove_ms: proved.prove_ms,
            public_preflight_ms: receipt.public_preflight_ms,
            verify_ms: receipt.verify_ms,
        },
        proof_bytes: proved.proof.len(),
        public_inputs: vec![
            PublicInput {
                name: format!("H_ep_raw{ADDR_BITS}"),
                value: hex::encode(receipt.public_values.h_ep),
            },
            PublicInput {
                name: format!("H_cfg_raw{ADDR_BITS}"),
                value: hex::encode(receipt.public_values.h_cfg),
            },
            PublicInput {
                name: "entry_raw".into(),
                value: format!("{:#x}", receipt.public_values.entry),
            },
            PublicInput {
                name: "final_raw".into(),
                value: format!("{:#x}", receipt.public_values.final_node),
            },
        ],
        verified: true,
    }
    .emit();

    println!("\n{PROFILE} total wall time: {:.2?}", total_start.elapsed());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_environment_has_a_small_explicit_surface() {
        assert!(ALLOWED_ENV.contains(&"ZKCFA_PROVIDER_BUNDLE"));
        assert!(ALLOWED_ENV.contains(&"ZKCFA_JSON"));
        assert!(!ALLOWED_ENV.contains(&"ZKCFA_UNKNOWN_CONTROL"));
        assert_eq!(
            unsupported_release_env(["ZKCFA_UNKNOWN_CONTROL".to_owned()]),
            vec!["ZKCFA_UNKNOWN_CONTROL"]
        );
    }
}
