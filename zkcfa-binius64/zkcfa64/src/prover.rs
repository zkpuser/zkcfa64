//! Confidential handoff loading, witness construction, and proof generation.
//!
//! Only this module handles private tracer artifacts, commitment openings, the raw instance, and
//! the witness. Its output contains opaque proof bytes and diagnostic prover metrics, never a
//! public vector for the verifier to trust.

use std::time::Instant;

use anyhow::{Result, ensure};
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_transcript::ProverTranscript;
use binius_verifier::{config::StdChallenger, hash::StdHashSuite};

use crate::{
    attestation::{RawProviderBundleConfig, load_raw_provider_handoff},
    raw::{
        RawInstance, canonical_public_words, preflight_raw_instance, validate_capacity_bounds,
        validate_raw_instance,
    },
    verifier::{ProofBytes, VerifierContext},
};

type RawZkProver = ZKProver<OptimalPackedB128, StdHashSuite>;

#[derive(Clone, Debug)]
pub(crate) struct ProverMetrics {
    pub(crate) nodes: usize,
    pub(crate) edges: usize,
    pub(crate) steps: usize,
    pub(crate) entry: u64,
    pub(crate) final_node: u64,
    pub(crate) ep_buffer_words: usize,
    pub(crate) cfg_buffer_words: usize,
    pub(crate) max_multiplicity_entry: usize,
    pub(crate) max_multiplicity: u64,
    pub(crate) private_load_ms: f64,
}

pub(crate) struct PreparedProver {
    key: RawZkProver,
    raw: RawInstance,
    metrics: ProverMetrics,
}

pub(crate) struct ProverOutput {
    pub(crate) proof: ProofBytes,
    pub(crate) metrics: ProverMetrics,
    pub(crate) prove_ms: f64,
}

impl PreparedProver {
    /// Open the confidential provider handoff against the verifier-authenticated statement.
    pub(crate) fn prepare(
        config: &RawProviderBundleConfig,
        verifier: &VerifierContext,
    ) -> Result<Self> {
        let private_load_start = Instant::now();
        let provider = load_raw_provider_handoff(config, verifier.statement().clone())?;
        let input_dir = provider
            .artifacts_dir
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("provider private directory is not UTF-8"))?;
        let params = verifier.params();
        let raw = RawInstance::from_typed_bundle_with_openings(
            input_dir,
            provider.ep_blind,
            provider.cfg_blind,
        )
        .map_err(|error| anyhow::anyhow!("load signed raw artifacts: {error}"))?;
        validate_raw_instance(&raw, params)?;
        validate_capacity_bounds(&raw, params)?;

        let values = raw.public_values(params);
        ensure!(
            values.h_cfg == provider.statement.h_cfg_raw24,
            "canonical raw CFG does not open the authority-signed H_cfg_raw24"
        );
        ensure!(
            values.h_ep == provider.statement.h_ep_raw24,
            "canonical raw path does not open the device-signed H_ep_raw24"
        );
        ensure!(
            values.entry == provider.statement.entry_raw,
            "canonical raw entry differs from the device-signed endpoint"
        );
        ensure!(
            values.final_node == provider.statement.final_raw,
            "canonical raw final node differs from the device-signed endpoint"
        );

        let (max_multiplicity_entry, max_multiplicity) = preflight_raw_instance(&raw, params)?;
        let (ep_buffer_words, cfg_buffer_words) = raw.buffer_word_counts(params);
        let metrics = ProverMetrics {
            nodes: raw.node_count(),
            edges: raw.edge_count(),
            steps: raw.step_count(),
            entry: raw.entry(),
            final_node: raw.final_node(),
            ep_buffer_words,
            cfg_buffer_words,
            max_multiplicity_entry,
            max_multiplicity,
            private_load_ms: private_load_start.elapsed().as_secs_f64() * 1e3,
        };
        let key = RawZkProver::setup(&verifier.clone_key_for_prover_setup())?;

        Ok(Self { key, raw, metrics })
    }

    pub(crate) const fn metrics(&self) -> &ProverMetrics {
        &self.metrics
    }

    /// Populate the private witness, check the relation locally, and emit only proof bytes.
    pub(crate) fn prove(self, verifier: &VerifierContext) -> Result<ProverOutput> {
        let prove_start = Instant::now();
        let circuit = verifier.circuit();
        let mut filler = circuit.new_witness_filler();
        verifier.walk().populate(&mut filler, &self.raw)?;
        circuit.populate_wire_witness(&mut filler)?;
        let witness = filler.into_value_vec();
        circuit
            .constraint_system()
            .verify(&witness)
            .map_err(|error| anyhow::anyhow!("raw constraint verification failed: {error}"))?;

        let expected_public = canonical_public_words(
            circuit.constraint_system(),
            self.raw.public_values(verifier.params()),
        )?;
        ensure!(
            witness.public() == expected_public,
            "prover witness public segment differs from the canonical relation ABI"
        );

        let mut transcript = ProverTranscript::new(StdChallenger::default());
        self.key.prove(&witness, rand::rng(), &mut transcript)?;
        let proof = ProofBytes::new(transcript.finalize());
        let prove_ms = prove_start.elapsed().as_secs_f64() * 1e3;

        Ok(ProverOutput {
            proof,
            metrics: self.metrics,
            prove_ms,
        })
    }
}
