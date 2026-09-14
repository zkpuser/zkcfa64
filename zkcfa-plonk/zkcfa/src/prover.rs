//! Confidential witness preparation and proving for the raw24 PLONK relation.
//!
//! Only this module opens the provider's `private/` directory. It receives verifier-generated
//! proving material and returns opaque proof bytes plus explicitly diagnostic witness metrics.

use std::time::{Duration, Instant};

use anyhow::{anyhow, ensure, Context, Result};
use ark_bls12_381::Fr as BlsScalar;
use ark_ff::PrimeField;
use plonk_core::circuit::Circuit;

use crate::{
    attestation::{load_provider_handoff, BundleConfig, PublicStatement},
    circuit::raw::RawPublicValues,
    raw_format::{RawInstance, RawOpenings},
    verifier::{
        public_values, ProofBytes, ProvingMaterial, RawCircuit, RawPc, RelationShape, TRANSCRIPT,
    },
};

/// Private-witness sizes reported for experiments. These are prover diagnostics, not public ABI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProverDiagnostics {
    pub(crate) nodes: usize,
    pub(crate) edges: usize,
    pub(crate) steps: usize,
}

pub(crate) struct PreparedProver {
    instance: RawInstance,
    public: RawPublicValues<BlsScalar>,
    padded_size: usize,
    diagnostics: ProverDiagnostics,
}

pub(crate) struct ProverOutput {
    pub(crate) proof: ProofBytes,
    pub(crate) diagnostics: ProverDiagnostics,
    pub(crate) prove_time: Duration,
}

impl PreparedProver {
    /// Open the confidential handoff and bind it to the verifier's exact authenticated statement.
    pub(crate) fn prepare(
        config: &BundleConfig,
        statement: &PublicStatement,
        expected_shape: &RelationShape,
    ) -> Result<Self> {
        let handoff = load_provider_handoff(config, statement)
            .context("authenticate confidential provider handoff")?;

        let openings = RawOpenings {
            ep: handoff.openings.ep.words(),
            cfg: handoff.openings.cfg.words(),
        };
        let instance = RawInstance::load(&handoff.private_dir, expected_shape.params, openings)
            .map_err(|error| anyhow!(error))
            .context("load canonical raw24 artifacts")?;

        let opened_h_ep = instance
            .h_ep_poseidon::<BlsScalar>()
            .map_err(|error| anyhow!(error))?;
        let opened_h_cfg = instance
            .h_cfg_poseidon::<BlsScalar>()
            .map_err(|error| anyhow!(error))?;
        ensure!(
            opened_h_ep == BlsScalar::from_be_bytes_mod_order(&statement.h_ep),
            "private raw EP does not open the signed Poseidon H_ep"
        );
        ensure!(
            opened_h_cfg == BlsScalar::from_be_bytes_mod_order(&statement.h_cfg),
            "private raw CFG does not open the signed Poseidon H_cfg"
        );
        ensure!(
            instance.entry() == statement.entry_raw,
            "private raw EP entry differs from the signed endpoint"
        );
        ensure!(
            instance.final_node() == statement.final_raw,
            "private raw EP final node differs from the signed endpoint"
        );

        let public = public_values(statement);
        let mut probe =
            RawCircuit::new(instance.clone(), public, 1).map_err(|error| anyhow!(error))?;
        let (constraints, raw_bound) = probe
            .probe_size()
            .map_err(|error| anyhow!("probe confidential raw24 witness: {error}"))?;
        let padded_size = raw_bound
            .checked_next_power_of_two()
            .context("raw24 circuit size overflows usize")?;
        ensure!(
            constraints == expected_shape.constraints
                && raw_bound == expected_shape.raw_bound
                && padded_size == expected_shape.padded_size,
            "private witness synthesized shape ({constraints}, {raw_bound}, {padded_size}) differs from verifier-derived shape ({}, {}, {})",
            expected_shape.constraints,
            expected_shape.raw_bound,
            expected_shape.padded_size
        );

        let diagnostics = ProverDiagnostics {
            nodes: instance.node_count,
            edges: instance.edge_count(),
            steps: instance.ep_len(),
        };
        Ok(Self {
            instance,
            public,
            padded_size,
            diagnostics,
        })
    }

    pub(crate) fn diagnostics(&self) -> &ProverDiagnostics {
        &self.diagnostics
    }

    /// Generate a proof with verifier-owned material and discard the prover's claimed PI vector.
    pub(crate) fn prove(self, material: ProvingMaterial) -> Result<ProverOutput> {
        let mut circuit = RawCircuit::new(self.instance, self.public, self.padded_size)
            .map_err(|error| anyhow!(error))?;
        let prove_start = Instant::now();
        let (proof, _prover_claimed_inputs) = circuit
            .gen_proof::<RawPc>(&material.public_parameters, material.prover_key, TRANSCRIPT)
            .map_err(|error| anyhow!("generate raw24 PLONK proof: {error}"))?;
        let prove_time = prove_start.elapsed();
        let proof = ProofBytes::encode(&proof)?;
        Ok(ProverOutput {
            proof,
            diagnostics: self.diagnostics,
            prove_time,
        })
    }
}
