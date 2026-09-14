//! Public-only setup and verification for the compiled raw-address relation.
//!
//! This module never accepts a provider handoff, raw instance, blinding, witness, or
//! prover-supplied public vector. It authenticates the public statement, owns the verifier setup,
//! reconstructs the complete Binius public segment, and verifies opaque proof bytes.

use std::time::Instant;

use anyhow::{Result, ensure};
use binius_frontend::{Circuit, CircuitStat};
use binius_transcript::VerifierTranscript;
use binius_verifier::{config::StdChallenger, hash::StdHashSuite, zk_config::ZKVerifier};

use crate::{
    attestation::{RawProviderBundleConfig, RawPublicStatement, load_raw_public_statement},
    raw::{
        RAW_N_PUBLIC, RawCfgWalk, RawParams, RawPublicValues, build_raw_circuit,
        canonical_inout_words, signed_raw_params,
    },
};

pub(crate) type RawVerifierKey = ZKVerifier<StdHashSuite>;

/// Opaque prover-to-verifier handoff. Public inputs are deliberately absent.
pub(crate) struct ProofBytes(Vec<u8>);

impl ProofBytes {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    fn transcript_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Verifier-owned relation and key material derived only from an authenticated public statement.
pub(crate) struct VerifierContext {
    statement: RawPublicStatement,
    params: RawParams,
    circuit: Circuit,
    walk: RawCfgWalk,
    stat: CircuitStat,
    key: RawVerifierKey,
}

/// Successful public authentication and cryptographic verification receipt.
pub(crate) struct VerificationReceipt {
    pub(crate) statement: RawPublicStatement,
    pub(crate) public_values: RawPublicValues,
    pub(crate) public_preflight_ms: f64,
    pub(crate) verify_ms: f64,
}

impl VerifierContext {
    /// Authenticate the public statement and compile its signed relation before private loading.
    pub(crate) fn prepare(config: &RawProviderBundleConfig) -> Result<Self> {
        let statement = load_raw_public_statement(config)?;
        let params = signed_raw_params(&statement.circuit)?;
        let (circuit, walk) = build_raw_circuit(params);
        validate_signed_configuration(
            &statement,
            params,
            statement.circuit.log_inv_rate,
            circuit.constraint_system(),
        )?;
        let stat = CircuitStat::collect(&circuit);
        let key = RawVerifierKey::setup(
            circuit.constraint_system().clone(),
            statement.circuit.log_inv_rate,
        )?;

        Ok(Self {
            statement,
            params,
            circuit,
            walk,
            stat,
            key,
        })
    }

    pub(crate) fn statement(&self) -> &RawPublicStatement {
        &self.statement
    }

    pub(crate) const fn params(&self) -> RawParams {
        self.params
    }

    pub(crate) fn circuit(&self) -> &Circuit {
        &self.circuit
    }

    pub(crate) fn walk(&self) -> &RawCfgWalk {
        &self.walk
    }

    pub(crate) const fn stat(&self) -> &CircuitStat {
        &self.stat
    }

    /// The Binius prover setup is derived from a clone of verifier-owned public key material.
    pub(crate) fn clone_key_for_prover_setup(&self) -> RawVerifierKey {
        self.key.clone()
    }

    /// Reload the public statement, rebuild all public words, and verify the proof.
    pub(crate) fn verify(
        &self,
        config: &RawProviderBundleConfig,
        proof: &ProofBytes,
    ) -> Result<VerificationReceipt> {
        let public_preflight_start = Instant::now();
        let statement = load_raw_public_statement(config)?;
        ensure!(
            statement == self.statement,
            "authenticated public statement changed after verifier setup"
        );
        validate_signed_configuration(
            &statement,
            self.params,
            self.key.log_inv_rate(),
            self.key.constraint_system(),
        )?;
        let public_values = public_values(&statement);
        let inout = canonical_inout_words(public_values);
        let public_preflight_ms = public_preflight_start.elapsed().as_secs_f64() * 1e3;

        let verify_start = Instant::now();
        let mut transcript =
            VerifierTranscript::new(StdChallenger::default(), proof.transcript_bytes());
        self.key.verify(&inout, &mut transcript)?;
        transcript.finalize()?;
        let verify_ms = verify_start.elapsed().as_secs_f64() * 1e3;

        Ok(VerificationReceipt {
            statement,
            public_values,
            public_preflight_ms,
            verify_ms,
        })
    }
}

fn validate_signed_configuration(
    statement: &RawPublicStatement,
    params: RawParams,
    log_inv_rate: usize,
    cs: &binius_core::constraint_system::ConstraintSystem,
) -> Result<()> {
    ensure!(
        signed_raw_params(&statement.circuit)? == params,
        "public signed raw configuration differs from the instantiated circuit parameters"
    );
    ensure!(
        statement.circuit.log_inv_rate == log_inv_rate,
        "public signed raw proof rate differs from the instantiated verifier"
    );
    ensure!(
        cs.n_inout == RAW_N_PUBLIC,
        "compiled raw public ABI differs from the instantiated verifier"
    );
    Ok(())
}

fn public_values(statement: &RawPublicStatement) -> RawPublicValues {
    RawPublicValues {
        h_ep: statement.h_ep_raw24,
        h_cfg: statement.h_cfg_raw24,
        entry: statement.entry_raw,
        final_node: statement.final_raw,
    }
}
