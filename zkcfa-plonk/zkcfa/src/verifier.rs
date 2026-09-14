//! Public-only setup and verification for the raw24 PLONK relation.
//!
//! This module owns the trusted statement-to-ABI mapping, the ephemeral research SRS, both
//! verification keys, and the public-input positions. It never opens the provider's private
//! directory. A deployment should replace the ephemeral setup with authenticated reusable keys.

use std::time::{Duration, Instant};

use anyhow::{anyhow, ensure, Context, Result};
use ark_bls12_381::{Bls12_381, Fr as BlsScalar};
use ark_ed_on_bls12_381::EdwardsParameters as JubJubParameters;
use ark_ff::PrimeField;
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::{sonic_pc::SonicKZG10, PolynomialCommitment};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use plonk_core::{
    circuit::Circuit,
    proof_system::{
        pi::PublicInputs as PlonkPublicInputs, Proof, ProverKey, Verifier,
        VerifierKey as PlonkVerifierKey,
    },
};
use rand_core::OsRng;

use crate::{
    attestation::{load_public_statement, BundleConfig, PublicStatement},
    circuit::raw::{RawPlonkCircuit, RawPublicValues},
    raw_format::{PathMode, RawParams},
};

pub(crate) type RawPc = SonicKZG10<Bls12_381, DensePolynomial<BlsScalar>>;
pub(crate) type RawCircuit = RawPlonkCircuit<BlsScalar, JubJubParameters>;
pub(crate) type RawProof = Proof<BlsScalar, RawPc>;
type RawPlonkVerifierKey = PlonkVerifierKey<BlsScalar, RawPc>;
type RawPcVerifierKey =
    <RawPc as PolynomialCommitment<BlsScalar, DensePolynomial<BlsScalar>>>::VerifierKey;
type RawUniversalParams =
    <RawPc as PolynomialCommitment<BlsScalar, DensePolynomial<BlsScalar>>>::UniversalParams;

pub(crate) const TRANSCRIPT: &[u8] = b"ZKCFA/raw24/poseidon/plonk";
const PUBLIC_INPUTS: usize = 4;

/// Capacity-derived circuit facts computed without reading a private witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelationShape {
    pub(crate) params: RawParams,
    pub(crate) encoding: &'static str,
    pub(crate) constraints: usize,
    pub(crate) raw_bound: usize,
    pub(crate) padded_size: usize,
    pub(crate) maximum_degree: usize,
}

/// Public statement authenticated before any confidential handoff is opened.
pub(crate) struct VerifierContext {
    config: BundleConfig,
    statement: PublicStatement,
    shape: RelationShape,
}

/// Verifier-owned setup material handed to the prover. No verifier key is exposed here.
pub(crate) struct ProvingMaterial {
    pub(crate) public_parameters: RawUniversalParams,
    pub(crate) prover_key: ProverKey<BlsScalar>,
}

struct VerificationMaterial {
    pc_verifier_key: RawPcVerifierKey,
    plonk_verifier_key: RawPlonkVerifierKey,
    public_input_positions: [usize; PUBLIC_INPUTS],
}

/// A verifier context after it has generated and retained all verification material.
pub(crate) struct ReadyVerifier {
    context: VerifierContext,
    material: VerificationMaterial,
}

/// The only cryptographic artifact returned across the prover/verifier boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProofBytes(Vec<u8>);

/// Public-only result of a successful verification.
pub(crate) struct VerificationReceipt {
    pub(crate) statement: PublicStatement,
    pub(crate) public_auth_time: Duration,
    pub(crate) verify_time: Duration,
}

impl VerifierContext {
    /// Authenticate public authority/device data and derive the relation shape without `private/`.
    pub(crate) fn prepare(config: BundleConfig) -> Result<Self> {
        let statement = load_public_statement(&config).context("authenticate public statement")?;
        let params = params_from_statement(&statement)?;
        let mut shape_circuit = RawCircuit::for_shape(params, 1).map_err(|error| anyhow!(error))?;
        let (constraints, raw_bound) = shape_circuit
            .probe_size()
            .map_err(|error| anyhow!("probe public relation shape: {error}"))?;
        let padded_size = raw_bound
            .checked_next_power_of_two()
            .context("raw24 circuit size overflows usize")?;
        let maximum_degree = padded_size
            .checked_mul(2)
            .context("raw24 SRS maximum degree overflows usize")?;
        let encoding = params.encoding().map_err(|error| anyhow!(error))?.label();

        Ok(Self {
            config,
            statement,
            shape: RelationShape {
                params,
                encoding,
                constraints,
                raw_bound,
                padded_size,
                maximum_degree,
            },
        })
    }

    pub(crate) fn statement(&self) -> &PublicStatement {
        &self.statement
    }

    pub(crate) fn shape(&self) -> &RelationShape {
        &self.shape
    }

    /// Generate the research SRS and compile a canonical shape witness under verifier control.
    pub(crate) fn setup(self) -> Result<(ReadyVerifier, ProvingMaterial)> {
        let mut rng = OsRng;
        let public_parameters = RawPc::setup(self.shape.maximum_degree, None, &mut rng)
            .map_err(|error| anyhow!("generate verifier-owned universal KZG SRS: {error:?}"))?;
        let mut circuit = RawCircuit::for_shape(self.shape.params, self.shape.padded_size)
            .map_err(|error| anyhow!(error))?;
        let (prover_key, (plonk_verifier_key, positions)) = circuit
            .compile::<RawPc>(&public_parameters)
            .map_err(|error| anyhow!("compile verifier-owned raw24 PLONK shape: {error}"))?;
        ensure!(
            plonk_verifier_key.padded_circuit_size() == self.shape.padded_size,
            "compiled PLONK verifier key has domain {}, expected {}",
            plonk_verifier_key.padded_circuit_size(),
            self.shape.padded_size
        );
        let public_input_positions = checked_public_input_positions(positions)?;

        // Keep only the constant-size PC verifier key. The domain-sized committer key generated
        // by trim is discarded here and never crosses back from the prover.
        let (_, pc_verifier_key) = RawPc::trim(&public_parameters, self.shape.padded_size, 0, None)
            .map_err(|error| anyhow!("prepare KZG verifier key: {error:?}"))?;
        ensure!(
            pc_verifier_key.supported_degree == self.shape.padded_size,
            "KZG verifier key supports degree {}, expected {}",
            pc_verifier_key.supported_degree,
            self.shape.padded_size
        );

        let ready = ReadyVerifier {
            context: self,
            material: VerificationMaterial {
                pc_verifier_key,
                plonk_verifier_key,
                public_input_positions,
            },
        };
        let proving = ProvingMaterial {
            public_parameters,
            prover_key,
        };
        Ok((ready, proving))
    }

    /// Reauthenticate every public field and reject any change since initial preparation.
    pub(crate) fn reauthenticate(&self) -> Result<(PublicStatement, Duration)> {
        let start = Instant::now();
        let statement = load_public_statement(&self.config)
            .context("independently reauthenticate public statement")?;
        let elapsed = start.elapsed();
        ensure!(
            statement == self.statement,
            "public statement changed after initial verifier authentication"
        );
        Ok((statement, elapsed))
    }
}

impl ReadyVerifier {
    /// Strictly decode an opaque proof, reload the signed statement, rebuild the ABI, and verify.
    pub(crate) fn verify(self, proof_bytes: &ProofBytes) -> Result<VerificationReceipt> {
        let (statement, public_auth_time) = self.context.reauthenticate()?;

        let verify_start = Instant::now();
        let proof = proof_bytes.decode()?;
        let values = public_values(&statement).ordered();
        let public_inputs = verifier_public_inputs(&self.material.public_input_positions, &values)?;
        let mut verifier = Verifier::<BlsScalar, JubJubParameters, RawPc>::new(TRANSCRIPT);
        verifier.verifier_key = Some(self.material.plonk_verifier_key);
        verifier
            .verify(&proof, &self.material.pc_verifier_key, &public_inputs)
            .map_err(|error| anyhow!("verify raw24 PLONK proof: {error}"))?;

        Ok(VerificationReceipt {
            statement,
            public_auth_time,
            verify_time: verify_start.elapsed(),
        })
    }
}

impl ProofBytes {
    pub(crate) fn encode(proof: &RawProof) -> Result<Self> {
        let mut bytes = Vec::new();
        proof
            .serialize(&mut bytes)
            .context("serialize raw24 PLONK proof")?;
        Ok(Self(bytes))
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    fn decode(&self) -> Result<RawProof> {
        let mut input = self.0.as_slice();
        let proof = RawProof::deserialize(&mut input).context("decode raw24 PLONK proof")?;
        ensure!(input.is_empty(), "raw24 PLONK proof has trailing bytes");
        Ok(proof)
    }
}

/// The verifier is the sole authority for the statement-to-circuit ABI mapping.
pub(crate) fn public_values(statement: &PublicStatement) -> RawPublicValues<BlsScalar> {
    RawPublicValues {
        h_ep: BlsScalar::from_be_bytes_mod_order(&statement.h_ep),
        h_cfg: BlsScalar::from_be_bytes_mod_order(&statement.h_cfg),
        entry: statement.entry_raw,
        final_node: statement.final_raw,
    }
}

fn params_from_statement(statement: &PublicStatement) -> Result<RawParams> {
    let path_mode =
        PathMode::from_label(&statement.circuit.path_mode).map_err(|error| anyhow!(error))?;
    Ok(RawParams {
        edge_cap: statement.circuit.edge_cap,
        ep_cap: statement.circuit.ep_cap,
        path_mode,
    })
}

fn checked_public_input_positions(positions: Vec<usize>) -> Result<[usize; PUBLIC_INPUTS]> {
    let positions: [usize; PUBLIC_INPUTS] = positions.try_into().map_err(|positions: Vec<_>| {
        anyhow!(
            "compiled circuit exposes {} public inputs, expected {PUBLIC_INPUTS}",
            positions.len()
        )
    })?;
    ensure!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "verifier-key public-input positions are not strictly increasing"
    );
    Ok(positions)
}

fn verifier_public_inputs(
    positions: &[usize; PUBLIC_INPUTS],
    attested_values: &[BlsScalar; PUBLIC_INPUTS],
) -> Result<PlonkPublicInputs<BlsScalar>> {
    let mut inputs = PlonkPublicInputs::new();
    for (&position, value) in positions.iter().zip(attested_values) {
        // `constrain_to_constant(var, 0, Some(-expected))` is this fork's exposure convention.
        inputs
            .add_input(position, &(-*value))
            .map_err(|error| anyhow!("construct verifier public input: {error}"))?;
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_input_positions_are_exact_and_ordered() {
        assert_eq!(
            checked_public_input_positions(vec![3, 5, 8, 13]).unwrap(),
            [3, 5, 8, 13]
        );
        assert!(checked_public_input_positions(vec![3, 5, 8]).is_err());
        assert!(checked_public_input_positions(vec![3, 5, 5, 13]).is_err());
        assert!(checked_public_input_positions(vec![3, 8, 5, 13]).is_err());
    }

    #[test]
    fn verifier_uses_the_negative_public_input_convention() {
        let positions = [1, 3, 5, 7];
        let values = [
            BlsScalar::from(11u64),
            BlsScalar::from(22u64),
            BlsScalar::from(33u64),
            BlsScalar::from(44u64),
        ];
        let inputs = verifier_public_inputs(&positions, &values).unwrap();
        let evaluations = inputs.as_evals(8);
        for (&position, value) in positions.iter().zip(values) {
            assert_eq!(evaluations[position], -value);
        }
    }

    #[test]
    fn opaque_proof_decoder_rejects_truncation_and_trailing_data() {
        let encoded = ProofBytes::encode(&RawProof::default()).unwrap();
        encoded.decode().unwrap();

        let mut trailing = encoded.0.clone();
        trailing.push(0);
        assert!(ProofBytes(trailing).decode().is_err());

        let mut truncated = encoded.0;
        truncated.pop();
        assert!(ProofBytes(truncated).decode().is_err());
    }
}
