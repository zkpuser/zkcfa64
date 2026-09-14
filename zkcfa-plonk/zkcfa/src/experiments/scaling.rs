//! Research-only scaling of the maintained raw24 PLONK/KZG relation.
//!
//! Inputs are synthetic typed artifacts, not authenticated acquisition evidence. The production
//! raw relation, canonical encoding, Poseidon computation, shape compiler, and cryptographic
//! prover/verifier are reused. Setup and witness synthesis are outside cryptographic proving.
//! This expands `Circuit::gen_proof` at its existing synthesis/prove boundary without changing it.

use std::{collections::HashMap, path::PathBuf, time::Instant};

use anyhow::{anyhow, ensure, Context, Result};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::EdwardsParameters;
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::{sonic_pc::SonicKZG10, PolynomialCommitment};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use plonk_core::{
    circuit::Circuit,
    proof_system::{pi::PublicInputs, Proof, Prover, Verifier},
};
use rand_core::{OsRng, RngCore};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::circuit::raw::{RawPlonkCircuit, RawPublicValues};
use crate::raw_format::{PathMode, RawInstance, RawOpenings, RawParams};

type Pc = SonicKZG10<Bls12_381, DensePolynomial<Fr>>;
type RawCircuit = RawPlonkCircuit<Fr, EdwardsParameters>;
const TRANSCRIPT: &[u8] = b"ZKCFA/raw24/poseidon/plonk";
const HELP: &str =
    "Research-only synthetic raw24 PLONK/KZG scaling; no acquisition or signatures.\n\
Usage: RAYON_NUM_THREADS=8 scaling --typed-dir DIR --edge-cap N --ep-cap N \
[--preflight] [--negative-check]\n\
Consumes unprojected complete translator, typed_cfg, and recorded_path. Every invocation uses \
fresh independent openings and, for proving, a fresh research SRS.";

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1e3
}

fn public_inputs(positions: &[usize], values: &[Fr; 4]) -> Result<PublicInputs<Fr>> {
    ensure!(positions.len() == 4, "expected exactly four public inputs");
    ensure!(
        positions.windows(2).all(|p| p[0] < p[1]),
        "unordered public input positions"
    );
    let mut result = PublicInputs::new();
    for (&position, value) in positions.iter().zip(values) {
        result
            .add_input(position, &(-*value))
            .map_err(|e| anyhow!("public input: {e}"))?;
    }
    Ok(result)
}

pub(super) fn run() -> Result<()> {
    let mut options = HashMap::new();
    let mut preflight = false;
    let mut negative_check = false;
    let mut args = std::env::args().skip(1);
    while let Some(key) = args.next() {
        match key.as_str() {
            "--help" | "-h" => {
                println!("{HELP}");
                return Ok(());
            }
            "--preflight" => {
                ensure!(!preflight, "duplicate --preflight");
                preflight = true;
            }
            "--negative-check" => {
                ensure!(!negative_check, "duplicate --negative-check");
                negative_check = true;
            }
            "--typed-dir" | "--edge-cap" | "--ep-cap" => {
                let value = args
                    .next()
                    .with_context(|| format!("missing value for {key}"))?;
                ensure!(
                    options.insert(key.clone(), value).is_none(),
                    "duplicate {key}"
                );
            }
            _ => anyhow::bail!("unknown argument {key}\n{HELP}"),
        }
    }
    ensure!(
        !(preflight && negative_check),
        "negative proof check requires a proof"
    );
    ensure!(
        std::env::var("RAYON_NUM_THREADS").as_deref() == Ok("8"),
        "set RAYON_NUM_THREADS=8"
    );
    let required = |key: &str| {
        options
            .get(key)
            .with_context(|| format!("missing {key}\n{HELP}"))
    };
    let typed_dir = PathBuf::from(required("--typed-dir")?).canonicalize()?;
    let params = RawParams {
        edge_cap: required("--edge-cap")?
            .parse()
            .context("invalid edge capacity")?,
        ep_cap: required("--ep-cap")?
            .parse()
            .context("invalid EP capacity")?,
        path_mode: PathMode::Complete,
    };
    ensure!(
        params.edge_cap >= 8 && params.edge_cap.is_power_of_two(),
        "invalid edge capacity"
    );
    ensure!(
        (16..=1 << 24).contains(&params.ep_cap) && params.ep_cap.is_power_of_two(),
        "invalid EP capacity"
    );
    let total_start = Instant::now();
    eprintln!("synthetic/research-only: canonical input and public shape checks; no signatures");
    let input_start = Instant::now();
    let mut input_sha256 = serde_json::Map::new();
    for name in ["translator", "typed_cfg", "recorded_path"] {
        input_sha256.insert(
            name.to_owned(),
            json!(hex::encode(Sha256::digest(std::fs::read(
                typed_dir.join(name)
            )?))),
        );
    }
    let mut rng = OsRng;
    let ep = loop {
        let value = [rng.next_u64(), rng.next_u64()];
        if value != [0, 0] {
            break value;
        }
    };
    let cfg = loop {
        let value = [rng.next_u64(), rng.next_u64()];
        if value != [0, 0] && value != ep {
            break value;
        }
    };
    let instance =
        RawInstance::load(&typed_dir, params, RawOpenings { ep, cfg }).map_err(|e| anyhow!(e))?;
    let expected = RawPublicValues {
        h_ep: instance.h_ep_poseidon::<Fr>().map_err(|e| anyhow!(e))?,
        h_cfg: instance.h_cfg_poseidon::<Fr>().map_err(|e| anyhow!(e))?,
        entry: instance.entry(),
        final_node: instance.final_node(),
    };
    let diagnostics = json!({"nodes":instance.node_count,"edges":instance.edge_count(),"steps":instance.ep_len()});
    let mut shape = RawCircuit::for_shape(params, 1).map_err(|e| anyhow!(e))?;
    let (constraints, raw_bound) = shape.probe_size().map_err(|e| anyhow!("shape: {e}"))?;
    drop(shape);
    let padded_domain = raw_bound
        .checked_next_power_of_two()
        .context("domain overflow")?;
    let mut witness_probe =
        RawCircuit::new(instance.clone(), expected, 1).map_err(|e| anyhow!(e))?;
    ensure!(
        witness_probe
            .probe_size()
            .map_err(|e| anyhow!("witness probe: {e}"))?
            == (constraints, raw_bound),
        "private witness differs from capacity-selected shape"
    );
    drop(witness_probe);
    let input_preflight_ms = elapsed_ms(input_start);
    let mut report = json!({
        "schema":"zkcfa.plonk.synthetic-scaling.v1", "backend":"plonk", "profile":"raw24-full-key",
        "scope":"synthetic relation benchmark; no acquisition or authentication claims", "path_mode":"complete",
        "instance":diagnostics, "capacity":{"edge_cap":params.edge_cap,"ep_cap":params.ep_cap,"ep_encoding":params.encoding().map_err(|e|anyhow!(e))?.label()},
        "constraints":{"plonk_gates":constraints,"raw_bound":raw_bound,"padded_domain":padded_domain},
        "input_sha256":input_sha256,"threads":8,"preflight":preflight,"satisfied":true,
        "phases_ms":{"input_preflight":input_preflight_ms},"verified":false
    });
    if preflight {
        report["phases_ms"]["total"] = json!(elapsed_ms(total_start));
        println!("{report}");
        return Ok(());
    }

    eprintln!("synthetic/research-only: fresh KZG SRS and capacity-selected setup, domain={padded_domain}");
    let setup_start = Instant::now();
    let public_parameters = Pc::setup(
        padded_domain.checked_mul(2).context("degree overflow")?,
        None,
        &mut rng,
    )
    .map_err(|e| anyhow!("KZG setup: {e:?}"))?;
    let srs_setup_ms = elapsed_ms(setup_start);
    let key_start = Instant::now();
    let mut shape = RawCircuit::for_shape(params, padded_domain).map_err(|e| anyhow!(e))?;
    let (prover_key, (verifier_key, positions)) = shape
        .compile::<Pc>(&public_parameters)
        .map_err(|e| anyhow!("compile: {e}"))?;
    ensure!(
        verifier_key.padded_circuit_size() == padded_domain,
        "wrong verifier domain"
    );
    drop(shape);
    let (commit_key, pc_verifier_key) = Pc::trim(&public_parameters, padded_domain, 0, None)
        .map_err(|e| anyhow!("KZG trim: {e:?}"))?;
    let key_compile_ms = elapsed_ms(key_start);
    let setup_ms = elapsed_ms(setup_start);
    let expected_inputs = public_inputs(&positions, &expected.ordered())?;

    eprintln!("synthetic/research-only: witness synthesis and local constraint check");
    let witness_start = Instant::now();
    let mut circuit = RawCircuit::new(instance, expected, padded_domain).map_err(|e| anyhow!(e))?;
    let mut prover = Prover::<Fr, EdwardsParameters, Pc>::new(TRANSCRIPT);
    circuit
        .gadget(prover.mut_cs())
        .map_err(|e| anyhow!("synthesize: {e}"))?;
    ensure!(
        prover.mut_cs().total_size() == constraints,
        "changed witness gate count"
    );
    prover.mut_cs().check_circuit_satisfied();
    ensure!(
        prover.mut_cs().get_pi() == &expected_inputs,
        "synthesized public inputs differ from independently opened statement"
    );
    prover.prover_key = Some(prover_key);
    let witness_localcheck_ms = elapsed_ms(witness_start);

    eprintln!("synthetic/research-only: cryptographic proving");
    let crypto_start = Instant::now();
    let proof = prover
        .prove(&commit_key)
        .map_err(|e| anyhow!("prove: {e}"))?;
    let cryptographic_prove_ms = elapsed_ms(crypto_start);
    let serialization_start = Instant::now();
    let mut bytes = Vec::new();
    proof.serialize(&mut bytes).context("encode proof")?;
    let proof_serialization_ms = elapsed_ms(serialization_start);

    eprintln!("synthetic/research-only: independent serialized-proof verification");
    let verify_start = Instant::now();
    let mut input = bytes.as_slice();
    let decoded = Proof::<Fr, Pc>::deserialize(&mut input).context("decode proof")?;
    ensure!(input.is_empty(), "trailing proof bytes");
    let mut verifier = Verifier::<Fr, EdwardsParameters, Pc>::new(TRANSCRIPT);
    verifier.verifier_key = Some(verifier_key.clone());
    verifier
        .verify(&decoded, &pc_verifier_key, &expected_inputs)
        .map_err(|e| anyhow!("verify: {e}"))?;
    let verify_ms = elapsed_ms(verify_start);
    let wrong_endpoint_rejected = if negative_check {
        let mut wrong = expected.ordered();
        wrong[3] += Fr::from(1u64);
        let mut verifier = Verifier::<Fr, EdwardsParameters, Pc>::new(TRANSCRIPT);
        verifier.verifier_key = Some(verifier_key);
        let rejected = verifier
            .verify(
                &decoded,
                &pc_verifier_key,
                &public_inputs(&positions, &wrong)?,
            )
            .is_err();
        ensure!(rejected, "proof accepted an altered endpoint");
        Some(rejected)
    } else {
        None
    };
    report["phases_ms"] = json!({"input_preflight":input_preflight_ms,"setup":setup_ms,
        "srs_setup":srs_setup_ms,"key_compile_and_trim":key_compile_ms,
        "witness_localcheck":witness_localcheck_ms,"cryptographic_prove":cryptographic_prove_ms,
        "proof_serialization":proof_serialization_ms,"verify":verify_ms,"total":elapsed_ms(total_start)});
    report["verified"] = json!(true);
    report["proof_bytes"] = json!(bytes.len());
    report["wrong_endpoint_rejected"] = json!(wrong_endpoint_rejected);
    println!("{report}");
    Ok(())
}
