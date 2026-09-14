//! Synthetic scaling measurements of the production raw24 circuit and proof system.
//!
//! This example is research-only: inputs are supplied typed artifacts, not authenticated QEMU
//! measurements. It does not issue or check a provider attestation, and must not be presented as
//! an end-to-end acquisition result. The actual circuit, witness, ZK prover, and verifier are
//! reused without modifications.
//!
//! Build with `RUSTFLAGS="-C target-cpu=native" cargo build --release --features experiments --example scaling`.
//! Run with `RAYON_NUM_THREADS=8 target/release/examples/scaling --typed-dir DIR
//! --path-mode complete --edge-cap 64 --ep-cap 64 --log-inv-rate 1`.

use std::{collections::HashMap, path::PathBuf, time::Instant};

use anyhow::{Context, Result, bail, ensure};
use binius_core::InoutSegment;
use binius_frontend::CircuitStat;
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{config::StdChallenger, hash::StdHashSuite, zk_config::ZKVerifier};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::attestation::{BACKEND, CIRCUIT_SCHEMA, PROFILE, RawCircuitConfig};
use crate::raw::{
    RawInstance, build_raw_circuit, canonical_inout_words, canonical_public_words,
    preflight_raw_instance, signed_raw_params, validate_capacity_bounds, validate_raw_instance,
};
use crate::raw_format::Blinding;

const HELP: &str = "Research-only synthetic raw24 scaling; no acquisition or signatures.\n\
Usage: RAYON_NUM_THREADS=8 scaling --typed-dir DIR --path-mode complete|shadow \
--edge-cap N --ep-cap N [--log-inv-rate N]\n\
DIR contains translator, typed_cfg, and recorded_path. Each invocation creates a fresh proof.\n\
stdout is one JSON result; progress and errors go to stderr.";

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1e3
}

fn fresh_blinding() -> Blinding {
    loop {
        if let Ok(value) = Blinding::from_words(rand::random(), rand::random()) {
            return value;
        }
    }
}

pub(super) fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut options = HashMap::new();
    while let Some(key) = args.next() {
        if key == "--help" || key == "-h" {
            println!("{HELP}");
            return Ok(());
        }
        ensure!(
            matches!(
                key.as_str(),
                "--typed-dir" | "--path-mode" | "--edge-cap" | "--ep-cap" | "--log-inv-rate"
            ),
            "unknown argument {key}\n{HELP}"
        );
        let value = args
            .next()
            .with_context(|| format!("missing value for {key}"))?;
        ensure!(
            options.insert(key.clone(), value).is_none(),
            "duplicate argument {key}"
        );
    }
    let required = |key: &str| -> Result<&str> {
        options
            .get(key)
            .map(String::as_str)
            .with_context(|| format!("missing {key}\n{HELP}"))
    };
    ensure!(
        !cfg!(feature = "raw64"),
        "build this raw24 example without --features raw64"
    );
    ensure!(
        std::env::var("RAYON_NUM_THREADS").as_deref() == Ok("8"),
        "set RAYON_NUM_THREADS=8 before starting this controlled experiment"
    );
    let typed_dir = PathBuf::from(required("--typed-dir")?).canonicalize()?;
    let path_mode = required("--path-mode")?.to_owned();
    let edge_cap: usize = required("--edge-cap")?
        .parse()
        .context("invalid edge capacity")?;
    let ep_cap: usize = required("--ep-cap")?
        .parse()
        .context("invalid EP capacity")?;
    let log_inv_rate: usize = options
        .get("--log-inv-rate")
        .map(String::as_str)
        .unwrap_or("1")
        .parse()
        .context("invalid FRI log inverse rate")?;
    ensure!(
        matches!(path_mode.as_str(), "complete" | "shadow"),
        "invalid path mode"
    );
    ensure!(
        edge_cap >= 8 && edge_cap.is_power_of_two(),
        "edge capacity must be a power of two >= 8"
    );
    ensure!(
        (16..=1 << 24).contains(&ep_cap) && ep_cap.is_power_of_two(),
        "EP capacity must be a power of two from 16 through 2^24"
    );
    ensure!(
        (1..=16).contains(&log_inv_rate),
        "FRI log inverse rate must be 1 through 16"
    );
    let config = RawCircuitConfig {
        schema: CIRCUIT_SCHEMA.to_owned(),
        profile: PROFILE.to_owned(),
        backend: BACKEND.to_owned(),
        path_mode,
        edge_cap,
        ep_cap,
        log_inv_rate,
    };
    // signed_raw_params is the production parameter derivation API; this local configuration
    // intentionally has no signature and confers no acquisition authenticity.
    let params = signed_raw_params(&config)?;
    let total_start = Instant::now();
    eprintln!("synthetic/research-only: loading typed artifacts; no QEMU or signature claims");
    let input_start = Instant::now();
    let mut source_hashes = serde_json::Map::new();
    for name in ["translator", "typed_cfg", "recorded_path"] {
        let bytes = std::fs::read(typed_dir.join(name))?;
        source_hashes.insert(name.to_owned(), json!(hex::encode(Sha256::digest(bytes))));
    }
    let ep_blind = fresh_blinding();
    let cfg_blind = loop {
        let candidate = fresh_blinding();
        if candidate != ep_blind {
            break candidate;
        }
    };
    let instance = RawInstance::from_typed_bundle_with_openings(
        typed_dir
            .to_str()
            .context("typed artifact path must be UTF-8")?,
        ep_blind,
        cfg_blind,
    )?;
    validate_capacity_bounds(&instance, params)?;
    validate_raw_instance(&instance, params)?;
    let (max_multiplicity_entry, max_multiplicity) = preflight_raw_instance(&instance, params)?;
    // These values hash canonical EP/CFG buffers independently of the circuit witness.
    let verifier_values = instance.public_values(params);
    let verifier_inout = canonical_inout_words(verifier_values);
    let (ep_buffer_words, cfg_buffer_words) = instance.buffer_word_counts(params);
    let input_preflight_ms = elapsed_ms(input_start);

    eprintln!("synthetic/research-only: compiling circuit and setting up keys");
    let setup_start = Instant::now();
    let (circuit, walk) = build_raw_circuit(params);
    let stat = CircuitStat::collect(&circuit);
    let circuit_build_ms = elapsed_ms(setup_start);
    let cs = circuit.constraint_system();
    let key_start = Instant::now();
    let verifier = ZKVerifier::<StdHashSuite>::setup(cs.clone(), log_inv_rate)?;
    let verifier_setup_ms = elapsed_ms(key_start);
    let key_start = Instant::now();
    let prover = ZKProver::<OptimalPackedB128, StdHashSuite>::setup(&verifier)?;
    let prover_setup_ms = elapsed_ms(key_start);
    let setup_ms = elapsed_ms(setup_start);

    eprintln!("synthetic/research-only: constructing witness, checking constraints, and proving");
    let prove_start = Instant::now();
    let mut filler = circuit.new_witness_filler();
    walk.populate(&mut filler, &instance)?;
    circuit.populate_wire_witness(&mut filler)?;
    let witness = filler.into_value_vec();
    cs.verify(&witness)
        .map_err(|error| anyhow::anyhow!("constraint verification failed: {error}"))?;
    ensure!(
        witness.public() == canonical_public_words(cs, verifier_values)?,
        "witness public segment differs from independently reconstructed canonical statement"
    );
    let witness_localcheck_ms = elapsed_ms(prove_start);
    let crypto_start = Instant::now();
    let mut transcript = ProverTranscript::new(StdChallenger::default());
    prover.prove(&witness, rand::rng(), &mut transcript)?;
    let proof = transcript.finalize();
    let crypto_prove_ms = elapsed_ms(crypto_start);
    let prove_total_ms = elapsed_ms(prove_start);
    let proof_bytes = proof.len();

    eprintln!("synthetic/research-only: verifying proof against canonical public inputs");
    let verify_start = Instant::now();
    let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof);
    verifier.verify(&verifier_inout, &mut transcript)?;
    transcript.finalize()?;
    let verify_ms = elapsed_ms(verify_start);
    // Reject concurrent input replacement instead of assigning the proof to mismatched files.
    for name in ["translator", "typed_cfg", "recorded_path"] {
        let digest = hex::encode(Sha256::digest(std::fs::read(typed_dir.join(name))?));
        if source_hashes[name] != json!(digest) {
            bail!("typed artifact changed during the run: {name}");
        }
    }
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "zkcfa.research.scaling.v1",
            "synthetic": true,
            "research_only": true,
            "acquisition_measured": false,
            "provider_signatures_checked": false,
            "profile": PROFILE,
            "backend": BACKEND,
            "typed_dir": typed_dir,
            "input_sha256": source_hashes,
            "path_mode": params.path_mode_label(),
            "path_statement": params.path_statement(),
            "addr_bits": 24,
            "rayon_num_threads": 8,
            "log_inv_rate": log_inv_rate,
            "edge_capacity": edge_cap,
            "ep_capacity": ep_cap,
            "ep_encoding": params.ep_encoding_label(),
            "multiplicity_bits": params.mult_bits(),
            "nodes": instance.node_count(),
            "edges": instance.edge_count(),
            "rows": instance.step_count(),
            "entry": format!("{:#x}", instance.entry()),
            "final_node": format!("{:#x}", instance.final_node()),
            "ep_buffer_words": ep_buffer_words,
            "cfg_buffer_words": cfg_buffer_words,
            "max_multiplicity_entry": max_multiplicity_entry,
            "max_multiplicity": max_multiplicity,
            "and_constraints": stat.n_and_constraints,
            "imul_constraints": stat.n_imul_constraints,
            "bmul_constraints": stat.n_bmul_constraints,
            "zero_constraints": stat.n_zero_constraints,
            "native_constraint_count": stat.n_and_constraints + stat.n_imul_constraints + stat.n_bmul_constraints + stat.n_zero_constraints,
            "gates": stat.n_gates,
            "committed_words": stat.committed_allocated,
            "value_words": cs.value_vec_len(),
            "public_words": cs.n_public_words(InoutSegment::Public),
            "hidden_words": cs.n_hidden_words(InoutSegment::Public),
            "private_input_words": cs.n_private,
            "input_preflight_ms": input_preflight_ms,
            "circuit_build_ms": circuit_build_ms,
            "verifier_setup_ms": verifier_setup_ms,
            "prover_setup_ms": prover_setup_ms,
            "setup_ms": setup_ms,
            "witness_localcheck_ms": witness_localcheck_ms,
            "crypto_prove_ms": crypto_prove_ms,
            "prove_total_ms": prove_total_ms,
            "verify_ms": verify_ms,
            "proof_bytes": proof_bytes,
            "total_ms": elapsed_ms(total_start),
            "verified": true,
            "timing_scope": "setup excludes input loading/preflight; prove_total includes witness filling, local checks, and cryptographic proving; verify includes transcript finalization",
        }))?
    );
    Ok(())
}
