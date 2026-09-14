//! Research-only compiled-constraint ablation of the production timestamped stack checker.
//!
//! The two circuits share raw24 records, SHA-256 commitments, and BinMult membership.
//! Their sole construction difference is the existing RawShadow inclusion switch. Every
//! supplied witness is validated against both complete compiled constraint systems. An
//! optional proof roundtrip uses only the complete production relation.
//!
//! Build: RUSTFLAGS="-C target-cpu=native" cargo build --release --features stack-control --example stack_control
//! Run: RAYON_NUM_THREADS=8 target/release/examples/stack_control --typed-dir DIR --ep-cap N [--prove]

use std::{collections::HashMap, path::PathBuf, time::Instant};

use anyhow::{Context, Result, ensure};
use binius_frontend::CircuitStat;
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{config::StdChallenger, hash::StdHashSuite, zk_config::ZKVerifier};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::attestation::{BACKEND, CIRCUIT_SCHEMA, PROFILE, RawCircuitConfig};
use crate::raw::{
    RawInstance, build_raw_stack_control, canonical_inout_words, canonical_public_words,
    preflight_raw_instance, signed_raw_params, validate_capacity_bounds, validate_raw_instance,
};
use crate::raw_format::Blinding;

pub(super) fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut options = HashMap::new();
    let mut prove = false;
    while let Some(key) = args.next() {
        if key == "--prove" {
            prove = true;
        } else {
            ensure!(
                matches!(key.as_str(), "--typed-dir" | "--ep-cap"),
                "unknown argument {key}"
            );
            let value = args
                .next()
                .with_context(|| format!("missing value for {key}"))?;
            ensure!(
                options.insert(key.clone(), value).is_none(),
                "duplicate argument {key}"
            );
        }
    }
    ensure!(!cfg!(feature = "raw64"), "stack_control measures raw24");
    ensure!(
        std::env::var("RAYON_NUM_THREADS").as_deref() == Ok("8"),
        "set RAYON_NUM_THREADS=8"
    );
    let typed_dir =
        PathBuf::from(options.get("--typed-dir").context("missing --typed-dir")?).canonicalize()?;
    let ep_cap: usize = options
        .get("--ep-cap")
        .context("missing --ep-cap")?
        .parse()?;
    ensure!(
        (16..=4096).contains(&ep_cap) && ep_cap.is_power_of_two(),
        "EP capacity must be a power of two in 16..=4096"
    );
    let params = signed_raw_params(&RawCircuitConfig {
        schema: CIRCUIT_SCHEMA.to_owned(),
        profile: PROFILE.to_owned(),
        backend: BACKEND.to_owned(),
        path_mode: "complete".to_owned(),
        edge_cap: 8,
        ep_cap,
        log_inv_rate: 1,
    })?;
    // Fixed distinct research openings make witness construction reproducible. They are not
    // used as production commitment randomness or to make privacy claims.
    let instance = RawInstance::from_typed_bundle_with_openings(
        typed_dir.to_str().context("non-UTF-8 input path")?,
        Blinding::from_words(1, 2)?,
        Blinding::from_words(3, 4)?,
    )?;
    validate_capacity_bounds(&instance, params)?;
    validate_raw_instance(&instance, params)?;
    let (_, max_multiplicity) = preflight_raw_instance(&instance, params)?;
    ensure!(
        instance.step_count() == ep_cap,
        "this experiment uses fully occupied EP capacity"
    );
    let mut source_hashes = serde_json::Map::new();
    for name in ["translator", "typed_cfg", "recorded_path"] {
        source_hashes.insert(
            name.to_owned(),
            json!(hex::encode(Sha256::digest(std::fs::read(
                typed_dir.join(name)
            )?))),
        );
    }
    let values = instance.public_values(params);
    let mut results = Vec::new();
    let mut counts = Vec::new();
    for include_shadow in [false, true] {
        eprintln!(
            "compiling {} stack, L={ep_cap}",
            if include_shadow { "with" } else { "without" }
        );
        let start = Instant::now();
        let (circuit, walk) = build_raw_stack_control(params, include_shadow);
        let build_ms = start.elapsed().as_secs_f64() * 1000.0;
        let stat = CircuitStat::collect(&circuit);
        let native = [
            stat.n_and_constraints,
            stat.n_imul_constraints,
            stat.n_bmul_constraints,
            stat.n_zero_constraints,
        ];
        let cs = circuit.constraint_system();
        let start = Instant::now();
        let mut filler = circuit.new_witness_filler();
        walk.populate(&mut filler, &instance)?;
        circuit.populate_wire_witness(&mut filler)?;
        let witness = filler.into_value_vec();
        cs.verify(&witness)
            .map_err(|error| anyhow::anyhow!("constraint verification failed: {error}"))?;
        ensure!(
            witness.public() == canonical_public_words(cs, values)?,
            "public witness differs from reconstructed statement"
        );
        let localcheck_ms = start.elapsed().as_secs_f64() * 1000.0;
        let mut result = json!({
            "include_stack": include_shadow, "and_constraints": native[0], "imul_constraints": native[1],
            "bmul_constraints": native[2], "zero_constraints": native[3], "native_constraint_count": native.iter().sum::<usize>(),
            "gates": stat.n_gates, "committed_words": stat.committed_allocated, "value_words": cs.value_vec_len(),
            "build_ms": build_ms, "witness_localcheck_ms": localcheck_ms, "constraints_verified": true,
            "public_statement_checked": true, "cryptographic_proof_requested": include_shadow && prove,
        });
        if include_shadow && prove {
            let verifier = ZKVerifier::<StdHashSuite>::setup(cs.clone(), 1)?;
            let prover = ZKProver::<OptimalPackedB128, StdHashSuite>::setup(&verifier)?;
            let mut transcript = ProverTranscript::new(StdChallenger::default());
            prover.prove(&witness, rand::rng(), &mut transcript)?;
            let proof = transcript.finalize();
            result["proof_bytes"] = json!(proof.len());
            let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof);
            verifier.verify(&canonical_inout_words(values), &mut transcript)?;
            transcript.finalize()?;
            result["proof_verified"] = json!(true);
        }
        counts.push(native);
        results.push(result);
    }
    for name in ["translator", "typed_cfg", "recorded_path"] {
        ensure!(
            source_hashes[name]
                == json!(hex::encode(Sha256::digest(std::fs::read(
                    typed_dir.join(name)
                )?))),
            "input changed during run"
        );
    }
    let delta: Vec<i64> = counts[1]
        .iter()
        .zip(counts[0])
        .map(|(a, b)| *a as i64 - b as i64)
        .collect();
    println!(
        "{}",
        serde_json::to_string(&json!({
            "schema": "zkcfa.research.stack-control.v1", "research_only": true, "synthetic": true,
            "measurement": "difference of independently compiled production relations with and without RawShadow",
            "constraint_units": "native Binius64 AND, integer multiplication, binary-field multiplication, and ZERO constraints",
            "acquisition_measured": false, "provider_signatures_checked": false,
            "profile": PROFILE, "backend": BACKEND, "path_mode": params.path_mode_label(),
            "ep_encoding": params.ep_encoding_label(), "addr_bits": 24, "stack_pointer_bits": 15, "stack_depth_bound": 32767,
            "rayon_num_threads": 8, "edge_capacity": params.edge_cap(), "ep_capacity": ep_cap,
            "active_rows": instance.step_count(), "typed_edges": instance.edge_count(), "nodes": instance.node_count(),
            "max_multiplicity": max_multiplicity, "input_sha256": source_hashes, "circuits": results,
            "stack_delta": {"and_constraints": delta[0], "imul_constraints": delta[1], "bmul_constraints": delta[2],
                "zero_constraints": delta[3], "native_constraint_count": delta.iter().sum::<i64>()},
            "timing_scope": "single-run diagnostic build/local-check timings; not a repeated proving-time experiment"
        }))?
    );
    Ok(())
}
