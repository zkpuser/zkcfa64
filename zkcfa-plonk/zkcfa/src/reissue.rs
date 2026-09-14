//! Strict authenticated reissuance from a provider Binius64 bundle to a PLONK bundle.
//!
//! This is deliberately a separate binary from the prover.  It authenticates and snapshots the
//! source acquisition, reopens its SHA-256 commitments, then issues a new statement with fresh
//! keys, openings, challenge, and Poseidon commitments.  Relabelling source JSON is never enough.

use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure, Context, Result};
use ark_bls12_381::Fr as BlsScalar;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{
    pkcs8::{spki::der::pem::LineEnding, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    attestation::{
        canonical_json, domain_hash, load_provider_handoff, load_public_statement,
        reviewed_commitment_config, sha256, BundleConfig, CircuitConfig, ExpectedChallenge,
        ALGORITHM, BACKEND, CIRCUIT_SCHEMA, PROFILE, REGISTRY_SCHEMA, REPORT_SCHEMA, SCOPE_SCHEMA,
        WORKER_SCHEMA,
    },
    poseidon::field_hex,
    raw_format::{PathMode, RawInstance, RawOpenings, RawParams, RAW_ADDR_LIMIT},
};

const AUTHORITY_SIGNATURE_DOMAIN: &[u8] = b"ZKCFA/raw/registry/signature\0";
const DEVICE_SIGNATURE_DOMAIN: &[u8] = b"ZKCFA/raw/report/signature\0";
const ENROLLMENT_SIGNATURE_DOMAIN: &[u8] = b"ZKCFA/raw/enrollment/signature\0";
const CONFIG_ID_DOMAIN: &[u8] = b"ZKCFA/raw/circuit/id\0";
const REGISTRY_ID_DOMAIN: &[u8] = b"ZKCFA/raw/registry/id\0";
const SCOPE_POLICY_DOMAIN: &[u8] = b"ZKCFA/raw/scope/digest\0";
const SOURCE_REPORT_ID_DOMAIN: &[u8] = b"ZKCFA/raw/source-report/id\0";
const KEY_ID_DOMAIN: &[u8] = b"ZKCFA/key/id\0";

const ENROLLMENT_SCHEMA: &str = "zkcfa.raw.enrollment";
const REISSUANCE_SCHEMA: &str = "zkcfa.plonk.reissuance.run";
const REISSUANCE_KIND: &str = "authenticated-reissuance";
const SOURCE_BACKEND: &str = "binius64";
const TARGET_DEVICE_ID: &str = "plonk-reissuer";

const JSON_LIMIT: u64 = 4 * 1024 * 1024;
const KEY_LIMIT: u64 = 1024 * 1024;
const ARTIFACT_LIMIT: u64 = 512 * 1024 * 1024;

const USAGE: &str = "usage: zkcfa-reissue \
--source-bundle PATH \
--source-authority-public PATH \
--source-authority-sha256 HEX64 \
--source-challenge-id HEX32 \
--source-nonce HEX64 \
--source-enrollment PATH \
--target-challenge-id HEX32 \
--target-nonce HEX64 \
--run-dir PATH";

#[derive(Clone, Debug)]
struct ReissueConfig {
    source_bundle: PathBuf,
    source_authority_public: PathBuf,
    source_authority_sha256: [u8; 32],
    source_challenge_id: String,
    source_nonce: [u8; 32],
    source_enrollment: PathBuf,
    target_challenge_id: String,
    target_nonce: [u8; 32],
    run_dir: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Provenance {
    kind: String,
    source_backend: String,
    source_registry_id: String,
    source_report_id: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceSummary {
    bundle: String,
    authority_public: String,
    authority_sha256: String,
    challenge_id: String,
    nonce: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtocolResult {
    schema: String,
    pub(crate) bundle: String,
    pub(crate) authority_public: String,
    pub(crate) authority_sha256: String,
    pub(crate) challenge_id: String,
    pub(crate) nonce: String,
    device_id: String,
    device_public: String,
    enrollment: String,
    raw_registry_id: String,
    raw_config_id: String,
    h_cfg_raw24: String,
    h_ep_raw24: String,
    provenance: Provenance,
    source: SourceSummary,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BiniusCircuitConfig {
    schema: String,
    profile: String,
    backend: String,
    log_inv_rate: usize,
    path_mode: String,
    edge_cap: usize,
    ep_cap: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScopePolicy {
    schema: String,
    architecture: String,
    boundary_kind: String,
    root_symbol: String,
    caller_symbol: String,
    scope_call_address: String,
    root_address: String,
    root_exit_blocks: Vec<String>,
    scope_return_address: String,
    sentinel: String,
    sentinel_address: String,
    require_complete_entry_exit: bool,
    position_independent: bool,
    canonical_entry: String,
    canonical_start_code: String,
    canonical_address_model: String,
    proof_path_compression: String,
    normalization: String,
    external_call_model: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
struct RawEndpoint {
    entry_raw: u64,
    final_raw: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisteredDevice {
    algorithm: String,
    key_id: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BiniusRegistryPayload {
    schema: String,
    application: String,
    raw_registry_id: String,
    binary_measurement: String,
    raw_config_id: String,
    h_cfg_raw24: String,
    circuit: BiniusCircuitConfig,
    allowed_endpoints: Vec<RawEndpoint>,
    devices: HashMap<String, RegisteredDevice>,
    scope_policy: ScopePolicy,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportPayload {
    schema: String,
    device_id: String,
    challenge_id: String,
    nonce: String,
    raw_registry_id: String,
    raw_config_id: String,
    binary_measurement: String,
    h_cfg_raw24: String,
    h_ep_raw24: String,
    entry_raw: u64,
    final_raw: u64,
    scope_policy_digest: String,
    runtime_code_match: bool,
    boundary_policy_satisfied: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerSecret {
    schema: String,
    raw_registry_id: String,
    raw_config_id: String,
    h_cfg_raw24: String,
    h_ep_raw24: String,
    ep_blind_low: String,
    ep_blind_high: String,
    cfg_blind_low: String,
    cfg_blind_high: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentPayload {
    schema: String,
    raw_registry_id: String,
    cfg_blind_low: String,
    cfg_blind_high: String,
    static_manifest_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    algorithm: String,
    key_id: String,
    payload: Value,
    signature: String,
}

struct SourceBundle {
    application: String,
    binary_measurement: [u8; 32],
    circuit: BiniusCircuitConfig,
    allowed_endpoints: Vec<RawEndpoint>,
    scope_policy: ScopePolicy,
    endpoint: RawEndpoint,
    raw_registry_id: [u8; 32],
    source_report_id: [u8; 32],
    h_cfg_sha256: [u8; 32],
    h_ep_sha256: [u8; 32],
    source_openings: RawOpenings,
    static_manifest_sha256: String,
    authority: VerifyingKey,
    device: VerifyingKey,
    artifacts: HashMap<&'static str, Vec<u8>>,
}

pub(crate) fn run_cli(arguments: impl IntoIterator<Item = OsString>) -> Result<ProtocolResult> {
    let config = parse_arguments(arguments)?;
    issue(config)
}

fn parse_arguments(arguments: impl IntoIterator<Item = OsString>) -> Result<ReissueConfig> {
    let mut arguments = arguments.into_iter();
    let mut values = HashMap::<String, OsString>::new();
    while let Some(argument) = arguments.next() {
        let flag = argument
            .into_string()
            .map_err(|_| anyhow::anyhow!("command-line flag is not UTF-8\n{USAGE}"))?;
        ensure!(
            flag.starts_with("--"),
            "unexpected positional argument {flag:?}\n{USAGE}"
        );
        ensure!(
            matches!(
                flag.as_str(),
                "--source-bundle"
                    | "--source-authority-public"
                    | "--source-authority-sha256"
                    | "--source-challenge-id"
                    | "--source-nonce"
                    | "--source-enrollment"
                    | "--target-challenge-id"
                    | "--target-nonce"
                    | "--run-dir"
            ),
            "unknown argument {flag:?}\n{USAGE}"
        );
        let value = arguments
            .next()
            .with_context(|| format!("{flag} requires a value\n{USAGE}"))?;
        ensure!(
            values.insert(flag.clone(), value).is_none(),
            "repeated argument {flag:?}\n{USAGE}"
        );
    }

    let mut take = |name: &str| {
        values
            .remove(name)
            .with_context(|| format!("missing required argument {name}\n{USAGE}"))
    };
    let source_bundle = PathBuf::from(take("--source-bundle")?);
    let source_authority_public = PathBuf::from(take("--source-authority-public")?);
    let source_authority_sha256 = parse_hex32_os(
        take("--source-authority-sha256")?,
        "source authority SHA-256",
    )?;
    let source_challenge_id =
        parse_hex16_os(take("--source-challenge-id")?, "source challenge id")?;
    let source_nonce = parse_hex32_os(take("--source-nonce")?, "source challenge nonce")?;
    let source_enrollment = PathBuf::from(take("--source-enrollment")?);
    let target_challenge_id =
        parse_hex16_os(take("--target-challenge-id")?, "target challenge id")?;
    let target_nonce = parse_hex32_os(take("--target-nonce")?, "target challenge nonce")?;
    let run_dir = PathBuf::from(take("--run-dir")?);
    ensure!(values.is_empty(), "internal argument parser error");
    ensure!(
        source_challenge_id != target_challenge_id,
        "target challenge id must be fresh and differ from the source challenge id"
    );
    ensure!(
        source_nonce != target_nonce,
        "target nonce must be fresh and differ from the source nonce"
    );
    Ok(ReissueConfig {
        source_bundle,
        source_authority_public,
        source_authority_sha256,
        source_challenge_id,
        source_nonce,
        source_enrollment,
        target_challenge_id,
        target_nonce,
        run_dir,
    })
}

fn authenticate_source(config: &ReissueConfig) -> Result<SourceBundle> {
    check_directory(&config.source_bundle, "source provider bundle root")?;
    check_exact_names(
        &config.source_bundle,
        &["private", "public"],
        "source provider bundle root",
    )?;
    let public_dir = config.source_bundle.join("public");
    let private_dir = config.source_bundle.join("private");
    check_directory(&public_dir, "source provider public directory")?;
    check_private_directory(&private_dir, "source provider private directory")?;
    check_exact_names(
        &public_dir,
        &["registry.json", "report.json"],
        "source provider public directory",
    )?;
    check_exact_names(
        &private_dir,
        &["recorded_path", "translator", "typed_cfg", "worker.json"],
        "source provider private directory",
    )?;

    let authority_bytes = read_regular(
        &config.source_authority_public,
        "source authority public key",
        false,
        KEY_LIMIT,
    )?;
    ensure!(
        sha256(&authority_bytes) == config.source_authority_sha256,
        "source authority public key does not match the independently configured SHA-256 pin"
    );
    let authority = VerifyingKey::from_public_key_pem(
        std::str::from_utf8(&authority_bytes).context("source authority PEM is not UTF-8")?,
    )
    .context("decode source Ed25519 authority public key")?;

    let registry_bytes = read_regular(
        &public_dir.join("registry.json"),
        "source signed registry",
        false,
        JSON_LIMIT,
    )?;
    let registry_value = verify_envelope_bytes(
        &registry_bytes,
        &authority,
        AUTHORITY_SIGNATURE_DOMAIN,
        "source signed registry",
    )?;
    let registry: BiniusRegistryPayload = serde_json::from_value(registry_value.clone())
        .context("decode source Binius64 registry payload")?;
    validate_binius_registry(&registry, &registry_value)?;
    let raw_registry_id = parse_hex32(&registry.raw_registry_id, "source registry id")?;
    let raw_config_id = parse_hex32(&registry.raw_config_id, "source config id")?;
    let h_cfg_sha256 = parse_hex32(&registry.h_cfg_raw24, "source SHA-256 H_cfg")?;
    let binary_measurement =
        parse_hex32(&registry.binary_measurement, "source binary measurement")?;

    let report_bytes = read_regular(
        &public_dir.join("report.json"),
        "source signed report",
        false,
        JSON_LIMIT,
    )?;
    let unsigned_report: Envelope =
        serde_json::from_slice(&report_bytes).context("decode source signed report envelope")?;
    let unsigned_device_id = unsigned_report
        .payload
        .get("device_id")
        .and_then(Value::as_str)
        .context("source report has no device_id")?
        .to_owned();
    validate_identifier(&unsigned_device_id, "source report device id")?;
    let registered_device = registry
        .devices
        .get(&unsigned_device_id)
        .context("source report device is not authorized by the source registry")?;
    let device = verifying_key_from_base64(&registered_device.public_key)?;
    let report_value = verify_envelope(
        unsigned_report,
        &device,
        DEVICE_SIGNATURE_DOMAIN,
        "source signed report",
    )?;
    let source_report_id = domain_hash(
        SOURCE_REPORT_ID_DOMAIN,
        &canonical_json(&report_value).context("canonicalize authenticated source report")?,
    );
    let report: ReportPayload =
        serde_json::from_value(report_value).context("decode source Binius64 report payload")?;
    validate_source_report(config, &registry, &report, &unsigned_device_id)?;
    let endpoint = RawEndpoint {
        entry_raw: report.entry_raw,
        final_raw: report.final_raw,
    };
    let h_ep_sha256 = parse_hex32(&report.h_ep_raw24, "source SHA-256 H_ep")?;

    let worker_bytes = read_regular(
        &private_dir.join("worker.json"),
        "source worker secret",
        true,
        JSON_LIMIT,
    )?;
    let worker: WorkerSecret =
        serde_json::from_slice(&worker_bytes).context("decode source worker secret")?;
    ensure!(
        worker.schema == WORKER_SCHEMA,
        "unsupported source worker schema"
    );
    ensure!(
        parse_hex32(&worker.raw_registry_id, "source worker registry id")? == raw_registry_id
            && parse_hex32(&worker.raw_config_id, "source worker config id")? == raw_config_id
            && parse_hex32(&worker.h_cfg_raw24, "source worker H_cfg")? == h_cfg_sha256
            && parse_hex32(&worker.h_ep_raw24, "source worker H_ep")? == h_ep_sha256,
        "source worker handoff differs from the authenticated source statement"
    );
    let source_openings = RawOpenings {
        ep: [
            parse_hex_word(&worker.ep_blind_low, "source ep_blind_low")?,
            parse_hex_word(&worker.ep_blind_high, "source ep_blind_high")?,
        ],
        cfg: [
            parse_hex_word(&worker.cfg_blind_low, "source cfg_blind_low")?,
            parse_hex_word(&worker.cfg_blind_high, "source cfg_blind_high")?,
        ],
    };
    ensure!(
        source_openings.ep != [0, 0]
            && source_openings.cfg != [0, 0]
            && source_openings.ep != source_openings.cfg,
        "source worker openings must be nonzero and independent"
    );

    let enrollment_bytes = read_regular(
        &config.source_enrollment,
        "source authority enrollment",
        true,
        JSON_LIMIT,
    )?;
    let enrollment_value = verify_envelope_bytes(
        &enrollment_bytes,
        &authority,
        ENROLLMENT_SIGNATURE_DOMAIN,
        "source authority enrollment",
    )?;
    let enrollment: EnrollmentPayload = serde_json::from_value(enrollment_value)
        .context("decode source authority enrollment payload")?;
    ensure!(
        enrollment.schema == ENROLLMENT_SCHEMA,
        "unsupported source authority enrollment schema"
    );
    ensure!(
        parse_hex32(&enrollment.raw_registry_id, "source enrollment registry id")?
            == raw_registry_id,
        "source authority enrollment belongs to another registry"
    );
    ensure!(
        parse_hex_word(&enrollment.cfg_blind_low, "source enrollment cfg_blind_low")?
            == source_openings.cfg[0]
            && parse_hex_word(
                &enrollment.cfg_blind_high,
                "source enrollment cfg_blind_high"
            )? == source_openings.cfg[1],
        "source authority enrollment does not authenticate the worker CFG opening"
    );
    parse_hex32(
        &enrollment.static_manifest_sha256,
        "source static-manifest SHA-256",
    )?;

    let mut artifacts = HashMap::new();
    for (name, label) in [
        ("translator", "source translator"),
        ("typed_cfg", "source typed CFG"),
        ("recorded_path", "source recorded path"),
    ] {
        artifacts.insert(
            name,
            read_regular(&private_dir.join(name), label, true, ARTIFACT_LIMIT)?,
        );
    }

    Ok(SourceBundle {
        application: registry.application,
        binary_measurement,
        circuit: registry.circuit,
        allowed_endpoints: registry.allowed_endpoints,
        scope_policy: registry.scope_policy,
        endpoint,
        raw_registry_id,
        source_report_id,
        h_cfg_sha256,
        h_ep_sha256,
        source_openings,
        static_manifest_sha256: enrollment.static_manifest_sha256,
        authority,
        device,
        artifacts,
    })
}

fn validate_binius_registry(registry: &BiniusRegistryPayload, value: &Value) -> Result<()> {
    ensure!(
        registry.schema == REGISTRY_SCHEMA,
        "unsupported source registry schema"
    );
    validate_identifier(&registry.application, "source registry application")?;
    validate_binius_circuit(&registry.circuit)?;
    validate_scope_policy(&registry.scope_policy, &registry.circuit.path_mode)?;
    validate_endpoints(&registry.allowed_endpoints)?;
    validate_devices(&registry.devices)?;

    let expected_config_id = domain_hash(
        CONFIG_ID_DOMAIN,
        &canonical_json(&serde_json::to_value(&registry.circuit)?)?,
    );
    ensure!(
        parse_hex32(&registry.raw_config_id, "source config id")? == expected_config_id,
        "source Binius64 circuit configuration identifier is not canonical"
    );
    let mut without_id = value.clone();
    without_id
        .as_object_mut()
        .context("source registry payload is not an object")?
        .remove("raw_registry_id")
        .context("source registry payload has no raw_registry_id")?;
    let expected_registry_id = domain_hash(REGISTRY_ID_DOMAIN, &canonical_json(&without_id)?);
    ensure!(
        parse_hex32(&registry.raw_registry_id, "source registry id")? == expected_registry_id,
        "source Binius64 registry identifier is not canonical"
    );
    parse_hex32(&registry.binary_measurement, "source binary measurement")?;
    parse_hex32(&registry.h_cfg_raw24, "source SHA-256 H_cfg")?;
    Ok(())
}

fn validate_binius_circuit(circuit: &BiniusCircuitConfig) -> Result<()> {
    ensure!(
        circuit.schema == CIRCUIT_SCHEMA
            && circuit.profile == PROFILE
            && circuit.backend == SOURCE_BACKEND,
        "source statement is not the reviewed Binius64 raw24 profile"
    );
    ensure!(
        matches!(circuit.path_mode.as_str(), "complete" | "shadow"),
        "source Binius64 path mode is unsupported"
    );
    ensure!(
        circuit.edge_cap >= 8
            && circuit.edge_cap <= RAW_ADDR_LIMIT as usize
            && circuit.edge_cap.is_power_of_two(),
        "source Binius64 EDGE_CAP is not a canonical power-of-two capacity"
    );
    ensure!(
        circuit.ep_cap >= 16
            && circuit.ep_cap <= RAW_ADDR_LIMIT as usize
            && circuit.ep_cap.is_power_of_two(),
        "source Binius64 EP_CAP is not a canonical power-of-two capacity"
    );
    ensure!(
        (1..=16).contains(&circuit.log_inv_rate),
        "source Binius64 log_inv_rate is outside 1..=16"
    );
    if circuit.ep_cap <= 1 << 14 {
        let query_count = 2usize
            .checked_mul(circuit.ep_cap - 1)
            .context("source Binius64 membership-query count overflow")?;
        let aggregate_capacity = circuit
            .edge_cap
            .checked_mul((1 << 12) - 1)
            .context("source Binius64 multiplicity capacity overflow")?;
        ensure!(
            query_count <= aggregate_capacity,
            "source Binius64 inline14 capacity pair is infeasible"
        );
    }
    Ok(())
}

fn validate_source_report(
    config: &ReissueConfig,
    registry: &BiniusRegistryPayload,
    report: &ReportPayload,
    unsigned_device_id: &str,
) -> Result<()> {
    ensure!(
        report.schema == REPORT_SCHEMA,
        "unsupported source report schema"
    );
    ensure!(
        report.device_id == unsigned_device_id,
        "source report device id changed during authenticated decoding"
    );
    parse_hex16(&report.challenge_id, "source report challenge id")?;
    let report_nonce = parse_hex32(&report.nonce, "source report nonce")?;
    ensure!(
        report.challenge_id == config.source_challenge_id,
        "source report challenge id is stale or unexpected"
    );
    ensure!(
        report_nonce == config.source_nonce,
        "source report nonce is stale or unexpected"
    );
    ensure!(
        report.raw_registry_id == registry.raw_registry_id
            && report.raw_config_id == registry.raw_config_id
            && report.binary_measurement == registry.binary_measurement
            && report.h_cfg_raw24 == registry.h_cfg_raw24,
        "source report is not bound to its authenticated registry"
    );
    ensure!(
        report.runtime_code_match && report.boundary_policy_satisfied,
        "source report does not attest runtime-code and boundary-policy success"
    );
    let endpoint = RawEndpoint {
        entry_raw: report.entry_raw,
        final_raw: report.final_raw,
    };
    validate_endpoint(endpoint, "source report")?;
    ensure!(
        registry.allowed_endpoints.contains(&endpoint),
        "source report endpoint is not authority-authorized"
    );
    let expected_scope_digest = domain_hash(
        SCOPE_POLICY_DOMAIN,
        &canonical_json(&serde_json::to_value(&registry.scope_policy)?)?,
    );
    ensure!(
        parse_hex32(&report.scope_policy_digest, "source scope-policy digest")?
            == expected_scope_digest,
        "source report is not bound to its authority scope policy"
    );
    parse_hex32(&report.h_ep_raw24, "source SHA-256 H_ep")?;
    Ok(())
}

fn issue(config: ReissueConfig) -> Result<ProtocolResult> {
    parse_hex16(&config.source_challenge_id, "source challenge id")?;
    parse_hex16(&config.target_challenge_id, "target challenge id")?;
    ensure!(
        config.source_challenge_id != config.target_challenge_id
            && config.source_nonce != config.target_nonce,
        "target challenge id and nonce must each differ from the source freshness values"
    );
    let source = authenticate_source(&config).context("authenticate Binius64 source bundle")?;
    let output = prepare_destination(&config.run_dir)?;
    reject_input_output_overlap(
        &output,
        &[
            (&config.source_bundle, "source bundle"),
            (
                &config.source_authority_public,
                "source authority public key",
            ),
            (&config.source_enrollment, "source enrollment"),
        ],
    )?;
    let mut staging = StagingDirectory::new(&output)?;
    let root = staging.path();
    let bundle = root.join("bundle");
    let public = bundle.join("public");
    let private = bundle.join("private");
    let keys = root.join("keys");
    let keys_public = keys.join("public");
    let keys_private = keys.join("private");
    let issuance = root.join("issuance");
    create_directory(&bundle, 0o755)?;
    create_directory(&public, 0o755)?;
    create_directory(&private, 0o700)?;
    create_directory(&keys, 0o755)?;
    create_directory(&keys_public, 0o755)?;
    create_directory(&keys_private, 0o700)?;
    create_directory(&issuance, 0o700)?;

    for name in ["translator", "typed_cfg", "recorded_path"] {
        let data = source
            .artifacts
            .get(name)
            .with_context(|| format!("source snapshot has no {name}"))?;
        write_new(&private.join(name), data, 0o600)?;
    }

    let path_mode = PathMode::from_label(&source.circuit.path_mode)
        .map_err(anyhow::Error::msg)
        .context("decode authenticated source path mode")?;
    let params = RawParams {
        edge_cap: source.circuit.edge_cap,
        ep_cap: source.circuit.ep_cap,
        path_mode,
    };
    let source_instance = RawInstance::load(&private, params, source.source_openings)
        .map_err(anyhow::Error::msg)
        .context("parse snapshotted Binius64 raw24 artifacts")?;
    ensure!(
        sha256_words(&source_instance.cfg_words()) == source.h_cfg_sha256
            && sha256_words(&source_instance.ep_words()) == source.h_ep_sha256,
        "source private raw24 artifacts do not open the authenticated SHA-256 commitments"
    );
    ensure!(
        source_instance.entry() == source.endpoint.entry_raw
            && source_instance.final_node() == source.endpoint.final_raw,
        "source private recorded path does not match the authenticated endpoints"
    );

    let target_openings = random_independent_openings(source.source_openings);
    let target_instance = RawInstance::load(&private, params, target_openings)
        .map_err(anyhow::Error::msg)
        .context("rebuild raw24 buffers with fresh PLONK openings")?;
    ensure!(
        target_instance.entry() == source.endpoint.entry_raw
            && target_instance.final_node() == source.endpoint.final_raw,
        "reissued PLONK path endpoints differ from the authenticated source"
    );
    let h_cfg = target_instance
        .h_cfg_poseidon::<BlsScalar>()
        .map_err(anyhow::Error::msg)
        .context("compute target Poseidon H_cfg")?;
    let h_ep = target_instance
        .h_ep_poseidon::<BlsScalar>()
        .map_err(anyhow::Error::msg)
        .context("compute target Poseidon H_ep")?;
    let h_cfg_hex = field_hex(h_cfg);
    let h_ep_hex = field_hex(h_ep);

    let target_authority = random_signing_key_excluding(&[source.authority]);
    let target_device = random_signing_key_excluding(&[
        source.authority,
        source.device,
        target_authority.verifying_key(),
    ]);
    let authority_public_pem = target_authority
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .context("encode target authority public key")?;
    let device_public_pem = target_device
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .context("encode target device public key")?;
    let authority_private_pem = target_authority
        .to_pkcs8_pem(LineEnding::LF)
        .context("encode target authority private key")?;
    let device_private_pem = target_device
        .to_pkcs8_pem(LineEnding::LF)
        .context("encode target device private key")?;
    write_new(
        &keys_public.join("authority.pem"),
        authority_public_pem.as_bytes(),
        0o644,
    )?;
    write_new(
        &keys_public.join("device.pem"),
        device_public_pem.as_bytes(),
        0o644,
    )?;
    write_new(
        &keys_private.join("authority.pem"),
        authority_private_pem.as_bytes(),
        0o600,
    )?;
    write_new(
        &keys_private.join("device.pem"),
        device_private_pem.as_bytes(),
        0o600,
    )?;

    let circuit = CircuitConfig {
        schema: CIRCUIT_SCHEMA.to_owned(),
        profile: PROFILE.to_owned(),
        backend: BACKEND.to_owned(),
        commitment: reviewed_commitment_config(),
        path_mode: source.circuit.path_mode.clone(),
        edge_cap: source.circuit.edge_cap,
        ep_cap: source.circuit.ep_cap,
    };
    let circuit_value = serde_json::to_value(&circuit)?;
    let raw_config_id = domain_hash(CONFIG_ID_DOMAIN, &canonical_json(&circuit_value)?);
    let provenance = Provenance {
        kind: REISSUANCE_KIND.to_owned(),
        source_backend: SOURCE_BACKEND.to_owned(),
        source_registry_id: hex::encode(source.raw_registry_id),
        source_report_id: hex::encode(source.source_report_id),
    };
    let mut registry_payload = json!({
        "schema": REGISTRY_SCHEMA,
        "application": source.application,
        "binary_measurement": hex::encode(source.binary_measurement),
        "raw_config_id": hex::encode(raw_config_id),
        "h_cfg_raw24": h_cfg_hex,
        "circuit": circuit_value,
        "allowed_endpoints": source.allowed_endpoints,
        "devices": {
            TARGET_DEVICE_ID: {
                "algorithm": ALGORITHM,
                "key_id": hex::encode(key_id(&target_device.verifying_key())),
                "public_key": BASE64.encode(target_device.verifying_key().as_bytes())
            }
        },
        "scope_policy": source.scope_policy,
        "provenance": provenance
    });
    let raw_registry_id = domain_hash(REGISTRY_ID_DOMAIN, &canonical_json(&registry_payload)?);
    registry_payload["raw_registry_id"] = Value::String(hex::encode(raw_registry_id));
    let registry_envelope = sign_payload(
        registry_payload,
        &target_authority,
        AUTHORITY_SIGNATURE_DOMAIN,
    )?;

    let enrollment_payload = json!({
        "schema": ENROLLMENT_SCHEMA,
        "raw_registry_id": hex::encode(raw_registry_id),
        "cfg_blind_low": format!("0x{:016x}", target_openings.cfg[0]),
        "cfg_blind_high": format!("0x{:016x}", target_openings.cfg[1]),
        "static_manifest_sha256": source.static_manifest_sha256
    });
    let enrollment_envelope = sign_payload(
        enrollment_payload,
        &target_authority,
        ENROLLMENT_SIGNATURE_DOMAIN,
    )?;
    let scope_policy_digest = domain_hash(
        SCOPE_POLICY_DOMAIN,
        &canonical_json(&registry_envelope["payload"]["scope_policy"])?,
    );
    let report_payload = json!({
        "schema": REPORT_SCHEMA,
        "device_id": TARGET_DEVICE_ID,
        "challenge_id": config.target_challenge_id,
        "nonce": hex::encode(config.target_nonce),
        "raw_registry_id": hex::encode(raw_registry_id),
        "raw_config_id": hex::encode(raw_config_id),
        "binary_measurement": hex::encode(source.binary_measurement),
        "h_cfg_raw24": h_cfg_hex,
        "h_ep_raw24": h_ep_hex,
        "entry_raw": source.endpoint.entry_raw,
        "final_raw": source.endpoint.final_raw,
        "scope_policy_digest": hex::encode(scope_policy_digest),
        "runtime_code_match": true,
        "boundary_policy_satisfied": true
    });
    let report_envelope = sign_payload(report_payload, &target_device, DEVICE_SIGNATURE_DOMAIN)?;
    let worker = json!({
        "schema": WORKER_SCHEMA,
        "raw_registry_id": hex::encode(raw_registry_id),
        "raw_config_id": hex::encode(raw_config_id),
        "h_cfg_raw24": h_cfg_hex,
        "h_ep_raw24": h_ep_hex,
        "ep_blind_low": format!("0x{:016x}", target_openings.ep[0]),
        "ep_blind_high": format!("0x{:016x}", target_openings.ep[1]),
        "cfg_blind_low": format!("0x{:016x}", target_openings.cfg[0]),
        "cfg_blind_high": format!("0x{:016x}", target_openings.cfg[1])
    });
    write_json_new(&public.join("registry.json"), &registry_envelope, 0o644)?;
    write_json_new(&public.join("report.json"), &report_envelope, 0o644)?;
    write_json_new(&private.join("worker.json"), &worker, 0o600)?;
    write_json_new(
        &issuance.join("enrollment.json"),
        &enrollment_envelope,
        0o600,
    )?;

    let authority_sha256 = sha256(authority_public_pem.as_bytes());
    let target_config = BundleConfig {
        root: bundle.clone(),
        authority_public: keys_public.join("authority.pem"),
        authority_sha256,
        challenge: ExpectedChallenge {
            challenge_id: config.target_challenge_id.clone(),
            nonce: config.target_nonce,
        },
    };
    let statement = load_public_statement(&target_config)
        .context("self-authenticate reissued PLONK public statement")?;
    let handoff = load_provider_handoff(&target_config, &statement)
        .context("self-authenticate reissued PLONK private handoff")?;
    ensure!(
        statement.h_cfg == parse_hex32(&h_cfg_hex, "target H_cfg")?
            && statement.h_ep == parse_hex32(&h_ep_hex, "target H_ep")?,
        "self-authenticated target commitments disagree with issuance"
    );
    let self_instance = RawInstance::load(
        &handoff.private_dir,
        params,
        RawOpenings {
            ep: handoff.openings.ep.words(),
            cfg: handoff.openings.cfg.words(),
        },
    )
    .map_err(anyhow::Error::msg)
    .context("self-reopen reissued PLONK artifacts")?;
    ensure!(
        self_instance
            .h_cfg_poseidon::<BlsScalar>()
            .map_err(anyhow::Error::msg)?
            == h_cfg
            && self_instance
                .h_ep_poseidon::<BlsScalar>()
                .map_err(anyhow::Error::msg)?
                == h_ep,
        "reissued private artifacts do not reopen the signed Poseidon commitments"
    );

    let bundle_path = output.join("bundle");
    let authority_public_path = output.join("keys/public/authority.pem");
    let device_public_path = output.join("keys/public/device.pem");
    let enrollment_path = output.join("issuance/enrollment.json");
    let result = ProtocolResult {
        schema: REISSUANCE_SCHEMA.to_owned(),
        bundle: path_text(&bundle_path)?,
        authority_public: path_text(&authority_public_path)?,
        authority_sha256: hex::encode(authority_sha256),
        challenge_id: config.target_challenge_id,
        nonce: hex::encode(config.target_nonce),
        device_id: TARGET_DEVICE_ID.to_owned(),
        device_public: path_text(&device_public_path)?,
        enrollment: path_text(&enrollment_path)?,
        raw_registry_id: hex::encode(raw_registry_id),
        raw_config_id: hex::encode(raw_config_id),
        h_cfg_raw24: h_cfg_hex,
        h_ep_raw24: h_ep_hex,
        provenance,
        source: SourceSummary {
            bundle: path_text(&canonical_existing(&config.source_bundle)?)?,
            authority_public: path_text(&canonical_existing(&config.source_authority_public)?)?,
            authority_sha256: hex::encode(config.source_authority_sha256),
            challenge_id: config.source_challenge_id,
            nonce: hex::encode(config.source_nonce),
        },
    };
    write_json_new(&root.join("protocol-result.json"), &result, 0o644)?;
    set_mode(root, 0o755)?;
    staging.publish(&output)?;
    Ok(result)
}

fn validate_scope_policy(scope: &ScopePolicy, path_mode: &str) -> Result<()> {
    ensure!(
        scope.schema == SCOPE_SCHEMA,
        "unsupported source scope-policy schema"
    );
    ensure!(
        matches!(scope.architecture.as_str(), "aarch64" | "x86_64"),
        "source scope policy selects an unsupported architecture"
    );
    ensure!(
        matches!(
            scope.boundary_kind.as_str(),
            "in-binary-direct-call-and-root-ret" | "external-root-entry-and-captured-return"
        ),
        "source scope policy selects an unsupported boundary kind"
    );
    ensure!(
        matches!(
            scope.external_call_model.as_str(),
            "none" | "plt-exact-return"
        ),
        "source scope policy selects an unsupported external-call model"
    );
    ensure!(
        scope.sentinel == "SCOPE_RETURN" && scope.sentinel_address == "0xffff0000",
        "source scope policy sentinel is not canonical"
    );
    ensure!(
        scope.require_complete_entry_exit,
        "source scope policy does not require complete entry/exit"
    );
    ensure!(
        scope.normalization == "qemu-root-scope",
        "source scope normalization is unsupported"
    );
    ensure!(
        matches!(
            scope.canonical_address_model.as_str(),
            "elf-virtual-address" | "pie-load-bias"
        ),
        "source scope policy selects an unsupported address model"
    );
    let expected_compression = if path_mode == "complete" {
        "none"
    } else {
        "shadow-safe"
    };
    ensure!(
        scope.proof_path_compression == expected_compression,
        "source scope compression disagrees with its signed path mode"
    );
    for (name, value) in [
        ("root_symbol", scope.root_symbol.as_str()),
        ("caller_symbol", scope.caller_symbol.as_str()),
        ("scope_call_address", scope.scope_call_address.as_str()),
        ("root_address", scope.root_address.as_str()),
        ("scope_return_address", scope.scope_return_address.as_str()),
        ("canonical_entry", scope.canonical_entry.as_str()),
        ("canonical_start_code", scope.canonical_start_code.as_str()),
    ] {
        ensure!(!value.is_empty(), "source scope policy has an empty {name}");
    }
    ensure!(
        !scope.root_exit_blocks.is_empty()
            && scope.root_exit_blocks.iter().all(|value| !value.is_empty())
            && scope.root_exit_blocks.iter().collect::<HashSet<_>>().len()
                == scope.root_exit_blocks.len(),
        "source scope policy has malformed root exit blocks"
    );
    Ok(())
}

fn validate_endpoints(endpoints: &[RawEndpoint]) -> Result<()> {
    ensure!(
        !endpoints.is_empty(),
        "source registry endpoint policy is empty"
    );
    ensure!(
        endpoints.windows(2).all(|pair| pair[0] < pair[1]),
        "source registry endpoints are repeated or not canonically sorted"
    );
    for endpoint in endpoints {
        validate_endpoint(*endpoint, "source registry endpoint")?;
    }
    Ok(())
}

fn validate_endpoint(endpoint: RawEndpoint, label: &str) -> Result<()> {
    ensure!(
        endpoint.entry_raw != 0
            && endpoint.entry_raw < RAW_ADDR_LIMIT
            && endpoint.final_raw != 0
            && endpoint.final_raw < RAW_ADDR_LIMIT,
        "{label} is outside raw24"
    );
    Ok(())
}

fn validate_devices(devices: &HashMap<String, RegisteredDevice>) -> Result<()> {
    ensure!(
        !devices.is_empty(),
        "source registry has no authorized device"
    );
    for (device_id, device) in devices {
        validate_identifier(device_id, "source registry device id")?;
        ensure!(
            device.algorithm == ALGORITHM,
            "source registry device uses an unsupported signature algorithm"
        );
        let key = verifying_key_from_base64(&device.public_key)?;
        ensure!(
            parse_hex32(&device.key_id, "source registered device key id")? == key_id(&key),
            "source registered device key id is not canonical"
        );
    }
    Ok(())
}

fn validate_identifier(identifier: &str, label: &str) -> Result<()> {
    ensure!(
        !identifier.is_empty()
            && identifier.len() <= 64
            && identifier
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && identifier
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "{label} is not canonical"
    );
    Ok(())
}

fn verify_envelope_bytes(
    bytes: &[u8],
    key: &VerifyingKey,
    domain: &[u8],
    label: &str,
) -> Result<Value> {
    let envelope: Envelope =
        serde_json::from_slice(bytes).with_context(|| format!("decode {label} envelope"))?;
    verify_envelope(envelope, key, domain, label)
}

fn verify_envelope(
    envelope: Envelope,
    key: &VerifyingKey,
    domain: &[u8],
    label: &str,
) -> Result<Value> {
    ensure!(
        envelope.algorithm == ALGORITHM,
        "{label} uses an unsupported signature algorithm"
    );
    ensure!(
        parse_hex32(&envelope.key_id, &format!("{label} key id"))? == key_id(key),
        "{label} key id differs from its verification key"
    );
    let signature_bytes = BASE64
        .decode(&envelope.signature)
        .with_context(|| format!("decode {label} Ed25519 signature"))?;
    ensure!(
        BASE64.encode(&signature_bytes) == envelope.signature,
        "{label} signature is not canonical base64"
    );
    let signature = Signature::from_slice(&signature_bytes)
        .with_context(|| format!("{label} signature has the wrong length"))?;
    let mut message = domain.to_vec();
    message.extend(canonical_json(&envelope.payload)?);
    key.verify(&message, &signature)
        .with_context(|| format!("invalid domain-separated signature on {label}"))?;
    Ok(envelope.payload)
}

fn sign_payload(payload: Value, key: &SigningKey, domain: &[u8]) -> Result<Value> {
    let mut message = domain.to_vec();
    message.extend(canonical_json(&payload)?);
    let signature: Signature = key.sign(&message);
    Ok(json!({
        "algorithm": ALGORITHM,
        "key_id": hex::encode(key_id(&key.verifying_key())),
        "payload": payload,
        "signature": BASE64.encode(signature.to_bytes())
    }))
}

fn verifying_key_from_base64(encoded: &str) -> Result<VerifyingKey> {
    let bytes = BASE64
        .decode(encoded)
        .context("decode source registered Ed25519 public key")?;
    ensure!(
        BASE64.encode(&bytes) == encoded,
        "source registered Ed25519 public key is not canonical base64"
    );
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("source registered Ed25519 public key is not 32 bytes"))?;
    VerifyingKey::from_bytes(&raw).context("invalid source registered Ed25519 public key")
}

fn key_id(key: &VerifyingKey) -> [u8; 32] {
    domain_hash(KEY_ID_DOMAIN, key.as_bytes())
}

fn random_signing_key_excluding(excluded: &[VerifyingKey]) -> SigningKey {
    loop {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let key = SigningKey::from_bytes(&bytes);
        bytes.fill(0);
        if excluded.iter().all(|item| item != &key.verifying_key()) {
            return key;
        }
    }
}

fn random_independent_openings(source: RawOpenings) -> RawOpenings {
    let mut ep = random_opening();
    while ep == source.ep || ep == source.cfg {
        ep = random_opening();
    }
    let mut cfg = random_opening();
    while cfg == ep || cfg == source.ep || cfg == source.cfg {
        cfg = random_opening();
    }
    RawOpenings { ep, cfg }
}

fn random_opening() -> [u64; 2] {
    loop {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        let opening = [
            u64::from_be_bytes(bytes[..8].try_into().expect("eight bytes")),
            u64::from_be_bytes(bytes[8..].try_into().expect("eight bytes")),
        ];
        bytes.fill(0);
        if opening != [0, 0] {
            return opening;
        }
    }
}

fn sha256_words(words: &[u64]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for word in words {
        digest.update(word.to_be_bytes());
    }
    digest.finalize().into()
}

fn parse_hex16_os(value: OsString, field: &str) -> Result<String> {
    let value = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("{field} is not UTF-8"))?;
    parse_hex16(&value, field)?;
    Ok(value)
}

fn parse_hex32_os(value: OsString, field: &str) -> Result<[u8; 32]> {
    let value = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("{field} is not UTF-8"))?;
    parse_hex32(&value, field)
}

fn parse_hex16(value: &str, field: &str) -> Result<[u8; 16]> {
    ensure!(
        value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "{field} must be canonical lowercase 16-byte hexadecimal"
    );
    let bytes = hex::decode(value).with_context(|| format!("{field} is not hexadecimal"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must contain exactly 16 bytes"))
}

fn parse_hex32(value: &str, field: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "{field} must be canonical lowercase 32-byte hexadecimal"
    );
    let bytes = hex::decode(value).with_context(|| format!("{field} is not hexadecimal"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must contain exactly 32 bytes"))
}

fn parse_hex_word(value: &str, field: &str) -> Result<u64> {
    let digits = value
        .strip_prefix("0x")
        .with_context(|| format!("{field} must start with 0x"))?;
    ensure!(
        digits.len() == 16
            && digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "{field} must be canonical lowercase 64-bit hexadecimal"
    );
    u64::from_str_radix(digits, 16).with_context(|| format!("{field} is not hexadecimal"))
}

fn check_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("stat {label} {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "{label} must be a directory and not a symlink"
    );
    Ok(())
}

fn check_private_directory(path: &Path, label: &str) -> Result<()> {
    check_directory(path, label)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::symlink_metadata(path)?.permissions().mode();
        ensure!(
            mode & 0o077 == 0,
            "{label} must not be accessible by group/other"
        );
    }
    Ok(())
}

fn check_exact_names(path: &Path, expected: &[&str], label: &str) -> Result<()> {
    let mut actual = std::fs::read_dir(path)
        .with_context(|| format!("read {label} {}", path.display()))?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_| std::io::Error::other("non-UTF-8 bundle filename"))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    actual.sort_unstable();
    let mut expected: Vec<_> = expected.iter().map(|name| (*name).to_owned()).collect();
    expected.sort_unstable();
    ensure!(
        actual == expected,
        "{label} must contain exactly {}; found {}",
        expected.join(", "),
        actual.join(", ")
    );
    Ok(())
}

fn read_regular(path: &Path, label: &str, private: bool, maximum_size: u64) -> Result<Vec<u8>> {
    let before = std::fs::symlink_metadata(path)
        .with_context(|| format!("stat {label} {}", path.display()))?;
    ensure!(
        before.file_type().is_file(),
        "{label} must be a regular non-symlink file"
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("open {label} without following links {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect open {label} {}", path.display()))?;
    ensure!(metadata.is_file(), "{label} must remain a regular file");
    ensure!(
        metadata.len() <= maximum_size,
        "{label} exceeds the {maximum_size}-byte input limit"
    );
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o177 == 0,
            "{label} must not be executable or accessible by group/other"
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum_size + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label} {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= maximum_size,
        "{label} grew beyond the {maximum_size}-byte input limit"
    );
    Ok(bytes)
}

fn prepare_destination(requested: &Path) -> Result<PathBuf> {
    ensure!(
        !requested.as_os_str().is_empty(),
        "run directory must not be empty"
    );
    let requested = if requested.is_absolute() {
        requested.to_owned()
    } else {
        std::env::current_dir()?.join(requested)
    };
    let name = requested
        .file_name()
        .context("run directory must name a child directory")?
        .to_owned();
    let parent = requested
        .parent()
        .context("run directory must have a parent")?;
    check_directory(parent, "run-directory parent")?;
    let parent = std::fs::canonicalize(parent)
        .with_context(|| format!("canonicalize run-directory parent {}", parent.display()))?;
    let output = parent.join(name);
    refuse_destination(&output, "reissuance run directory")?;
    Ok(output)
}

fn reject_input_output_overlap(output: &Path, inputs: &[(&PathBuf, &str)]) -> Result<()> {
    for (input, label) in inputs {
        let input = canonical_existing(input)?;
        ensure!(
            output != input && !output.starts_with(&input) && !input.starts_with(output),
            "run directory must not equal, contain, or be contained by {label}: {}",
            input.display()
        );
    }
    Ok(())
}

fn canonical_existing(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).with_context(|| format!("canonicalize {}", path.display()))
}

fn refuse_destination(path: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => bail!("refusing to overwrite existing {label}: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {label} {}", path.display())),
    }
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .with_context(|| format!("output path is not UTF-8: {}", path.display()))
}

fn create_directory(path: &Path, mode: u32) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(mode);
    }
    builder
        .create(path)
        .with_context(|| format!("create directory {}", path.display()))?;
    set_mode(path, mode)
}

fn write_json_new(path: &Path, value: &impl Serialize, mode: u32) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .with_context(|| format!("serialize JSON output {}", path.display()))?;
    bytes.push(b'\n');
    write_new(path, &bytes, mode)
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create output {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write output {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync output {}", path.display()))?;
    set_mode(path, mode)
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("set permissions on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

struct StagingDirectory {
    path: PathBuf,
    armed: bool,
}

impl StagingDirectory {
    fn new(output: &Path) -> Result<Self> {
        let parent = output.parent().context("output has no parent")?;
        let output_name = output
            .file_name()
            .context("output has no directory name")?
            .to_string_lossy();
        for _ in 0..128 {
            let mut random = [0u8; 12];
            OsRng.fill_bytes(&mut random);
            let path = parent.join(format!(".{output_name}.tmp-{}", hex::encode(random)));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => {
                    if let Err(error) = set_mode(&path, 0o700) {
                        let _ = std::fs::remove_dir(&path);
                        return Err(error);
                    }
                    return Ok(Self { path, armed: true });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("create staging directory {}", path.display()))
                }
            }
        }
        bail!("could not allocate a unique staging directory")
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn publish(&mut self, output: &Path) -> Result<()> {
        rename_noreplace(&self.path, output).with_context(|| {
            format!(
                "atomically publish {} as {}",
                self.path.display(),
                output.display()
            )
        })?;
        self.armed = false;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in source path"))?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in destination path")
    })?;
    // SAFETY: both C strings are live and NUL-terminated for the duration of the call. RENAME_EXCL
    // makes publication fail instead of replacing an entry created after our initial checks.
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn rename_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in source path"))?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in destination path")
    })?;
    // SAFETY: both C strings are valid for this call; RENAME_NOREPLACE provides atomic no-clobber.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn rename_noreplace(_source: &Path, _destination: &Path) -> std::io::Result<()> {
    // A check followed by `rename` would race and could overwrite a destination
    // created by another process. Fail closed until the target exposes an atomic
    // no-replace primitive equivalent to renameat2/RENAME_NOREPLACE or
    // renameatx_np/RENAME_EXCL.
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-clobber publication is supported only on macOS and Linux",
    ))
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests;
