//! Authentication preflight for provider-produced raw24 PLONK statements.
//!
//! The authority-signed configuration fixes the exact Poseidon field, permutation parameters,
//! word packing, artifact domains, and chaining rule. The device signature binds both resulting
//! commitments to the runtime measurement, endpoint, verifier challenge, and authority registry.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use anyhow::{ensure, Context, Result};
use ark_bls12_381::Fr as BlsScalar;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{pkcs8::DecodePublicKey, Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::poseidon::{
    constants_sha256, parse_field_hex, CFG_DOMAIN, CONSTRUCTION, EP_DOMAIN, FIELD, OUTPUT, PACKING,
    RATE, SBOX, SCHEME, WIDTH,
};

pub(crate) const REGISTRY_SCHEMA: &str = "zkcfa.raw.registry";
pub(crate) const REPORT_SCHEMA: &str = "zkcfa.raw.report";
pub(crate) const WORKER_SCHEMA: &str = "zkcfa.raw.worker";
pub(crate) const CIRCUIT_SCHEMA: &str = "zkcfa.raw.circuit";
pub(crate) const SCOPE_SCHEMA: &str = "zkcfa.raw.scope";
pub(crate) const PROFILE: &str = "raw24-full-key";
pub(crate) const BACKEND: &str = "plonk";
pub(crate) const ALGORITHM: &str = "Ed25519";

const AUTHORITY_SIGNATURE_DOMAIN: &[u8] = b"ZKCFA/raw/registry/signature\0";
const DEVICE_SIGNATURE_DOMAIN: &[u8] = b"ZKCFA/raw/report/signature\0";
const REGISTRY_ID_DOMAIN: &[u8] = b"ZKCFA/raw/registry/id\0";
const CONFIG_ID_DOMAIN: &[u8] = b"ZKCFA/raw/circuit/id\0";
const SCOPE_POLICY_DOMAIN: &[u8] = b"ZKCFA/raw/scope/digest\0";
const KEY_ID_DOMAIN: &[u8] = b"ZKCFA/key/id\0";
const REISSUANCE_KIND: &str = "authenticated-reissuance";

const TRANSLATOR_FILE: &str = "translator";
const TYPED_CFG_FILE: &str = "typed_cfg";
const RECORDED_PATH_FILE: &str = "recorded_path";

const ADDR_BITS: u32 = 24;
const RAW_ADDR_LIMIT: u64 = 1 << ADDR_BITS;

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

/// Verifier-selected challenge.  It is configured out of band and must match the signed report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExpectedChallenge {
    pub(crate) challenge_id: String,
    pub(crate) nonce: [u8; 32],
}

/// Out-of-band trust and freshness configuration for one provider bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BundleConfig {
    pub(crate) root: PathBuf,
    pub(crate) authority_public: PathBuf,
    pub(crate) authority_sha256: [u8; 32],
    pub(crate) challenge: ExpectedChallenge,
}

/// Exact proof-native commitment profile selected by the authority.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommitmentConfig {
    pub(crate) scheme: String,
    pub(crate) field: String,
    pub(crate) width: usize,
    pub(crate) rate: usize,
    pub(crate) sbox: String,
    pub(crate) full_rounds: usize,
    pub(crate) partial_rounds: usize,
    pub(crate) capacity_tag: u64,
    pub(crate) output: String,
    pub(crate) construction: String,
    pub(crate) packing: String,
    pub(crate) ep_domain: u64,
    pub(crate) cfg_domain: u64,
    pub(crate) constants_sha256: String,
}

/// Authority-signed PLONK relation and capacity parameters.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CircuitConfig {
    pub(crate) schema: String,
    pub(crate) profile: String,
    pub(crate) backend: String,
    pub(crate) commitment: CommitmentConfig,
    pub(crate) path_mode: String,
    pub(crate) edge_cap: usize,
    pub(crate) ep_cap: usize,
}

/// Signature-authenticated public raw24 statement.  No private bundle file is needed to load it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PublicStatement {
    pub(crate) application: String,
    pub(crate) raw_registry_id: [u8; 32],
    pub(crate) raw_config_id: [u8; 32],
    pub(crate) binary_measurement: [u8; 32],
    pub(crate) h_cfg: [u8; 32],
    pub(crate) h_ep: [u8; 32],
    pub(crate) entry_raw: u64,
    pub(crate) final_raw: u64,
    pub(crate) circuit: CircuitConfig,
    pub(crate) device_id: String,
    pub(crate) challenge: ExpectedChallenge,
    pub(crate) scope_policy_digest: [u8; 32],
}

/// A confidential nonzero 128-bit commitment opening.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Opening([u64; 2]);

impl Opening {
    fn from_words(low: u64, high: u64) -> Result<Self> {
        ensure!(
            low != 0 || high != 0,
            "raw artifact commitment opening must be nonzero"
        );
        Ok(Self([low, high]))
    }

    pub(crate) const fn words(self) -> [u64; 2] {
        self.0
    }
}

impl core::fmt::Debug for Opening {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Opening(<redacted>)")
    }
}

/// The two independently provisioned openings in the confidential worker handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ArtifactOpenings {
    pub(crate) ep: Opening,
    pub(crate) cfg: Opening,
}

/// Confidential handoff bound to a separately authenticated public statement.
#[derive(Clone, Debug)]
pub(crate) struct PrivateHandoff {
    pub(crate) private_dir: PathBuf,
    pub(crate) openings: ArtifactOpenings,
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct ProviderBundle {
    public: PublicStatement,
    openings: ArtifactOpenings,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    algorithm: String,
    key_id: String,
    payload: Value,
    signature: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisteredDevice {
    algorithm: String,
    key_id: String,
    public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceProvenance {
    kind: String,
    source_backend: String,
    source_registry_id: String,
    source_report_id: String,
}

fn deserialize_optional_provenance<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<SourceProvenance>, D::Error>
where
    D: Deserializer<'de>,
{
    SourceProvenance::deserialize(deserializer).map(Some)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
struct RawEndpoint {
    entry_raw: u64,
    final_raw: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryPayload {
    schema: String,
    application: String,
    raw_registry_id: String,
    binary_measurement: String,
    raw_config_id: String,
    h_cfg_raw24: String,
    circuit: CircuitConfig,
    allowed_endpoints: Vec<RawEndpoint>,
    devices: HashMap<String, RegisteredDevice>,
    scope_policy: ScopePolicy,
    #[serde(default, deserialize_with = "deserialize_optional_provenance")]
    provenance: Option<SourceProvenance>,
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

/// Load and authenticate the signed public statement without touching `private/`.
pub(crate) fn load_public_statement(config: &BundleConfig) -> Result<PublicStatement> {
    validate_expected_challenge(&config.challenge)?;
    check_directory(&config.root, "raw provider bundle root")?;
    let public_dir = config.root.join("public");
    check_directory(&public_dir, "raw provider public directory")?;
    check_exact_file_set(
        &public_dir,
        &["registry.json", "report.json"],
        "raw provider public directory",
    )?;
    for (path, label) in [
        (public_dir.join("registry.json"), "raw authority registry"),
        (public_dir.join("report.json"), "raw device report"),
    ] {
        check_regular_file(&path, label)?;
    }

    check_regular_file(&config.authority_public, "authority public key")?;
    let authority_bytes = std::fs::read(&config.authority_public)
        .with_context(|| format!("read authority key {}", config.authority_public.display()))?;
    ensure!(
        sha256(&authority_bytes) == config.authority_sha256,
        "authority public key does not match the independently configured SHA-256 pin"
    );
    let authority_pem =
        std::str::from_utf8(&authority_bytes).context("authority PEM is not UTF-8")?;
    let authority = VerifyingKey::from_public_key_pem(authority_pem)
        .context("decode Ed25519 authority public key")?;

    let registry_path = public_dir.join("registry.json");
    let registry_value = verify_envelope(&registry_path, &authority, AUTHORITY_SIGNATURE_DOMAIN)?;
    let registry: RegistryPayload = serde_json::from_value(registry_value.clone())
        .context("decode signed raw authority registry")?;
    ensure!(
        registry.schema == REGISTRY_SCHEMA,
        "unsupported raw authority-registry schema"
    );
    validate_identifier(&registry.application, "raw registry application")?;
    validate_circuit(&registry.circuit)?;
    validate_scope_policy(&registry.scope_policy, &registry.circuit.path_mode)?;
    validate_endpoints(&registry.allowed_endpoints)?;
    validate_registered_devices(&registry.devices)?;
    if let Some(provenance) = &registry.provenance {
        validate_source_provenance(provenance)?;
    }

    let raw_config_id = domain_hash(
        CONFIG_ID_DOMAIN,
        &canonical_json(&serde_json::to_value(&registry.circuit)?)?,
    );
    ensure!(
        parse_hex32(&registry.raw_config_id, "raw config id")? == raw_config_id,
        "raw circuit configuration identifier is not canonical"
    );
    let mut registry_without_id = registry_value.clone();
    registry_without_id
        .as_object_mut()
        .context("raw authority registry payload is not an object")?
        .remove("raw_registry_id")
        .context("raw authority registry has no identifier")?;
    let raw_registry_id = domain_hash(REGISTRY_ID_DOMAIN, &canonical_json(&registry_without_id)?);
    ensure!(
        parse_hex32(&registry.raw_registry_id, "raw registry id")? == raw_registry_id,
        "raw authority registry identifier is not canonical"
    );
    let binary_measurement = parse_hex32(&registry.binary_measurement, "raw binary measurement")?;
    let h_cfg = parse_poseidon_digest(&registry.h_cfg_raw24, "signed raw H_cfg")?;

    // Select the authority-registered device from the unsigned identifier, then authenticate the
    // entire report under that exact device key.  The identifier is checked again after decode.
    let report_path = public_dir.join("report.json");
    let report_envelope: Envelope = read_json(&report_path)?;
    let unsigned_device_id = report_envelope
        .payload
        .get("device_id")
        .and_then(Value::as_str)
        .context("raw device report has no device_id")?
        .to_owned();
    validate_identifier(&unsigned_device_id, "raw report device")?;
    let registered_device = registry
        .devices
        .get(&unsigned_device_id)
        .context("raw device report is signed by a device absent from the authority registry")?;
    let device_key = verifying_key_from_base64(&registered_device.public_key)?;
    let report_value =
        verify_decoded_envelope(report_envelope, &device_key, DEVICE_SIGNATURE_DOMAIN)?;
    let report: ReportPayload =
        serde_json::from_value(report_value).context("decode signed raw device report")?;
    ensure!(
        report.schema == REPORT_SCHEMA,
        "unsupported raw device-report schema"
    );
    ensure!(
        report.device_id == unsigned_device_id,
        "raw device identifier changed while decoding report"
    );
    parse_hex16(&report.challenge_id, "raw device-report challenge id")?;
    parse_hex32(&report.nonce, "raw device-report nonce")?;
    ensure!(
        report.challenge_id == config.challenge.challenge_id,
        "raw device report challenge id is stale or unexpected"
    );
    ensure!(
        parse_hex32(&report.nonce, "raw device-report nonce")? == config.challenge.nonce,
        "raw device report nonce is stale or unexpected"
    );
    ensure!(
        report.runtime_code_match,
        "raw device did not attest a runtime code match"
    );
    ensure!(
        report.boundary_policy_satisfied,
        "raw device did not attest the registered boundary policy"
    );
    ensure!(
        report.raw_registry_id == registry.raw_registry_id,
        "raw device report is bound to another authority registry"
    );
    ensure!(
        report.raw_config_id == registry.raw_config_id,
        "raw device report configuration differs from authority registry"
    );
    ensure!(
        report.binary_measurement == registry.binary_measurement,
        "raw device report binary measurement differs from authority registry"
    );
    ensure!(
        report.h_cfg_raw24 == registry.h_cfg_raw24,
        "raw device report H_cfg differs from authority registry"
    );
    let actual_endpoint = RawEndpoint {
        entry_raw: report.entry_raw,
        final_raw: report.final_raw,
    };
    validate_raw_endpoint(actual_endpoint, "raw device report")?;
    ensure!(
        registry.allowed_endpoints.contains(&actual_endpoint),
        "raw device endpoint pair is not authorized by authority policy"
    );
    let scope_policy_digest = domain_hash(
        SCOPE_POLICY_DOMAIN,
        &canonical_json(&serde_json::to_value(&registry.scope_policy)?)?,
    );
    ensure!(
        parse_hex32(&report.scope_policy_digest, "raw scope-policy digest")? == scope_policy_digest,
        "raw device report is not bound to the authority scope policy"
    );
    let h_ep = parse_poseidon_digest(&report.h_ep_raw24, "signed raw H_ep")?;

    Ok(PublicStatement {
        application: registry.application,
        raw_registry_id,
        raw_config_id,
        binary_measurement,
        h_cfg,
        h_ep,
        entry_raw: report.entry_raw,
        final_raw: report.final_raw,
        circuit: registry.circuit,
        device_id: report.device_id,
        challenge: config.challenge.clone(),
        scope_policy_digest,
    })
}

/// Load the confidential prover handoff already bound to an authenticated public statement.
///
/// Keeping the public authentication outside this function lets the verifier establish the
/// statement first and pass that exact statement across the prover boundary.
pub(crate) fn load_provider_handoff(
    config: &BundleConfig,
    public: &PublicStatement,
) -> Result<PrivateHandoff> {
    check_exact_file_set(
        &config.root,
        &["public", "private"],
        "raw provider bundle root",
    )?;
    let private_dir = config.root.join("private");
    check_private_directory(&private_dir, "raw provider private directory")?;
    check_exact_file_set(
        &private_dir,
        &[
            "worker.json",
            TRANSLATOR_FILE,
            TYPED_CFG_FILE,
            RECORDED_PATH_FILE,
        ],
        "raw provider private directory",
    )?;
    for (path, label) in [
        (private_dir.join("worker.json"), "raw worker secret"),
        (private_dir.join(TRANSLATOR_FILE), "raw translator"),
        (private_dir.join(TYPED_CFG_FILE), "raw typed CFG"),
        (private_dir.join(RECORDED_PATH_FILE), "raw recorded path"),
    ] {
        check_private_file(&path, label)?;
    }

    let secret: WorkerSecret = read_json(&private_dir.join("worker.json"))?;
    ensure!(
        secret.schema == WORKER_SCHEMA,
        "unsupported raw worker schema"
    );
    ensure!(
        parse_hex32(&secret.raw_registry_id, "worker raw registry id")? == public.raw_registry_id,
        "raw worker secret belongs to another registry"
    );
    ensure!(
        parse_hex32(&secret.raw_config_id, "worker raw config id")? == public.raw_config_id,
        "raw worker secret configuration differs from registry"
    );
    ensure!(
        parse_poseidon_digest(&secret.h_cfg_raw24, "worker raw H_cfg")? == public.h_cfg,
        "raw worker secret does not identify signed H_cfg"
    );
    ensure!(
        parse_poseidon_digest(&secret.h_ep_raw24, "worker raw H_ep")? == public.h_ep,
        "raw worker secret does not identify signed H_ep"
    );
    let ep = Opening::from_words(
        parse_hex_word(&secret.ep_blind_low, "ep_blind_low")?,
        parse_hex_word(&secret.ep_blind_high, "ep_blind_high")?,
    )?;
    let cfg = Opening::from_words(
        parse_hex_word(&secret.cfg_blind_low, "cfg_blind_low")?,
        parse_hex_word(&secret.cfg_blind_high, "cfg_blind_high")?,
    )?;
    ensure!(
        ep != cfg,
        "raw worker secret reuses the H_ep opening for H_cfg"
    );

    Ok(PrivateHandoff {
        private_dir,
        openings: ArtifactOpenings { ep, cfg },
    })
}

#[cfg(test)]
fn load_provider_bundle(config: &BundleConfig) -> Result<ProviderBundle> {
    let public = load_public_statement(config)?;
    let handoff = load_provider_handoff(config, &public)?;
    Ok(ProviderBundle {
        public,
        openings: handoff.openings,
    })
}

/// Parse the out-of-band trust anchor, challenge, and bundle location exactly once.
pub(crate) fn provider_config_from_env() -> Result<BundleConfig> {
    validate_release_env()?;
    let root = PathBuf::from(
        std::env::var_os("ZKCFA_PROVIDER_BUNDLE").context("ZKCFA_PROVIDER_BUNDLE is required")?,
    );
    let authority_public = PathBuf::from(
        std::env::var_os("ZKCFA_AUTHORITY_PUBLIC").context("ZKCFA_AUTHORITY_PUBLIC is required")?,
    );
    let authority_sha256 = parse_hex32(
        &std::env::var("ZKCFA_AUTHORITY_SHA256")
            .context("ZKCFA_AUTHORITY_SHA256 must pin the independently trusted authority PEM")?,
        "authority SHA-256 pin",
    )?;
    let challenge = ExpectedChallenge {
        challenge_id: std::env::var("ZKCFA_EXPECTED_CHALLENGE_ID")
            .context("ZKCFA_EXPECTED_CHALLENGE_ID is required")?,
        nonce: parse_hex32(
            &std::env::var("ZKCFA_EXPECTED_NONCE").context("ZKCFA_EXPECTED_NONCE is required")?,
            "expected raw challenge nonce",
        )?,
    };
    validate_expected_challenge(&challenge)?;
    Ok(BundleConfig {
        root,
        authority_public,
        authority_sha256,
        challenge,
    })
}

fn validate_circuit(config: &CircuitConfig) -> Result<()> {
    ensure!(
        config.schema == CIRCUIT_SCHEMA,
        "unsupported raw circuit-config schema"
    );
    ensure!(
        config.profile == PROFILE,
        "raw registry selects another encoding profile"
    );
    ensure!(
        config.backend == BACKEND,
        "raw signed circuit must select the PLONK backend"
    );
    validate_commitment(&config.commitment)?;
    ensure!(
        matches!(config.path_mode.as_str(), "complete" | "shadow"),
        "raw registry selects an unsupported path mode"
    );
    ensure!(
        config.edge_cap >= 8 && config.edge_cap.is_power_of_two(),
        "raw registry EDGE_CAP is not a canonical power-of-two capacity"
    );
    ensure!(
        config.ep_cap >= 16 && config.ep_cap <= 1 << ADDR_BITS && config.ep_cap.is_power_of_two(),
        "raw registry EP_CAP is out of range or not a power of two"
    );
    Ok(())
}

fn validate_commitment(config: &CommitmentConfig) -> Result<()> {
    let constants =
        plonk_hashing::poseidon::constants::PoseidonConstants::<BlsScalar>::generate::<WIDTH>();
    ensure!(config.scheme == SCHEME, "unsupported raw commitment scheme");
    ensure!(config.field == FIELD, "unsupported raw commitment field");
    ensure!(
        config.width == WIDTH && config.rate == RATE,
        "unsupported raw Poseidon width/rate"
    );
    ensure!(config.sbox == SBOX, "unsupported raw Poseidon S-box");
    ensure!(
        config.full_rounds == constants.full_rounds
            && config.partial_rounds == constants.partial_rounds,
        "raw Poseidon round counts differ from the reviewed permutation"
    );
    ensure!(
        config.capacity_tag == 3 && constants.domain_tag == BlsScalar::from(config.capacity_tag),
        "raw Poseidon capacity tag differs from the reviewed permutation"
    );
    ensure!(
        config.output == OUTPUT,
        "unsupported raw Poseidon output coordinate"
    );
    ensure!(
        config.construction == CONSTRUCTION,
        "unsupported raw Poseidon chaining construction"
    );
    ensure!(
        config.packing == PACKING,
        "unsupported raw Poseidon word packing"
    );
    ensure!(
        config.ep_domain == EP_DOMAIN && config.cfg_domain == CFG_DOMAIN,
        "raw Poseidon artifact domains differ from the reviewed profile"
    );
    ensure!(
        parse_hex32(&config.constants_sha256, "Poseidon constants SHA-256")?
            == constants_sha256::<BlsScalar>(),
        "raw Poseidon constants fingerprint differs from the reviewed permutation"
    );
    Ok(())
}

/// Canonical Poseidon commitment profile embedded in every reissued PLONK registry.
#[allow(dead_code)] // Called by the separately compiled `zkcfa-reissue` binary.
pub(crate) fn reviewed_commitment_config() -> CommitmentConfig {
    let constants =
        plonk_hashing::poseidon::constants::PoseidonConstants::<BlsScalar>::generate::<WIDTH>();
    CommitmentConfig {
        scheme: SCHEME.to_owned(),
        field: FIELD.to_owned(),
        width: WIDTH,
        rate: RATE,
        sbox: SBOX.to_owned(),
        full_rounds: constants.full_rounds,
        partial_rounds: constants.partial_rounds,
        capacity_tag: 3,
        output: OUTPUT.to_owned(),
        construction: CONSTRUCTION.to_owned(),
        packing: PACKING.to_owned(),
        ep_domain: EP_DOMAIN,
        cfg_domain: CFG_DOMAIN,
        constants_sha256: hex::encode(constants_sha256::<BlsScalar>()),
    }
}

fn validate_scope_policy(scope: &ScopePolicy, path_mode: &str) -> Result<()> {
    ensure!(
        scope.schema == SCOPE_SCHEMA,
        "unsupported raw scope-policy schema"
    );
    ensure!(
        matches!(scope.architecture.as_str(), "aarch64" | "x86_64"),
        "raw scope policy selects an unsupported architecture"
    );
    ensure!(
        matches!(
            scope.boundary_kind.as_str(),
            "in-binary-direct-call-and-root-ret" | "external-root-entry-and-captured-return"
        ),
        "raw scope policy selects an unsupported boundary kind"
    );
    ensure!(
        scope.sentinel == "SCOPE_RETURN" && scope.sentinel_address == "0xffff0000",
        "raw scope policy sentinel is not canonical"
    );
    ensure!(
        scope.require_complete_entry_exit,
        "raw scope policy does not require complete root entry/exit"
    );
    ensure!(
        scope.normalization == "qemu-root-scope",
        "raw scope normalization is unsupported"
    );
    ensure!(
        matches!(
            scope.canonical_address_model.as_str(),
            "elf-virtual-address" | "pie-load-bias"
        ),
        "raw scope policy selects an unsupported canonical address model"
    );
    let expected_compression = if path_mode == "complete" {
        "none"
    } else {
        "shadow-safe"
    };
    ensure!(
        scope.proof_path_compression == expected_compression,
        "raw scope compression policy disagrees with the signed path mode"
    );
    ensure!(
        matches!(
            scope.external_call_model.as_str(),
            "none" | "plt-exact-return"
        ),
        "raw scope selects an unsupported external-call model"
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
        ensure!(!value.is_empty(), "raw scope policy has an empty {name}");
    }
    ensure!(
        !scope.root_exit_blocks.is_empty()
            && scope.root_exit_blocks.iter().all(|value| !value.is_empty())
            && scope.root_exit_blocks.iter().collect::<HashSet<_>>().len()
                == scope.root_exit_blocks.len(),
        "raw scope policy has malformed root exit blocks"
    );
    Ok(())
}

fn validate_endpoints(endpoints: &[RawEndpoint]) -> Result<()> {
    ensure!(
        !endpoints.is_empty(),
        "raw authority registry endpoint policy is empty"
    );
    ensure!(
        endpoints.iter().copied().collect::<HashSet<_>>().len() == endpoints.len(),
        "raw authority registry endpoint policy contains duplicates"
    );
    ensure!(
        endpoints.windows(2).all(|pair| pair[0] < pair[1]),
        "raw authority registry endpoint policy is not in canonical sorted order"
    );
    for endpoint in endpoints {
        validate_raw_endpoint(*endpoint, "authority endpoint policy")?;
    }
    Ok(())
}

fn validate_registered_devices(devices: &HashMap<String, RegisteredDevice>) -> Result<()> {
    ensure!(
        !devices.is_empty(),
        "raw authority registry has no authorized device"
    );
    for (device_id, device) in devices {
        validate_identifier(device_id, "raw registry device")?;
        ensure!(
            device.algorithm == ALGORITHM,
            "raw registry device uses an unsupported signature algorithm"
        );
        let key = verifying_key_from_base64(&device.public_key)?;
        ensure!(
            key_id(&key) == parse_hex32(&device.key_id, "registered device key id")?,
            "registered raw device key identifier is not canonical"
        );
    }
    Ok(())
}

fn validate_source_provenance(provenance: &SourceProvenance) -> Result<()> {
    ensure!(
        provenance.kind == REISSUANCE_KIND && provenance.source_backend == "binius64",
        "raw PLONK statement does not identify the reviewed authenticated reissuance"
    );
    parse_hex32(
        &provenance.source_registry_id,
        "source provenance registry id",
    )?;
    parse_hex32(&provenance.source_report_id, "source provenance report id")?;
    Ok(())
}

fn validate_raw_endpoint(endpoint: RawEndpoint, label: &str) -> Result<()> {
    ensure!(
        endpoint.entry_raw != 0 && endpoint.entry_raw < RAW_ADDR_LIMIT,
        "{label} entry is outside raw24"
    );
    ensure!(
        endpoint.final_raw != 0 && endpoint.final_raw < RAW_ADDR_LIMIT,
        "{label} final node is outside raw24"
    );
    Ok(())
}

fn validate_expected_challenge(challenge: &ExpectedChallenge) -> Result<()> {
    parse_hex16(&challenge.challenge_id, "expected raw challenge id")?;
    Ok(())
}

fn verify_envelope(path: &Path, key: &VerifyingKey, domain: &[u8]) -> Result<Value> {
    let envelope: Envelope = read_json(path)?;
    verify_decoded_envelope(envelope, key, domain)
}

fn verify_decoded_envelope(envelope: Envelope, key: &VerifyingKey, domain: &[u8]) -> Result<Value> {
    ensure!(
        envelope.algorithm == ALGORITHM,
        "unsupported raw signature algorithm"
    );
    ensure!(
        parse_hex32(&envelope.key_id, "raw envelope key id")? == key_id(key),
        "raw envelope key id differs from verification key"
    );
    let signature_bytes = BASE64
        .decode(&envelope.signature)
        .context("decode raw Ed25519 signature")?;
    let signature = Signature::from_slice(&signature_bytes)
        .context("raw Ed25519 signature has the wrong length")?;
    let mut message = domain.to_vec();
    message.extend(canonical_json(&envelope.payload)?);
    key.verify(&message, &signature)
        .context("invalid domain-separated raw Ed25519 envelope signature")?;
    Ok(envelope.payload)
}

fn verifying_key_from_base64(encoded: &str) -> Result<VerifyingKey> {
    let bytes = BASE64
        .decode(encoded)
        .context("decode registered raw Ed25519 public key")?;
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("registered raw Ed25519 public key is not 32 bytes"))?;
    VerifyingKey::from_bytes(&raw).context("invalid registered raw Ed25519 public key")
}

fn key_id(key: &VerifyingKey) -> [u8; 32] {
    domain_hash(KEY_ID_DOMAIN, key.as_bytes())
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
                .all(|byte| { byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' }),
        "{label} identifier is not canonical"
    );
    Ok(())
}

fn check_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("stat {label} {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "{label} must be a regular non-symlink file"
    );
    Ok(())
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

fn check_exact_file_set(path: &Path, expected: &[&str], label: &str) -> Result<()> {
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
    let mut expected: Vec<String> = expected.iter().map(|name| (*name).to_owned()).collect();
    expected.sort_unstable();
    ensure!(
        actual == expected,
        "{label} must contain exactly {}; found {}",
        expected.join(", "),
        actual.join(", ")
    );
    Ok(())
}

fn check_private_directory(path: &Path, label: &str) -> Result<()> {
    check_directory(path, label)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::symlink_metadata(path)
            .with_context(|| format!("stat {label} {}", path.display()))?
            .permissions()
            .mode();
        ensure!(
            mode & 0o077 == 0,
            "{label} must not be accessible by group/other"
        );
    }
    Ok(())
}

fn check_private_file(path: &Path, label: &str) -> Result<()> {
    check_regular_file(path, label)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::symlink_metadata(path)
            .with_context(|| format!("stat {label} {}", path.display()))?
            .permissions()
            .mode();
        ensure!(
            mode & 0o177 == 0,
            "{label} must not be executable or accessible by group/other"
        );
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    check_regular_file(path, "JSON input")?;
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse JSON {}", path.display()))
}

/// Provider-compatible canonical JSON: sorted keys, no whitespace, and ASCII strings only.
pub(crate) fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    fn write(value: &Value, output: &mut Vec<u8>) -> Result<()> {
        match value {
            Value::Null => output.extend_from_slice(b"null"),
            Value::Bool(false) => output.extend_from_slice(b"false"),
            Value::Bool(true) => output.extend_from_slice(b"true"),
            Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
            Value::String(string) => {
                ensure!(
                    string.is_ascii(),
                    "raw canonical JSON contains a non-ASCII string"
                );
                output.extend_from_slice(serde_json::to_string(string)?.as_bytes());
            }
            Value::Array(values) => {
                output.push(b'[');
                for (index, item) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    write(item, output)?;
                }
                output.push(b']');
            }
            Value::Object(values) => {
                output.push(b'{');
                let mut keys: Vec<&String> = values.keys().collect();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    ensure!(
                        key.is_ascii(),
                        "raw canonical JSON contains a non-ASCII key"
                    );
                    if index != 0 {
                        output.push(b',');
                    }
                    output.extend_from_slice(serde_json::to_string(key)?.as_bytes());
                    output.push(b':');
                    write(&values[key], output)?;
                }
                output.push(b'}');
            }
        }
        Ok(())
    }

    let mut output = Vec::new();
    write(value, &mut output)?;
    Ok(output)
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
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

fn parse_poseidon_digest(value: &str, field: &str) -> Result<[u8; 32]> {
    parse_field_hex::<BlsScalar>(value, field).map_err(anyhow::Error::msg)?;
    parse_hex32(value, field)
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

#[cfg(test)]
mod tests;
