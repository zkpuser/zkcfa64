//! Signed handoff for the compiled raw-address relation.
//!
//! The authority signs the independently blinded static CFG commitment plus the normalized-
//! instance proof configuration, measurement, endpoint policy, device keys, and scope policy.
//! A registered device independently signs the per-run statement (`H_ep`, the same registry and
//! configuration identity, actual endpoints, scope-policy digest, and verifier challenge). The
//! confidential worker handoff contains only the commitment identities and openings; ordinary
//! artifact hashes remain device-local because publishing them would create an avoidable
//! enumeration oracle against the blinded commitments.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey, pkcs8::DecodePublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::raw_format::Blinding;

pub(crate) const REGISTRY_SCHEMA: &str = "zkcfa.raw.registry";
pub(crate) const REPORT_SCHEMA: &str = "zkcfa.raw.report";
pub(crate) const WORKER_SCHEMA: &str = "zkcfa.raw.worker";
pub(crate) const CIRCUIT_SCHEMA: &str = "zkcfa.raw.circuit";
pub(crate) const SCOPE_SCHEMA: &str = "zkcfa.raw.scope";
#[cfg(not(feature = "raw64"))]
pub(crate) const PROFILE: &str = "raw24-full-key";
#[cfg(feature = "raw64")]
pub(crate) const PROFILE: &str = "raw64-typed-channels";
pub(crate) const BACKEND: &str = "binius64";
pub(crate) const ALGORITHM: &str = "Ed25519";

const AUTHORITY_SIGNATURE_DOMAIN: &[u8] = b"ZKCFA/raw/registry/signature\0";
const DEVICE_SIGNATURE_DOMAIN: &[u8] = b"ZKCFA/raw/report/signature\0";
const REGISTRY_ID_DOMAIN: &[u8] = b"ZKCFA/raw/registry/id\0";
const CONFIG_ID_DOMAIN: &[u8] = b"ZKCFA/raw/circuit/id\0";
const SCOPE_POLICY_DOMAIN: &[u8] = b"ZKCFA/raw/scope/digest\0";
const KEY_ID_DOMAIN: &[u8] = b"ZKCFA/key/id\0";

const TRANSLATOR_FILE: &str = "translator";
const TYPED_CFG_FILE: &str = "typed_cfg";
const RECORDED_PATH_FILE: &str = "recorded_path";

pub(crate) const ADDR_BITS: u32 = if cfg!(feature = "raw64") { 64 } else { 24 };
const RAW_ADDR_MAX: u64 = if cfg!(feature = "raw64") {
    u64::MAX
} else {
    (1 << 24) - 1
};
// Address width and matching-call row width are independent parameters.
const MAX_EP_CAP: usize = 1 << 24;
#[cfg(test)]
const RAW_SCOPE_SENTINEL: u64 = RAW_ADDR_MAX;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExpectedChallenge {
    challenge_id: String,
    nonce: [u8; 32],
}

impl ExpectedChallenge {
    pub(crate) fn label(&self) -> &'static str {
        "signed-expected-challenge-matched"
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RawProviderBundleConfig {
    pub(crate) root: PathBuf,
    pub(crate) authority_public: PathBuf,
    pub(crate) authority_sha256: [u8; 32],
    pub(crate) challenge: ExpectedChallenge,
}

/// Public-only verifier statement. Constructing this value reads exactly the authority key pin,
/// authority registry, and device report; it never opens `private/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawPublicStatement {
    pub(crate) application: String,
    pub(crate) raw_registry_id: [u8; 32],
    pub(crate) raw_config_id: [u8; 32],
    pub(crate) h_cfg_raw24: [u8; 32],
    pub(crate) h_ep_raw24: [u8; 32],
    pub(crate) entry_raw: u64,
    pub(crate) final_raw: u64,
    pub(crate) circuit: RawCircuitConfig,
    pub(crate) device_id: String,
    pub(crate) challenge: ExpectedChallenge,
    pub(crate) scope_policy_digest: [u8; 32],
}

/// Signature-checked public statement plus the confidential prover handoff.
#[derive(Clone, Debug)]
pub(crate) struct RawProviderBundle {
    pub(crate) statement: RawPublicStatement,
    pub(crate) artifacts_dir: PathBuf,
    pub(crate) ep_blind: Blinding,
    pub(crate) cfg_blind: Blinding,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCircuitConfig {
    pub(crate) schema: String,
    pub(crate) profile: String,
    pub(crate) backend: String,
    pub(crate) path_mode: String,
    pub(crate) edge_cap: usize,
    pub(crate) ep_cap: usize,
    pub(crate) log_inv_rate: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawScopePolicy {
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
    circuit: RawCircuitConfig,
    allowed_endpoints: Vec<RawEndpoint>,
    devices: HashMap<String, RegisteredDevice>,
    scope_policy: RawScopePolicy,
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

/// Load and cryptographically authenticate only the public verifier statement.
pub(crate) fn load_raw_public_statement(
    config: &RawProviderBundleConfig,
) -> Result<RawPublicStatement> {
    check_directory(&config.root, "raw provider bundle root")?;
    let public_dir = config.root.join("public");
    check_directory(&public_dir, "raw provider public directory")?;
    check_exact_file_set(
        &public_dir,
        &["registry.json", "report.json"],
        "raw provider public directory",
    )?;

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
    validate_application_name(&registry.application)?;
    validate_circuit_config(&registry.circuit)?;
    validate_scope_policy(&registry.scope_policy, &registry.circuit.path_mode)?;
    ensure!(
        !registry.allowed_endpoints.is_empty(),
        "raw authority registry endpoint policy is empty"
    );
    ensure!(
        registry
            .allowed_endpoints
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len()
            == registry.allowed_endpoints.len(),
        "raw authority registry endpoint policy contains duplicates"
    );
    ensure!(
        registry
            .allowed_endpoints
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "raw authority registry endpoint policy is not in canonical sorted order"
    );
    for endpoint in &registry.allowed_endpoints {
        validate_raw_endpoint(*endpoint, "authority endpoint policy")?;
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
    parse_hex32(&registry.binary_measurement, "raw binary measurement")?;
    let h_cfg_raw24 = parse_hex32(&registry.h_cfg_raw24, "signed raw H_cfg")?;

    let report_path = public_dir.join("report.json");
    let report_envelope: Envelope = read_json(&report_path)?;
    let unsigned_device_id = report_envelope
        .payload
        .get("device_id")
        .and_then(Value::as_str)
        .context("raw device report has no device_id")?
        .to_owned();
    let registered_device = registry
        .devices
        .get(&unsigned_device_id)
        .context("raw device report is signed by a device absent from the authority registry")?;
    ensure!(
        registered_device.algorithm == ALGORITHM,
        "raw registry device uses an unsupported signature algorithm"
    );
    let device_key = verifying_key_from_base64(&registered_device.public_key)?;
    ensure!(
        key_id(&device_key) == parse_hex32(&registered_device.key_id, "registered device key id")?,
        "registered raw device key identifier is not canonical"
    );
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
    validate_challenge(&report, &config.challenge)?;
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
    let h_ep_raw24 = parse_hex32(&report.h_ep_raw24, "signed raw H_ep")?;

    Ok(RawPublicStatement {
        application: registry.application,
        raw_registry_id,
        raw_config_id,
        h_cfg_raw24,
        h_ep_raw24,
        entry_raw: report.entry_raw,
        final_raw: report.final_raw,
        circuit: registry.circuit,
        device_id: report.device_id,
        challenge: config.challenge.clone(),
        scope_policy_digest,
    })
}

/// Load the public statement plus the confidential prover handoff.
#[cfg(test)]
pub(crate) fn load_raw_provider_bundle(
    config: &RawProviderBundleConfig,
) -> Result<RawProviderBundle> {
    let public = load_raw_public_statement(config)?;
    load_raw_provider_handoff(config, public)
}

/// Load only the confidential handoff for an already authenticated public statement.
///
/// This lets the verifier establish the circuit from public data before the prover is allowed to
/// touch `private/`, while preserving the convenience loader above for callers and tests.
pub(crate) fn load_raw_provider_handoff(
    config: &RawProviderBundleConfig,
    public: RawPublicStatement,
) -> Result<RawProviderBundle> {
    check_exact_file_set(
        &config.root,
        &["public", "private"],
        "raw provider bundle root",
    )?;
    let private_dir = config.root.join("private");
    check_private_permissions(&private_dir, "raw provider private directory")?;
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
    let secret_path = private_dir.join("worker.json");
    check_private_file_0600(&secret_path, "raw worker secret")?;
    let secret: WorkerSecret = read_json(&secret_path)?;
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
        parse_hex32(&secret.h_cfg_raw24, "worker raw H_cfg")? == public.h_cfg_raw24,
        "raw worker secret does not open signed H_cfg"
    );
    ensure!(
        parse_hex32(&secret.h_ep_raw24, "worker raw H_ep")? == public.h_ep_raw24,
        "raw worker secret does not open signed H_ep"
    );
    for (path, label) in [
        (private_dir.join(TRANSLATOR_FILE), "raw translator"),
        (private_dir.join(TYPED_CFG_FILE), "raw typed CFG"),
        (private_dir.join(RECORDED_PATH_FILE), "raw recorded path"),
    ] {
        check_regular_file(&path, label)?;
    }
    let ep_blind = Blinding::from_words(
        parse_hex_word(&secret.ep_blind_low, "ep_blind_low")?,
        parse_hex_word(&secret.ep_blind_high, "ep_blind_high")?,
    )?;
    let cfg_blind = Blinding::from_words(
        parse_hex_word(&secret.cfg_blind_low, "cfg_blind_low")?,
        parse_hex_word(&secret.cfg_blind_high, "cfg_blind_high")?,
    )?;
    ensure!(
        ep_blind != cfg_blind,
        "raw worker secret reuses the H_ep opening for H_cfg"
    );

    Ok(RawProviderBundle {
        statement: public,
        artifacts_dir: private_dir,
        ep_blind,
        cfg_blind,
    })
}

pub(crate) fn raw_provider_config_from_env() -> Result<RawProviderBundleConfig> {
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
    Ok(RawProviderBundleConfig {
        root,
        authority_public,
        authority_sha256,
        challenge,
    })
}

fn validate_circuit_config(config: &RawCircuitConfig) -> Result<()> {
    ensure!(
        config.schema == CIRCUIT_SCHEMA,
        "unsupported raw circuit-config schema"
    );
    ensure!(
        config.profile == PROFILE,
        "raw registry selects another profile"
    );
    ensure!(
        config.backend == BACKEND,
        "raw registry selects another backend"
    );
    ensure!(
        config.log_inv_rate > 0 && config.log_inv_rate <= 16,
        "raw registry log_inv_rate is outside the reviewed range"
    );
    ensure!(
        matches!(config.path_mode.as_str(), "complete" | "shadow"),
        "raw registry selects an unsupported path mode"
    );
    ensure!(
        config.edge_cap >= 8 && config.edge_cap.is_power_of_two(),
        "raw registry EDGE_CAP is not a canonical power-of-two capacity"
    );
    ensure!(
        config.ep_cap >= 16 && config.ep_cap <= MAX_EP_CAP && config.ep_cap.is_power_of_two(),
        "raw registry EP_CAP is out of range or not a power of two"
    );
    Ok(())
}

fn validate_scope_policy(scope: &RawScopePolicy, path_mode: &str) -> Result<()> {
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
    let expected_compression = if path_mode == "complete" {
        "none"
    } else {
        "shadow-safe"
    };
    ensure!(
        scope.proof_path_compression == expected_compression,
        "raw scope compression policy disagrees with signed path mode"
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
        (
            "canonical_address_model",
            scope.canonical_address_model.as_str(),
        ),
    ] {
        ensure!(!value.is_empty(), "raw scope policy has an empty {name}");
    }
    ensure!(
        !scope.root_exit_blocks.is_empty()
            && scope.root_exit_blocks.iter().all(|v| !v.is_empty())
            && scope.root_exit_blocks.iter().collect::<HashSet<_>>().len()
                == scope.root_exit_blocks.len(),
        "raw scope policy has malformed root exit blocks"
    );
    Ok(())
}

fn validate_raw_endpoint(endpoint: RawEndpoint, label: &str) -> Result<()> {
    ensure!(
        endpoint.entry_raw != 0 && endpoint.entry_raw <= RAW_ADDR_MAX,
        "{label} entry is outside the compiled {ADDR_BITS}-bit profile"
    );
    ensure!(
        endpoint.final_raw != 0 && endpoint.final_raw <= RAW_ADDR_MAX,
        "{label} final node is outside the compiled {ADDR_BITS}-bit profile"
    );
    Ok(())
}

fn validate_challenge(report: &ReportPayload, expected: &ExpectedChallenge) -> Result<()> {
    ensure!(
        report.challenge_id == expected.challenge_id,
        "raw device report challenge id is stale or unexpected"
    );
    ensure!(
        parse_hex32(&report.nonce, "raw device-report nonce")? == expected.nonce,
        "raw device report nonce is stale or unexpected"
    );
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

fn validate_application_name(application: &str) -> Result<()> {
    ensure!(
        !application.is_empty()
            && application.len() <= 64
            && application
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && application
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "raw registry application identifier is not canonical"
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

fn check_private_permissions(path: &Path, label: &str) -> Result<()> {
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

fn check_private_file_0600(path: &Path, label: &str) -> Result<()> {
    check_regular_file(path, label)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
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
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse JSON {}", path.display()))
}

/// Canonical JSON shared with the provider: sorted keys, no whitespace, ASCII strings only.
pub(crate) fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    fn write(value: &Value, out: &mut Vec<u8>) -> Result<()> {
        match value {
            Value::Null => out.extend_from_slice(b"null"),
            Value::Bool(false) => out.extend_from_slice(b"false"),
            Value::Bool(true) => out.extend_from_slice(b"true"),
            Value::Number(number) => out.extend_from_slice(number.to_string().as_bytes()),
            Value::String(string) => {
                ensure!(
                    string.is_ascii(),
                    "raw canonical JSON contains a non-ASCII string"
                );
                out.extend_from_slice(serde_json::to_string(string)?.as_bytes());
            }
            Value::Array(values) => {
                out.push(b'[');
                for (index, item) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    write(item, out)?;
                }
                out.push(b']');
            }
            Value::Object(values) => {
                out.push(b'{');
                let mut keys: Vec<&String> = values.keys().collect();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    ensure!(
                        key.is_ascii(),
                        "raw canonical JSON contains a non-ASCII key"
                    );
                    if index != 0 {
                        out.push(b',');
                    }
                    out.extend_from_slice(serde_json::to_string(key)?.as_bytes());
                    out.push(b':');
                    write(&values[key], out)?;
                }
                out.push(b'}');
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    write(value, &mut out)?;
    Ok(out)
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
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f')),
        "{field} must be canonical lowercase 32-byte hexadecimal"
    );
    let bytes = hex::decode(value).with_context(|| format!("{field} is not hexadecimal"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must contain exactly 32 bytes"))
}

fn parse_hex16(value: &str, field: &str) -> Result<[u8; 16]> {
    ensure!(
        value.len() == 32
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f')),
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
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f')),
        "{field} must be canonical lowercase 64-bit hexadecimal"
    );
    u64::from_str_radix(digits, 16).with_context(|| format!("{field} is not hexadecimal"))
}

#[cfg(test)]
mod tests;
