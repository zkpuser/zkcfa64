use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::{
    pkcs8::{spki::der::pem::LineEnding, EncodePublicKey},
    Signer, SigningKey,
};
use serde_json::json;

use super::*;

const RAW_SCOPE_SENTINEL: u64 = RAW_ADDR_LIMIT - 1;
static FIXTURE_NUMBER: AtomicU64 = AtomicU64::new(0);

struct TestBundle {
    root: PathBuf,
    trust_anchor: PathBuf,
}

impl Drop for TestBundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
        let _ = std::fs::remove_file(&self.trust_anchor);
    }
}

fn set_private(path: &Path, directory: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )
        .unwrap();
    }
}

fn write_json(path: &Path, value: &Value) {
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn sign(payload: Value, key: &SigningKey, domain: &[u8]) -> Value {
    let mut message = domain.to_vec();
    message.extend(canonical_json(&payload).unwrap());
    let signature: Signature = key.sign(&message);
    json!({
        "algorithm": ALGORITHM,
        "key_id": hex::encode(key_id(&key.verifying_key())),
        "payload": payload,
        "signature": BASE64.encode(signature.to_bytes())
    })
}

fn circuit() -> Value {
    serde_json::to_value(CircuitConfig {
        schema: CIRCUIT_SCHEMA.to_owned(),
        profile: PROFILE.to_owned(),
        backend: BACKEND.to_owned(),
        commitment: reviewed_commitment_config(),
        path_mode: "complete".to_owned(),
        edge_cap: 8,
        ep_cap: 16,
    })
    .unwrap()
}

fn cfg_hash() -> String {
    crate::poseidon::field_hex(BlsScalar::from(0x22u64))
}

fn ep_hash() -> String {
    crate::poseidon::field_hex(BlsScalar::from(0x66u64))
}

fn scope() -> Value {
    json!({
        "schema": SCOPE_SCHEMA,
        "architecture": "x86_64",
        "boundary_kind": "external-root-entry-and-captured-return",
        "root_symbol": "main",
        "caller_symbol": "external-loader",
        "scope_call_address": "SCOPE_RETURN",
        "root_address": "0x401000",
        "root_exit_blocks": ["0x401008"],
        "scope_return_address": "SCOPE_RETURN",
        "sentinel": "SCOPE_RETURN",
        "sentinel_address": "0xffff0000",
        "require_complete_entry_exit": true,
        "position_independent": true,
        "canonical_entry": "0x401000",
        "canonical_start_code": "0x401000",
        "canonical_address_model": "pie-load-bias",
        "proof_path_compression": "none",
        "normalization": "qemu-root-scope",
        "external_call_model": "none"
    })
}

fn fixture() -> (TestBundle, BundleConfig) {
    let number = FIXTURE_NUMBER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "zkcfa-plonk-attestation-test-{}-{number}",
        std::process::id()
    ));
    let public = root.join("public");
    let private = root.join("private");
    std::fs::create_dir_all(&public).unwrap();
    std::fs::create_dir(&private).unwrap();
    set_private(&private, true);
    for (name, body) in [
        ("translator", "SCOPE_RETURN\n0x401000\n"),
        (
            "typed_cfg",
            "SCOPE_RETURN jmp 0x401000\n0x401000 jmp SCOPE_RETURN\n",
        ),
        (
            "recorded_path",
            "initial_node=SCOPE_RETURN final_node=SCOPE_RETURN\njump 0x401000\njump SCOPE_RETURN\n",
        ),
    ] {
        let path = private.join(name);
        std::fs::write(&path, body).unwrap();
        set_private(&path, false);
    }

    let authority = SigningKey::from_bytes(&[0x31; 32]);
    let device = SigningKey::from_bytes(&[0x32; 32]);
    let authority_pem = authority
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let trust_anchor = root.with_extension("trusted-authority.pem");
    std::fs::write(&trust_anchor, authority_pem.as_bytes()).unwrap();

    let circuit = circuit();
    let config_id = domain_hash(CONFIG_ID_DOMAIN, &canonical_json(&circuit).unwrap());
    let mut registry = json!({
        "schema": REGISTRY_SCHEMA,
        "application": "crc32",
        "binary_measurement": "11".repeat(32),
        "raw_config_id": hex::encode(config_id),
        "h_cfg_raw24": cfg_hash(),
        "circuit": circuit,
        "allowed_endpoints": [{
            "entry_raw": RAW_SCOPE_SENTINEL,
            "final_raw": RAW_SCOPE_SENTINEL
        }],
        "devices": {
            "device-1": {
                "algorithm": ALGORITHM,
                "key_id": hex::encode(key_id(&device.verifying_key())),
                "public_key": BASE64.encode(device.verifying_key().as_bytes())
            }
        },
        "scope_policy": scope(),
        "provenance": {
            "kind": REISSUANCE_KIND,
            "source_backend": "binius64",
            "source_registry_id": "77".repeat(32),
            "source_report_id": "88".repeat(32)
        }
    });
    let registry_id = domain_hash(REGISTRY_ID_DOMAIN, &canonical_json(&registry).unwrap());
    registry["raw_registry_id"] = Value::String(hex::encode(registry_id));
    write_json(
        &public.join("registry.json"),
        &sign(registry.clone(), &authority, AUTHORITY_SIGNATURE_DOMAIN),
    );

    let scope_digest = domain_hash(
        SCOPE_POLICY_DOMAIN,
        &canonical_json(&registry["scope_policy"]).unwrap(),
    );
    let report = json!({
        "schema": REPORT_SCHEMA,
        "device_id": "device-1",
        "challenge_id": "33".repeat(16),
        "nonce": "44".repeat(32),
        "raw_registry_id": hex::encode(registry_id),
        "raw_config_id": hex::encode(config_id),
        "binary_measurement": "11".repeat(32),
        "h_cfg_raw24": cfg_hash(),
        "h_ep_raw24": ep_hash(),
        "entry_raw": RAW_SCOPE_SENTINEL,
        "final_raw": RAW_SCOPE_SENTINEL,
        "scope_policy_digest": hex::encode(scope_digest),
        "runtime_code_match": true,
        "boundary_policy_satisfied": true
    });
    write_json(
        &public.join("report.json"),
        &sign(report, &device, DEVICE_SIGNATURE_DOMAIN),
    );
    let worker_path = private.join("worker.json");
    write_json(
        &worker_path,
        &json!({
            "schema": WORKER_SCHEMA,
            "raw_registry_id": hex::encode(registry_id),
            "raw_config_id": hex::encode(config_id),
            "h_cfg_raw24": cfg_hash(),
            "h_ep_raw24": ep_hash(),
            "ep_blind_low": "0x0123456789abcdef",
            "ep_blind_high": "0xfedcba9876543210",
            "cfg_blind_low": "0x1111111111111111",
            "cfg_blind_high": "0x2222222222222222"
        }),
    );
    set_private(&worker_path, false);

    let config = BundleConfig {
        root: root.clone(),
        authority_public: trust_anchor.clone(),
        authority_sha256: sha256(authority_pem.as_bytes()),
        challenge: ExpectedChallenge {
            challenge_id: "33".repeat(16),
            nonce: [0x44; 32],
        },
    };
    (TestBundle { root, trust_anchor }, config)
}

fn rewrite_report(config: &BundleConfig, mutate: impl FnOnce(&mut Value)) {
    let path = config.root.join("public/report.json");
    let envelope: Envelope = read_json(&path).unwrap();
    let mut payload = envelope.payload;
    mutate(&mut payload);
    let device = SigningKey::from_bytes(&[0x32; 32]);
    write_json(&path, &sign(payload, &device, DEVICE_SIGNATURE_DOMAIN));
}

fn rewrite_registry(config: &BundleConfig, mutate: impl FnOnce(&mut Value)) {
    let path = config.root.join("public/registry.json");
    let envelope: Envelope = read_json(&path).unwrap();
    let mut payload = envelope.payload;
    mutate(&mut payload);
    let mut without_id = payload.clone();
    without_id
        .as_object_mut()
        .unwrap()
        .remove("raw_registry_id");
    payload["raw_registry_id"] = Value::String(hex::encode(domain_hash(
        REGISTRY_ID_DOMAIN,
        &canonical_json(&without_id).unwrap(),
    )));
    let authority = SigningKey::from_bytes(&[0x31; 32]);
    write_json(
        &path,
        &sign(payload, &authority, AUTHORITY_SIGNATURE_DOMAIN),
    );
}

fn rewrite_worker(config: &BundleConfig, mutate: impl FnOnce(&mut Value)) {
    let path = config.root.join("private/worker.json");
    let mut worker: Value = read_json(&path).unwrap();
    mutate(&mut worker);
    write_json(&path, &worker);
    set_private(&path, false);
}

#[test]
fn authenticated_poseidon_statement_and_private_openings_compose() {
    let (_guard, config) = fixture();
    let bundle = load_provider_bundle(&config).unwrap();
    assert_eq!(bundle.public.application, "crc32");
    assert_eq!(bundle.public.binary_measurement, [0x11; 32]);
    assert_eq!(hex::encode(bundle.public.h_cfg), cfg_hash());
    assert_eq!(hex::encode(bundle.public.h_ep), ep_hash());
    assert_eq!(bundle.public.entry_raw, RAW_SCOPE_SENTINEL);
    assert_eq!(bundle.public.final_raw, RAW_SCOPE_SENTINEL);
    assert_eq!(bundle.public.circuit.backend, BACKEND);
    assert_eq!(bundle.public.circuit.edge_cap, 8);
    assert_eq!(bundle.public.circuit.ep_cap, 16);
    assert_eq!(
        bundle.openings.ep.words(),
        [0x0123456789abcdef, 0xfedcba9876543210]
    );
    assert_eq!(
        bundle.openings.cfg.words(),
        [0x1111111111111111, 0x2222222222222222]
    );
    assert_eq!(format!("{:?}", bundle.openings.ep), "Opening(<redacted>)");
}

#[test]
fn source_provenance_is_optional_and_strict_when_present() {
    let (_guard, config) = fixture();
    rewrite_registry(&config, |payload| {
        payload
            .as_object_mut()
            .unwrap()
            .remove("provenance")
            .unwrap();
    });
    let registry: Value = read_json(&config.root.join("public/registry.json")).unwrap();
    let registry_id = registry["payload"]["raw_registry_id"].clone();
    rewrite_report(&config, |payload| {
        payload["raw_registry_id"] = registry_id.clone();
    });
    rewrite_worker(&config, |worker| {
        worker["raw_registry_id"] = registry_id;
    });
    load_public_statement(&config).unwrap();

    let (_guard, config) = fixture();
    rewrite_registry(&config, |payload| {
        payload["provenance"] = Value::Null;
    });
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(
        error.contains("decode signed raw authority registry"),
        "{error}"
    );

    let (_guard, config) = fixture();
    rewrite_registry(&config, |payload| {
        payload["provenance"]["kind"] = Value::String("device-acquisition".into())
    });
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("authenticated reissuance"), "{error}");

    let (_guard, config) = fixture();
    rewrite_registry(&config, |payload| {
        payload["provenance"]["source_report_id"] = Value::String("FF".repeat(32))
    });
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("canonical lowercase"), "{error}");
}

#[test]
fn release_environment_has_a_small_explicit_surface() {
    assert!(ALLOWED_ENV.contains(&"ZKCFA_PROVIDER_BUNDLE"));
    assert!(ALLOWED_ENV.contains(&"ZKCFA_JSON"));
    assert!(!ALLOWED_ENV.contains(&"ZKCFA_UNKNOWN_CONTROL"));
    assert_eq!(
        unsupported_release_env([
            "ZKCFA_UNKNOWN_CONTROL".to_owned(),
            "ZKCFA_ANOTHER_UNKNOWN_CONTROL".to_owned(),
            "RAYON_NUM_THREADS".to_owned(),
        ]),
        vec!["ZKCFA_ANOTHER_UNKNOWN_CONTROL", "ZKCFA_UNKNOWN_CONTROL"]
    );
}

#[test]
fn public_loader_never_requires_private_handoff() {
    let (_guard, config) = fixture();
    std::fs::remove_dir_all(config.root.join("private")).unwrap();
    let statement = load_public_statement(&config).unwrap();
    assert_eq!(hex::encode(statement.h_cfg), cfg_hash());
    assert!(load_provider_bundle(&config).is_err());
}

#[test]
fn authority_pin_and_both_signature_domains_fail_closed() {
    let (_guard, mut config) = fixture();
    config.authority_sha256[0] ^= 1;
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(
        error.contains("independently configured SHA-256 pin"),
        "{error}"
    );

    let (_guard, config) = fixture();
    let path = config.root.join("public/report.json");
    let mut envelope: Value = read_json(&path).unwrap();
    envelope["signature"] = Value::String(BASE64.encode([0u8; 64]));
    write_json(&path, &envelope);
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("signature"), "{error}");

    let (_guard, config) = fixture();
    let registry: Value = read_json(&config.root.join("public/registry.json")).unwrap();
    write_json(&config.root.join("public/report.json"), &registry);
    assert!(load_public_statement(&config).is_err());
}

#[test]
fn expected_challenge_and_nonce_are_mandatory_and_canonical() {
    let (_guard, mut config) = fixture();
    config.challenge.challenge_id = "77".repeat(16);
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("stale or unexpected"), "{error}");

    let (_guard, mut config) = fixture();
    config.challenge.nonce[0] ^= 1;
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("nonce is stale or unexpected"), "{error}");

    let (_guard, mut config) = fixture();
    config.challenge.challenge_id = "UPPERCASE-IS-NOT-A-CHALLENGE".into();
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("canonical lowercase"), "{error}");
}

#[test]
fn backend_is_authenticated_as_plonk_not_binius64() {
    let (_guard, config) = fixture();
    rewrite_registry(&config, |payload| {
        payload["circuit"]["backend"] = Value::String("binius64".into())
    });
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("must select the PLONK backend"), "{error}");
}

#[test]
fn canonical_config_registry_and_device_identities_are_checked() {
    let (_guard, config) = fixture();
    rewrite_registry(&config, |payload| {
        payload["circuit"]["edge_cap"] = Value::from(16)
    });
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(
        error.contains("configuration identifier is not canonical"),
        "{error}"
    );

    let (_guard, config) = fixture();
    rewrite_registry(&config, |payload| {
        payload["devices"]["device-1"]["key_id"] = Value::String("77".repeat(32))
    });
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(
        error.contains("device key identifier is not canonical"),
        "{error}"
    );

    let (_guard, config) = fixture();
    rewrite_report(&config, |payload| {
        payload["raw_config_id"] = Value::String("77".repeat(32))
    });
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("configuration differs"), "{error}");
}

#[test]
fn endpoint_scope_and_runtime_claims_are_bound() {
    let (_guard, config) = fixture();
    rewrite_report(&config, |payload| {
        payload["entry_raw"] = Value::from(0x401000u64)
    });
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("not authorized"), "{error}");

    let (_guard, config) = fixture();
    rewrite_report(&config, |payload| {
        payload["scope_policy_digest"] = Value::String("77".repeat(32))
    });
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(
        error.contains("not bound to the authority scope"),
        "{error}"
    );

    let (_guard, config) = fixture();
    rewrite_report(&config, |payload| {
        payload["runtime_code_match"] = Value::Bool(false)
    });
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("runtime code match"), "{error}");
}

#[test]
fn worker_identities_and_openings_fail_closed() {
    let (_guard, config) = fixture();
    rewrite_worker(&config, |worker| {
        worker["h_ep_raw24"] = Value::String(crate::poseidon::field_hex(BlsScalar::from(77u64)))
    });
    let error = load_provider_bundle(&config).unwrap_err().to_string();
    assert!(error.contains("does not identify signed H_ep"), "{error}");

    let (_guard, config) = fixture();
    rewrite_worker(&config, |worker| {
        worker["ep_blind_low"] = Value::String("0x0000000000000000".into());
        worker["ep_blind_high"] = Value::String("0x0000000000000000".into());
    });
    let error = load_provider_bundle(&config).unwrap_err().to_string();
    assert!(error.contains("opening must be nonzero"), "{error}");

    let (_guard, config) = fixture();
    rewrite_worker(&config, |worker| {
        worker["cfg_blind_low"] = worker["ep_blind_low"].clone();
        worker["cfg_blind_high"] = worker["ep_blind_high"].clone();
    });
    let error = load_provider_bundle(&config).unwrap_err().to_string();
    assert!(error.contains("reuses the H_ep opening"), "{error}");
}

#[test]
fn exact_file_sets_and_unknown_json_fields_are_rejected() {
    let (_guard, config) = fixture();
    std::fs::write(config.root.join("public/authority.pem"), "embedded trust\n").unwrap();
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("must contain exactly"), "{error}");

    let (_guard, config) = fixture();
    std::fs::write(config.root.join("private/evidence.json"), "{}\n").unwrap();
    let error = load_provider_bundle(&config).unwrap_err().to_string();
    assert!(error.contains("must contain exactly"), "{error}");

    let (_guard, config) = fixture();
    rewrite_report(&config, |payload| {
        payload["recorded_path_sha256"] = Value::String("77".repeat(32))
    });
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("decode signed raw device report"), "{error}");
}

#[cfg(unix)]
#[test]
fn symlinks_and_public_private_permissions_are_rejected() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let (_guard, config) = fixture();
    let report = config.root.join("public/report.json");
    let saved = config.root.join("saved-report.json");
    std::fs::rename(&report, &saved).unwrap();
    symlink(&saved, &report).unwrap();
    let error = load_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("regular non-symlink"), "{error}");

    let (_guard, config) = fixture();
    let private = config.root.join("private");
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();
    let error = load_provider_bundle(&config).unwrap_err().to_string();
    assert!(error.contains("group/other"), "{error}");

    let (_guard, config) = fixture();
    let path = config.root.join("private/typed_cfg");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = load_provider_bundle(&config).unwrap_err().to_string();
    assert!(error.contains("group/other"), "{error}");
}

#[test]
fn signed_capacities_and_canonical_json_match_provider_vectors() {
    let value = circuit();
    let vector = hex::encode(domain_hash(
        CONFIG_ID_DOMAIN,
        &canonical_json(&value).unwrap(),
    ));
    assert_eq!(
        vector,
        "8a19a5d38fc54ad1d4ed311a8e37d89f45f2620fe2592d27cfc81a5b9eaa1d44"
    );

    let mut invalid = value.clone();
    invalid["ep_cap"] = Value::from(24);
    let config: CircuitConfig = serde_json::from_value(invalid).unwrap();
    assert!(validate_circuit(&config).is_err());

    let mut valid = value;
    valid["edge_cap"] = Value::from(16);
    valid["ep_cap"] = Value::from(32);
    let config: CircuitConfig = serde_json::from_value(valid).unwrap();
    validate_circuit(&config).unwrap();

    let mut wrong_constants = circuit();
    wrong_constants["commitment"]["constants_sha256"] = Value::String("00".repeat(32));
    let config: CircuitConfig = serde_json::from_value(wrong_constants).unwrap();
    assert!(validate_circuit(&config).is_err());
}

/// Opt-in cross-repository smoke test for an actual provider-generated bundle.
#[test]
#[ignore = "requires the five ZKCFA provider trust/challenge environment variables"]
fn configured_provider_bundle_smoke() {
    let config = provider_config_from_env().unwrap();
    let public = load_public_statement(&config).unwrap();
    let handoff = load_provider_handoff(&config, &public).unwrap();
    assert_eq!(public.circuit.backend, BACKEND);
    assert_ne!(handoff.openings.ep, handoff.openings.cfg);
}
