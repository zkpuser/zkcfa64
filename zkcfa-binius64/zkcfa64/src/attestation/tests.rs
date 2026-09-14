use super::*;
use ed25519_dalek::{
    Signer, SigningKey,
    pkcs8::{EncodePublicKey, spki::der::pem::LineEnding},
};
use serde_json::json;

struct TestBundle(PathBuf, PathBuf);
impl Drop for TestBundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
        let _ = std::fs::remove_file(&self.1);
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
    json!({"algorithm": ALGORITHM, "key_id": hex::encode(key_id(&key.verifying_key())), "payload": payload, "signature": BASE64.encode(signature.to_bytes())})
}

fn circuit() -> Value {
    json!({
        "schema": CIRCUIT_SCHEMA,
        "profile": PROFILE,
        "backend": BACKEND,
        "path_mode": "complete", "edge_cap": 8, "ep_cap": 16,
        "log_inv_rate": 1
    })
}

fn scope() -> Value {
    json!({"schema":SCOPE_SCHEMA,"architecture":"x86_64","boundary_kind":"external-root-entry-and-captured-return",
        "root_symbol":"crc32_scope","caller_symbol":"_start",
        "scope_call_address":"0x400000","root_address":"0x400000","root_exit_blocks":["0x400008"],
        "scope_return_address":"0xffff0000","sentinel":"SCOPE_RETURN","sentinel_address":"0xffff0000",
        "require_complete_entry_exit":true,"position_independent":false,"canonical_entry":"0x400000",
        "canonical_start_code":"0x400000","canonical_address_model":"runtime ELF virtual address",
        "proof_path_compression":"none","normalization":"qemu-root-scope",
        "external_call_model":"none"})
}

fn fixture() -> (TestBundle, RawProviderBundleConfig) {
    let root = std::env::temp_dir().join(format!(
        "zkcfa-raw-provider-test-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let public = root.join("public");
    let private = root.join("private");
    std::fs::create_dir_all(&public).unwrap();
    std::fs::create_dir(&private).unwrap();
    set_private(&private, true);
    for (name, body) in [
        ("translator", "SCOPE_RETURN\n0x400000\n"),
        (
            "typed_cfg",
            "SCOPE_RETURN jmp 0x400000\n0x400000 jmp SCOPE_RETURN\n",
        ),
        (
            "recorded_path",
            "initial_node=SCOPE_RETURN final_node=SCOPE_RETURN\njump 0x400000\njump SCOPE_RETURN\n",
        ),
    ] {
        std::fs::write(private.join(name), body).unwrap();
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
    let mut registry = json!({"schema":REGISTRY_SCHEMA,"application":"crc32","binary_measurement":"11".repeat(32),
        "raw_config_id":hex::encode(config_id),"h_cfg_raw24":"22".repeat(32),"circuit":circuit,
        "allowed_endpoints":[{"entry_raw":RAW_SCOPE_SENTINEL,"final_raw":RAW_SCOPE_SENTINEL}],
        "devices":{"device-1":{"algorithm":ALGORITHM,"key_id":hex::encode(key_id(&device.verifying_key())),
            "public_key":BASE64.encode(device.verifying_key().as_bytes())}},"scope_policy":scope()});
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
    let report = json!({"schema":REPORT_SCHEMA,"device_id":"device-1","challenge_id":"33".repeat(16),
        "nonce":"44".repeat(32),"raw_registry_id":hex::encode(registry_id),
        "raw_config_id":hex::encode(config_id),"binary_measurement":"11".repeat(32),"h_cfg_raw24":"22".repeat(32),
        "h_ep_raw24":"66".repeat(32),
        "entry_raw":RAW_SCOPE_SENTINEL,"final_raw":RAW_SCOPE_SENTINEL,"scope_policy_digest":hex::encode(scope_digest),
        "runtime_code_match":true,"boundary_policy_satisfied":true});
    write_json(
        &public.join("report.json"),
        &sign(report, &device, DEVICE_SIGNATURE_DOMAIN),
    );
    write_json(
        &private.join("worker.json"),
        &json!({"schema":WORKER_SCHEMA,
            "raw_registry_id":hex::encode(registry_id),"raw_config_id":hex::encode(config_id),
            "h_cfg_raw24":"22".repeat(32),"h_ep_raw24":"66".repeat(32),
            "ep_blind_low":"0x0123456789abcdef","ep_blind_high":"0xfedcba9876543210",
            "cfg_blind_low":"0x1111111111111111","cfg_blind_high":"0x2222222222222222",
        }),
    );
    set_private(&private.join("worker.json"), false);
    let config = RawProviderBundleConfig {
        root: root.clone(),
        authority_public: trust_anchor.clone(),
        authority_sha256: sha256(authority_pem.as_bytes()),
        challenge: ExpectedChallenge {
            challenge_id: "33".repeat(16),
            nonce: [0x44; 32],
        },
    };
    (TestBundle(root, trust_anchor), config)
}

fn rewrite_report(config: &RawProviderBundleConfig, mutate: impl FnOnce(&mut Value)) {
    let path = config.root.join("public/report.json");
    let envelope: Envelope = read_json(&path).unwrap();
    let mut payload = envelope.payload;
    mutate(&mut payload);
    let device = SigningKey::from_bytes(&[0x32; 32]);
    write_json(&path, &sign(payload, &device, DEVICE_SIGNATURE_DOMAIN));
}

fn rewrite_registry(config: &RawProviderBundleConfig, mutate: impl FnOnce(&mut Value)) {
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

#[test]
fn two_domain_separated_signatures_and_challenge_compose() {
    let (_guard, config) = fixture();
    let bundle = load_raw_provider_bundle(&config).unwrap();
    assert_eq!(bundle.statement.application, "crc32");
    assert_eq!(
        bundle.statement.challenge.label(),
        "signed-expected-challenge-matched"
    );
    assert_eq!(bundle.statement.entry_raw, RAW_SCOPE_SENTINEL);
}

#[test]
fn verifier_public_loader_never_requires_private_handoff() {
    let (_guard, config) = fixture();
    std::fs::remove_dir_all(config.root.join("private")).unwrap();
    let statement = load_raw_public_statement(&config).unwrap();
    assert_eq!(statement.h_cfg_raw24, [0x22; 32]);
    assert!(load_raw_provider_bundle(&config).is_err());
}

#[test]
fn private_handoff_rejects_unexpected_files() {
    let (_guard, config) = fixture();
    std::fs::write(config.root.join("private/evidence.json"), "{}\n").unwrap();
    let error = load_raw_provider_bundle(&config).unwrap_err().to_string();
    assert!(error.contains("must contain exactly"), "{error}");
}

#[test]
fn full_handoff_rejects_unexpected_root_entries() {
    let (_guard, config) = fixture();
    std::fs::write(config.root.join("manifest.json"), "{}\n").unwrap();
    let error = load_raw_provider_bundle(&config).unwrap_err().to_string();
    assert!(
        error.contains("bundle root must contain exactly"),
        "{error}"
    );
}

#[test]
fn public_handoff_rejects_embedded_trust_material() {
    let (_guard, config) = fixture();
    std::fs::write(config.root.join("public/authority.pem"), "untrusted\n").unwrap();
    let error = load_raw_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("must contain exactly"), "{error}");
}

#[test]
fn stale_challenge_fails_closed() {
    let (_guard, mut config) = fixture();
    config.challenge = ExpectedChallenge {
        challenge_id: "77".repeat(16),
        nonce: [0x44; 32],
    };
    assert!(
        load_raw_provider_bundle(&config)
            .unwrap_err()
            .to_string()
            .contains("stale")
    );
}

#[test]
fn unexpected_nonce_fails_closed() {
    let (_guard, mut config) = fixture();
    config.challenge = ExpectedChallenge {
        challenge_id: "33".repeat(16),
        nonce: [0x45; 32],
    };
    let error = load_raw_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("nonce is stale or unexpected"), "{error}");
}

#[test]
fn authority_key_pin_is_independent_and_mandatory() {
    let (_guard, mut config) = fixture();
    config.authority_sha256[0] ^= 1;
    let error = load_raw_public_statement(&config).unwrap_err().to_string();
    assert!(
        error.contains("independently configured SHA-256 pin"),
        "{error}"
    );

    let (_guard, mut config) = fixture();
    config.authority_public = config.root.join("public/authority.pem");
    let error = load_raw_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("read authority key"), "{error}");
}

#[test]
fn public_signature_tamper_is_rejected() {
    let (_guard, config) = fixture();
    let path = config.root.join("public/report.json");
    let mut envelope: Value = read_json(&path).unwrap();
    envelope["signature"] = Value::String(BASE64.encode([0u8; 64]));
    write_json(&path, &envelope);
    let error = load_raw_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("signature"), "{error}");
}

#[test]
fn authority_signature_cannot_be_replayed_as_device_signature() {
    let (_guard, config) = fixture();
    let registry: Value = read_json(&config.root.join("public/registry.json")).unwrap();
    write_json(&config.root.join("public/report.json"), &registry);
    assert!(load_raw_provider_bundle(&config).is_err());
}

#[test]
fn device_config_and_measurement_must_equal_authority_registry() {
    let (_guard, config) = fixture();
    rewrite_report(&config, |payload| {
        payload["raw_config_id"] = Value::String("77".repeat(32))
    });
    let error = load_raw_provider_bundle(&config).unwrap_err().to_string();
    assert!(error.contains("configuration differs"), "{error}");

    let (_guard, config) = fixture();
    rewrite_report(&config, |payload| {
        payload["binary_measurement"] = Value::String("77".repeat(32))
    });
    let error = load_raw_provider_bundle(&config).unwrap_err().to_string();
    assert!(error.contains("measurement differs"), "{error}");

    let (_guard, config) = fixture();
    rewrite_report(&config, |payload| {
        payload["h_cfg_raw24"] = Value::String("77".repeat(32))
    });
    let error = load_raw_provider_bundle(&config).unwrap_err().to_string();
    assert!(error.contains("H_cfg differs"), "{error}");
}

#[test]
fn device_endpoint_and_scope_must_be_authorized() {
    let (_guard, config) = fixture();
    rewrite_report(&config, |payload| {
        payload["entry_raw"] = Value::from(0x400000u64)
    });
    let error = load_raw_provider_bundle(&config).unwrap_err().to_string();
    assert!(error.contains("not authorized"), "{error}");

    let (_guard, config) = fixture();
    rewrite_report(&config, |payload| {
        payload["scope_policy_digest"] = Value::String("77".repeat(32))
    });
    let error = load_raw_provider_bundle(&config).unwrap_err().to_string();
    assert!(
        error.contains("not bound to the authority scope"),
        "{error}"
    );
}

#[test]
fn proof_parameter_change_needs_a_new_config_identity() {
    let (_guard, config) = fixture();
    rewrite_registry(&config, |payload| {
        payload["circuit"]["log_inv_rate"] = Value::from(2)
    });
    let error = load_raw_provider_bundle(&config).unwrap_err().to_string();
    assert!(
        error.contains("configuration identifier is not canonical"),
        "{error}"
    );
}

#[test]
fn signed_capacities_are_bounded_powers_of_two() {
    let mut value = circuit();
    value["ep_cap"] = Value::from(8);
    let config: RawCircuitConfig = serde_json::from_value(value).unwrap();
    let error = validate_circuit_config(&config).unwrap_err().to_string();
    assert!(error.contains("EP_CAP"), "{error}");

    let mut value = circuit();
    value["ep_cap"] = Value::from(24);
    let config: RawCircuitConfig = serde_json::from_value(value).unwrap();
    let error = validate_circuit_config(&config).unwrap_err().to_string();
    assert!(error.contains("EP_CAP"), "{error}");

    let mut value = circuit();
    value["edge_cap"] = Value::from(12);
    let config: RawCircuitConfig = serde_json::from_value(value).unwrap();
    let error = validate_circuit_config(&config).unwrap_err().to_string();
    assert!(error.contains("EDGE_CAP"), "{error}");

    let mut value = circuit();
    value["edge_cap"] = Value::from(16);
    value["ep_cap"] = Value::from(32);
    let config: RawCircuitConfig = serde_json::from_value(value).unwrap();
    validate_circuit_config(&config).unwrap();
}

#[test]
fn authenticated_profile_must_match_the_compiled_relation() {
    let (_guard, config) = fixture();
    rewrite_registry(&config, |payload| {
        payload["circuit"]["profile"] = Value::String(
            if cfg!(feature = "raw64") {
                "raw24-full-key"
            } else {
                "raw64-typed-channels"
            }
            .into(),
        );
    });
    let error = load_raw_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("another profile"), "{error}");
}

#[test]
fn wide_addresses_do_not_expand_the_matching_call_row_domain() {
    let mut value = circuit();
    value["ep_cap"] = Value::from(1u64 << 25);
    let config: RawCircuitConfig = serde_json::from_value(value).unwrap();
    let error = validate_circuit_config(&config).unwrap_err().to_string();
    assert!(error.contains("EP_CAP"), "{error}");
    let endpoint = RawEndpoint {
        entry_raw: 0x0000_5555_5540_1234,
        final_raw: RAW_SCOPE_SENTINEL,
    };
    assert_eq!(
        validate_raw_endpoint(endpoint, "wide fixture").is_ok(),
        cfg!(feature = "raw64")
    );
}

#[test]
fn protocol_objects_reject_unknown_fields() {
    let mut circuit_object = circuit();
    circuit_object["unknown_field"] = Value::String("unexpected".into());
    assert!(serde_json::from_value::<RawCircuitConfig>(circuit_object).is_err());

    let mut scope = scope();
    scope["unknown_field"] = Value::String("unexpected".into());
    assert!(serde_json::from_value::<RawScopePolicy>(scope).is_err());
}

#[test]
fn endpoint_policy_must_be_canonically_sorted() {
    let (_guard, config) = fixture();
    rewrite_registry(&config, |payload| {
        payload["allowed_endpoints"] = json!([
            {"entry_raw": RAW_SCOPE_SENTINEL, "final_raw": RAW_SCOPE_SENTINEL},
            {"entry_raw": 0x400000u64, "final_raw": 0x400000u64}
        ]);
    });
    let error = load_raw_public_statement(&config).unwrap_err().to_string();
    assert!(error.contains("canonical sorted order"), "{error}");
}

#[test]
fn public_payload_refuses_unblinded_artifact_hash_oracles() {
    let (_guard, config) = fixture();
    rewrite_report(&config, |payload| {
        payload["recorded_path_sha256"] = Value::String("77".repeat(32))
    });
    let error = load_raw_provider_bundle(&config).unwrap_err().to_string();
    assert!(error.contains("decode signed raw device report"), "{error}");
}

#[test]
fn python_provider_raw_config_cross_vector() {
    let value = circuit();
    assert_eq!(
        hex::encode(domain_hash(
            CONFIG_ID_DOMAIN,
            &canonical_json(&value).unwrap()
        )),
        if cfg!(feature = "raw64") {
            "6b67e38e870e71a350b85b5a0ff900920b9d5788a40ecdf26b508ff26f6611f2"
        } else {
            "bdd2a50f0d5716899d7f06ebf01e0a6e84ee3d1873e7d10dce746fc6a2136dbc"
        }
    );
}
