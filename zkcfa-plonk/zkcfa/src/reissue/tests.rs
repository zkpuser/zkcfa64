use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

static FIXTURE_NUMBER: AtomicU64 = AtomicU64::new(0);
const SOURCE_OPENINGS: RawOpenings = RawOpenings {
    ep: [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210],
    cfg: [0x1123_4567_89ab_cdef, 0xeedc_ba98_7654_3210],
};

struct Fixture {
    root: PathBuf,
    config: ReissueConfig,
    authority_public_bytes: Vec<u8>,
    source_authority: SigningKey,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn scope() -> ScopePolicy {
    ScopePolicy {
        schema: SCOPE_SCHEMA.to_owned(),
        architecture: "x86_64".to_owned(),
        boundary_kind: "external-root-entry-and-captured-return".to_owned(),
        root_symbol: "main".to_owned(),
        caller_symbol: "external-loader".to_owned(),
        scope_call_address: "SCOPE_RETURN".to_owned(),
        root_address: "0x401000".to_owned(),
        root_exit_blocks: vec!["0x401008".to_owned()],
        scope_return_address: "SCOPE_RETURN".to_owned(),
        sentinel: "SCOPE_RETURN".to_owned(),
        sentinel_address: "0xffff0000".to_owned(),
        require_complete_entry_exit: true,
        position_independent: true,
        canonical_entry: "0x401000".to_owned(),
        canonical_start_code: "0x401000".to_owned(),
        canonical_address_model: "pie-load-bias".to_owned(),
        proof_path_compression: "none".to_owned(),
        normalization: "qemu-root-scope".to_owned(),
        external_call_model: "none".to_owned(),
    }
}

fn fixture() -> Fixture {
    let number = FIXTURE_NUMBER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "zkcfa-plonk-reissue-test-{}-{number}",
        std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    set_mode(&root, 0o700).unwrap();
    let source_run = root.join("source");
    let source_bundle = source_run.join("bundle");
    let public = source_bundle.join("public");
    let private = source_bundle.join("private");
    create_directory(&source_run, 0o700).unwrap();
    create_directory(&source_bundle, 0o755).unwrap();
    create_directory(&public, 0o755).unwrap();
    create_directory(&private, 0o700).unwrap();
    write_new(
        &private.join("translator"),
        b"SCOPE_RETURN\n0x401000\n",
        0o600,
    )
    .unwrap();
    write_new(
        &private.join("typed_cfg"),
        b"SCOPE_RETURN jmp 0x401000\n0x401000 jmp SCOPE_RETURN\n",
        0o600,
    )
    .unwrap();
    write_new(
        &private.join("recorded_path"),
        b"initial_node=SCOPE_RETURN final_node=SCOPE_RETURN\njump 0x401000\njump SCOPE_RETURN\n",
        0o600,
    )
    .unwrap();

    let params = RawParams {
        edge_cap: 8,
        ep_cap: 16,
        path_mode: PathMode::Complete,
    };
    let instance = RawInstance::load(&private, params, SOURCE_OPENINGS).unwrap();
    let h_cfg = sha256_words(&instance.cfg_words());
    let h_ep = sha256_words(&instance.ep_words());
    let authority = random_signing_key_excluding(&[]);
    let device = random_signing_key_excluding(&[authority.verifying_key()]);
    let authority_public = authority
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let authority_public_path = source_run.join("authority.pem");
    write_new(&authority_public_path, authority_public.as_bytes(), 0o644).unwrap();

    let circuit = BiniusCircuitConfig {
        schema: CIRCUIT_SCHEMA.to_owned(),
        profile: PROFILE.to_owned(),
        backend: SOURCE_BACKEND.to_owned(),
        log_inv_rate: 1,
        path_mode: "complete".to_owned(),
        edge_cap: 8,
        ep_cap: 16,
    };
    let circuit_value = serde_json::to_value(&circuit).unwrap();
    let config_id = domain_hash(CONFIG_ID_DOMAIN, &canonical_json(&circuit_value).unwrap());
    let scope = scope();
    let scope_value = serde_json::to_value(&scope).unwrap();
    let mut registry = json!({
        "schema": REGISTRY_SCHEMA,
        "application": "crc32",
        "binary_measurement": "11".repeat(32),
        "raw_config_id": hex::encode(config_id),
        "h_cfg_raw24": hex::encode(h_cfg),
        "circuit": circuit,
        "allowed_endpoints": [{
            "entry_raw": RAW_ADDR_LIMIT - 1,
            "final_raw": RAW_ADDR_LIMIT - 1
        }],
        "devices": {
            "source-device": {
                "algorithm": ALGORITHM,
                "key_id": hex::encode(key_id(&device.verifying_key())),
                "public_key": BASE64.encode(device.verifying_key().as_bytes())
            }
        },
        "scope_policy": scope
    });
    let registry_id = domain_hash(REGISTRY_ID_DOMAIN, &canonical_json(&registry).unwrap());
    registry["raw_registry_id"] = Value::String(hex::encode(registry_id));
    let registry_envelope = sign_payload(registry, &authority, AUTHORITY_SIGNATURE_DOMAIN).unwrap();
    write_json_new(&public.join("registry.json"), &registry_envelope, 0o644).unwrap();

    let scope_digest = domain_hash(SCOPE_POLICY_DOMAIN, &canonical_json(&scope_value).unwrap());
    let report = json!({
        "schema": REPORT_SCHEMA,
        "device_id": "source-device",
        "challenge_id": "33".repeat(16),
        "nonce": "44".repeat(32),
        "raw_registry_id": hex::encode(registry_id),
        "raw_config_id": hex::encode(config_id),
        "binary_measurement": "11".repeat(32),
        "h_cfg_raw24": hex::encode(h_cfg),
        "h_ep_raw24": hex::encode(h_ep),
        "entry_raw": RAW_ADDR_LIMIT - 1,
        "final_raw": RAW_ADDR_LIMIT - 1,
        "scope_policy_digest": hex::encode(scope_digest),
        "runtime_code_match": true,
        "boundary_policy_satisfied": true
    });
    write_json_new(
        &public.join("report.json"),
        &sign_payload(report, &device, DEVICE_SIGNATURE_DOMAIN).unwrap(),
        0o644,
    )
    .unwrap();
    write_json_new(
        &private.join("worker.json"),
        &json!({
            "schema": WORKER_SCHEMA,
            "raw_registry_id": hex::encode(registry_id),
            "raw_config_id": hex::encode(config_id),
            "h_cfg_raw24": hex::encode(h_cfg),
            "h_ep_raw24": hex::encode(h_ep),
            "ep_blind_low": format!("0x{:016x}", SOURCE_OPENINGS.ep[0]),
            "ep_blind_high": format!("0x{:016x}", SOURCE_OPENINGS.ep[1]),
            "cfg_blind_low": format!("0x{:016x}", SOURCE_OPENINGS.cfg[0]),
            "cfg_blind_high": format!("0x{:016x}", SOURCE_OPENINGS.cfg[1])
        }),
        0o600,
    )
    .unwrap();
    let enrollment_path = source_run.join("enrollment.json");
    let enrollment = json!({
        "schema": ENROLLMENT_SCHEMA,
        "raw_registry_id": hex::encode(registry_id),
        "cfg_blind_low": format!("0x{:016x}", SOURCE_OPENINGS.cfg[0]),
        "cfg_blind_high": format!("0x{:016x}", SOURCE_OPENINGS.cfg[1]),
        "static_manifest_sha256": "55".repeat(32)
    });
    write_json_new(
        &enrollment_path,
        &sign_payload(enrollment, &authority, ENROLLMENT_SIGNATURE_DOMAIN).unwrap(),
        0o600,
    )
    .unwrap();
    let config = ReissueConfig {
        source_bundle,
        source_authority_public: authority_public_path,
        source_authority_sha256: sha256(authority_public.as_bytes()),
        source_challenge_id: "33".repeat(16),
        source_nonce: [0x44; 32],
        source_enrollment: enrollment_path,
        target_challenge_id: "66".repeat(16),
        target_nonce: [0x77; 32],
        run_dir: root.join("target"),
    };
    Fixture {
        root,
        config,
        authority_public_bytes: authority_public.into_bytes(),
        source_authority: authority,
    }
}

#[test]
fn authenticates_and_reissues_with_fresh_keys_openings_and_provenance() {
    let fixture = fixture();
    let result = issue(fixture.config.clone()).unwrap();
    assert_eq!(result.challenge_id, "66".repeat(16));
    assert_eq!(result.nonce, "77".repeat(32));
    let output = &fixture.config.run_dir;
    let target_authority = std::fs::read(output.join("keys/public/authority.pem")).unwrap();
    assert_ne!(target_authority, fixture.authority_public_bytes);
    let registry: Value =
        serde_json::from_slice(&std::fs::read(output.join("bundle/public/registry.json")).unwrap())
            .unwrap();
    assert_eq!(registry["payload"]["circuit"]["backend"], BACKEND);
    assert_eq!(registry["payload"]["provenance"]["kind"], REISSUANCE_KIND);
    assert_eq!(
        registry["payload"]["provenance"]["source_backend"],
        SOURCE_BACKEND
    );
    let worker: WorkerSecret =
        serde_json::from_slice(&std::fs::read(output.join("bundle/private/worker.json")).unwrap())
            .unwrap();
    let target_ep = [
        parse_hex_word(&worker.ep_blind_low, "ep").unwrap(),
        parse_hex_word(&worker.ep_blind_high, "ep").unwrap(),
    ];
    let target_cfg = [
        parse_hex_word(&worker.cfg_blind_low, "cfg").unwrap(),
        parse_hex_word(&worker.cfg_blind_high, "cfg").unwrap(),
    ];
    assert_ne!(target_ep, [0, 0]);
    assert_ne!(target_cfg, [0, 0]);
    assert_ne!(target_ep, target_cfg);
    assert!(![SOURCE_OPENINGS.ep, SOURCE_OPENINGS.cfg].contains(&target_ep));
    assert!(![SOURCE_OPENINGS.ep, SOURCE_OPENINGS.cfg].contains(&target_cfg));
    assert_eq!(
        std::fs::read(output.join("bundle/private/typed_cfg")).unwrap(),
        std::fs::read(fixture.config.source_bundle.join("private/typed_cfg")).unwrap()
    );
    let recorded: Value =
        serde_json::from_slice(&std::fs::read(output.join("protocol-result.json")).unwrap())
            .unwrap();
    assert_eq!(recorded["bundle"], result.bundle);
    assert_eq!(recorded["authority_sha256"], result.authority_sha256);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(output.join("keys/private/authority.pem"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(output.join("bundle/private"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}

#[test]
fn rejects_tampered_source_signature_without_publishing_partial_output() {
    let fixture = fixture();
    let report_path = fixture.config.source_bundle.join("public/report.json");
    let mut report: Value = serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
    report["signature"] = Value::String(BASE64.encode([0u8; 64]));
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    let error = format!("{:#}", issue(fixture.config.clone()).unwrap_err());
    assert!(
        error.contains("invalid domain-separated signature"),
        "{error}"
    );
    assert!(!fixture.config.run_dir.exists());
    let partials: Vec<_> = std::fs::read_dir(&fixture.root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".target.tmp-"))
        .collect();
    assert!(partials.is_empty());
}

#[test]
fn rejects_existing_output_stale_challenge_and_insecure_private_input() {
    let existing = fixture();
    std::fs::create_dir(&existing.config.run_dir).unwrap();
    let error = format!("{:#}", issue(existing.config.clone()).unwrap_err());
    assert!(error.contains("refusing to overwrite"), "{error}");

    let stale_fixture = fixture();
    let mut stale = stale_fixture.config.clone();
    stale.target_challenge_id = stale.source_challenge_id.clone();
    let error = format!("{:#}", issue(stale).unwrap_err());
    assert!(error.contains("must each differ"), "{error}");
    assert!(!stale_fixture.config.run_dir.exists());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let fixture = fixture();
        let worker = fixture.config.source_bundle.join("private/worker.json");
        std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = format!("{:#}", issue(fixture.config.clone()).unwrap_err());
        assert!(error.contains("group/other"), "{error}");
        assert!(!fixture.config.run_dir.exists());
    }

    let overlap_fixture = fixture();
    let mut overlap = overlap_fixture.config.clone();
    overlap.run_dir = overlap.source_bundle.join("private/reissued");
    let error = format!("{:#}", issue(overlap).unwrap_err());
    assert!(
        error.contains("must not equal, contain, or be contained"),
        "{error}"
    );
    assert!(!overlap_fixture
        .config
        .source_bundle
        .join("private/reissued")
        .exists());
}

#[test]
fn rejects_artifact_tamper_and_wrong_enrollment_binding() {
    let tampered = fixture();
    let typed_cfg = tampered.config.source_bundle.join("private/typed_cfg");
    std::fs::write(
        &typed_cfg,
        b"SCOPE_RETURN jmp SCOPE_RETURN\n0x401000 jmp SCOPE_RETURN\n",
    )
    .unwrap();
    set_mode(&typed_cfg, 0o600).unwrap();
    let error = format!("{:#}", issue(tampered.config.clone()).unwrap_err());
    assert!(
        error.contains("authenticated SHA-256 commitments")
            || error.contains("parse snapshotted Binius64"),
        "{error}"
    );
    assert!(!tampered.config.run_dir.exists());

    let fixture = fixture();
    let enrollment = &fixture.config.source_enrollment;
    let mut value: Value = serde_json::from_slice(&std::fs::read(enrollment).unwrap()).unwrap();
    value["payload"]["cfg_blind_low"] = Value::String("0x0000000000000001".to_owned());
    let resigned = sign_payload(
        value["payload"].take(),
        &fixture.source_authority,
        ENROLLMENT_SIGNATURE_DOMAIN,
    )
    .unwrap();
    std::fs::write(enrollment, serde_json::to_vec_pretty(&resigned).unwrap()).unwrap();
    set_mode(enrollment, 0o600).unwrap();
    let error = format!("{:#}", issue(fixture.config.clone()).unwrap_err());
    assert!(
        error.contains("does not authenticate the worker CFG opening"),
        "{error}"
    );
    assert!(!fixture.config.run_dir.exists());
}

#[test]
fn rejects_binius_inline14_capacity_pairs_with_insufficient_multiplicity_range() {
    let circuit = BiniusCircuitConfig {
        schema: CIRCUIT_SCHEMA.to_owned(),
        profile: PROFILE.to_owned(),
        backend: SOURCE_BACKEND.to_owned(),
        log_inv_rate: 1,
        path_mode: "complete".to_owned(),
        edge_cap: 8,
        ep_cap: 1 << 14,
    };
    let error = validate_binius_circuit(&circuit).unwrap_err().to_string();
    assert!(
        error.contains("inline14 capacity pair is infeasible"),
        "{error}"
    );
}
