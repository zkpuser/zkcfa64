use super::*;

const PARAMS: RawParams = RawParams {
    edge_cap: 8,
    ep_cap: 8,
    path_mode: PathMode::Complete,
};
const OPENINGS: RawOpenings = RawOpenings {
    ep: [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210],
    cfg: [0x1123_4567_89ab_cdef, 0xeedc_ba98_7654_3210],
};
const TRANSLATOR: &str = concat!("SCOPE_RETURN\n", "0x401000\n", "0x401010\n", "0xfffe0000\n",);
const TYPED_CFG: &str = concat!(
    "SCOPE_RETURN cal 0x401000\n",
    "SCOPE_RETURN crt SCOPE_RETURN\n",
    "0x401000 cal 0xfffe0000\n",
    "0x401000 crt 0x401010\n",
);
const RECORDED_PATH: &str = concat!(
    "initial_node=SCOPE_RETURN final_node=SCOPE_RETURN\n",
    "call 0x401000 SCOPE_RETURN\n",
    "call 0xfffe0000 0x401010\n",
    "ret 0x401010\n",
    "ret SCOPE_RETURN\n",
);

fn fixture() -> RawInstance {
    parse_artifacts(TRANSLATOR, TYPED_CFG, RECORDED_PATH, PARAMS, OPENINGS).unwrap()
}

#[test]
fn semantic_domains_and_encoding_boundary_are_exact() {
    assert_eq!(
        PathMode::Complete.header_word(),
        u64::from_be_bytes(*b"COMPLETE")
    );
    assert_eq!(
        PathMode::Shadow.header_word(),
        u64::from_be_bytes(*b"SHADOWED")
    );
    assert_eq!(
        PathMode::from_label("complete").unwrap(),
        PathMode::Complete
    );
    assert_eq!(PathMode::from_label("shadow").unwrap(), PathMode::Shadow);
    assert!(PathMode::from_label("compressed").is_err());
    assert_eq!(
        RawEncoding::for_ep_cap(1 << 14).unwrap(),
        RawEncoding::Inline14
    );
    assert_eq!(
        RawEncoding::for_ep_cap((1 << 14) + 1).unwrap(),
        RawEncoding::Shared24
    );
    assert!(RawEncoding::for_ep_cap((1 << 24) + 1).is_err());
}

#[test]
fn relation_widths_follow_the_signed_ep_capacity() {
    let params = |ep_cap| RawParams {
        edge_cap: 1,
        ep_cap,
        path_mode: PathMode::Complete,
    };

    // The exact BinMult query count is 2 * (EP_CAP - 1), and one
    // table entry can receive the entire count.
    assert_eq!(params(2).membership_query_count().unwrap(), 2);
    assert_eq!(params(2).mult_bits().unwrap(), 2);
    assert_eq!(params(2_048).mult_bits().unwrap(), 12);
    assert_eq!(params(2_049).membership_query_count().unwrap(), 4_096);
    assert_eq!(params(2_049).mult_bits().unwrap(), 13);
    assert_eq!(params(1 << 14).mult_bits().unwrap(), 15);
    assert_eq!(params((1 << 14) + 1).mult_bits().unwrap(), 16);
    assert_eq!(params(1 << 24).mult_bits().unwrap(), 25);

    // The range backend requires an even width. These are the smallest
    // even widths covering max_slot = floor(EP_CAP / 2) - 1.
    assert_eq!(params(2).shadow_slot_bits().unwrap(), 2);
    assert_eq!(params(8).shadow_slot_bits().unwrap(), 2);
    assert_eq!(params(10).shadow_slot_bits().unwrap(), 4);
    assert_eq!(params(1 << 14).shadow_slot_bits().unwrap(), 14);
    assert_eq!(params(131_074).shadow_slot_bits().unwrap(), 18);
    assert_eq!(params(1 << 24).shadow_slot_bits().unwrap(), 24);

    assert!(params(1).membership_query_count().is_err());
    assert!(params(1).mult_bits().is_err());
    assert!(params(1).shadow_slot_bits().is_err());
    assert!(params((1 << 24) + 1).mult_bits().is_err());
    assert!(params((1 << 24) + 1).shadow_slot_bits().is_err());
}

#[test]
fn provider_tokens_are_injective_and_reserved() {
    assert_eq!(parse_raw_addr("SCOPE_RETURN").unwrap(), 0xff_ffff);
    assert_eq!(parse_raw_addr("0xfffe0000").unwrap(), 0xff_0000);
    assert_eq!(parse_raw_addr("0xfffefffe").unwrap(), 0xff_fffe);
    assert!(parse_raw_addr("0xfffeffff").is_err());
    assert!(parse_raw_addr("0xff0000").is_err());
    assert!(parse_raw_addr("0xffffff").is_err());
    assert!(parse_raw_addr("0x0").is_err());
    assert!(parse_raw_addr("401000").is_err());
    assert!(parse_raw_addr("0X401000").is_err());
    assert!(parse_raw_addr("0xABCDEF").is_err());
}

#[test]
fn strict_text_parsers_derive_exact_matching_call_hints() {
    let instance = fixture();
    assert_eq!(instance.node_count, 4);
    assert_eq!(instance.edges.len(), 4);
    assert_eq!(instance.steps.len(), 5);
    assert_eq!(instance.steps[3].hint, 2);
    assert_eq!(instance.steps[4].hint, 1);
    assert!(instance
        .edges
        .windows(2)
        .all(|pair| pair[0].key() < pair[1].key()));
    assert!(instance.edges.iter().all(|edge| edge.etype != ET_RET));
}

#[test]
fn cfg_and_ep_words_match_the_cf2_layout() {
    let instance = fixture();
    let cfg = instance.cfg_words();
    assert_eq!(cfg.len(), RAW_CFG_HEADER_WORDS + PARAMS.edge_cap);
    assert_eq!(
        &cfg[..10],
        &[
            MAGIC_RAW_CFG,
            8,
            4,
            24,
            0,
            0,
            0,
            0,
            OPENINGS.cfg[0],
            OPENINGS.cfg[1],
        ]
    );
    assert_eq!(cfg[RAW_CFG_HEADER_WORDS + 4], PAD_KEY | 4);
    assert_eq!(cfg[RAW_CFG_HEADER_WORDS + 7], PAD_KEY | 7);

    let ep = instance.ep_words();
    assert_eq!(ep.len(), RAW_EP_HEADER_WORDS + PARAMS.ep_cap);
    assert_eq!(
        &ep[..10],
        &[
            MAGIC_RAW_EP_INLINE,
            8,
            5,
            24,
            OPENINGS.ep[0],
            OPENINGS.ep[1],
            0,
            PathMode::Complete.header_word(),
            0,
            0,
        ]
    );
    assert_eq!(
        ep[RAW_EP_HEADER_WORDS + 3],
        TAG_RET | (0x401010 << 2) | (2 << RAW_HINT_SHIFT)
    );
    assert_eq!(ep[RAW_EP_HEADER_WORDS + 5], 0);
}

#[test]
fn shared24_reuses_the_cal_ret_payload_without_truncation() {
    let step = RawStep {
        dst: 0x401100,
        tag: TAG_RET,
        aux: 0,
        hint: 125_801,
    };
    let word = step.word(RawEncoding::Shared24);
    assert_eq!(
        word,
        TAG_RET | (0x401100 << 2) | (125_801u64 << RAW_EDGE_SHIFT)
    );
    assert_eq!(word >> RAW_HINT_SHIFT, 0);
}

#[test]
fn input_cannot_augment_or_retype_the_static_cfg() {
    let missing_call = concat!(
        "SCOPE_RETURN cal 0x401000\n",
        "SCOPE_RETURN crt SCOPE_RETURN\n",
        "0x401000 crt 0x401010\n",
    );
    let error =
        parse_artifacts(TRANSLATOR, missing_call, RECORDED_PATH, PARAMS, OPENINGS).unwrap_err();
    assert!(error.contains("not a static CFG edge"), "{error}");

    let ret_cfg = "SCOPE_RETURN ret 0x401000\n";
    let error = parse_typed_cfg(ret_cfg, &parse_translator(TRANSLATOR).unwrap()).unwrap_err();
    assert!(error.contains("contains RET"), "{error}");
}

#[test]
fn cfg_duplicates_and_type_aliases_are_rejected() {
    let duplicate = concat!("SCOPE_RETURN cal 0x401000\n", "SCOPE_RETURN cal 0x401000\n",);
    let alias = concat!("SCOPE_RETURN cal 0x401000\n", "SCOPE_RETURN crt 0x401000\n",);
    let nodes = parse_translator(TRANSLATOR).unwrap();
    assert!(parse_typed_cfg(duplicate, &nodes)
        .unwrap_err()
        .contains("repeats endpoint"));
    assert!(parse_typed_cfg(alias, &nodes)
        .unwrap_err()
        .contains("type aliases"));
}

#[test]
fn malformed_stack_and_capacity_fail_closed() {
    let wrong_return = RECORDED_PATH.replace("ret 0x401010", "ret SCOPE_RETURN");
    assert!(
        parse_artifacts(TRANSLATOR, TYPED_CFG, &wrong_return, PARAMS, OPENINGS,)
            .unwrap_err()
            .contains("expected")
    );
    let too_small = RawParams {
        ep_cap: 4,
        ..PARAMS
    };
    assert!(
        parse_artifacts(TRANSLATOR, TYPED_CFG, RECORDED_PATH, too_small, OPENINGS,)
            .unwrap_err()
            .contains("exceed EP_CAP")
    );
    assert!(parse_artifacts(
        TRANSLATOR,
        TYPED_CFG,
        RECORDED_PATH,
        PARAMS,
        RawOpenings {
            ep: OPENINGS.cfg,
            cfg: OPENINGS.cfg,
        },
    )
    .unwrap_err()
    .contains("reuse"));
}
