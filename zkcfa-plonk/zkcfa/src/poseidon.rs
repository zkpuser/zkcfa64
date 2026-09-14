//! Exact proof-native commitment used by the raw24 PLONK statement.
//!
//! The permutation implementation in this repository accepts two field elements at a time.
//! We therefore define a hash explicitly as a chain of two-to-one compressions instead of
//! calling it a generic sponge.  The first compression absorbs an artifact domain and the exact
//! number of raw `u64` words.  Subsequent compressions absorb three words at a time, packed as a
//! 192-bit little-limb integer.  The length in the first compression makes the zero padding in
//! the final packed element unambiguous.

use ark_ff::{BigInteger, PrimeField};
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    poseidon_ref::{NativeSpecRef, PoseidonRef},
};
use sha2::{Digest, Sha256};

pub(crate) const WIDTH: usize = 3;
pub(crate) const RATE: usize = WIDTH - 1;
pub(crate) const WORDS_PER_FIELD: usize = 3;

pub(crate) const EP_DOMAIN: u64 = 0x5a4b_4346_412f_4550; // `ZKCFA/EP`
pub(crate) const CFG_DOMAIN: u64 = 0x5a4b_4346_412f_4346; // `ZKCFA/CF`

pub(crate) const SCHEME: &str = "poseidon";
pub(crate) const FIELD: &str = "bls12-381-fr";
pub(crate) const SBOX: &str = "x^5";
pub(crate) const CONSTRUCTION: &str = "domain-length-chain";
pub(crate) const PACKING: &str = "u64x3-little-limb";
pub(crate) const OUTPUT: &str = "state-1";

/// Native reference for the exact chain enforced by the circuit.
pub(crate) fn hash_words<F: PrimeField>(domain: u64, words: &[u64]) -> Result<F, String> {
    let constants = PoseidonConstants::<F>::generate::<WIDTH>();
    let mut state = compress(
        &constants,
        F::from(domain),
        F::from(u64::try_from(words.len()).map_err(|_| "raw commitment length exceeds u64")?),
    )?;
    for chunk in words.chunks(WORDS_PER_FIELD) {
        state = compress(&constants, state, pack_words(chunk))?;
    }
    Ok(state)
}

fn compress<F: PrimeField>(
    constants: &PoseidonConstants<F>,
    left: F,
    right: F,
) -> Result<F, String> {
    let mut context = ();
    let mut hasher =
        PoseidonRef::<(), NativeSpecRef<F>, WIDTH>::new(&mut context, constants.clone());
    hasher
        .input(left)
        .map_err(|error| format!("Poseidon left input: {error}"))?;
    hasher
        .input(right)
        .map_err(|error| format!("Poseidon right input: {error}"))?;
    Ok(hasher.output_hash(&mut context))
}

fn pack_words<F: PrimeField>(words: &[u64]) -> F {
    debug_assert!(!words.is_empty() && words.len() <= WORDS_PER_FIELD);
    let radix = F::from(2u64).pow([64]);
    let mut power = F::one();
    let mut packed = F::zero();
    for word in words {
        packed += F::from(*word) * power;
        power *= radix;
    }
    packed
}

/// Stable fingerprint of the permutation parameters used by both native and circuit paths.
/// The signed circuit configuration carries this value, so a dependency update cannot silently
/// change the authority-approved commitment.
pub(crate) fn constants_sha256<F: PrimeField>() -> [u8; 32] {
    let constants = PoseidonConstants::<F>::generate::<WIDTH>();
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"ZKCFA/Poseidon/parameters\0");
    for value in [
        WIDTH as u64,
        RATE as u64,
        constants.full_rounds as u64,
        constants.partial_rounds as u64,
    ] {
        transcript.extend_from_slice(&value.to_be_bytes());
    }
    append_field(&mut transcript, constants.domain_tag);
    for value in &constants.round_constants {
        append_field(&mut transcript, *value);
    }
    for row in constants.mds_matrices.m.iter_rows() {
        for value in row {
            append_field(&mut transcript, *value);
        }
    }
    Sha256::digest(transcript).into()
}

fn append_field<F: PrimeField>(output: &mut Vec<u8>, value: F) {
    let bytes = value.into_repr().to_bytes_be();
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(&bytes);
}

pub(crate) fn field_hex<F: PrimeField>(value: F) -> String {
    let bytes = value.into_repr().to_bytes_be();
    let mut canonical = vec![0u8; 32usize.saturating_sub(bytes.len())];
    canonical.extend_from_slice(&bytes);
    hex::encode(canonical)
}

pub(crate) fn parse_field_hex<F: PrimeField>(value: &str, label: &str) -> Result<F, String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!(
            "{label} must be canonical lowercase 32-byte field hexadecimal"
        ));
    }
    let bytes = hex::decode(value).map_err(|error| format!("decode {label}: {error}"))?;
    let field = F::from_be_bytes_mod_order(&bytes);
    if field_hex(field) != value {
        return Err(format!("{label} is not a canonical field element"));
    }
    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    #[test]
    fn length_and_artifact_domains_are_distinct() {
        let one = hash_words::<Fr>(EP_DOMAIN, &[7]).unwrap();
        let trailing_zero = hash_words::<Fr>(EP_DOMAIN, &[7, 0]).unwrap();
        let cfg = hash_words::<Fr>(CFG_DOMAIN, &[7]).unwrap();
        assert_ne!(one, trailing_zero);
        assert_ne!(one, cfg);
    }

    #[test]
    fn field_hex_is_canonical_and_rejects_reduction() {
        let value = Fr::from(0xabcdu64);
        let encoded = field_hex(value);
        assert_eq!(parse_field_hex::<Fr>(&encoded, "test").unwrap(), value);
        assert!(parse_field_hex::<Fr>(&"ff".repeat(32), "test").is_err());
        assert!(parse_field_hex::<Fr>(&encoded.to_uppercase(), "test").is_err());
    }

    #[test]
    fn reviewed_protocol_vectors_are_stable() {
        assert_eq!(
            hex::encode(constants_sha256::<Fr>()),
            "baf89ddffb5c66a027315f419650f80a5320861a55207b2aa3d5c0ebb08ed6e3"
        );
        assert_eq!(
            field_hex(hash_words::<Fr>(EP_DOMAIN, &[1, 2, 3, 4, 5]).unwrap()),
            "39fae45b9e4f4daecf378cae861e49c9e15456c94ca35d9ce96d7462042d36c3"
        );
        // Two words exercise the final partial three-u64 packing group.
        assert_eq!(
            field_hex(hash_words::<Fr>(CFG_DOMAIN, &[u64::MAX, 7]).unwrap()),
            "3f52f93926f1eb51a154a271420fb10cd89740f89ef291d87ea26b11b38429d6"
        );
    }
}
