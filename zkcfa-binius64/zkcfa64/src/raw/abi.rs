//! Canonical relation public inputs and Binius public-vector reconstruction.

use super::*;

/// Encode the authenticated raw statement as the ten inout words accepted by the verifier API.
///
/// Circuit constants are deliberately absent: current Binius64 verifiers obtain them from the
/// constraint system and reject callers that restate the complete public segment.
pub(crate) fn canonical_inout_words(values: RawPublicValues) -> [Word; RAW_N_PUBLIC] {
    let mut inout = [Word::ZERO; RAW_N_PUBLIC];
    for (i, word) in digest_words(&values.h_ep).into_iter().enumerate() {
        inout[RAW_OFF_EP_DIGEST + i] = Word(word);
    }
    for (i, word) in digest_words(&values.h_cfg).into_iter().enumerate() {
        inout[RAW_OFF_CFG_DIGEST + i] = Word(word);
    }
    inout[RAW_OFF_ENTRY] = Word(values.entry);
    inout[RAW_OFF_FINAL] = Word(values.final_node);
    inout
}

/// Rebuild the complete Binius public segment for prover-side witness consistency checks.
///
/// This vector contains verifier-owned circuit constants in addition to the ten statement words;
/// it must not be passed to the current Binius64 verifier API.
pub(crate) fn canonical_public_words(
    cs: &ConstraintSystem,
    values: RawPublicValues,
) -> Result<Vec<Word>> {
    ensure!(
        cs.n_inout == RAW_N_PUBLIC,
        "compiled raw public ABI has {} inout words, expected {RAW_N_PUBLIC}",
        cs.n_inout
    );
    let mut public = vec![Word::ZERO; cs.n_public_words(InoutSegment::Public)];
    public[..cs.n_const()].copy_from_slice(&cs.constants);
    let base = cs.offset_inout();
    public[base..base + RAW_N_PUBLIC].copy_from_slice(&canonical_inout_words(values));
    Ok(public)
}
