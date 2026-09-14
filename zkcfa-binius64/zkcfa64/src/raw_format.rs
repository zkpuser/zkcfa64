//! Canonical primitives shared by the raw relation and its signed handoff.

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

pub(crate) const ET_JMP: u64 = 0;
pub(crate) const ET_CAL: u64 = 1;
pub(crate) const ET_RET: u64 = 2;
pub(crate) const ET_CRT: u64 = 3;

pub(crate) const TAG_JMP: u64 = 0;
pub(crate) const TAG_CAL: u64 = 1;
pub(crate) const TAG_RET: u64 = 2;
pub(crate) const TAG_RESERVED: u64 = 3;

pub(crate) const fn etype_of_tag(tag: u64) -> u64 {
    match tag {
        TAG_JMP => ET_JMP,
        TAG_CAL => ET_CAL,
        TAG_RET => ET_RET,
        TAG_RESERVED => ET_CRT,
        _ => tag,
    }
}

/// A confidential, nonzero 128-bit opening for one artifact commitment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Blinding([u64; 2]);

impl Blinding {
    pub(crate) fn from_words(lo: u64, hi: u64) -> Result<Self> {
        let value = Self([lo, hi]);
        if value.is_zero() {
            bail!("artifact blinding must be nonzero");
        }
        Ok(value)
    }

    #[cfg(test)]
    pub(crate) const fn from_words_const(lo: u64, hi: u64) -> Self {
        assert!(lo != 0 || hi != 0, "artifact blinding must be nonzero");
        Self([lo, hi])
    }

    pub(crate) const fn words(self) -> [u64; 2] {
        self.0
    }

    const fn is_zero(self) -> bool {
        self.0[0] == 0 && self.0[1] == 0
    }
}

impl core::fmt::Debug for Blinding {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Blinding(<redacted>)")
    }
}

pub(crate) fn buf_digest(words: &[u64]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for word in words {
        hash.update(word.to_be_bytes());
    }
    hash.finalize().into()
}

pub(crate) fn digest_words(digest: &[u8; 32]) -> [u64; 4] {
    core::array::from_fn(|index| {
        u64::from_be_bytes(digest[8 * index..8 * index + 8].try_into().unwrap())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openings_are_nonzero_and_redacted() {
        assert!(Blinding::from_words(0, 0).is_err());
        let opening = Blinding::from_words(1, 2).unwrap();
        assert_eq!(opening.words(), [1, 2]);
        assert_eq!(format!("{opening:?}"), "Blinding(<redacted>)");
    }

    #[test]
    fn digest_words_are_big_endian() {
        let digest: [u8; 32] = core::array::from_fn(|index| index as u8);
        assert_eq!(digest_words(&digest)[0], 0x0001_0203_0405_0607);
    }
}
