//! Address-native raw24 zkCFA relation.
//!
//! The public commitments bind a typed full-key CFG and either a complete QEMU path or the
//! explicitly selected stack-safe projection. EP and CFG use independent secret openings.

use std::{collections::HashSet, path::Path};

use anyhow::{Result, bail, ensure};
use binius_circuits::sha256::sha256_fixed;
use binius_core::{InoutSegment, constraint_system::ConstraintSystem, word::Word};
#[cfg(feature = "construction-control")]
use binius_field::{Field, Ghash128b, arithmetic_traits::InvertOrZero};
#[cfg(feature = "construction-control")]
use binius_frontend::Hint;
use binius_frontend::{Circuit, CircuitBuilder, Wire, WitnessFiller};

use crate::raw_format::{
    Blinding, ET_CAL, ET_CRT, ET_JMP, TAG_CAL, TAG_JMP, TAG_RESERVED, TAG_RET, buf_digest,
    digest_words, etype_of_tag,
};

mod abi;
mod binmult;
mod circuit;
mod encoding;
mod field;
mod instance;
#[cfg(feature = "construction-control")]
mod research;
mod stack;

pub(crate) use abi::{canonical_inout_words, canonical_public_words};
use binmult::*;
#[cfg(feature = "construction-control")]
pub(crate) use circuit::RawMembershipKind;
#[cfg(feature = "stack-control")]
pub(crate) use circuit::build_raw_stack_control;
use circuit::*;
pub(crate) use circuit::{RawCfgWalk, build_raw_circuit};
use encoding::*;
pub(crate) use encoding::{RAW_N_PUBLIC, RawParams, RawPublicValues, signed_raw_params};
use field::*;
pub(crate) use instance::{
    RawInstance, preflight_raw_instance, validate_capacity_bounds, validate_raw_instance,
};
#[cfg(feature = "construction-control")]
pub(crate) use research::build_raw_membership_control;
#[cfg(feature = "construction-control")]
use research::*;
use stack::*;

#[cfg(test)]
mod tests;
