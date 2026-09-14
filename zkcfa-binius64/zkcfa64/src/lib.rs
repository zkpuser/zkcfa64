//! Signed zkCFA proving and verification on the selected Binius64 relation.
//!
//! The public entry point runs the authenticated application flow. Explicit
//! experiment features expose separate CLI runners for synthetic measurements.

#![recursion_limit = "256"]

mod attestation;
mod prover;
#[cfg_attr(feature = "raw64", path = "raw64.rs")]
mod raw;
mod raw_format;
mod report;
mod runner;
mod verifier;

#[cfg(feature = "experiments")]
pub mod experiments;

/// Prove and verify a signed provider bundle using the compiled relation.
pub fn run() -> anyhow::Result<()> {
    runner::run()
}
