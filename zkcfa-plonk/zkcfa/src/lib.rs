//! Signed raw24 zkCFA proving, verification, and authenticated bundle reissuance.

mod attestation;
mod circuit;
mod poseidon;
mod prover;
mod raw_format;
mod reissue;
mod report;
mod runner;
mod verifier;

#[cfg(feature = "experiments")]
pub mod experiments;

/// Run the signed application flow, optionally stopping after preflight checks.
pub fn run(preflight: bool) -> anyhow::Result<()> {
    runner::run(preflight)
}

/// Run the authenticated reissuance CLI and print its existing JSON result.
pub fn run_reissue() -> anyhow::Result<()> {
    let result = reissue::run_cli(std::env::args_os().skip(1))?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
