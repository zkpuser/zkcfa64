//! Synthetic paper experiment runners, separate from the signed application flow.
//!
//! These entry points parse the corresponding example's command-line arguments.
//! They measure raw24 and reject a binary compiled with the raw64 relation.

#[cfg(all(feature = "construction-control", not(feature = "raw64")))]
mod construction_control;
#[cfg(not(feature = "raw64"))]
mod scaling;
#[cfg(all(feature = "stack-control", not(feature = "raw64")))]
mod stack_control;

/// Run synthetic scaling with the complete production raw24 circuit.
pub fn run_scaling() -> anyhow::Result<()> {
    #[cfg(not(feature = "raw64"))]
    return scaling::run();
    #[cfg(feature = "raw64")]
    anyhow::bail!("scaling measures raw24; build without --features raw64")
}

/// Compare membership constructions while retaining the other raw24 checks.
#[cfg(feature = "construction-control")]
pub fn run_construction_control() -> anyhow::Result<()> {
    #[cfg(not(feature = "raw64"))]
    return construction_control::run();
    #[cfg(feature = "raw64")]
    anyhow::bail!("construction_control measures raw24; build without --features raw64")
}

/// Measure the timestamped-stack check's contribution to the raw24 circuit.
#[cfg(feature = "stack-control")]
pub fn run_stack_control() -> anyhow::Result<()> {
    #[cfg(not(feature = "raw64"))]
    return stack_control::run();
    #[cfg(feature = "raw64")]
    anyhow::bail!("stack_control measures raw24; build without --features raw64")
}
