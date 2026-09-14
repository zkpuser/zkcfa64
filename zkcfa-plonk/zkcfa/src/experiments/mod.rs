//! Synthetic paper measurements, enabled separately from the signed application flow.

mod scaling;

/// Run the raw24 PLONK/KZG scaling CLI on supplied synthetic artifacts.
pub fn run_scaling() -> anyhow::Result<()> {
    scaling::run()
}
