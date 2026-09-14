//! Authenticated Binius64-to-PLONK bundle reissuance.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    zkcfa::run_reissue()?;
    Ok(())
}
