//! Same-backend control: sealed BinMult, exact indexed selection, and weighted LogUp.
//!
//! This example is research-only: inputs are supplied typed artifacts, not authenticated QEMU
//! measurements. It does not issue or check a provider attestation, and must not be presented as
//! an end-to-end acquisition result. The actual circuit, witness, ZK prover, and verifier are
//! reused; only the private-table membership gadget is selected by this research example.
//! All variants retain SHA-256 commitments, all record checks, and timestamped stack checks.
//! LogUp uses the characteristic-independent weighted variant of Eagen--Haböck (2024/2067),
//! with its weighted column sealed before the rational-identity challenge.
//!
//! Build with `RUSTFLAGS="-C target-cpu=native" cargo build --release --features construction-control --example construction_control`.
//! Run with `RAYON_NUM_THREADS=8 target/release/examples/construction_control --membership binmult|indexed|logup --typed-dir DIR
//! --path-mode complete --edge-cap 64 --ep-cap 64 --log-inv-rate 1`.

fn main() -> anyhow::Result<()> {
    zkcfa::experiments::run_construction_control()
}
