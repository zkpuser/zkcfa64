//! Synthetic scaling measurements of the production raw24 circuit and proof system.
//!
//! This example is research-only: inputs are supplied typed artifacts, not authenticated QEMU
//! measurements. It does not issue or check a provider attestation, and must not be presented as
//! an end-to-end acquisition result. The actual circuit, witness, ZK prover, and verifier are
//! reused without modifications.
//!
//! Build with `RUSTFLAGS="-C target-cpu=native" cargo build --release --features experiments --example scaling`.
//! Run with `RAYON_NUM_THREADS=8 target/release/examples/scaling --typed-dir DIR
//! --path-mode complete --edge-cap 64 --ep-cap 64 --log-inv-rate 1`.

fn main() -> anyhow::Result<()> {
    zkcfa::experiments::run_scaling()
}
