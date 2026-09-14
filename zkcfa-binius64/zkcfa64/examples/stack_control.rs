//! Research-only compiled-constraint ablation of the production timestamped stack checker.
//!
//! The two circuits share raw24 records, SHA-256 commitments, and BinMult membership.
//! Their sole construction difference is the existing RawShadow inclusion switch. Every
//! supplied witness is validated against both complete compiled constraint systems. An
//! optional proof roundtrip uses only the complete production relation.
//!
//! Build: RUSTFLAGS="-C target-cpu=native" cargo build --release --features stack-control --example stack_control
//! Run: RAYON_NUM_THREADS=8 target/release/examples/stack_control --typed-dir DIR --ep-cap N [--prove]

fn main() -> anyhow::Result<()> {
    zkcfa::experiments::run_stack_control()
}
