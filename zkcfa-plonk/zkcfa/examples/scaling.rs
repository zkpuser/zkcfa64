//! Research-only scaling of the maintained raw24 PLONK/KZG relation.
//!
//! Inputs are synthetic typed artifacts, not authenticated acquisition evidence. The production
//! raw relation, canonical encoding, Poseidon computation, shape compiler, and cryptographic
//! prover/verifier are reused. Setup and witness synthesis are outside cryptographic proving.
//! This expands `Circuit::gen_proof` at its existing synthesis/prove boundary without changing it.

fn main() -> anyhow::Result<()> {
    zkcfa::experiments::run_scaling()
}
