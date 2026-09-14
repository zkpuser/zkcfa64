//! Poseidon commitment opening and domain-separated challenge derivation.

use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::{
    constraint_system::{StandardComposer, Variable},
    error::Error,
};
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    zprize_constraints::{PlonkSpecZZ, PoseidonZZRef},
};

use crate::poseidon::{WIDTH as POSEIDON_WIDTH, WORDS_PER_FIELD};

use super::fixed;

const POSEIDON_RATE: usize = POSEIDON_WIDTH - 1;

pub(super) fn with_domain<F, P>(
    composer: &mut StandardComposer<F, P>,
    domain: u64,
    inputs: &[Variable],
) -> Vec<Variable>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let mut output = Vec::with_capacity(inputs.len() + 1);
    output.push(fixed(composer, domain));
    output.extend_from_slice(inputs);
    output
}

pub(super) fn poseidon_chain<F, P>(
    composer: &mut StandardComposer<F, P>,
    inputs: &[Variable],
) -> Result<Variable, Error>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    if inputs.is_empty() {
        return Err(Error::CircuitInputsNotFound);
    }
    let constants = PoseidonConstants::<F>::generate::<POSEIDON_WIDTH>();
    let mut current = None;
    let mut index = 0;
    while index < inputs.len() {
        let mut hasher = safe_poseidon_hasher(composer, constants.clone());
        let mut occupied = 0;
        if let Some(previous) = current {
            hasher
                .input(previous)
                .map_err(|_| Error::CircuitInputsNotFound)?;
            occupied += 1;
        }
        while occupied < POSEIDON_RATE && index < inputs.len() {
            hasher
                .input(inputs[index])
                .map_err(|_| Error::CircuitInputsNotFound)?;
            occupied += 1;
            index += 1;
        }
        current = Some(hasher.output_hash(composer));
    }
    current.ok_or(Error::CircuitInputsNotFound)
}

/// Build a Poseidon compression gadget with the internal capacity tag fixed in the circuit
/// description. `PoseidonZZRef::new` allocates that tag as an unconstrained input in this fork;
/// replacing state[0] is therefore mandatory before any round is emitted.
fn safe_poseidon_hasher<F, P>(
    composer: &mut StandardComposer<F, P>,
    constants: PoseidonConstants<F>,
) -> PoseidonZZRef<StandardComposer<F, P>, PlonkSpecZZ<F>, POSEIDON_WIDTH>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let domain_tag = constants.domain_tag;
    let mut hasher = PoseidonZZRef::<_, PlonkSpecZZ<F>, POSEIDON_WIDTH>::new(composer, constants);
    hasher.elements[0] = composer.add_witness_to_circuit_description(domain_tag);
    hasher
}

fn poseidon_compress<F, P>(
    composer: &mut StandardComposer<F, P>,
    constants: &PoseidonConstants<F>,
    left: Variable,
    right: Variable,
) -> Result<Variable, Error>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let mut hasher = safe_poseidon_hasher(composer, constants.clone());
    hasher
        .input(left)
        .map_err(|_| Error::CircuitInputsNotFound)?;
    hasher
        .input(right)
        .map_err(|_| Error::CircuitInputsNotFound)?;
    Ok(hasher.output_hash(composer))
}

pub(super) fn poseidon_commitment_words<F, P>(
    composer: &mut StandardComposer<F, P>,
    domain: u64,
    words: &[Variable],
) -> Result<Variable, Error>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let constants = PoseidonConstants::<F>::generate::<POSEIDON_WIDTH>();
    let domain = fixed(composer, domain);
    let length = fixed(
        composer,
        u64::try_from(words.len()).map_err(|_| Error::CircuitInputsNotFound)?,
    );
    let mut state = poseidon_compress(composer, &constants, domain, length)?;
    let radix = F::from(2u64).pow([64]);
    let radix_squared = F::from(2u64).pow([128]);
    for chunk in words.chunks(WORDS_PER_FIELD) {
        let packed = match chunk {
            [a] => *a,
            [a, b] => {
                composer.arithmetic_gate(|gate| gate.witness(*a, *b, None).add(F::one(), radix))
            }
            [a, b, c] => composer.arithmetic_gate(|gate| {
                gate.witness(*a, *b, None)
                    .add(F::one(), radix)
                    .fan_in_3(radix_squared, *c)
            }),
            _ => return Err(Error::CircuitInputsNotFound),
        };
        state = poseidon_compress(composer, &constants, state, packed)?;
    }
    Ok(state)
}
