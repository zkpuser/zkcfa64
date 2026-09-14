//! CFG membership queries and the multiplicity grand-product argument.

use std::collections::HashMap;

use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::{
    constraint_system::{StandardComposer, Variable},
    error::Error,
};

use crate::raw_format::{RawInstance, ET_CRT, RAW_ADDR_BITS, TAG_CAL, TAG_RET};

use super::{
    add,
    commitment::{poseidon_chain, with_domain},
    fixed, mul, pin, sub, StepWires, RAW_EDGE_SHIFT,
};

const MEMBERSHIP_DOMAIN_0: u64 = 0x5a4b_4346_412f_4d30;
const MEMBERSHIP_DOMAIN_1: u64 = 0x5a4b_4346_412f_4d31;

fn query_values(instance: &RawInstance) -> Vec<u64> {
    let table = instance.cfg_table();
    let query_count = instance
        .params
        .membership_query_count()
        .expect("validated raw parameters have a bounded membership-query count");
    let mut queries = Vec::with_capacity(query_count);
    for row in 1..instance.params.ep_cap {
        let neutral_forward = table[(2 * (row - 1)) % table.len()];
        let neutral_crt = table[(2 * (row - 1) + 1) % table.len()];
        match (instance.steps.get(row - 1), instance.steps.get(row)) {
            (Some(previous), Some(step)) => {
                let forward = if step.tag == TAG_RET {
                    neutral_forward
                } else {
                    (previous.dst << RAW_EDGE_SHIFT) | (step.tag << RAW_ADDR_BITS) | step.dst
                };
                let crt = if step.tag == TAG_CAL {
                    (previous.dst << RAW_EDGE_SHIFT) | (ET_CRT << RAW_ADDR_BITS) | step.aux
                } else {
                    neutral_crt
                };
                queries.push(forward);
                queries.push(crt);
            }
            _ => {
                queries.push(neutral_forward);
                queries.push(neutral_crt);
            }
        }
    }
    queries
}

pub(super) fn host_multiplicities(instance: &RawInstance) -> Result<Vec<u64>, String> {
    let table = instance.cfg_table();
    let positions: HashMap<_, _> = table
        .iter()
        .copied()
        .enumerate()
        .map(|(row, key)| (key, row))
        .collect();
    let mut multiplicities = vec![0u64; table.len()];
    for query in query_values(instance) {
        let row = positions
            .get(&query)
            .copied()
            .ok_or_else(|| format!("raw membership query {query:#x} is absent from CFG"))?;
        multiplicities[row] += 1;
    }
    let bits = instance.params.mult_bits()?;
    if let Some((row, count)) = multiplicities
        .iter()
        .copied()
        .enumerate()
        .find(|(_, count)| *count >= (1u64 << bits))
    {
        return Err(format!(
            "raw CFG entry {row} multiplicity {count} exceeds {bits} bits"
        ));
    }
    Ok(multiplicities)
}

pub(super) fn constrain_membership<F, P>(
    composer: &mut StandardComposer<F, P>,
    instance: &RawInstance,
    table: &[Variable],
    steps: &StepWires,
    multiplicities: &[u64],
    h_ep: Variable,
    h_cfg: Variable,
) -> Result<(), Error>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let query_count = instance
        .params
        .membership_query_count()
        .map_err(|_| Error::CircuitInputsNotFound)?;
    let mut queries = Vec::with_capacity(query_count);
    let one = fixed(composer, 1);
    let edge_shift = F::from(2u64).pow([RAW_EDGE_SHIFT as u64]);
    let type_shift = F::from(2u64).pow([RAW_ADDR_BITS as u64]);
    for row in 1..instance.params.ep_cap {
        let neutral_forward = table[(2 * (row - 1)) % table.len()];
        let neutral_crt = table[(2 * (row - 1) + 1) % table.len()];
        let forward = composer.arithmetic_gate(|gate| {
            gate.witness(steps.dst[row - 1], steps.etype[row], None)
                .add(edge_shift, type_shift)
                .fan_in_3(F::one(), steps.dst[row])
        });
        let not_return = sub(composer, one, steps.is_ret[row]);
        let active_forward = mul(composer, steps.active[row], not_return);
        queries.push(composer.conditional_select(active_forward, forward, neutral_forward));

        let crt = composer.arithmetic_gate(|gate| {
            gate.witness(steps.dst[row - 1], steps.aux[row], None)
                .add(edge_shift, F::one())
                .constant(F::from(ET_CRT) * type_shift)
        });
        queries.push(composer.conditional_select(steps.is_call[row], crt, neutral_crt));
    }

    let mult_bits = instance
        .params
        .mult_bits()
        .map_err(|_| Error::CircuitInputsNotFound)?;
    let mut mult_vars = Vec::with_capacity(multiplicities.len());
    let mut bit_vars = Vec::with_capacity(multiplicities.len());
    let mut mult_sum = composer.zero_var();
    for &value in multiplicities {
        let variable = composer.add_input(F::from(value));
        let bits = decompose_bits(composer, variable, value, mult_bits);
        mult_sum = add(composer, mult_sum, variable);
        mult_vars.push(variable);
        bit_vars.push(bits);
    }
    pin(composer, mult_sum, query_count as u64);

    let mut challenge_inputs = with_domain(composer, MEMBERSHIP_DOMAIN_0, &[h_ep, h_cfg]);
    challenge_inputs.extend(mult_vars.iter().copied());
    let challenge_0 = poseidon_chain(composer, &challenge_inputs)?;
    let challenge_1_inputs = with_domain(composer, MEMBERSHIP_DOMAIN_1, &[challenge_0]);
    let challenge_1 = poseidon_chain(composer, &challenge_1_inputs)?;
    for challenge in [challenge_0, challenge_1] {
        constrain_grand_product(composer, table, &queries, &bit_vars, challenge);
    }
    Ok(())
}

fn decompose_bits<F, P>(
    composer: &mut StandardComposer<F, P>,
    variable: Variable,
    value: u64,
    bit_count: usize,
) -> Vec<Variable>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let bits: Vec<_> = (0..bit_count)
        .map(|bit| {
            let variable = composer.add_input(F::from((value >> bit) & 1));
            composer.boolean_gate(variable);
            variable
        })
        .collect();
    let mut packed = composer.zero_var();
    for bit in bits.iter().rev() {
        packed = composer.arithmetic_gate(|gate| {
            gate.witness(packed, *bit, None)
                .add(F::from(2u64), F::one())
        });
    }
    composer.assert_equal(packed, variable);
    bits
}

fn constrain_grand_product<F, P>(
    composer: &mut StandardComposer<F, P>,
    table: &[Variable],
    queries: &[Variable],
    multiplicity_bits: &[Vec<Variable>],
    challenge: Variable,
) where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let one = fixed(composer, 1);
    let mut lhs = one;
    for query in queries {
        let factor = sub(composer, challenge, *query);
        lhs = mul(composer, lhs, factor);
    }

    let mut rhs = one;
    for ((key, bits), _) in table.iter().zip(multiplicity_bits).zip(0..) {
        let mut power = sub(composer, challenge, *key);
        let mut contribution = one;
        for (index, bit) in bits.iter().enumerate() {
            let selected = composer.conditional_select_one(*bit, power);
            contribution = mul(composer, contribution, selected);
            if index + 1 < bits.len() {
                power = mul(composer, power, power);
            }
        }
        rhs = mul(composer, rhs, contribution);
    }
    composer.assert_equal(lhs, rhs);
}
