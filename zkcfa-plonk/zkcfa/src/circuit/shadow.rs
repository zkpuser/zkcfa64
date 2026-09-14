//! Capacity-sized CF2 shadow-stack relation.
//!
//! A CALL contributes `(slot, call-row, return-site)` and a RET contributes
//! `(slot, matching-call-row, destination)` to a masked grand product. Equality of the products,
//! the depth recurrence, and the ordered matching hint enforce balanced LIFO returns.

use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::constraint_system::{StandardComposer, Variable};
use plonk_core::error::Error;
use plonk_hashing::poseidon::{
    constants::PoseidonConstants,
    zprize_constraints::{PlonkSpecZZ, PoseidonZZRef},
};

const FS_WIDTH: usize = 3;

/// Capacity-sized raw24 shadow relation. `slot_bits` and `hint_bits` are
/// circuit parameters authenticated through the raw statement and headers.
#[allow(clippy::too_many_arguments)]
pub(crate) fn enforce_cf2_shadow_stack<F, P>(
    composer: &mut StandardComposer<F, P>,
    ep_dst_vars: &[Variable],
    is_call_vars: &[Variable],
    is_ret_vars: &[Variable],
    aux_vars: &[Variable],
    hint_vars: &[Variable],
    ep_hash_var: Variable,
    cfg_hash_var: Variable,
    slot_bits: usize,
    hint_bits: usize,
) -> Result<(), Error>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let n = ep_dst_vars.len();
    let one = F::one();
    let zero_var = composer.zero_var();

    // Bind the multiset challenges to both signed artifact commitments.
    let pc = PoseidonConstants::<F>::generate::<FS_WIDTH>();
    let chi = {
        let mut h = PoseidonZZRef::<_, PlonkSpecZZ<F>, FS_WIDTH>::new(composer, pc.clone());
        // This fork's constructor allocates the Poseidon capacity tag as a free input. Replace
        // it with a circuit-description constant before emitting any permutation round.
        h.elements[0] = composer.add_witness_to_circuit_description(pc.domain_tag);
        h.input(ep_hash_var)
            .map_err(|_| Error::CircuitInputsNotFound)?;
        h.input(cfg_hash_var)
            .map_err(|_| Error::CircuitInputsNotFound)?;
        h.output_hash(composer)
    };
    let gam = {
        let mut h = PoseidonZZRef::<_, PlonkSpecZZ<F>, FS_WIDTH>::new(composer, pc);
        h.elements[0] = composer.add_witness_to_circuit_description(F::from(3u64));
        h.input(chi).map_err(|_| Error::CircuitInputsNotFound)?;
        h.input(ep_hash_var)
            .map_err(|_| Error::CircuitInputsNotFound)?;
        h.output_hash(composer)
    };
    let gam2 = composer.arithmetic_gate(|g| g.witness(gam, gam, None).mul(one));

    // Pin both grand-product accumulators to one.
    let mut acc_p = composer.add_witness_to_circuit_description(one);
    let mut acc_q = composer.add_witness_to_circuit_description(one);
    let mut depth = zero_var;

    for t in 0..n {
        let is_call = is_call_vars[t];
        let is_ret = is_ret_vars[t];

        // A RET consumes the current top slot; a CALL then grows the depth for the next row.
        let slot = composer.arithmetic_gate(|g| g.witness(depth, is_ret, None).add(one, -one));
        depth = composer.arithmetic_gate(|g| g.witness(slot, is_call, None).add(one, one));
        composer.range_gate(slot, slot_bits);

        let slot_term = composer.arithmetic_gate(|g| g.witness(gam2, slot, None).mul(one));

        // A matching CALL row must strictly precede its RET row.
        if t >= 1 {
            let ordered_hint = composer.arithmetic_gate(|g| {
                g.witness(hint_vars[t], zero_var, None)
                    .add(-one, F::zero())
                    .constant(F::from((t - 1) as u64))
            });
            composer.range_gate(ordered_hint, hint_bits);
        }

        let call_token = composer.arithmetic_gate(|g| {
            g.witness(slot_term, gam, None)
                .add(one, F::from(t as u64))
                .fan_in_3(one, aux_vars[t])
        });
        let call_factor =
            composer.arithmetic_gate(|g| g.witness(chi, call_token, None).add(one, -one));
        let return_token = composer.arithmetic_gate(|g| {
            g.witness(gam, hint_vars[t], None)
                .mul(one)
                .fan_in_3(one, ep_dst_vars[t])
        });
        let return_factor = composer.arithmetic_gate(|g| {
            g.witness(chi, return_token, None)
                .add(one, -one)
                .fan_in_3(-one, slot_term)
        });

        // Non-CALL and non-RET rows contribute the multiplicative identity.
        let f_p = composer.conditional_select_one(is_call, call_factor);
        let f_q = composer.conditional_select_one(is_ret, return_factor);
        acc_p = composer.arithmetic_gate(|g| g.witness(acc_p, f_p, None).mul(one));
        acc_q = composer.arithmetic_gate(|g| g.witness(acc_q, f_q, None).mul(one));
    }

    composer.assert_equal(depth, zero_var);
    composer.assert_equal(acc_p, acc_q);
    Ok(())
}
