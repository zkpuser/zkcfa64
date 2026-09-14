//! PLONK relation for the signed raw24 provider handoff.
//!
//! The circuit opens the two authority/device-signed Poseidon commitments used by
//! the PLONK provider format. CFG membership uses the same full 50-bit edge keys and a
//! multiplicity grand product; the CFG table remains a private witness rather
//! than being compiled into the proving key.

use std::marker::PhantomData;

use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use plonk_core::{
    circuit::Circuit,
    constraint_system::{StandardComposer, Variable},
    error::Error,
};

use crate::{
    poseidon::{CFG_DOMAIN, EP_DOMAIN},
    raw_format::{
        RawEdge, RawEncoding, RawInstance, RawOpenings, RawParams, RawStep, ET_JMP, MAGIC_RAW_CFG,
        PAD_KEY, RAW_ADDR_BITS, RAW_CFG_HEADER_WORDS, RAW_EP_HEADER_WORDS, TAG_JMP,
    },
};

use super::shadow::enforce_cf2_shadow_stack;

mod commitment;
mod membership;

use commitment::{poseidon_chain, poseidon_commitment_words, with_domain};
use membership::{constrain_membership, host_multiplicities};

const RAW_EDGE_SHIFT: u32 = RAW_ADDR_BITS + 2;
const RAW_HINT_SHIFT: u32 = 2 + 2 * RAW_ADDR_BITS;

/// PLONK public ABI: H_ep, H_cfg, entry, final.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RawPublicValues<F: PrimeField> {
    pub(crate) h_ep: F,
    pub(crate) h_cfg: F,
    pub(crate) entry: u64,
    pub(crate) final_node: u64,
}

impl<F: PrimeField> RawPublicValues<F> {
    pub(crate) fn ordered(self) -> [F; 4] {
        [
            self.h_ep,
            self.h_cfg,
            F::from(self.entry),
            F::from(self.final_node),
        ]
    }
}

/// One reusable-capacity PLONK circuit.  No selector depends on an active row
/// count, a table key, or any other private value.
#[derive(Clone, Debug)]
pub(crate) struct RawPlonkCircuit<F, P>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    instance: RawInstance,
    public: RawPublicValues<F>,
    padded_size: usize,
    #[cfg(test)]
    multiplicity_override: Option<Vec<u64>>,
    _field: PhantomData<(F, P)>,
}

impl<F, P> RawPlonkCircuit<F, P>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    pub(crate) fn new(
        instance: RawInstance,
        public: RawPublicValues<F>,
        padded_size: usize,
    ) -> Result<Self, String> {
        instance.validate()?;
        if instance.h_ep_poseidon::<F>()? != public.h_ep {
            return Err("raw EP opening does not match signed H_ep".to_owned());
        }
        if instance.h_cfg_poseidon::<F>()? != public.h_cfg {
            return Err("raw CFG opening does not match signed H_cfg".to_owned());
        }
        if instance.entry() != public.entry || instance.final_node() != public.final_node {
            return Err("raw path endpoints do not match the signed endpoint pair".to_owned());
        }
        host_multiplicities(&instance)?;
        Ok(Self {
            instance,
            public,
            padded_size: padded_size.max(1),
            #[cfg(test)]
            multiplicity_override: None,
            _field: PhantomData,
        })
    }

    /// Construct a canonical valid witness used only to compile the capacity-selected relation.
    /// Its values are irrelevant to preprocessing: for fixed signed parameters, every loop count,
    /// selector and permutation wire is witness-independent.
    pub(crate) fn for_shape(params: RawParams, padded_size: usize) -> Result<Self, String> {
        let instance = RawInstance {
            params,
            encoding: params.encoding()?,
            node_count: 2,
            edges: vec![RawEdge {
                src: 1,
                dst: 2,
                etype: ET_JMP,
            }],
            steps: vec![
                RawStep {
                    dst: 1,
                    tag: TAG_JMP,
                    aux: 0,
                    hint: 0,
                },
                RawStep {
                    dst: 2,
                    tag: TAG_JMP,
                    aux: 0,
                    hint: 0,
                },
            ],
            openings: RawOpenings {
                ep: [1, 0],
                cfg: [2, 0],
            },
        };
        let public = RawPublicValues {
            h_ep: instance.h_ep_poseidon::<F>()?,
            h_cfg: instance.h_cfg_poseidon::<F>()?,
            entry: instance.entry(),
            final_node: instance.final_node(),
        };
        Self::new(instance, public, padded_size)
    }

    /// Compose once to select the smallest safe power-of-two circuit domain.
    pub(crate) fn probe_size(&mut self) -> Result<(usize, usize), Error> {
        let mut composer = StandardComposer::<F, P>::new();
        self.gadget(&mut composer)?;
        let constraints = composer.total_size();
        let bound = composer.circuit_bound();
        composer.check_circuit_satisfied();
        Ok((constraints, bound))
    }

    fn multiplicities(&self) -> Result<Vec<u64>, Error> {
        let honest =
            host_multiplicities(&self.instance).map_err(|_| Error::CircuitInputsNotFound)?;
        #[cfg(test)]
        if let Some(values) = &self.multiplicity_override {
            return Ok(values.clone());
        }
        Ok(honest)
    }
}

impl<F, P> Circuit<F, P> for RawPlonkCircuit<F, P>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    const CIRCUIT_ID: [u8; 32] = *b"zkcfa.raw24.poseidon.plonk.cf2gp";

    fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
        let cfg_words = self.instance.cfg_words();
        let ep_words = self.instance.ep_words();
        let cfg_vars = add_words(composer, &cfg_words);
        let ep_vars = add_words(composer, &ep_words);

        constrain_headers(composer, &self.instance, &cfg_vars, &ep_vars);
        constrain_openings(composer, &cfg_vars, &ep_vars);

        let h_ep_var = poseidon_commitment_words(composer, EP_DOMAIN, &ep_vars)?;
        let h_cfg_var = poseidon_commitment_words(composer, CFG_DOMAIN, &cfg_vars)?;

        let table_vars = &cfg_vars[RAW_CFG_HEADER_WORDS..];
        constrain_cfg_prefix(composer, &self.instance, &cfg_vars, table_vars);

        let step_wires = constrain_execution_path(composer, &self.instance, &ep_vars);
        let multiplicities = self.multiplicities()?;
        constrain_membership(
            composer,
            &self.instance,
            table_vars,
            &step_wires,
            &multiplicities,
            h_ep_var,
            h_cfg_var,
        )?;

        let ep_seed_inputs = with_domain(composer, EP_DOMAIN, &[h_ep_var]);
        let ep_seed = poseidon_chain(composer, &ep_seed_inputs)?;
        let cfg_seed_inputs = with_domain(composer, CFG_DOMAIN, &[h_cfg_var]);
        let cfg_seed = poseidon_chain(composer, &cfg_seed_inputs)?;
        let shadow_slot_bits = self
            .instance
            .params
            .shadow_slot_bits()
            .map_err(|_| Error::CircuitInputsNotFound)?;
        enforce_cf2_shadow_stack(
            composer,
            &step_wires.dst,
            &step_wires.is_call,
            &step_wires.is_ret,
            &step_wires.aux,
            &step_wires.hint,
            ep_seed,
            cfg_seed,
            shadow_slot_bits,
            self.instance.encoding.hint_bits() as usize,
        )?;

        expose_public_inputs(
            composer,
            h_ep_var,
            h_cfg_var,
            step_wires.entry,
            step_wires.final_node,
            self.public,
        );
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        self.padded_size
    }
}

struct StepWires {
    dst: Vec<Variable>,
    aux: Vec<Variable>,
    hint: Vec<Variable>,
    etype: Vec<Variable>,
    is_call: Vec<Variable>,
    is_ret: Vec<Variable>,
    active: Vec<Variable>,
    entry: Variable,
    final_node: Variable,
}

struct TagWires {
    is_call: Vec<Variable>,
    is_ret: Vec<Variable>,
    etype: Vec<Variable>,
}

/// Exact two-bit tag decode. Active tag 3 is rejected separately; inactive
/// rows are the all-zero encoding.
fn decode_tags<F, P>(
    composer: &mut StandardComposer<F, P>,
    values: &[u64],
    variables: &[Variable],
) -> TagWires
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let one = F::one();
    let two = F::from(2u64);
    let three = F::from(3u64);
    let mut result = TagWires {
        is_call: Vec::with_capacity(variables.len()),
        is_ret: Vec::with_capacity(variables.len()),
        etype: Vec::with_capacity(variables.len()),
    };
    for (&value, &tag) in values.iter().zip(variables) {
        let low = composer.add_input(F::from(value & 1));
        let high = composer.add_input(F::from((value >> 1) & 1));
        composer.boolean_gate(low);
        composer.boolean_gate(high);
        composer.arithmetic_gate(|gate| gate.witness(high, low, Some(tag)).add(two, one));
        let is_call = composer
            .arithmetic_gate(|gate| gate.witness(high, low, None).mul(-one).add(F::zero(), one));
        let is_ret = composer
            .arithmetic_gate(|gate| gate.witness(high, low, None).mul(-one).add(one, F::zero()));
        let is_reserved = composer.arithmetic_gate(|gate| gate.witness(high, low, None).mul(one));
        let etype =
            composer.arithmetic_gate(|gate| gate.witness(tag, is_reserved, None).add(one, -three));
        result.is_call.push(is_call);
        result.is_ret.push(is_ret);
        result.etype.push(etype);
    }
    result
}

fn add_words<F, P>(composer: &mut StandardComposer<F, P>, words: &[u64]) -> Vec<Variable>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    words
        .iter()
        .map(|word| composer.add_input(F::from(*word)))
        .collect()
}

fn pin<F, P>(composer: &mut StandardComposer<F, P>, variable: Variable, value: u64)
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    composer.constrain_to_constant(variable, F::from(value), None);
}

fn fixed<F, P>(composer: &mut StandardComposer<F, P>, value: u64) -> Variable
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    composer.add_witness_to_circuit_description(F::from(value))
}

fn add<F, P>(composer: &mut StandardComposer<F, P>, left: Variable, right: Variable) -> Variable
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    composer.arithmetic_gate(|gate| gate.witness(left, right, None).add(F::one(), F::one()))
}

fn sub<F, P>(composer: &mut StandardComposer<F, P>, left: Variable, right: Variable) -> Variable
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    composer.arithmetic_gate(|gate| gate.witness(left, right, None).add(F::one(), -F::one()))
}

fn mul<F, P>(composer: &mut StandardComposer<F, P>, left: Variable, right: Variable) -> Variable
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    composer.arithmetic_gate(|gate| gate.witness(left, right, None).mul(F::one()))
}

fn assert_zero<F, P>(composer: &mut StandardComposer<F, P>, variable: Variable)
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    composer.assert_equal(variable, composer.zero_var());
}

fn constrain_headers<F, P>(
    composer: &mut StandardComposer<F, P>,
    instance: &RawInstance,
    cfg: &[Variable],
    ep: &[Variable],
) where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    pin(composer, cfg[0], MAGIC_RAW_CFG);
    pin(composer, cfg[1], instance.params.edge_cap as u64);
    pin(composer, cfg[3], RAW_ADDR_BITS as u64);
    for variable in &cfg[4..8] {
        pin(composer, *variable, 0);
    }

    pin(composer, ep[0], instance.encoding.magic());
    pin(composer, ep[1], instance.params.ep_cap as u64);
    pin(composer, ep[3], RAW_ADDR_BITS as u64);
    pin(
        composer,
        ep[6],
        if instance.encoding == RawEncoding::Shared24 {
            instance.encoding.hint_bits() as u64
        } else {
            0
        },
    );
    pin(composer, ep[7], instance.params.path_mode.header_word());
    pin(composer, ep[8], 0);
    pin(composer, ep[9], 0);
}

fn constrain_openings<F, P>(
    composer: &mut StandardComposer<F, P>,
    cfg: &[Variable],
    ep: &[Variable],
) where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    // These are the only raw-buffer words not already fixed or reconstructed from narrower
    // canonical limbs. Their 64-bit ranges are load-bearing for injective 3x-u64 packing.
    for variable in [ep[4], ep[5], cfg[8], cfg[9]] {
        composer.range_gate(variable, 64);
    }
    let ep_lo_zero = composer.is_zero_with_output(ep[4]);
    let ep_hi_zero = composer.is_zero_with_output(ep[5]);
    let cfg_lo_zero = composer.is_zero_with_output(cfg[8]);
    let cfg_hi_zero = composer.is_zero_with_output(cfg[9]);
    let ep_both_zero = mul(composer, ep_lo_zero, ep_hi_zero);
    let cfg_both_zero = mul(composer, cfg_lo_zero, cfg_hi_zero);
    assert_zero(composer, ep_both_zero);
    assert_zero(composer, cfg_both_zero);

    let lo_difference = sub(composer, ep[4], cfg[8]);
    let hi_difference = sub(composer, ep[5], cfg[9]);
    let lo_equal = composer.is_zero_with_output(lo_difference);
    let hi_equal = composer.is_zero_with_output(hi_difference);
    let openings_equal = mul(composer, lo_equal, hi_equal);
    assert_zero(composer, openings_equal);
}

fn boolean_prefix<F, P>(
    composer: &mut StandardComposer<F, P>,
    values: impl Iterator<Item = bool>,
    count_var: Variable,
) -> Vec<Variable>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let bits: Vec<_> = values
        .map(|value| {
            let variable = composer.add_input(F::from(value as u64));
            composer.boolean_gate(variable);
            variable
        })
        .collect();
    pin(composer, bits[0], 1);
    let one = fixed(composer, 1);
    for pair in bits.windows(2) {
        let prior_zero = sub(composer, one, pair[0]);
        let forbidden_rise = mul(composer, pair[1], prior_zero);
        assert_zero(composer, forbidden_rise);
    }
    let mut sum = composer.zero_var();
    for bit in &bits {
        sum = add(composer, sum, *bit);
    }
    composer.assert_equal(sum, count_var);
    bits
}

fn constrain_cfg_prefix<F, P>(
    composer: &mut StandardComposer<F, P>,
    instance: &RawInstance,
    cfg: &[Variable],
    table: &[Variable],
) where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let live = boolean_prefix(
        composer,
        (0..instance.params.edge_cap).map(|row| row < instance.edges.len()),
        cfg[2],
    );
    for (row, (&table_word, &is_live)) in table.iter().zip(&live).enumerate() {
        let real_key = mul(composer, is_live, table_word);
        composer.range_gate(real_key, 50);
        let is_zero = composer.is_zero_with_output(real_key);
        let live_zero = mul(composer, is_live, is_zero);
        assert_zero(composer, live_zero);

        let padding = fixed(composer, PAD_KEY | row as u64);
        let canonical = composer.conditional_select(is_live, real_key, padding);
        composer.assert_equal(canonical, table_word);
    }
}

fn constrain_execution_path<F, P>(
    composer: &mut StandardComposer<F, P>,
    instance: &RawInstance,
    ep_words: &[Variable],
) -> StepWires
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let cap = instance.params.ep_cap;
    let mut dst_values = vec![0u64; cap];
    let mut tag_values = vec![0u64; cap];
    let mut aux_values = vec![0u64; cap];
    let mut hint_values = vec![0u64; cap];
    for (row, step) in instance.steps.iter().enumerate() {
        dst_values[row] = step.dst;
        tag_values[row] = step.tag;
        aux_values[row] = step.aux;
        hint_values[row] = step.hint as u64;
    }
    let dst = add_words(composer, &dst_values);
    let tag = add_words(composer, &tag_values);
    let aux = add_words(composer, &aux_values);
    let hint = add_words(composer, &hint_values);
    let active = boolean_prefix(
        composer,
        (0..cap).map(|row| row < instance.steps.len()),
        ep_words[2],
    );
    let decoded = decode_tags(composer, &tag_values, &tag);
    let one = fixed(composer, 1);
    let two_to_26 = F::from(2u64).pow([RAW_EDGE_SHIFT as u64]);
    let two_to_50 = F::from(2u64).pow([RAW_HINT_SHIFT as u64]);

    for row in 0..cap {
        composer.range_gate(dst[row], RAW_ADDR_BITS as usize);
        composer.range_gate(aux[row], RAW_ADDR_BITS as usize);
        composer.range_gate(hint[row], instance.encoding.hint_bits() as usize);

        let inactive = sub(composer, one, active[row]);
        let inactive_word = mul(composer, inactive, ep_words[RAW_EP_HEADER_WORDS + row]);
        assert_zero(composer, inactive_word);

        let dst_zero = composer.is_zero_with_output(dst[row]);
        let active_zero_dst = mul(composer, active[row], dst_zero);
        assert_zero(composer, active_zero_dst);

        let reserved = composer.arithmetic_gate(|gate| {
            gate.witness(tag[row], decoded.is_call[row], None)
                .add(F::one(), -F::one())
                .fan_in_3(-F::from(2u64), decoded.is_ret[row])
        });
        let active_reserved = mul(composer, active[row], reserved);
        assert_zero(composer, active_reserved);

        let call_aux = mul(composer, decoded.is_call[row], aux[row]);
        composer.assert_equal(call_aux, aux[row]);
        let ret_hint = mul(composer, decoded.is_ret[row], hint[row]);
        composer.assert_equal(ret_hint, hint[row]);

        let packed = match instance.encoding {
            RawEncoding::Inline14 => {
                let low = composer.arithmetic_gate(|gate| {
                    gate.witness(tag[row], dst[row], None)
                        .add(F::one(), F::from(4u64))
                        .fan_in_3(two_to_26, aux[row])
                });
                composer.arithmetic_gate(|gate| {
                    gate.witness(low, hint[row], None).add(F::one(), two_to_50)
                })
            }
            RawEncoding::Shared24 => {
                let payload = add(composer, aux[row], hint[row]);
                composer.arithmetic_gate(|gate| {
                    gate.witness(tag[row], dst[row], None)
                        .add(F::one(), F::from(4u64))
                        .fan_in_3(two_to_26, payload)
                })
            }
        };
        composer.assert_equal(packed, ep_words[RAW_EP_HEADER_WORDS + row]);
    }
    pin(composer, tag[0], 0);

    let mut final_node = composer.zero_var();
    for row in 0..cap {
        let next = active.get(row + 1).copied().unwrap_or(composer.zero_var());
        let is_final = sub(composer, active[row], next);
        let selected = mul(composer, is_final, dst[row]);
        final_node = add(composer, final_node, selected);
    }

    let entry = dst[0];
    StepWires {
        dst,
        aux,
        hint,
        etype: decoded.etype,
        is_call: decoded.is_call,
        is_ret: decoded.is_ret,
        active,
        entry,
        final_node,
    }
}

fn expose_public_inputs<F, P>(
    composer: &mut StandardComposer<F, P>,
    h_ep: Variable,
    h_cfg: Variable,
    entry: Variable,
    final_node: Variable,
    public: RawPublicValues<F>,
) where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    let variables = [h_ep, h_cfg, entry, final_node];
    for (variable, value) in variables.into_iter().zip(public.ordered()) {
        composer.constrain_to_constant(variable, F::zero(), Some(-value));
    }
}

#[cfg(test)]
mod tests;
