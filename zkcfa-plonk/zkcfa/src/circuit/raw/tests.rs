use super::*;
use crate::raw_format::{
    PathMode, RawEdge, RawOpenings, RawParams, RawStep, ET_CAL, ET_CRT, ET_JMP, TAG_CAL, TAG_JMP,
    TAG_RET,
};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::EdwardsParameters;
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::{sonic_pc::SonicKZG10, PolynomialCommitment};
use ark_serialize::CanonicalSerialize;
use rand_core::OsRng;

type TestCircuit = RawPlonkCircuit<Fr, EdwardsParameters>;
type TestPc = SonicKZG10<Bls12_381, DensePolynomial<Fr>>;

fn circuit(instance: RawInstance) -> TestCircuit {
    let public = RawPublicValues {
        h_ep: instance.h_ep_poseidon::<Fr>().unwrap(),
        h_cfg: instance.h_cfg_poseidon::<Fr>().unwrap(),
        entry: instance.entry(),
        final_node: instance.final_node(),
    };
    TestCircuit::new(instance, public, 1).expect("valid raw fixture")
}

fn fixture() -> TestCircuit {
    circuit(RawInstance {
        params: RawParams {
            edge_cap: 2,
            ep_cap: 2,
            path_mode: PathMode::Complete,
        },
        encoding: RawEncoding::Inline14,
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
            ep: [0x11, 0x22],
            cfg: [0x33, 0x44],
        },
    })
}

fn nested_call_return_fixture() -> TestCircuit {
    // The two outer RET rows (4 and 6) pop the same slot but return to
    // distinct sites. The extra CFG edges make swapping those sites a
    // membership-valid walk, isolating the time-indexed shadow binding.
    let mut edges = vec![
        RawEdge {
            src: 1,
            dst: 2,
            etype: ET_CAL,
        },
        RawEdge {
            src: 1,
            dst: 3,
            etype: ET_CRT,
        },
        RawEdge {
            src: 2,
            dst: 4,
            etype: ET_CAL,
        },
        RawEdge {
            src: 2,
            dst: 5,
            etype: ET_CRT,
        },
        RawEdge {
            src: 3,
            dst: 6,
            etype: ET_CAL,
        },
        RawEdge {
            src: 3,
            dst: 7,
            etype: ET_CRT,
        },
        RawEdge {
            src: 7,
            dst: 8,
            etype: ET_JMP,
        },
        // Decoys used only by the same-depth return-site swap below.
        RawEdge {
            src: 7,
            dst: 6,
            etype: ET_CAL,
        },
        RawEdge {
            src: 7,
            dst: 7,
            etype: ET_CRT,
        },
        RawEdge {
            src: 3,
            dst: 8,
            etype: ET_JMP,
        },
    ];
    edges.sort_by_key(|edge| edge.key());

    circuit(RawInstance {
        params: RawParams {
            edge_cap: 16,
            ep_cap: 8,
            path_mode: PathMode::Complete,
        },
        encoding: RawEncoding::Inline14,
        node_count: 8,
        edges,
        steps: vec![
            RawStep {
                dst: 1,
                tag: TAG_JMP,
                aux: 0,
                hint: 0,
            },
            RawStep {
                dst: 2,
                tag: TAG_CAL,
                aux: 3,
                hint: 0,
            },
            RawStep {
                dst: 4,
                tag: TAG_CAL,
                aux: 5,
                hint: 0,
            },
            RawStep {
                dst: 5,
                tag: TAG_RET,
                aux: 0,
                hint: 2,
            },
            RawStep {
                dst: 3,
                tag: TAG_RET,
                aux: 0,
                hint: 1,
            },
            RawStep {
                dst: 6,
                tag: TAG_CAL,
                aux: 7,
                hint: 0,
            },
            RawStep {
                dst: 7,
                tag: TAG_RET,
                aux: 0,
                hint: 5,
            },
            RawStep {
                dst: 8,
                tag: TAG_JMP,
                aux: 0,
                hint: 0,
            },
        ],
        openings: RawOpenings {
            ep: [0x11, 0x22],
            cfg: [0x33, 0x44],
        },
    })
}

fn longer_linear_fixture() -> TestCircuit {
    circuit(RawInstance {
        params: RawParams {
            edge_cap: 4,
            ep_cap: 4,
            path_mode: PathMode::Complete,
        },
        encoding: RawEncoding::Inline14,
        node_count: 4,
        edges: vec![
            RawEdge {
                src: 1,
                dst: 2,
                etype: ET_JMP,
            },
            RawEdge {
                src: 2,
                dst: 3,
                etype: ET_JMP,
            },
            RawEdge {
                src: 3,
                dst: 4,
                etype: ET_JMP,
            },
        ],
        steps: (1..=4)
            .map(|dst| RawStep {
                dst,
                tag: TAG_JMP,
                aux: 0,
                hint: 0,
            })
            .collect(),
        openings: RawOpenings {
            ep: [0x55, 0x66],
            cfg: [0x77, 0x88],
        },
    })
}

fn check(mut circuit: TestCircuit) {
    let mut composer = StandardComposer::<Fr, EdwardsParameters>::new();
    circuit.gadget(&mut composer).expect("compose raw circuit");
    composer.check_circuit_satisfied();
}

fn assert_rejected(circuit: TestCircuit) {
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(circuit))).is_err(),
        "dishonest raw witness unexpectedly satisfied the circuit"
    );
}

#[test]
fn public_abi_order_is_poseidon_then_endpoints() {
    let values = RawPublicValues {
        h_ep: Fr::from(1u64),
        h_cfg: Fr::from(2u64),
        entry: 3,
        final_node: 4,
    };
    assert_eq!(
        values.ordered(),
        [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64)
        ]
    );
    let _: PhantomData<RawPlonkCircuit<Fr, EdwardsParameters>> = PhantomData;
}

#[test]
fn canonical_shape_and_real_witness_compile_the_same_verifier_key() {
    let mut witness = longer_linear_fixture();
    let params = witness.instance.params;
    let mut shape = TestCircuit::for_shape(params, 1).unwrap();
    let (shape_constraints, shape_bound) = shape.probe_size().unwrap();
    let (witness_constraints, witness_bound) = witness.probe_size().unwrap();
    assert_eq!(shape_constraints, witness_constraints);
    assert_eq!(shape_bound, witness_bound);

    let padded_size = shape_bound.next_power_of_two();
    shape.padded_size = padded_size;
    witness.padded_size = padded_size;
    let parameters = TestPc::setup(padded_size * 2, None, &mut OsRng).unwrap();
    let (_, (shape_key, shape_positions)) = shape.compile::<TestPc>(&parameters).unwrap();
    let (_, (witness_key, witness_positions)) = witness.compile::<TestPc>(&parameters).unwrap();
    assert_eq!(shape_positions, witness_positions);

    let mut shape_bytes = Vec::new();
    let mut witness_bytes = Vec::new();
    shape_key.serialize(&mut shape_bytes).unwrap();
    witness_key.serialize(&mut witness_bytes).unwrap();
    assert_eq!(shape_bytes, witness_bytes);
}

#[test]
fn honest_raw_relation_satisfies_every_gate() {
    check(fixture());
    check(nested_call_return_fixture());
}

#[test]
fn tampered_public_h_ep_is_rejected_by_gates() {
    let mut circuit = fixture();
    circuit.public.h_ep += Fr::from(1u64);
    assert_rejected(circuit);
}

#[test]
fn tampered_public_h_cfg_is_rejected_by_gates() {
    let mut circuit = fixture();
    circuit.public.h_cfg += Fr::from(1u64);
    assert_rejected(circuit);
}

#[test]
fn tampered_public_entry_is_rejected_by_gates() {
    let mut circuit = fixture();
    circuit.public.entry += 1;
    assert_rejected(circuit);
}

#[test]
fn tampered_public_final_is_rejected_by_gates() {
    let mut circuit = fixture();
    circuit.public.final_node += 1;
    assert_rejected(circuit);
}

#[test]
fn tampered_ep_opening_is_rejected_by_gates() {
    let mut circuit = fixture();
    circuit.instance.openings.ep[0] ^= 1;
    assert_rejected(circuit);
}

#[test]
fn tampered_cfg_opening_is_rejected_by_gates() {
    let mut circuit = fixture();
    circuit.instance.openings.cfg[0] ^= 1;
    assert_rejected(circuit);
}

#[test]
fn wrong_return_hint_is_rejected_after_reopening_ep_commitment() {
    let mut circuit = nested_call_return_fixture();
    circuit.instance.steps[3].hint = 1;
    circuit.public.h_ep = circuit.instance.h_ep_poseidon::<Fr>().unwrap();

    assert_eq!(
        circuit.public.h_ep,
        circuit.instance.h_ep_poseidon::<Fr>().unwrap()
    );
    assert!(host_multiplicities(&circuit.instance).is_ok());
    assert_rejected(circuit);
}

#[test]
fn same_depth_return_site_swap_is_rejected_after_reopening_ep_commitment() {
    let mut circuit = nested_call_return_fixture();
    let first_return_site = circuit.instance.steps[4].dst;
    circuit.instance.steps[4].dst = circuit.instance.steps[6].dst;
    circuit.instance.steps[6].dst = first_return_site;
    circuit.public.h_ep = circuit.instance.h_ep_poseidon::<Fr>().unwrap();

    assert_eq!(circuit.instance.entry(), 1);
    assert_eq!(circuit.instance.final_node(), 8);
    assert_eq!(
        circuit.public.h_ep,
        circuit.instance.h_ep_poseidon::<Fr>().unwrap()
    );
    assert!(host_multiplicities(&circuit.instance).is_ok());
    assert_rejected(circuit);
}

#[test]
fn incorrect_binmult_multiplicities_are_rejected() {
    let mut circuit = fixture();
    // Honest counts are [1, 1]. Preserve their sum so this reaches the
    // two challenge grand products instead of failing only cardinality.
    circuit.multiplicity_override = Some(vec![2, 0]);
    assert_rejected(circuit);
}

#[test]
fn inline_binmult_accepts_a_count_above_the_old_twelve_bit_limit() {
    let instance = RawInstance {
        params: RawParams {
            edge_cap: 1,
            ep_cap: 2_049,
            path_mode: PathMode::Complete,
        },
        encoding: RawEncoding::Inline14,
        node_count: 1,
        edges: vec![RawEdge {
            src: 1,
            dst: 1,
            etype: ET_JMP,
        }],
        steps: vec![RawStep {
            dst: 1,
            tag: TAG_JMP,
            aux: 0,
            hint: 0,
        }],
        openings: RawOpenings {
            ep: [0x11, 0x22],
            cfg: [0x33, 0x44],
        },
    };
    instance.validate().expect("valid padded inline relation");
    assert_eq!(instance.params.mult_bits().unwrap(), 13);
    assert_eq!(host_multiplicities(&instance).unwrap(), vec![4_096]);
}
