use halo2_proofs::{
    halo2curves::bn256::G1Affine,
    plonk::{keygen_pk, keygen_vk},
    poly::commitment::ParamsProver,
};
use itertools::Itertools;
use plonk_verifier::{
    loader::native::NativeLoader,
    system::halo2::{compile, transcript::evm::EvmTranscript, Config as PlonkConfig},
    verifier::PlonkVerifier,
};
use prover::{
    aggregation_circuit::{AggregationCircuit, Plonk, PoseidonTranscript, Snark},
    circuit_witness::CircuitWitness,
    circuits::gen_pi_circuit,
    utils::{fixed_rng, gen_num_instance, gen_proof},
    ProverParams,
};
use zkevm_common::prover::CircuitConfig;

fn main() {
    const CIRCUIT_CONFIG: CircuitConfig = CircuitConfig {
        block_gas_limit: 63000,
        max_txs: 3,
        max_calldata: 10500,
        max_bytecode: 24634,
        max_rws: 476052,
        min_k: 20,
        pad_to: 476052,
        min_k_aggregation: 21,
        keccak_padding: 336000,
    };

    let pi_snark = {
        let param = ProverParams::setup(CIRCUIT_CONFIG.min_k as u32, fixed_rng());
        let witness = CircuitWitness::dummy(CIRCUIT_CONFIG).unwrap();
        let circuit = gen_pi_circuit::<
            { CIRCUIT_CONFIG.max_txs },
            { CIRCUIT_CONFIG.max_calldata },
            { CIRCUIT_CONFIG.max_rws },
            _,
        >(&witness, fixed_rng())
        .unwrap();
        let pk = {
            let vk = keygen_vk(&param, &circuit).unwrap();
            keygen_pk(&param, vk, &circuit).unwrap()
        };
        let instance = circuit.instance();
        let proof = gen_proof::<
            _,
            _,
            PoseidonTranscript<NativeLoader, _>,
            PoseidonTranscript<NativeLoader, _>,
            _,
        >(
            &param,
            &pk,
            circuit,
            instance.clone(),
            fixed_rng(),
            false,
            false,
        );
        let protocol = compile(
            &param,
            pk.get_vk(),
            PlonkConfig::kzg().with_num_instance(gen_num_instance(&instance)),
        );
        Snark::new(protocol, instance, proof)
    };

    let accept = {
        let params = ProverParams::setup(CIRCUIT_CONFIG.min_k_aggregation as u32, fixed_rng());
        let circuit = AggregationCircuit::new(&params, [pi_snark], fixed_rng());
        let pk = {
            let vk = keygen_vk(&params, &circuit).unwrap();
            keygen_pk(&params, vk, &circuit).unwrap()
        };
        let instance = circuit.instance();
        let proof = gen_proof::<
            _,
            _,
            EvmTranscript<G1Affine, _, _, _>,
            EvmTranscript<G1Affine, _, _, _>,
            _,
        >(
            &params,
            &pk,
            circuit,
            instance.clone(),
            fixed_rng(),
            false,
            false,
        );
        let protocol = compile(
            &params,
            pk.get_vk(),
            PlonkConfig::kzg()
                .with_accumulator_indices(Some((0..16).map(|row| (0, row)).collect_vec()))
                .with_num_instance(instance.iter().map(|instance| instance.len()).collect()),
        );
        let proof = Plonk::read_proof(
            &params.get_g()[0].into(),
            &protocol,
            &instance,
            &mut EvmTranscript::<G1Affine, NativeLoader, _, _>::new(proof.as_slice()),
        )
        .unwrap();
        Plonk::verify(
            &params.get_g()[0].into(),
            &(params.g2(), params.s_g2()).into(),
            &protocol,
            &instance,
            &proof,
        )
        .unwrap()
    };
    assert!(accept);
}
