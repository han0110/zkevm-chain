#![cfg(feature = "autogen")]

use eth_types::Address;
use eth_types::Bytes;
use eth_types::U256;
use halo2_proofs::halo2curves::bn256::{Fq, Fr, G1Affine};
use halo2_proofs::plonk::keygen_pk;
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::ParamsProver;
use plonk_verifier::loader::evm::EvmLoader;
use plonk_verifier::loader::native::NativeLoader;
use plonk_verifier::{
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::PlonkVerifier,
};
use prover::aggregation_circuit::AggregationCircuit;
use prover::aggregation_circuit::Plonk;
use prover::aggregation_circuit::PoseidonTranscript;
use prover::aggregation_circuit::Snark;
use prover::circuit_witness::CircuitWitness;
use prover::dummy_circuit;
use prover::public_input_circuit;
use prover::super_circuit;
use prover::utils::collect_instance;
use prover::utils::fixed_rng;
use prover::utils::gen_num_instance;
use prover::utils::gen_proof;
use prover::ProverParams;
use std::env::var;
use std::fs;
use std::io::Write;
use std::rc::Rc;
use zkevm_common::prover::*;

#[derive(Clone, Default, Debug, serde::Serialize, serde::Deserialize)]
struct Verifier {
    label: String,
    config: CircuitConfig,
    instance: Vec<U256>,
    proof: Bytes,
    runtime_code: Bytes,
    address: Address,
}

impl Verifier {
    fn build(&mut self) -> &Self {
        let mut tmp = [0; 20];
        let bytes = self.label.as_bytes();
        let x = 20 - bytes.len();
        for (i, v) in bytes.iter().enumerate() {
            tmp[i + x] = *v;
        }
        self.address = Address::from(tmp);

        self
    }
}

fn write_bytes(name: &str, vec: &[u8]) {
    let dir = "./../build/plonk-verifier";
    fs::create_dir_all(dir).unwrap_or_else(|_| panic!("create {}", dir));
    let path = format!("{}/{}", dir, name);
    fs::File::create(&path)
        .unwrap_or_else(|_| panic!("create {}", &path))
        .write_all(vec)
        .unwrap_or_else(|_| panic!("write {}", &path));
}

fn gen_verifier(params: &ProverParams, vk: &VerifyingKey<G1Affine>, config: Config) -> Vec<u8> {
    let num_instance = config.num_instance.clone();
    let svk = params.get_g()[0].into();
    let dk = (params.g2(), params.s_g2()).into();
    let protocol = compile(params, vk, config);

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = Plonk::read_proof(&svk, &protocol, &instances, &mut transcript).unwrap();
    Plonk::verify(&svk, &dk, &protocol, &instances, &proof).unwrap();

    loader.runtime_code()
}

macro_rules! gen_match {
    ($LABEL:expr, $CIRCUIT:ident, $GAS:expr) => {{
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .try_init();

        prover::match_circuit_params!(
            $GAS,
            {
                let snark = {
                    let witness = CircuitWitness::dummy(CIRCUIT_CONFIG).unwrap();
                    let circuit = $CIRCUIT::gen_circuit::<
                        { CIRCUIT_CONFIG.max_txs },
                        { CIRCUIT_CONFIG.max_calldata },
                        { CIRCUIT_CONFIG.max_rws },
                        _,
                    >(&witness, fixed_rng())
                    .expect("gen_static_circuit");
                    let instance = circuit.instance();

                    let params = ProverParams::setup(CIRCUIT_CONFIG.min_k as u32, fixed_rng());
                    let vk = keygen_vk(&params, &circuit).expect("vk");
                    let pk = keygen_pk(&params, vk, &circuit).expect("pk");

                    {
                        let mut data = Verifier::default();
                        data.label = format!("{}-{}", $LABEL, CIRCUIT_CONFIG.block_gas_limit);
                        data.config = CIRCUIT_CONFIG;
                        data.runtime_code = gen_verifier(
                            &params,
                            &pk.get_vk(),
                            Config::kzg().with_num_instance(gen_num_instance(&circuit.instance())),
                        )
                        .into();

                        if var("ONLY_EVM").is_ok() {
                            log::info!("returning early");
                            let data = data.build();
                            write_bytes(&data.label, &serde_json::to_vec(data).unwrap());
                            return;
                        }

                        if log::log_enabled!(log::Level::Debug) {
                            let proof = gen_proof::<
                                _,
                                _,
                                EvmTranscript<G1Affine, _, _, _>,
                                EvmTranscript<G1Affine, _, _, _>,
                                _,
                            >(
                                &params,
                                &pk,
                                circuit.clone(),
                                circuit.instance(),
                                fixed_rng(),
                                true,
                            );
                            data.instance = collect_instance(&circuit.instance());
                            data.proof = proof.into();
                        }

                        let data = data.build();
                        write_bytes(&data.label, &serde_json::to_vec(data).unwrap());
                    }

                    let proof = gen_proof::<
                        _,
                        _,
                        PoseidonTranscript<NativeLoader, _>,
                        PoseidonTranscript<NativeLoader, _>,
                        _,
                    >(
                        &params, &pk, circuit, instance.clone(), fixed_rng(), true
                    );

                    let protocol = compile(
                        &params,
                        pk.get_vk(),
                        Config::kzg().with_num_instance(gen_num_instance(&instance)),
                    );

                    Snark::new(protocol, instance, proof)
                };

                let agg_params =
                    ProverParams::setup(CIRCUIT_CONFIG.min_k_aggregation as u32, fixed_rng());
                let agg_circuit = AggregationCircuit::new(&agg_params, [snark], fixed_rng());
                let agg_vk = keygen_vk(&agg_params, &agg_circuit).expect("vk");

                let mut data = Verifier::default();
                data.label = format!("{}-{}-a", $LABEL, CIRCUIT_CONFIG.block_gas_limit);
                data.config = CIRCUIT_CONFIG;
                data.runtime_code = gen_verifier(
                    &agg_params,
                    &agg_vk,
                    Config::kzg()
                        .with_num_instance(AggregationCircuit::num_instance())
                        .with_accumulator_indices(Some(AggregationCircuit::accumulator_indices())),
                )
                .into();

                if log::log_enabled!(log::Level::Debug) {
                    let agg_pk = keygen_pk(&agg_params, agg_vk, &agg_circuit).expect("pk");
                    let proof = gen_proof::<
                        _,
                        _,
                        EvmTranscript<G1Affine, _, _, _>,
                        EvmTranscript<G1Affine, _, _, _>,
                        _,
                    >(
                        &agg_params,
                        &agg_pk,
                        agg_circuit.clone(),
                        agg_circuit.instance(),
                        fixed_rng(),
                        true,
                    );
                    data.instance = collect_instance(&agg_circuit.instance());
                    data.proof = proof.into();
                }

                let data = data.build();
                write_bytes(&data.label, &serde_json::to_vec(data).unwrap());
            },
            {
                panic!("no circuit parameters found");
            }
        );
    }};
}

// wrapper
macro_rules! gen {
    ($LABEL:expr, $CIRCUIT:ident, $GAS:expr) => {{
        fn func() {
            gen_match!($LABEL, $CIRCUIT, $GAS);
        }
        func();
    }};
}

macro_rules! for_each {
    ($LABEL:expr, $CIRCUIT:ident) => {{
        gen!($LABEL, $CIRCUIT, 63_000);
        gen!($LABEL, $CIRCUIT, 150_000);
        gen!($LABEL, $CIRCUIT, 300_000);
    }};
}

#[test]
fn autogen_verifier_super() {
    for_each!("super", super_circuit);
}

#[test]
fn autogen_verifier_pi() {
    for_each!("pi", public_input_circuit);
}

#[test]
fn autogen_verifier_dummy() {
    for_each!("dummy", dummy_circuit);
}
