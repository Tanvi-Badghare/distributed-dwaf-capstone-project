use criterion::{criterion_group, criterion_main, Criterion};
use zkp_layer::circuits::ml_inference_circuit::MlInferenceCircuit;
use zkp_layer::prover::generate_proof;
use zkp_layer::verifier::verify_proof;

use ark_bls12_381::Bls12_381;
use ark_groth16::{generate_random_parameters, prepare_verifying_key};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::test_rng;

/// Benchmarks ONLY proof verification time.
/// Proof generation is done once before benchmarking.
fn benchmark_proof_verification(c: &mut Criterion) {
    // RNG
    let mut rng = test_rng();

    // ---- Dummy Test Data ----
    let features = vec![1u64, 0u64, 1u64, 0u64];
    let classification = 1u64;

    // ---- Build Circuit Instance ----
    let circuit = MlInferenceCircuit {
        features: features.clone(),
        classification,
    };

    // ---- Setup (trusted setup simulation) ----
    let params =
        generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng)
            .expect("failed to generate parameters");

    let pvk = prepare_verifying_key(&params.vk);

    // ---- Generate Proof Once ----
    let proof =
        generate_proof(circuit, &params, &mut rng)
            .expect("proof generation failed");

    // ---- Public Inputs ----
    let public_inputs = vec![classification.into()];

    // ---- Benchmark Verification ----
    c.bench_function("proof_verification", |b| {
        b.iter(|| {
            let result =
                verify_proof(&pvk, &proof, &public_inputs)
                    .expect("verification failed");

            assert!(result);
        })
    });
}

criterion_group!(benches, benchmark_proof_verification);
criterion_main!(benches);
