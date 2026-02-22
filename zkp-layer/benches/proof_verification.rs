use criterion::{criterion_group, criterion_main, Criterion};
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds};
use ark_groth16::prepare_verifying_key;
use ark_serialize::CanonicalDeserialize;
use zkp_waf::prover::{setup_prover, generate_proof};
use zkp_waf::verifier::validator_verify_threat;

fn make_poseidon() -> PoseidonConfig<Fr> {
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(255, 2, 8, 31, 0);
    PoseidonConfig::<Fr>::new(8, 31, 17, mds, ark, 2, 1)
}

fn bench_proof_verification(c: &mut Criterion) {
    let poseidon = make_poseidon();
    let pk = setup_prover(poseidon.clone()).expect("setup failed");
    let pvk = prepare_verifying_key(&pk.vk);

    let features: Vec<f64> = vec![0.5; 41];
    let weights: Vec<f64> = vec![0.3; 12];

    let proof_data = generate_proof(
        &features,
        &weights,
        "malicious",
        0.85,
        &pk,
        poseidon.clone(),
    )
    .expect("proof generation failed");

    c.bench_function("proof_verification", |b| {
        b.iter(|| {
            validator_verify_threat(
                &proof_data.proof_bytes,
                &proof_data.public_inputs,
                &pvk,
            )
            .expect("verification failed");
        });
    });
}

criterion_group!(benches, bench_proof_verification);
criterion_main!(benches);