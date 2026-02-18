use criterion::{criterion_group, criterion_main, Criterion};
use zkp_layer::{
    generate_proof,
    setup_prover,
    validator_verify_threat,
};
use ark_bn254::Fr;
use ark_sponge::poseidon::PoseidonConfig;

fn bench_proof_verification(c: &mut Criterion) {
    let poseidon = PoseidonConfig::<Fr>::default();
    let pk = setup_prover(&poseidon).unwrap();

    let features = vec![Fr::from(1u64); 41];
    let weights = vec![Fr::from(2u64); 12];

    let proof_data = generate_proof(
        &pk,
        &poseidon,
        features,
        weights,
        true,
        0.85,
    ).unwrap();

    c.bench_function("proof_verification", |b| {
        b.iter(|| {
            validator_verify_threat(
                &proof_data.proof,
                &proof_data.public_inputs,
            ).unwrap();
        });
    });
}

criterion_group!(benches, bench_proof_verification);
criterion_main!(benches);
