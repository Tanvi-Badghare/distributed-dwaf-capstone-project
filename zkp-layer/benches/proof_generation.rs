use criterion::{criterion_group, criterion_main, Criterion};
use zkp_layer::{generate_proof, setup_prover};
use ark_bn254::Fr;
use ark_sponge::poseidon::PoseidonConfig;

fn bench_proof_generation(c: &mut Criterion) {
    let poseidon = PoseidonConfig::<Fr>::default();
    let pk = setup_prover(&poseidon).unwrap();

    c.bench_function("proof_generation", |b| {
        b.iter(|| {
            let features = vec![Fr::from(1u64); 41];
            let weights = vec![Fr::from(2u64); 12];

            generate_proof(
                &pk,
                &poseidon,
                features,
                weights,
                true,
                0.85,
            ).unwrap();
        });
    });
}

criterion_group!(benches, bench_proof_generation);
criterion_main!(benches);
