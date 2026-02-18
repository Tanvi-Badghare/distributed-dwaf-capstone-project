use criterion::{criterion_group, criterion_main, Criterion};
use ark_bn254::Fr;
use ark_sponge::poseidon::PoseidonConfig;
use zkp_layer::utils::compute_commitment;

fn bench_commitment(c: &mut Criterion) {
    let poseidon = PoseidonConfig::<Fr>::default();

    c.bench_function("poseidon_commitment_41_features", |b| {
        b.iter(|| {
            let features = vec![Fr::from(1u64); 41];
            compute_commitment(&poseidon, &features).unwrap();
        });
    });
}

criterion_group!(benches, bench_commitment);
criterion_main!(benches);
