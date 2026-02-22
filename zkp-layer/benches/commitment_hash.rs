use criterion::{criterion_group, criterion_main, Criterion};
use ark_bn254::Fr;
use zkp_waf::utils::compute_commitment;

fn bench_commitment(c: &mut Criterion) {
    c.bench_function("commitment_hash_41_features", |b| {
        b.iter(|| {
            let features = vec![Fr::from(1u64); 41];
            compute_commitment(&features)
        });
    });
}

criterion_group!(benches, bench_commitment);
criterion_main!(benches);