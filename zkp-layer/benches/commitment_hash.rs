use criterion::{criterion_group, criterion_main, Criterion};
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds};
use zkp_waf::utils::compute_commitment;

fn make_poseidon() -> PoseidonConfig<Fr> {
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(255, 2, 8, 31, 0);
    PoseidonConfig::<Fr>::new(8, 31, 17, mds, ark, 2, 1)
}

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