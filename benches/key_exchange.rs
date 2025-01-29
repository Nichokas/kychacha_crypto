use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve_msg::{derive_chacha_key, derive_shared_secret, generate_keypair};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

pub fn generate_ephemeral_keypair_bench(c: &mut Criterion) {
    c.bench_function("generate_ephemeral_keypair", |b| {
        b.iter(|| {
            black_box(generate_keypair());
        })
    });
}

use criterion::BatchSize;

pub fn derive_shared_secret_bench(c: &mut Criterion) {
    let test_secret = StaticSecret::random();
    let test_public = PublicKey::from(&test_secret);

    c.bench_function("derive_shared_secret", |b| {
        b.iter_batched(
            || EphemeralSecret::random(), // Setup
            |ephemeral_secret| {
                black_box(derive_shared_secret(ephemeral_secret, &test_public));
            },
            BatchSize::SmallInput,
        )
    });
}

pub fn derive_chacha_key_bench(c: &mut Criterion) {
    c.bench_function("derive_chacha_key", |b| {
        b.iter_batched(
            || {
                let test_secret = EphemeralSecret::random();
                PublicKey::from(&test_secret);

                let static_secret = StaticSecret::random();
                let static_public = PublicKey::from(&static_secret);
                derive_shared_secret(test_secret, &static_public)
            }, // Setup
            |shared_secret| {
                black_box(derive_chacha_key(shared_secret,None));
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, generate_ephemeral_keypair_bench,derive_chacha_key_bench);
criterion_main!(benches);