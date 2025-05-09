use chacha20poly1305::aead::Aead;
use chacha20poly1305::{aead::AeadCore, ChaCha20Poly1305, KeyInit};
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use chacha20poly1305::aead::rand_core::{RngCore, CryptoRng};
use chacha20poly1305::aead::rand_core::OsRng as ChaChaOsRng;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

fn key_derivation_benchmark(c: &mut Criterion) {
    c.bench_function("chacha_key_derivation", |b| {
        b.iter_batched(
            || {
                let mut key = [0u8; 32];
                let mut rng = ChaCha20Rng::from_os_rng();
                rng.fill(&mut key);
                key
            },
            |key| {
                let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
                black_box(cipher);
            },
            BatchSize::SmallInput,
        )
    });
}

fn encryption_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha_encryption");

    for size in [16, 128, 1024, 4096].iter() {
        group.bench_with_input(format!("encrypt_{}B", size), size, |b, &size| {
            b.iter_batched(
                || {
                    let mut rng = ChaChaOsRng;
                    let key = ChaCha20Poly1305::generate_key(&mut rng);
                    let msg = vec![0u8; size];
                    (key, msg)
                },
                |(key, msg)| {
                    let cipher = ChaCha20Poly1305::new(&key);
                    let mut rng = ChaChaOsRng;
                    let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);
                    cipher.encrypt(&nonce, &*msg).unwrap()
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn decryption_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha_decryption");

    for size in [16, 128, 1024, 4096].iter() {
        group.bench_with_input(format!("decrypt_{}B", size), size, |b, &size| {
            b.iter_batched(
                || {
                    let mut rng = ChaChaOsRng;
                    let key = ChaCha20Poly1305::generate_key(&mut rng);
                    let cipher = ChaCha20Poly1305::new(&key);
                    let mut rng = ChaChaOsRng;
                    let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);
                    let msg = vec![0u8; size];
                    let ct = cipher.encrypt(&nonce, &*msg).unwrap();
                    (key, nonce, ct)
                },
                |(key, nonce, ct)| {
                    let cipher = ChaCha20Poly1305::new(&key);
                    cipher.decrypt(&nonce, &*ct).unwrap()
                },
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(1000);
    targets =
        key_derivation_benchmark,
        encryption_benchmark,
        decryption_benchmark
}

criterion_main!(benches);