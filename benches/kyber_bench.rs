// benches/kyber_bench.rs
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use kychacha_crypto::{decrypt, encrypt, generate_keypair};
use libcrux_ml_kem::mlkem768::{self};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn keygen_benchmark(c: &mut Criterion) {
    c.bench_function("mlkem_keypair_generation", |b| {
        b.iter(|| {
            black_box(generate_keypair());
        });
    });
}

fn encapsulation_benchmark(c: &mut Criterion) {
    let server_kp = generate_keypair();

    c.bench_function("mlkem_encapsulation", |b| {
        b.iter(|| {
            let mut rng = ChaCha20Rng::from_os_rng();
            let mut randomness = [0u8; 32];
            rng.fill_bytes(&mut randomness);
            let (_ct, _ss) = black_box(mlkem768::encapsulate(&server_kp.public_key(), randomness));
        });
    });
}

fn decapsulation_benchmark(c: &mut Criterion) {
    let server_kp = generate_keypair();
    let mut rng = ChaCha20Rng::from_os_rng();
    let mut randomness = [0u8; 32];
    rng.fill_bytes(&mut randomness);
    let (ct, _) = mlkem768::encapsulate(&server_kp.public_key(), randomness);

    c.bench_function("mlkem_decapsulation", |b| {
        b.iter(|| {
            black_box(mlkem768::decapsulate(&server_kp.private_key(), &ct));
        });
    });
}

fn full_encryption_benchmark(c: &mut Criterion) {
    let server_kp = generate_keypair();
    let messages = vec![
        ("short", b"test".to_vec()),
        ("medium", vec![0u8; 1024]),
        ("long", vec![0u8; 4096]),
    ];

    for (name, message) in messages {
        c.bench_function(&format!("full_encryption_{}", name), |b| {
            b.iter_batched(
                || message.clone(),
                |msg| black_box(encrypt(&server_kp.public_key(), &msg)),
                BatchSize::SmallInput,
            )
        });
    }
}

fn full_decryption_benchmark(c: &mut Criterion) {
    let server_kp = generate_keypair();
    let messages = vec![
        ("short", encrypt(&server_kp.public_key(), b"test").unwrap()),
        (
            "medium",
            encrypt(&server_kp.public_key(), &vec![0u8; 1024]).unwrap(),
        ),
        (
            "long",
            encrypt(&server_kp.public_key(), &vec![0u8; 4096]).unwrap(),
        ),
    ];

    for (name, ciphertext) in messages {
        c.bench_function(&format!("full_decryption_{}", name), |b| {
            b.iter(|| {
                black_box(decrypt(&ciphertext, &server_kp.private_key()).unwrap());
            })
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(1000);
    targets =
        keygen_benchmark,
        encapsulation_benchmark,
        decapsulation_benchmark,
        full_encryption_benchmark,
        full_decryption_benchmark
}

criterion_main!(benches);