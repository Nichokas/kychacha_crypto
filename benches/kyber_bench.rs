// benches/kyber_bench.rs
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use oqs::kem;
use kychacha_crypto::{decrypt_stream, encrypt_stream, generate_keypair};
use std::io::Cursor;

fn initialize() -> kem::Kem {
    oqs::init();

    #[cfg(feature = "mlkem512")]
    {
        return kem::Kem::new(kem::Algorithm::MlKem512).unwrap();
    }

    #[cfg(feature = "mlkem768")]
    {
        return kem::Kem::new(kem::Algorithm::MlKem768).unwrap();
    }

    #[cfg(feature = "mlkem1024")]
    {
        return kem::Kem::new(kem::Algorithm::MlKem1024).unwrap();
    }

    // Default fallback if no feature is enabled
    panic!("No ML-KEM algorithm feature selected")
}

fn keygen_benchmark(c: &mut Criterion) {
    c.bench_function("mlkem_keypair_generation", |b| {
        b.iter(|| {
            black_box(generate_keypair().unwrap());
        });
    });
}

fn encapsulation_benchmark(c: &mut Criterion) {
    let server_kp = generate_keypair().unwrap();

    c.bench_function("mlkem_encapsulation", |b| {
        b.iter(|| {
            let kem = initialize();
            let (_ct, _ss) = black_box(kem.encapsulate(&server_kp.public_key.key)).unwrap();
        });
    });
}

fn decapsulation_benchmark(c: &mut Criterion) {
    let kem = initialize();
    let server_kp = generate_keypair().unwrap();
    let (ct, _) = kem.encapsulate(&server_kp.public_key.key).unwrap();

    c.bench_function("mlkem_decapsulation", |b| {
        b.iter(|| {
            black_box(kem.decapsulate(&server_kp.private_key.key, &ct).unwrap());
        });
    });
}

fn full_encryption_benchmark(c: &mut Criterion) {
    let server_kp = generate_keypair().unwrap();
    let messages = vec![
        ("short", b"test".to_vec()),
        ("medium", vec![0u8; 1024]),
        ("long", vec![0u8; 4096]),
    ];

    for (name, message) in messages {
        c.bench_function(&format!("full_encryption_{}", name), |b| {
            b.iter_batched(
                || message.clone(),
                |msg| {
                    let mut output = Vec::new();
                    black_box(encrypt_stream(server_kp.public_key.clone(), &mut Cursor::new(&msg), &mut output).unwrap());
                    output
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn full_decryption_benchmark(c: &mut Criterion) {
    let server_kp = generate_keypair().unwrap();

    // Pre-encrypt the messages using the streaming API
    let mut short_encrypted = Vec::new();
    encrypt_stream(server_kp.public_key.clone(), &mut Cursor::new(b"test"), &mut short_encrypted).unwrap();

    let mut medium_encrypted = Vec::new();
    encrypt_stream(server_kp.public_key.clone(), &mut Cursor::new(&vec![0u8; 1024]), &mut medium_encrypted).unwrap();

    let mut long_encrypted = Vec::new();
    encrypt_stream(server_kp.public_key.clone(), &mut Cursor::new(&vec![0u8; 4096]), &mut long_encrypted).unwrap();

    let messages = vec![
        ("short", short_encrypted),
        ("medium", medium_encrypted),
        ("long", long_encrypted),
    ];

    for (name, ciphertext) in messages {
        c.bench_function(&format!("full_decryption_{}", name), |b| {
            b.iter_batched(
                || ciphertext.clone(),
                |ct| {
                    let mut output = Vec::new();
                    black_box(decrypt_stream(&server_kp.private_key, &mut Cursor::new(ct), &mut output).unwrap());
                    output
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
        keygen_benchmark,
        encapsulation_benchmark,
        decapsulation_benchmark,
        full_encryption_benchmark,
        full_decryption_benchmark
}

criterion_main!(benches);
