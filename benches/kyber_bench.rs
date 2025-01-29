// benches/kyber_bench.rs
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use curve_msg::{decrypt, encrypt, generate_keypair};

fn keygen_benchmark(c: &mut Criterion) {
    c.bench_function("kyber_keypair_generation", |b| {
        b.iter(|| {
            black_box(generate_keypair().unwrap());
        });
    });
}

fn encapsulation_benchmark(c: &mut Criterion) {
    let server_kp = generate_keypair().unwrap();

    c.bench_function("kyber_encapsulation", |b| {
        b.iter(|| {
            let (ct, _ss) = kyberlib::encapsulate(&server_kp.public, &mut rand::thread_rng()).unwrap();
            black_box(ct);
        });
    });
}

fn decapsulation_benchmark(c: &mut Criterion) {
    let server_kp = generate_keypair().unwrap();
    let (ct, _) = kyberlib::encapsulate(&server_kp.public, &mut rand::thread_rng()).unwrap();

    c.bench_function("kyber_decapsulation", |b| {
        b.iter(|| {
            let ss = kyberlib::decapsulate(&ct, &server_kp.secret).unwrap();
            black_box(ss);
        });
    });
}

fn full_encryption_benchmark(c: &mut Criterion) {
    let server_kp = generate_keypair().unwrap();
    let messages = vec![
        ("short", b"test".to_vec()),
        ("medium", vec![0u8; 1024]),
        ("long", vec![0u8; 4096])
    ];

    for (name, message) in messages {
        c.bench_function(
            &format!("full_encryption_{}", name),
            |b| b.iter_batched(
                || message.clone(),
                |msg| black_box(encrypt(&server_kp.public, &msg).unwrap()),
                BatchSize::SmallInput
            )
        );
    }
}

fn full_decryption_benchmark(c: &mut Criterion) {
    let server_kp = generate_keypair().unwrap();
    let messages = vec![
        ("short", encrypt(&server_kp.public, b"test").unwrap()),
        ("medium", encrypt(&server_kp.public, &vec![0u8; 1024]).unwrap()),
        ("long", encrypt(&server_kp.public, &vec![0u8; 4096]).unwrap())
    ];

    for (name, ciphertext) in messages {
        c.bench_function(
            &format!("full_decryption_{}", name),
            |b| b.iter(|| {
                black_box(decrypt(&ciphertext, &server_kp).unwrap());
            })
        );
    }
}

criterion_group!{
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