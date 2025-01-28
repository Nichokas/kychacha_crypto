use base64::{engine::general_purpose, Engine as _};
use criterion::{criterion_group, criterion_main, Criterion, black_box};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use curve_msg::{encrypt, decrypt};

pub fn encryption_bench(c: &mut Criterion) {
    let test_secret = EphemeralSecret::random();
    let test_public = PublicKey::from(&test_secret);
    c.bench_function("encryption", |b| {
        b.iter(|| {
            black_box(encrypt(test_public, b"Hello world! :3").unwrap());
        })
    });
}

pub fn decryption_bench(c: &mut Criterion) {
    EphemeralSecret::random();
    
    let static_secret_base64 = "gvDEoSbdLpuRZfBwiQoTF1iSvHDt1MBx1dnqsUsgqvw=";
    let static_secret_bytes = general_purpose::STANDARD.decode(static_secret_base64)
        .expect("Failed to decode static secret");
    let static_secret_arr = <[u8; 32]>::try_from(static_secret_bytes.as_slice())
        .expect("Incorrect length for static secret");

    let static_secret = StaticSecret::from(static_secret_arr);
    
    c.bench_function("decryption", |b| {
        b.iter(|| {
            black_box(decrypt(r#"{"ephemeral_public":"ZoBZC5w8AHUAb1+soCkWGZuxfuwkhoNuIfKv5Ej1IRs=","nonce":"xgTfn/wSOZ0FYDJj","ciphertext":"apgXRjjICkLMvu7MF0ggKogdleopTO1eAoUHf+hdtg=="}"#, static_secret.clone()).unwrap());
        })
    });
}

criterion_group!(benches, encryption_bench, decryption_bench);
criterion_main!(benches);