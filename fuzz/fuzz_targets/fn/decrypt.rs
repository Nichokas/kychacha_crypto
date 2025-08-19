#![no_main]

use kychacha_crypto::{SecretKey, decrypt_stream, encrypt_stream, generate_keypair};
use libfuzzer_sys::fuzz_target;
use std::io::{Cursor, Write};
use tempfile::tempfile;

fuzz_target!(|data: &[u8]| {
    // init -----------
    let keypair = generate_keypair().unwrap();
    let mut file = tempfile().unwrap();
    encrypt_stream(
        keypair.public_key,
        &mut Cursor::new(b"Hello World"),
        &mut file,
    )
    .unwrap();
    let mut uselessfile = tempfile().unwrap();
    let mut fuzzing_file = tempfile().unwrap();
    fuzzing_file.write_all(data).unwrap();
    // ----------------

    // all is fuzz
    if let Ok(secret_key) = SecretKey::from_bytes(&data.to_vec()) {
        if let Ok(plaintext) = decrypt_stream(&secret_key, &mut fuzzing_file, &mut uselessfile) {
            let _ = plaintext;
        }
    }

    // only data is fuzz
    {
        if let Ok(plaintext) =
            decrypt_stream(&keypair.private_key, &mut fuzzing_file, &mut uselessfile)
        {
            let _ = plaintext;
        }
    }

    // only key is fuzz
    if let Ok(secret_key) = SecretKey::from_bytes(&data.to_vec()) {
        if let Ok(plaintext) = decrypt_stream(&secret_key, &mut file, &mut uselessfile) {
            let _ = plaintext;
        }
    }
});
