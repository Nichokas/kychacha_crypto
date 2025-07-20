#![no_main]

use libfuzzer_sys::fuzz_target;
use kychacha_crypto::{bytes_to_secret_key, decrypt, encrypt, generate_keypair};

fuzz_target!(|data: &[u8]| {
    // init -----------
    let keypair = generate_keypair().unwrap();
    let ciphertext = encrypt(keypair.public_key,b"Hello World").unwrap();
    // ----------------

    // all is fuzz
    if let Ok(secret_key) = bytes_to_secret_key(&data.to_vec()) {
        if let Ok(public_key) = decrypt(data, &secret_key) {
            let _ = public_key;
        }
    }

    // only data is fuzz
    if let Ok(public_key) = decrypt(data, &keypair.private_key) {
            let _ = public_key;
    }

    // only key is fuzz
    if let Ok(secret_key) = bytes_to_secret_key(&data.to_vec()) {
        if let Ok(public_key) = decrypt(&ciphertext, &secret_key) {
            let _ = public_key;
        }
    }
});