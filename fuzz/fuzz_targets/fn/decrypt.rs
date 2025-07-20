#![no_main]

use libfuzzer_sys::fuzz_target;
use kychacha_crypto::{bytes_to_secret_key, encrypt, generate_keypair, decrypt_from_reader};
use bincode::de::read::SliceReader;

fuzz_target!(|data: &[u8]| {
    // init -----------
    let keypair = generate_keypair().unwrap();
    let ciphertext = encrypt(keypair.public_key, b"Hello World").unwrap();
    // ----------------

    // all is fuzz
    if let Ok(secret_key) = bytes_to_secret_key(&data.to_vec()) {
        let reader = SliceReader::new(data);
        if let Ok(plaintext) = decrypt_from_reader(reader, &secret_key) {
            let _ = plaintext;
        }
    }

    // only data is fuzz
    {
        let reader = SliceReader::new(data);
        if let Ok(plaintext) = decrypt_from_reader(reader, &keypair.private_key) {
            let _ = plaintext;
        }
    }

    // only key is fuzz
    if let Ok(secret_key) = bytes_to_secret_key(&data.to_vec()) {
        let reader = SliceReader::new(&ciphertext);
        if let Ok(plaintext) = decrypt_from_reader(reader, &secret_key) {
            let _ = plaintext;
        }
    }
});