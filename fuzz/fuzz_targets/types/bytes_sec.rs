#![no_main]

use kychacha_crypto::SecretKey;
use libfuzzer_sys::fuzz_target;

// Bytes <=> Secret key
fuzz_target!(|data: &[u8]| {
    if let Ok(secret_key) = SecretKey::from_bytes(&data.to_vec()) {
        let _ = secret_key.to_vec();
    }
});
