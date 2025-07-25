#![no_main]

use kychacha_crypto::{bytes_to_secret_key, secret_key_to_bytes};
use libfuzzer_sys::fuzz_target;

// Bytes <=> Secret key
fuzz_target!(|data: &[u8]| {
    if let Ok(secret_key) = bytes_to_secret_key(&data.to_vec()) {
        let _ = secret_key_to_bytes(secret_key);
    }
});
