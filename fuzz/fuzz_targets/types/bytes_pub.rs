#![no_main]

use libfuzzer_sys::fuzz_target;
use kychacha_crypto::{bytes_to_public_key, public_key_to_bytes};

// Bytes <=> Public key
fuzz_target!(|data: &[u8]| {
    if let Ok(public_key) = bytes_to_public_key(&data.to_vec()) {
        let _ = public_key_to_bytes(public_key);
    }
});