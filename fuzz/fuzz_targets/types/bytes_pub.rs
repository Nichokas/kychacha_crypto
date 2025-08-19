#![no_main]

use kychacha_crypto::{PublicKey};
use libfuzzer_sys::fuzz_target;

// Bytes <=> Public key
fuzz_target!(|data: &[u8]| {
    if let Ok(public_key) = PublicKey::from_bytes(&data.to_vec()) {
        let _ = public_key.to_vec();
    }
});
