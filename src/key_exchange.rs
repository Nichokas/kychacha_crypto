//! Kyber-1024 key exchange implementation (NIST PQC Round 3)

use anyhow::{anyhow, Error};
use hkdf::Hkdf;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use zerocopy::IntoBytes;
use libcrux_ml_kem::*;
use libcrux_ml_kem::mlkem768::MlKem768KeyPair;

/// Derives 256-bit ChaCha20 key from Kyber shared secret
///
/// Uses HKDF-SHA256 with protocol-specific context
///
/// # Security
/// Context string prevents key reuse in different protocol components
pub fn derive_chacha_key(shared_secret: &MlKemSharedSecret) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"chacha-encryption-v1", &mut okm)
        .expect("HKDF failed");
    okm
}

/// Generates ML-KEM keypair
///
/// # Example
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use kychacha_crypto::generate_keypair;
///
/// let keypair = generate_keypair();
/// Ok(())
/// # }
/// ```
pub fn generate_keypair() -> MlKem768KeyPair {
    let mut rng = ChaCha20Rng::from_os_rng();
    let mut randomness = [0u8; 64];
    rng.fill(&mut randomness);
    mlkem768::generate_key_pair(randomness)
}
