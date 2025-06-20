//! Kyber-1024 key exchange implementation (NIST PQC Round 3)

use hkdf::Hkdf;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;
use zerocopy::IntoBytes;
use oqs;
use oqs::kem::SharedSecret;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use crate::{MlKemKeyPair,select_oqs};

/// Derives 256-bit ChaCha20 key from Kyber shared secret
///
/// Uses HKDF-SHA256 with protocol-specific context
///
/// # Security
/// Context string prevents key reuse in different protocol components
pub fn derive_chacha_key(shared_secret: SharedSecret) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, &shared_secret.into_vec());
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
pub fn generate_keypair() -> MlKemKeyPair {
    let kem = select_oqs();
    let (public_key,private_key) = kem.keypair().unwrap();
    MlKemKeyPair {
        public_key,
        private_key,
    }
}
