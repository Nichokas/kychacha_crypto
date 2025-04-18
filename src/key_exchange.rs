//! Kyber-1024 key exchange implementation (NIST PQC Round 3)

use anyhow::{anyhow, Error};
use hkdf::Hkdf;
use kyberlib::{keypair, SharedSecret};
use rand::thread_rng;
use sha2::Sha256;
use zerocopy::IntoBytes;

/// Kyber-768 key sizes
pub const KYBER_PUBLIC_KEY_BYTES: usize = 1184;
/// Kyber-768 key sizes
pub const KYBER_SECRET_KEY_BYTES: usize = 2400;

/// Derives 256-bit ChaCha20 key from Kyber shared secret
///
/// Uses HKDF-SHA256 with protocol-specific context
///
/// # Security
/// Context string prevents key reuse in different protocol components
pub fn derive_chacha_key(shared_secret: &SharedSecret) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"chacha-encryption-v1", &mut okm)
        .expect("HKDF failed");
    okm
}

/// Generates CPA-secure Kyber-1024 keypair
///
/// # Example
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use kychacha_crypto::generate_keypair;
///
/// let keypair = generate_keypair()?;
/// Ok(())
/// # }
/// ```
pub fn generate_keypair() -> std::result::Result<kyberlib::Keypair, Error> {
    let mut rng = thread_rng();
    keypair(&mut rng).map_err(|e| anyhow!("Key generation failed: {}", e))
}
