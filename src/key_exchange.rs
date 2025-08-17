//! Kyber-1024 key exchange implementation (NIST PQC Round 3)

use crate::{MlKemKeyPair, PublicKey, SecretKey, given_oqs, select_oqs, SecurityLevel};

use anyhow::Result;
use hkdf::Hkdf;
use oqs;
use oqs::kem::SharedSecret;
use sha2::Sha256;

/// Derives 256-bit ChaCha20 key from Kyber shared secret
///
/// Uses HKDF-SHA256 with protocol-specific context
///
/// # Security
/// Context string prevents key reuse in different protocol components
///
/// # Errors
/// Returns error if HKDF expansion fails
pub(crate) fn derive_chacha_key(shared_secret: SharedSecret) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, &shared_secret.into_vec());
    let mut okm = [0u8; 32];
    hk.expand(b"chacha-encryption-v1", &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF key derivation failed: {}", e))?;
    Ok(okm)
}

/// Generates ML-KEM keypair
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
///
/// # Errors
/// Returns error if keypair generation fails
pub fn generate_keypair() -> Result<MlKemKeyPair> {
    let (sec, kem) = given_oqs()?;
    let (gpublic_key, gprivate_key) = kem
        .keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate ML-KEM keypair: {}", e))?;
    Ok(MlKemKeyPair {
        public_key: PublicKey {
            security: sec.clone(),
            key: gpublic_key,
        },
        private_key: SecretKey {
            security: sec,
            key: gprivate_key,
        },
    })
}

/// Generates an ML-KEM keypair for a specified security level (runtime selection).
///
/// This allows choosing the parameter set without relying on compile-time feature flags.
/// You must ensure the crate was compiled with support for the desired level (enable the corresponding feature).
///
/// # Example
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use kychacha_crypto::{generate_keypair_with_level, SecurityLevel};
/// let kp = generate_keypair_with_level(SecurityLevel::MlKem1024)?;
/// # Ok(())
/// # }
/// ```
pub fn generate_keypair_with_level(security: SecurityLevel) -> Result<MlKemKeyPair> {
    let kem = select_oqs(&security)?; // uses already initialized liboqs
    let (gpublic_key, gprivate_key) = kem
        .keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate ML-KEM keypair: {}", e))?;
    Ok(MlKemKeyPair {
        public_key: PublicKey {
            security: security.clone(),
            key: gpublic_key,
        },
        private_key: SecretKey { security, key: gprivate_key },
    })
}
