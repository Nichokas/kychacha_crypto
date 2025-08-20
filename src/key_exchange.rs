//! ML-KEM (Kyber) key exchange and keypair generation utilities.

use crate::{MlKemKeyPair, PublicKey, SecretKey, SecurityLevel, SignSecurityLevel, given_oqs, select_oqs};

use anyhow::Result;
use hkdf::Hkdf;
use oqs;
use oqs::kem::SharedSecret;
use sha2::Sha256;
use crate::types::{SignPublicKey, SignSecretKey};

/// Derive a 32-byte ChaCha20-Poly1305 key from an ML-KEM shared secret via HKDF-SHA256
/// with a fixed context string to avoid cross-protocol key reuse.
/// Returns an error only if HKDF expansion fails.
pub(crate) fn derive_chacha_key(shared_secret: SharedSecret) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, &shared_secret.into_vec());
    let mut okm = [0u8; 32];
    hk.expand(b"chacha-encryption-v1", &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF key derivation failed: {}", e))?;
    Ok(okm)
}

/// Generate a keypair using the crate's default (feature-selected) ML-KEM (and Dilithium if enabled).
/// When signature features are enabled a signature keypair is also produced.
pub fn generate_keypair() -> Result<MlKemKeyPair> {
    let (sec, ssec, _, _) = given_oqs()?;

    #[cfg(any(feature = "dilithium2", feature = "dilithium3", feature = "dilithium5"))]
    {
        if let Some(sign_sec) = ssec {
            generate_keypair_with_level(&sec, Some(&sign_sec))
        } else {
            anyhow::bail!("Signature module enabled but no signature security level available")
        }
    }

    #[cfg(not(any(feature = "dilithium2", feature = "dilithium3", feature = "dilithium5")))]
    generate_keypair_with_level(&sec, None)
}

/// Generate a keypair for a specific ML-KEM security level (and optional Dilithium level).
/// The requested levels must be enabled at compile time via features.
///
/// # Example
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use kychacha_crypto::{generate_keypair_with_level, SecurityLevel, SignSecurityLevel};
/// let kp = generate_keypair_with_level(&SecurityLevel::MlKem1024, Some(&SignSecurityLevel::Dilithium3))?;
/// # Ok(())
/// # }
/// ```
pub fn generate_keypair_with_level(security: &SecurityLevel, sign_sec: Option<&SignSecurityLevel>) -> Result<MlKemKeyPair> {
    let (kem, sig) = select_oqs(security, sign_sec)?;
    let (gpublic_key, gprivate_key) = kem
        .keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate ML-KEM keypair: {}", e))?;

    #[cfg(any(feature = "dilithium2", feature = "dilithium3", feature = "dilithium5"))]
    let result = if let Some(sign_security) = sign_sec {
        if let Some(sig_instance) = sig {
            let (signpublic, signprivate) = sig_instance
                .keypair()
                .map_err(|e| anyhow::anyhow!("Failed to generate signature keypair: {}", e))?;

            Ok(MlKemKeyPair {
                public_key: PublicKey {
                    security: security.clone(),
                    key: gpublic_key,
                },
                private_key: SecretKey {
                    security: security.clone(),
                    key: gprivate_key,
                },
                public_sign_key: SignPublicKey {
                    security: sign_security.clone(),
                    key: signpublic,
                },
                private_sign_key: SignSecretKey {
                    security: sign_security.clone(),
                    key: signprivate,
                }
            })
        } else {
            anyhow::bail!("Signature module enabled but no signature algorithm instance available")
        }
    } else {
        anyhow::bail!("Signature features are enabled, but no signature security level was specified. Please provide a SignSecurityLevel.")
    };

    #[cfg(not(any(feature = "dilithium2", feature = "dilithium3", feature = "dilithium5")))]
    let result = Ok(MlKemKeyPair {
        public_key: PublicKey {
            security: security.clone(),
            key: gpublic_key,
        },
        private_key: SecretKey {
            security: security.clone(),
            key: gprivate_key,
        }
    });

    result
}
