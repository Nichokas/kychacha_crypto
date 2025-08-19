//! Kyber-1024 key exchange implementation (NIST PQC Round 3)

use crate::{MlKemKeyPair, PublicKey, SecretKey, SecurityLevel, SignSecurityLevel, given_oqs, select_oqs};

use anyhow::Result;
use hkdf::Hkdf;
use oqs;
use oqs::kem::SharedSecret;
use sha2::Sha256;
use crate::types::{SignPublicKey, SignSecretKey};

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
    let (sec, ssec, kem, sig) = given_oqs()?;
    let (gpublic_key, gprivate_key) = kem
        .keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate ML-KEM keypair: {}", e))?;

    #[cfg(any(feature = "dilithium2", feature = "dilithium3", feature = "dilithium5"))]
    let result = if let Some(sig_instance) = sig {
        let (sigpublic, sigprivate) = sig_instance
            .keypair()
            .map_err(|e| anyhow::anyhow!("Failed to generate signature keypair: {}", e))?;

        Ok(MlKemKeyPair {
            public_key: PublicKey {
                security: sec.clone(),
                key: gpublic_key,
            },
            private_key: SecretKey {
                security: sec,
                key: gprivate_key,
            },
            public_sign_key: SignPublicKey {
                security: ssec.clone().unwrap(),
                key: sigpublic,
            },
            private_sign_key: SignSecretKey {
                security: ssec.unwrap(),
                key: sigprivate,
            }
        })
    } else {
        anyhow::bail!("Signature module enabled but no signature algorithm instance available")
    };

    #[cfg(not(any(feature = "dilithium2", feature = "dilithium3", feature = "dilithium5")))]
    let result = Ok(MlKemKeyPair {
        public_key: PublicKey {
            security: sec.clone(),
            key: gpublic_key,
        },
        private_key: SecretKey {
            security: sec,
            key: gprivate_key,
        },
    });

    result
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
