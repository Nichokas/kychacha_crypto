use oqs::kem::{PublicKey as libPublicKey, SecretKey as libSecretKey};
use serde::{Deserialize, Serialize};
use bincode::serde::{encode_to_vec,borrow_decode_from_slice};
use crate::select_bincode_config;
use anyhow::Result;

/// SecurityLevel defines the parameter sets (security strengths) supported by the ML-KEM algorithm.
///
/// Each variant corresponds to a NIST PQC Round 3 Kyber parameter set.
///
/// # Variants
/// - `MlKem512`: 512-bit security level
/// - `MlKem768`: 768-bit security level
/// - `MlKem1024`: 1024-bit security level
#[repr(u16)]
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum SecurityLevel {
    MlKem512 = 512,
    MlKem768 = 768,
    MlKem1024 = 1024,
}

/// SecretKey holds the private component of an ML-KEM key pair along with its security level.
///
/// Provides serialization (`to_vec`) and deserialization (`from_bytes`) helpers.
///
/// # Fields
/// * `security`: The chosen `SecurityLevel`.
/// * `key`: The underlying OQS secret key.
///
/// # Examples
/// ```
/// use kychacha_crypto::SecretKey;
/// use kychacha_crypto::generate_keypair;
///
/// let kp = generate_keypair().unwrap();
/// let sk = kp.private_key;
/// let bytes = sk.to_vec().unwrap();
/// let sk2 = SecretKey::from_bytes(&bytes).unwrap();
/// assert_eq!(sk, sk2);
/// ```
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct SecretKey {
    /// The security level associated with this secret key.
    pub security: SecurityLevel,
    /// The underlying OQS secret key blob.
    pub key: libSecretKey,
}

impl SecretKey {
    /// Serializes this `SecretKey` into a bincode-encoded `Vec<u8>`.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(encode_to_vec(self,select_bincode_config()?)?)
    }
    /// Deserializes a `SecretKey` from a bincode-encoded byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(borrow_decode_from_slice(bytes,select_bincode_config()?)?.0)
    }
}

/// PublicKey holds the public component of an ML-KEM key pair along with its security level.
///
/// Provides serialization (`to_vec`) and deserialization (`from_bytes`) helpers.
///
/// # Fields
/// * `security`: The chosen `SecurityLevel`.
/// * `key`: The underlying OQS public key.
///
/// # Examples
/// ```
/// use kychacha_crypto::PublicKey;
/// use kychacha_crypto::generate_keypair;
///
/// let kp = generate_keypair().unwrap();
/// let pk = kp.public_key;
/// let bytes = pk.to_vec().unwrap();
/// let pk2 = PublicKey::from_bytes(&bytes).unwrap();
/// assert_eq!(pk, pk2);
/// ```
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    /// The security level associated with this public key.
    pub security: SecurityLevel,
    /// The underlying OQS public key blob.
    pub key: libPublicKey,
}

impl PublicKey {
    /// Serializes this `PublicKey` into a bincode-encoded `Vec<u8>`.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(encode_to_vec(self,select_bincode_config()?)?)
    }
    /// Deserializes a `PublicKey` from a bincode-encoded byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(borrow_decode_from_slice(bytes,select_bincode_config()?)?.0)
    }
}

/// MlKemKeyPair contains both the private and public KEM keys for ML-KEM operations.
///
/// Provides serialization (`to_vec`) and deserialization (`from_bytes`) helpers.
///
/// # Fields
/// * `private_key`: The `SecretKey` component.
/// * `public_key`: The `PublicKey` component.
///
/// # Examples
/// ```
/// use kychacha_crypto::MlKemKeyPair;
/// use kychacha_crypto::generate_keypair;
///
/// let kp = generate_keypair().unwrap();
/// let bytes = kp.to_vec().unwrap();
/// let kp2 = MlKemKeyPair::from_bytes(&bytes).unwrap();
/// assert_eq!(kp, kp2);
/// ```
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct MlKemKeyPair {
    /// The `SecretKey` component (private key) of the key pair.
    pub private_key: SecretKey,
    /// The `PublicKey` component (public key) of the key pair.
    pub public_key: PublicKey,
}

impl MlKemKeyPair {
    /// Serializes this `MlKemKeyPair` into a bincode-encoded `Vec<u8>`.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(encode_to_vec(self,select_bincode_config()?)?)
    }
    /// Deserializes an `MlKemKeyPair` from a bincode-encoded byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(borrow_decode_from_slice(bytes,select_bincode_config()?)?.0)
    }
}