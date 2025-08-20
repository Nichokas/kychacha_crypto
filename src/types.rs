use crate::select_bincode_config;
use anyhow::Result;
use bincode::serde::{borrow_decode_from_slice, encode_to_vec};
use num_bigint::BigUint;
use oqs::kem::{PublicKey as libPublicKey, SecretKey as libSecretKey};
use oqs::sig::{PublicKey as libSignPublicKey, SecretKey as libSignSecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn hash_bytes_to_decimal_hex(bytes: &[u8]) -> (String, String) {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let dec = BigUint::from_bytes_be(&digest).to_str_radix(10);
    let hex = digest.iter().map(|b| format!("{:02x}", b)).collect();
    (dec, hex)
}

/// Security levels for ML-KEM (Kyber) parameter sets.
#[repr(u16)]
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum SecurityLevel {
    MlKem512 = 512,
    MlKem768 = 768,
    MlKem1024 = 1024,
}

#[repr(u16)]
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum SignSecurityLevel {
    Dilithium2 = 2,
    Dilithium3 = 3,
    Dilithium5 = 5,
}

/// ML-KEM secret key with associated security level.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct SecretKey {
    pub security: SecurityLevel,
    pub key: libSecretKey,
}

impl SecretKey {
    /// Serializes this `SecretKey` into a bincode-encoded `Vec<u8>`.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(encode_to_vec(self, select_bincode_config()?)?)
    }
    /// Deserializes a `SecretKey` from a bincode-encoded byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(borrow_decode_from_slice(bytes, select_bincode_config()?)?.0)
    }

    /// Returns the SHA-256 hash of the secret key as a decimal string.
    pub fn hash_decimal(&self) -> String {
        hash_bytes_to_decimal_hex(self.key.as_ref()).0
    }

    /// Returns the SHA-256 hash of the secret key as a hexadecimal string.
    pub fn hash_hex(&self) -> String {
        hash_bytes_to_decimal_hex(self.key.as_ref()).1
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct SignSecretKey {
    pub security: SignSecurityLevel,
    pub key: libSignSecretKey,
}

impl SignSecretKey {
    /// Serializes this `SecretKey` into a bincode-encoded `Vec<u8>`.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(encode_to_vec(self, select_bincode_config()?)?)
    }
    /// Deserializes a `SecretKey` from a bincode-encoded byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(borrow_decode_from_slice(bytes, select_bincode_config()?)?.0)
    }

    /// Returns the SHA-256 hash of the secret key as a decimal string.
    pub fn hash_decimal(&self) -> String {
        hash_bytes_to_decimal_hex(self.key.as_ref()).0
    }

    /// Returns the SHA-256 hash of the secret key as a hexadecimal string.
    pub fn hash_hex(&self) -> String {
        hash_bytes_to_decimal_hex(self.key.as_ref()).1
    }
}

/// ML-KEM public key with associated security level.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub security: SecurityLevel,
    pub key: libPublicKey,
}

impl PublicKey {
    /// Serializes this `PublicKey` into a bincode-encoded `Vec<u8>`.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(encode_to_vec(self, select_bincode_config()?)?)
    }
    /// Deserializes a `PublicKey` from a bincode-encoded byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(borrow_decode_from_slice(bytes, select_bincode_config()?)?.0)
    }

    /// Returns the SHA-256 hash of the public key as a decimal string.
    pub fn hash_decimal(&self) -> String {
        hash_bytes_to_decimal_hex(self.key.as_ref()).0
    }

    /// Returns the SHA-256 hash of the public key as a hexadecimal string.
    pub fn hash_hex(&self) -> String {
        hash_bytes_to_decimal_hex(self.key.as_ref()).1
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct SignPublicKey {
    pub security: SignSecurityLevel,
    pub key: libSignPublicKey,
}

impl SignPublicKey {
    /// Serializes this `PublicKey` into a bincode-encoded `Vec<u8>`.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(encode_to_vec(self, select_bincode_config()?)?)
    }
    /// Deserializes a `PublicKey` from a bincode-encoded byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(borrow_decode_from_slice(bytes, select_bincode_config()?)?.0)
    }

    /// Returns the SHA-256 hash of the public key as a decimal string.
    pub fn hash_decimal(&self) -> String {
        hash_bytes_to_decimal_hex(self.key.as_ref()).0
    }

    /// Returns the SHA-256 hash of the public key as a hexadecimal string.
    pub fn hash_hex(&self) -> String {
        hash_bytes_to_decimal_hex(self.key.as_ref()).1
    }
}

/// Combined ML-KEM (and optional Dilithium) keypair. Public hash covers only public material.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct MlKemKeyPair {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
    #[cfg(any(feature = "dilithium2", feature = "dilithium3", feature = "dilithium5"))]
    pub private_sign_key: SignSecretKey,
    #[cfg(any(feature = "dilithium2", feature = "dilithium3", feature = "dilithium5"))]
    pub public_sign_key: SignPublicKey,
}

impl MlKemKeyPair {
    /// Serializes this `MlKemKeyPair` into a bincode-encoded `Vec<u8>`.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(encode_to_vec(self, select_bincode_config()?)?)
    }
    /// Deserializes an `MlKemKeyPair` from a bincode-encoded byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(borrow_decode_from_slice(bytes, select_bincode_config()?)?.0)
    }

    /// Returns the SHA-256 hash (decimal) derived ONLY from public key material.
    /// Order: public KEM key [|| public signing key]. Private keys are NEVER hashed.
    pub fn hash_decimal(&self) -> String {
        let mut all = Vec::new();
        all.extend_from_slice(self.public_key.key.as_ref());
        #[cfg(any(feature = "dilithium2", feature = "dilithium3", feature = "dilithium5"))]
        {
            all.extend_from_slice(self.public_sign_key.key.as_ref());
        }
        hash_bytes_to_decimal_hex(&all).0
    }

    /// Returns the SHA-256 hash (hex) derived ONLY from public key material.
    /// Order: public KEM key [|| public signing key]. Private keys are NEVER hashed.
    pub fn hash_hex(&self) -> String {
        let mut all = Vec::new();
        all.extend_from_slice(self.public_key.key.as_ref());
        #[cfg(any(feature = "dilithium2", feature = "dilithium3", feature = "dilithium5"))]
        {
            all.extend_from_slice(self.public_sign_key.key.as_ref());
        }
        hash_bytes_to_decimal_hex(&all).1
    }
}
