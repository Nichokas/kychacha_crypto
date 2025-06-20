// lib.rs
mod encryption;
mod key_exchange;

#[cfg(test)]
mod tests;

use anyhow::{Context, Error, Result};
use bincode::serde::{borrow_decode_from_slice, encode_to_vec};
pub use encryption::*;
pub use key_exchange::*;
use oqs;
use oqs::kem;
use oqs::kem::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

/// Serialized encrypted data format
#[derive(Serialize, Deserialize)]
pub struct EncryptedData {
    #[serde(with = "serde_bytes")]
    /// Kyber ciphertext
    pub ciphertext: Vec<u8>,
    /// ChaCha20 random nonce
    pub nonce: Vec<u8>,
    /// Encrypted message with authentication tag
    pub encrypted_msg: Vec<u8>,
}

#[derive(Clone,Eq, PartialEq)]
pub struct MlKemKeyPair {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
}

/// (only for tests)
#[derive(Serialize, Deserialize)]
pub struct TestData {
    #[serde(with = "serde_bytes")]
    pub secret_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    pub encrypted_data: Vec<u8>,
}

/// Converts secret key to byte vector
/// # Example
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use kychacha_crypto::{secret_key_to_bytes, generate_keypair};
///
/// let keypair = generate_keypair();
///
/// let pk_bytes = secret_key_to_bytes(keypair.private_key);
/// Ok(())
/// # }
/// ```
pub fn secret_key_to_bytes(sk: SecretKey) -> Vec<u8> {
    sk.into_vec()
}

/// Converts public key to byte vector
/// # Example
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use kychacha_crypto::{public_key_to_bytes, generate_keypair};
///
/// let keypair = generate_keypair();
///
/// let pk_bytes = public_key_to_bytes(keypair.public_key);
/// Ok(())
/// # }
/// ```
pub fn public_key_to_bytes(pk: PublicKey) -> Vec<u8> {
    pk.into_vec()
}

/// Reconstructs secret key from bytes
pub fn bytes_to_secret_key(bytes: &Vec<u8>) -> SecretKey {
    let kem = select_oqs();
    kem.secret_key_from_bytes(bytes).unwrap().to_owned()
}

/// Reconstructs public key from bytes
pub fn bytes_to_public_key(bytes: &Vec<u8>) -> PublicKey {
    let kem = select_oqs();
    kem.public_key_from_bytes(bytes).unwrap().to_owned()
}

fn select_oqs() -> kem::Kem {
    oqs::init();
    #[cfg(feature = "mlkem512")]
    {
        oqs::kem::Kem::new(kem::Algorithm::MlKem512).unwrap()
    }
    #[cfg(feature = "mlkem768")]
    {
        kem::Kem::new(kem::Algorithm::MlKem768).unwrap()
    }
    #[cfg(feature = "mlkem1024")]
    {
        oqs::kem::Kem::new(kem::Algorithm::MlKem1024).unwrap()
    }
}

/// Hybrid encryption with Kyber + ChaCha
/// # Example
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use kychacha_crypto::{encrypt, generate_keypair};
///
/// let keypair = generate_keypair();
///
/// let data = encrypt(keypair.public_key, b"the data")?; 
/// Ok(())
/// # }
/// ```
pub fn encrypt(server_pubkey: PublicKey, message: &[u8]) -> std::result::Result<Vec<u8>, Error> {

    let kem = select_oqs();

    let (ct, ss) = kem.encapsulate(&server_pubkey).unwrap();
    
    let chacha_key = derive_chacha_key(ss);
    
    let (nonce, ciphertext) = encrypt_with_key(&chacha_key, message)?;

    // Serialize data
    let data = EncryptedData {
        ciphertext: ct.into_vec(),
        nonce: nonce.as_slice().to_owned(),
        encrypted_msg: ciphertext,
    };

    let config = bincode::config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    encode_to_vec(&data, config).context("Serialization error")
}

/// Hybrid decryption workflow:
/// 1. Deserialize encrypted data
/// 2. Kyber decapsulation
/// 3. ChaCha20-Poly1305 decryption
///
/// # Example
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use kychacha_crypto::{decrypt, encrypt, generate_keypair};
///
/// let keypair = generate_keypair();
/// let data = encrypt(keypair.public_key, b"the data")?;
///
/// let decrypted = decrypt(&data, &keypair.private_key)?;
/// Ok(())
/// # }
/// ```
pub fn decrypt(encrypted_data: &[u8], private_key: &SecretKey) -> Result<String> {
    oqs::init();
    #[cfg(feature = "mlkem512")]
    let kem = oqs::kem::Kem::new(kem::Algorithm::MlKem512).unwrap();
    #[cfg(feature = "mlkem768")]
    let kem = kem::Kem::new(kem::Algorithm::MlKem768).unwrap();
    #[cfg(feature = "mlkem1024")]
    let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::MlKem1024).unwrap();

    let config = bincode::config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    let (data, _size): (EncryptedData, usize) = borrow_decode_from_slice(encrypted_data, config)?;

    let ct = kem.ciphertext_from_bytes(&data.ciphertext).unwrap();

    let shared_secret = kem.decapsulate(private_key,ct).unwrap();
    let chacha_key = derive_chacha_key(shared_secret);

    let plaintext = decrypt_with_key(&chacha_key, &data.nonce, &data.encrypted_msg)?;
    String::from_utf8(plaintext).context("Invalid UTF-8")
}
