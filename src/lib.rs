// lib.rs
mod encryption;
mod key_exchange;

#[cfg(test)]
mod tests;

pub use encryption::*;
pub use key_exchange::*;

use anyhow::{anyhow, Context, Error, Result};
use bincode::serde::{borrow_decode_from_slice, encode_to_vec};
use kyberlib::{decapsulate, encapsulate, KYBER_CIPHERTEXT_BYTES};
pub use kyberlib::{Keypair, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use zerocopy::IntoBytes;

/// Serialized encrypted data format
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData {
    #[serde(with = "serde_bytes")]
    /// Kyber ciphertext (1568 bytes)
    pub ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    /// ChaCha20 random nonce (12 bytes)
    pub nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    /// Encrypted message with authentication tag
    pub encrypted_msg: Vec<u8>,
}

/// (only for tests)
#[derive(Serialize, Deserialize)]
pub struct TestData {
    pub secret_key: Vec<u8>,
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
/// let keypair = generate_keypair()?;
///
/// let pk_bytes = secret_key_to_bytes(&keypair.secret);
/// assert_eq!(pk_bytes.len(), 2400);
/// Ok(())
/// # }
/// ```
pub fn secret_key_to_bytes(sk: &SecretKey) -> Vec<u8> {
    sk.as_bytes().to_vec()
}

/// Converts public key to byte vector
/// # Example
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use kychacha_crypto::{public_key_to_bytes, generate_keypair};
///
/// let keypair = generate_keypair()?;
///
/// let pk_bytes = public_key_to_bytes(&keypair.public);
/// assert_eq!(pk_bytes.len(), 1184);
/// Ok(())
/// # }
/// ```
pub fn public_key_to_bytes(pk: &PublicKey) -> Vec<u8> {
    pk.as_bytes().to_vec()
}

/// Reconstructs secret key from bytes
/// # Error
/// Returns error if input ≠ 2400 bytes
pub fn bytes_to_secret_key(bytes: &[u8]) -> Result<SecretKey> {
    let array: [u8; KYBER_SECRET_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid secret key length"))?;
    Ok(SecretKey::from(array))
}

/// Reconstructs public key from bytes
/// # Error
/// Returns error if input ≠ 1184 bytes
pub fn bytes_to_public_key(bytes: &[u8]) -> Result<PublicKey> {
    let array: [u8; KYBER_PUBLIC_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid public key length"))?;
    Ok(PublicKey::from(array))
}

/// Hybrid encryption with Kyber + ChaCha
/// # Example
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use kychacha_crypto::{encrypt, generate_keypair};
///
/// let keypair = generate_keypair()?;
///
/// let data = encrypt(&keypair.public, b"the data")?;
/// Ok(())
/// # }
/// ```
pub fn encrypt(server_pubkey: &PublicKey, message: &[u8]) -> std::result::Result<Vec<u8>, Error> {
    // 1. Client encapsulate a shared secret
    let (kyber_ciphertext, shared_secret) = encapsulate(server_pubkey, &mut rand::thread_rng())
        .map_err(|e| anyhow!("Encapsulation failed: {}", e))?;

    debug_assert_eq!(kyber_ciphertext.as_bytes().len(), KYBER_CIPHERTEXT_BYTES);

    // 2. Derivate key for ChaCha20Poly1305
    let chacha_key = derive_chacha_key(&shared_secret);

    // 3. Encrypt the message
    let (nonce, ciphertext) = encrypt_with_key(&chacha_key, message)?;

    // 4. Serialize data
    let data = EncryptedData {
        ciphertext: kyber_ciphertext.as_bytes().to_vec(),
        nonce: nonce.to_vec(),
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
/// let keypair = generate_keypair()?;
/// let data = encrypt(&keypair.public, b"the data")?;
///
/// let decrypted = decrypt(&data, &keypair)?;
/// Ok(())
/// # }
/// ```
pub fn decrypt(encrypted_data: &[u8], server_kp: &Keypair) -> Result<String> {
    let config = bincode::config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    let (data, _size): (EncryptedData, usize) = borrow_decode_from_slice(encrypted_data, config)?;

    let kyber_ciphertext_array: [u8; KYBER_CIPHERTEXT_BYTES] = data
        .ciphertext
        .try_into()
        .map_err(|_| anyhow!("Tamaño de ciphertext inválido"))?;

    let shared_secret = decapsulate(&kyber_ciphertext_array, &server_kp.secret)
        .map_err(|e| anyhow!("Encapsulation failed: {}", e))?;
    let chacha_key = derive_chacha_key(&shared_secret);

    let plaintext = decrypt_with_key(&chacha_key, &data.nonce, &data.encrypted_msg)?;
    String::from_utf8(plaintext).context("UTF-8 inválido")
}
