// lib.rs
mod encryption;
mod key_exchange;

#[cfg(test)]
mod tests;

use std::io::Read;
pub use encryption::*;
pub use key_exchange::*;

use anyhow::{anyhow, Context, Error, Result};
use bincode::serde::{borrow_decode_from_slice, encode_to_vec};
use rand_chacha::ChaCha20Rng;
use libcrux_ml_kem::*;
use libcrux_ml_kem::mlkem768::{MlKem768Ciphertext, MlKem768KeyPair, MlKem768PrivateKey, MlKem768PublicKey};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use zerocopy::IntoBytes;

/// Serialized encrypted data format
#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData {
    #[serde(with = "serde_bytes")]
    /// Kyber ciphertext
    pub ciphertext: [u8; 1088],
    /// ChaCha20 random nonce
    pub nonce: Vec<u8>,
    /// Encrypted message with authentication tag
    pub encrypted_msg: Vec<u8>,
}

/// (only for tests)
#[derive(Serialize, Deserialize)]
pub struct TestData {
    #[serde(with = "serde_bytes")]
    pub secret_key: [u8; 2400],
    #[serde(with = "serde_bytes")]
    pub public_key: [u8; 1184],
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
/// let pk_bytes = secret_key_to_bytes(&keypair.private_key());
/// Ok(())
/// # }
/// ```
pub fn secret_key_to_bytes(sk: &MlKem768PrivateKey) -> [u8; 2400] {
    sk.as_slice().to_owned()
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
/// let pk_bytes = public_key_to_bytes(&keypair.public_key());
/// Ok(())
/// # }
/// ```
pub fn public_key_to_bytes(pk: &MlKem768PublicKey) -> [u8; 1184] {
    pk.as_slice().to_owned()
}

/// Reconstructs secret key from bytes
pub fn bytes_to_secret_key(bytes: &[u8;2400]) -> Result<MlKem768PrivateKey> {
    Ok(MlKem768PrivateKey::from(bytes))
}

/// Reconstructs public key from bytes
pub fn bytes_to_public_key(bytes: &[u8; 1184]) -> Result<MlKem768PublicKey> {
    Ok(MlKem768PublicKey::from(bytes))
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
/// let data = encrypt(&keypair.public_key(), b"the data")?;
/// Ok(())
/// # }
/// ```
pub fn encrypt(server_pubkey: &MlKem768PublicKey, message: &[u8]) -> std::result::Result<Vec<u8>, Error> {
    let mut rng = ChaCha20Rng::from_os_rng();
    let mut randomness = [0u8; 32];
    rng.fill_bytes(&mut randomness);
    let (kyber_ciphertext, shared_secret) = mlkem768::encapsulate(server_pubkey, randomness);
    
    let chacha_key = derive_chacha_key(&shared_secret);
    
    let (nonce, ciphertext) = encrypt_with_key(&chacha_key, message)?;

    // Serialize data
    let data = EncryptedData {
        ciphertext: kyber_ciphertext.as_slice().to_owned(),
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
/// let data = encrypt(&keypair.public_key(), b"the data")?;
///
/// let decrypted = decrypt(&data, &keypair.private_key())?;
/// Ok(())
/// # }
/// ```
pub fn decrypt(encrypted_data: &[u8], private_key: &MlKem768PrivateKey) -> Result<String> {
    let config = bincode::config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    let (data, _size): (EncryptedData, usize) = borrow_decode_from_slice(encrypted_data, config)?;

    let kyber_ciphertext_array: MlKem768Ciphertext = data
        .ciphertext
        .try_into()
        .map_err(|_| anyhow!("Invalid ciphertext size"))?;

    let shared_secret = mlkem768::decapsulate(private_key,&kyber_ciphertext_array);
    let chacha_key = derive_chacha_key(&shared_secret);

    let plaintext = decrypt_with_key(&chacha_key, &data.nonce, &data.encrypted_msg)?;
    String::from_utf8(plaintext).context("Invalid UTF-8")
}
