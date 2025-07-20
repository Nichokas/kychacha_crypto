// lib.rs

//! # Features
//! |Name|Default?|What does it do?                     |
//! |----|--------|-------------------------------------|
//! |mlkem512|x|Select Ml-Kem security level to 512 (private key size)|
//! |mlkem768|✅|Select Ml-Kem security level to 768 (private key size)|
//! |mlkem1024|x|Select Ml-Kem security level to 1024 (private key size)|
//! |bincode_normal_limit|✅|Puts bincode serialization size limit to 500mb|
//! |bincode_big_limit|x|Puts bincode serialization size limit to 2gb|
//! |bincode_no_limit|x|Removes bincode serialization size limit, if you select this option your program is going to be susceptible to OOM attacks ("memory overflow")|
//! # Which functions to use
//! |Situation|Encrypt|Decrypt|
//! |---|---|---|
//! |Using files/using [`std::io::Read`]|[`encrypt`]|[`decrypt_from_reader`]|
//! |Using variables/not using [`std::io::Read`]|[`encrypt`]|[`decrypt_from_stream`]|
//! # A Simple Example
//! ```
//! use std::io::Cursor;
//! use std::error::Error;
//! use bincode::de::read::SliceReader;
//! use kychacha_crypto::{decrypt_from_reader, encrypt, generate_keypair};
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     // Generate keypairs for alice and bob
//!     let alice_keypair = generate_keypair()?;
//!     let bob_keypair = generate_keypair()?;
//!
//!     // encrypt the text to bob
//!     let ciphertext = encrypt(bob_keypair.public_key, b"Hi bob! :D")?;
//!
//!     // read the text as bob
//!     let reader = SliceReader::new(&ciphertext);
//!
//!     let plaintext = decrypt_from_reader(reader,&bob_keypair.private_key)?;
//!
//!     assert_eq!(plaintext, "Hi bob! :D".to_string());
//!     Ok(())
//! }
//! ```
mod encryption;
mod key_exchange;

#[cfg(test)]
mod tests;

use std::io::{BufReader, Read};
use anyhow::{Context, Error, Result};
use bincode::config::Config;
use bincode::de::read::{Reader, SliceReader};
use bincode::serde::{decode_from_reader, encode_to_vec};
pub use encryption::*;
pub use key_exchange::*;
use oqs;
use oqs::kem;
use oqs::kem::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use bincode::config::Configuration;

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
/// let keypair = generate_keypair()?;
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
/// let keypair = generate_keypair()?;
///
/// let pk_bytes = public_key_to_bytes(keypair.public_key);
/// Ok(())
/// # }
/// ```
pub fn public_key_to_bytes(pk: PublicKey) -> Vec<u8> {
    pk.into_vec()
}

/// Reconstructs secret key from bytes
///
/// # Errors
/// Returns error if the byte array is invalid or key reconstruction fails
pub fn bytes_to_secret_key(bytes: &Vec<u8>) -> Result<SecretKey> {
    let kem = select_oqs()?;
    kem.secret_key_from_bytes(bytes)
        .ok_or_else(|| anyhow::anyhow!("Failed to reconstruct secret key from bytes"))
        .map(|sk| sk.to_owned())
}

/// Reconstructs public key from bytes
///
/// # Errors
/// Returns error if the byte array is invalid or key reconstruction fails
pub fn bytes_to_public_key(bytes: &Vec<u8>) -> Result<PublicKey> {
    let kem = select_oqs()?;
    kem.public_key_from_bytes(bytes)
        .ok_or_else(|| anyhow::anyhow!("Failed to reconstruct public key from bytes"))
        .map(|pk| pk.to_owned())
}

fn select_oqs() -> Result<kem::Kem> {
    oqs::init();

    #[cfg(feature = "mlkem512")]
    {
        return kem::Kem::new(kem::Algorithm::MlKem512)
            .map_err(|e| anyhow::anyhow!("Failed to initialize ML-KEM-512: {}", e));
    }

    #[cfg(feature = "mlkem768")]
    {
        return kem::Kem::new(kem::Algorithm::MlKem768)
            .map_err(|e| anyhow::anyhow!("Failed to initialize ML-KEM-768: {}", e));
    }

    #[cfg(feature = "mlkem1024")]
    {
        return kem::Kem::new(kem::Algorithm::MlKem1024)
            .map_err(|e| anyhow::anyhow!("Failed to initialize ML-KEM-1024: {}", e));
    }

    // Default fallback if no feature is enabled
    anyhow::bail!("No ML-KEM algorithm feature selected")
}

fn select_bincode_config() -> Result<impl Config> {
    #[cfg(feature = "bincode_normal_limit")]
    {
        return Ok(
            bincode::config::standard()
                .with_big_endian()
                .with_variable_int_encoding()
                .with_limit::<500_000_000>(),
        );
    }
    #[cfg(feature = "bincode_big_limit")]
    {
        return Ok(
            bincode::config::standard()
                .with_big_endian()
                .with_variable_int_encoding()
                .with_limit::<2_000_000_000>(),
        );
    }
    #[cfg(feature = "bincode_no_limit")]
    {
        return Ok(
            bincode::config::standard()
                .with_big_endian()
                .with_variable_int_encoding(),
        );
    }
    anyhow::bail!("No bincode configuration feature selected")
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
/// let data = encrypt(keypair.public_key, b"the data")?; 
/// Ok(())
/// # }
/// ```
pub fn encrypt(server_pubkey: PublicKey, message: &[u8]) -> std::result::Result<Vec<u8>, Error> {
    let kem = select_oqs()?;

    let (ct, ss) = kem.encapsulate(&server_pubkey)
        .map_err(|e| anyhow::anyhow!("Failed to encapsulate with public key: {}", e))?;
    
    let chacha_key = derive_chacha_key(ss)?;
    
    let (nonce, ciphertext) = encrypt_with_key(&chacha_key, message)?;

    // Serialize data
    let data = EncryptedData {
        ciphertext: ct.into_vec(),
        nonce: nonce.as_slice().to_owned(),
        encrypted_msg: ciphertext,
    };

    let config = match select_bincode_config() {
        Ok(config) => config,
        Err(_) => anyhow::bail!("The bincode (kychacha_crypto crate) configuration feature flag is not properly configuration.")
    };

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
/// use std::io::Cursor;
/// use bincode::de::read::SliceReader;
/// use kychacha_crypto::{decrypt_from_reader, encrypt, generate_keypair};
///
/// // Generate keypair and encrypt some data
/// let keypair = generate_keypair()?;
/// let encrypted_data = encrypt(keypair.public_key, b"secret message")?;
///
/// // Create a SliceReader from the encrypted data
/// let reader = SliceReader::new(&encrypted_data);
///
/// let decrypted = decrypt_from_reader(reader, &keypair.private_key)?;
/// assert_eq!(decrypted, "secret message");
/// # Ok(())
/// # }
/// ```
pub fn decrypt_from_reader<R: Reader>(mut reader: R, private_key: &SecretKey) -> Result<String> {
    let kem = select_oqs()?;

    let config = match select_bincode_config() {
        Ok(config) => config,
        Err(_) => anyhow::bail!("The bincode (kychacha_crypto crate) configuration feature flag is not properly configuration.")
    };

    let data: EncryptedData = decode_from_reader(&mut reader, config)?;

    let ct = kem.ciphertext_from_bytes(&data.ciphertext)
        .ok_or_else(|| anyhow::anyhow!("Failed to reconstruct ciphertext from bytes"))?;

    let shared_secret = kem.decapsulate(private_key, ct)
        .map_err(|e| anyhow::anyhow!("Failed to decapsulate shared secret: {}", e))?;
    let chacha_key = derive_chacha_key(shared_secret)?;

    let plaintext = decrypt_with_key(&chacha_key, &data.nonce, &data.encrypted_msg)?;
    String::from_utf8(plaintext).context("Invalid UTF-8")
}

/// Decrypts data from a stream that implements std::io::Read
///
/// # Example showing file-based usage
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use std::fs::File;
/// use std::io::{BufReader, Write};
/// use kychacha_crypto::{decrypt_from_stream, encrypt, generate_keypair};
///
/// // Generate keypair
/// let keypair = generate_keypair()?;
///
/// // Encrypt data
/// let encrypted_data = encrypt(keypair.public_key, b"file content example")?;
///
/// // Write encrypted data to a file
/// {
///     let mut file = File::create("encrypted.bin")?;
///     file.write_all(&encrypted_data)?;
/// }
///
/// // Later, read and decrypt from the file
/// let file = File::open("encrypted.bin")?;
/// let reader = BufReader::new(file); // Using BufReader for efficiency
///
/// let decrypted = decrypt_from_stream(reader, &keypair.private_key)?;
/// assert_eq!(decrypted, "file content example");
/// # Ok(())
/// # }
/// ```
pub fn decrypt_from_stream<R: Read>(reader: R, private_key: &SecretKey) -> Result<String> {
    let mut buf_reader = BufReader::new(reader);
    decrypt_from_reader(&mut buf_reader, private_key)
}

/// Decrypts data from a byte slice.
///
/// # Deprecated
///
/// This function is deprecated and will be removed in future versions.
/// Please use `decrypt_from_reader` or `decrypt_from_stream` instead.
#[deprecated(
    since = "4.2.0",
    note = "This function is deprecated for better API consistency. Use `decrypt_from_reader` instead."
)]
pub fn decrypt(encrypted_data: &[u8], private_key: &SecretKey) -> Result<String> {
    let reader = SliceReader::new(encrypted_data);
    decrypt_from_reader(reader, private_key)
}