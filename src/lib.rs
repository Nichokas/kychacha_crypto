// lib.rs

//! # Features
//! |Name|Default?|What does it do?                     |
//! |----|--------|-------------------------------------|
//! |mlkem512|x|Select Ml-Kem security level to 512 (private key size)|
//! |mlkem768|✅|Select Ml-Kem security level to 768 (private key size)|
//! |mlkem1024|x|Select Ml-Kem security level to 1024 (private key size)|
//! |small-buffer|x|Use a 4 KB buffer for encryption and decryption (files < 1 MB), for environments with very restricted amount of ram|
//! |recommended-buffer|✅|Use a 64 KB buffer for encryption and decryption (files < 100 MB), recommended value for most use cases.|
//! |medium-buffer|✅|Use a 8 MB buffer for encryption and decryption (files 100 MB–5 GB), recommended for large files: logs, CSV/JSON, et cetera.|
//! |large-buffer|x|Use a 1GB buffer for encryption and decryption (files > 5 GB), recommended for extremely large files like backups and 4K/8K video without compression.|
//! # A Simple Example
//! ```
//! use std::error::Error;
//! use kychacha_crypto::{decrypt_stream, encrypt_stream, generate_keypair};
//! use std::io::Cursor;
//!
//! fn main() -> Result<(), Box<dyn Error>> {
//!     // Generate keypairs for alice and bob
//!     let alice_keypair = generate_keypair()?;
//!     let bob_keypair = generate_keypair()?;
//!
//!     // sink for storing the encrypted data
//!     let mut sink = Vec::new();
//!
//!     // encrypt the text to bob
//!     encrypt_stream(bob_keypair.public_key, &mut Cursor::new(b"Hi bob! :D"), &mut sink)?;
//!
//!     let mut decrypted_bytes = Vec::new();
//!
//!     decrypt_stream(&bob_keypair.private_key, &mut Cursor::new(sink), &mut decrypted_bytes)?;
//!
//!     assert_eq!(String::from_utf8_lossy(&decrypted_bytes), "Hi bob! :D");
//!     Ok(())
//! }
//! ```
//!
//! # A Example With files
mod encryption;
mod key_exchange;
#[cfg(test)]
mod tests;
mod types;

use anyhow::Result;
use bincode::config::Config;
use bincode::de::read::Reader;
use bincode::enc::write::Writer;
use bincode::encode_into_writer;
use encryption::*;
use key_exchange::derive_chacha_key;
pub use key_exchange::generate_keypair;
use oqs;
use oqs::kem;
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Write};
pub(crate) use types::SecurityLevel;
pub use types::{MlKemKeyPair, PublicKey, SecretKey};

#[cfg(feature = "small-buffer")]
pub(crate) const BUFFER_SIZE: usize = 4 * 1024;
#[cfg(feature = "recommended-buffer")]
pub(crate) const BUFFER_SIZE: usize = 64 * 1024;
#[cfg(feature = "medium-buffer")]
pub(crate) const BUFFER_SIZE: usize = 8 * 1024 * 1024;
#[cfg(feature = "large-buffer")]
pub(crate) const BUFFER_SIZE: usize = 1 * 1024 * 1024 * 1024;

/// (only for tests)
#[derive(Serialize, Deserialize)]
pub(crate) struct TestData {
    #[serde(with = "serde_bytes")]
    pub secret_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    pub encrypted_data: Vec<u8>,
}

pub(crate) fn given_oqs() -> Result<(SecurityLevel, kem::Kem)> {
    oqs::init();

    #[cfg(feature = "mlkem512")]
    {
        return Ok((
            SecurityLevel::MlKem512,
            kem::Kem::new(kem::Algorithm::MlKem512)
                .map_err(|e| anyhow::anyhow!("Failed to initialize ML-KEM-512: {}", e))?,
        ));
    }

    #[cfg(feature = "mlkem768")]
    {
        return Ok((
            SecurityLevel::MlKem768,
            kem::Kem::new(kem::Algorithm::MlKem768)
                .map_err(|e| anyhow::anyhow!("Failed to initialize ML-KEM-768: {}", e))?,
        ));
    }

    #[cfg(feature = "mlkem1024")]
    {
        return Ok((
            SecurityLevel::MlKem1024,
            kem::Kem::new(kem::Algorithm::MlKem1024)
                .map_err(|e| anyhow::anyhow!("Failed to initialize ML-KEM-1024: {}", e))?,
        ));
    }

    // Default fallback if no feature is enabled
    anyhow::bail!("No ML-KEM algorithm feature selected")
}

pub(crate) fn select_oqs(sec: &SecurityLevel) -> Result<kem::Kem> {
    oqs::init();
    if sec == &SecurityLevel::MlKem512 {
        return kem::Kem::new(kem::Algorithm::MlKem512)
            .map_err(|e| anyhow::anyhow!("Failed to initialize ML-KEM-512: {}", e));
    }

    if sec == &SecurityLevel::MlKem768 {
        return kem::Kem::new(kem::Algorithm::MlKem768)
            .map_err(|e| anyhow::anyhow!("Failed to initialize ML-KEM-768: {}", e));
    }

    if sec == &SecurityLevel::MlKem1024 {
        return kem::Kem::new(kem::Algorithm::MlKem1024)
            .map_err(|e| anyhow::anyhow!("Failed to initialize ML-KEM-1024: {}", e));
    }

    anyhow::bail!("No ML-KEM with the specified security level found.");
}

fn select_bincode_config() -> Result<impl Config> {
    Ok(bincode::config::standard()
        .with_big_endian()
        .with_variable_int_encoding())
}

struct IoWWrapper<W: Write>(pub W);

impl<W: Write> Writer for IoWWrapper<W> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), bincode::error::EncodeError> {
        self.0
            .write_all(bytes)
            .map_err(|e| bincode::error::EncodeError::Io { inner: e, index: 0 })
    }
}

struct IoRWrapper<R: Read>(pub R);

impl<R: Read> Reader for IoRWrapper<R> {
    fn read(&mut self, bytes: &mut [u8]) -> Result<(), bincode::error::DecodeError> {
        self.0
            .read_exact(bytes)
            .map_err(|e| bincode::error::DecodeError::Io {
                inner: e,
                additional: 0,
            })
    }
}

/// Hybrid encryption with Kyber + ChaCha
/// # Example
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use std::fs::File;
/// use std::io::{Cursor, Write};
/// use kychacha_crypto::{encrypt_stream, generate_keypair};
///
/// // Generate keypair
/// let keypair = generate_keypair()?;
///
/// // Create file and get writer
/// let mut file = File::create("encrypted.bin")?;
///
/// // Encrypt data
/// encrypt_stream(keypair.public_key, &mut Cursor::new(b"file content example"), &mut file)?;
///
/// // Now the encrypted.bin file contains the encrypted data
/// # Ok(())
/// # }
/// ```
pub fn encrypt_stream<R: Read, W: Write>(
    server_pubkey: PublicKey,
    reader: &mut R,
    io_writer: &mut W,
) -> Result<()> {
    let kem = select_oqs(&server_pubkey.security)?;

    let (ct, ss) = kem
        .encapsulate(&server_pubkey.key)
        .map_err(|e| anyhow::anyhow!("Failed to encapsulate with public key: {}", e))?;

    let chacha_key = derive_chacha_key(ss)?;

    let config = match select_bincode_config() {
        Ok(config) => config,
        Err(_) => anyhow::bail!(
            "The bincode (kychacha_crypto crate) configuration feature flag is not properly configured."
        ),
    };

    let mut writer = IoWWrapper(io_writer);

    encode_into_writer(ct.into_vec(), &mut writer, config)?;

    encrypt_with_key_stream(&chacha_key, reader, &mut writer.0)?;

    Ok(())
}

/// Decrypts data from a stream that implements std::io::Read
///
/// # Example showing file-based usage
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use std::fs::File;
/// use std::io::Cursor;
/// use kychacha_crypto::{decrypt_stream, encrypt_stream, generate_keypair};
///
/// // Generate keypair
/// let keypair = generate_keypair()?;
///
/// // First, create some encrypted data
/// let mut encrypted_data = Vec::new();
/// encrypt_stream(keypair.public_key, &mut Cursor::new(b"hello world"), &mut encrypted_data)?;
///
/// // Now decrypt it
/// let mut decrypted_data = Vec::new();
/// decrypt_stream(&keypair.private_key, &mut Cursor::new(encrypted_data), &mut decrypted_data)?;
///
/// assert_eq!(String::from_utf8_lossy(&decrypted_data), "hello world");
/// # Ok(())
/// # }
/// ```
pub fn decrypt_stream<R: Read, W: Write>(
    private_key: &SecretKey,
    reader: &mut R,
    writer: &mut W,
) -> Result<()> {
    let kem = select_oqs(&private_key.security)?;

    let mut wreader = IoRWrapper(reader);

    let config = match select_bincode_config() {
        Ok(config) => config,
        Err(_) => anyhow::bail!(
            "The bincode (kychacha_crypto crate) configuration feature flag is not properly configured."
        ),
    };

    let ct_bytes: Vec<u8> = bincode::decode_from_reader(&mut wreader, config)?;
    let ct = kem
        .ciphertext_from_bytes(&ct_bytes)
        .ok_or_else(|| anyhow::anyhow!("Error while retreating the ciphertext from bytes"))?;

    let ss = kem
        .decapsulate(&private_key.key, &ct)
        .map_err(|e| anyhow::anyhow!("Error decapsulating KEM: {}", e))?;
    let chacha_key = derive_chacha_key(ss)?;

    let mut nonce_bytes = [0u8; 12];
    wreader.0.read_exact(&mut nonce_bytes)?;

    decrypt_with_key_stream(&chacha_key, &nonce_bytes, wreader, writer)?;

    Ok(())
}

/// Decrypts data from a byte slice.
///
/// # Deprecated
///
/// This function is deprecated and will be removed in future versions.
/// Please use `decrypt_stream` instead.
#[deprecated(
    since = "4.2.0",
    note = "This function is deprecated because it's susceptible to OOM attacks. Use `decrypt_from_stream` instead."
)]
pub fn decrypt(encrypted_data: &[u8], private_key: &SecretKey) -> Result<String> {
    let mut buf = Vec::new();
    decrypt_stream(
        private_key,
        &mut std::io::Cursor::new(encrypted_data),
        &mut buf,
    )?;
    Ok(String::from_utf8_lossy(&buf).into())
}

/// Encrypts data from a &[[u8]].
///
/// # Deprecated
///
/// This function is deprecated and will be removed in future versions.
/// Please use `encrypt_stream` instead.
#[deprecated(
    since = "4.2.0",
    note = "This function is deprecated because it's susceptible to OOM attacks. Use `decrypt_from_stream` instead."
)]
pub fn encrypt(server_pubkey: PublicKey, message: &[u8]) -> Result<Vec<u8>> {
    let mut sink = Vec::new();
    encrypt_stream(server_pubkey, &mut Cursor::new(message), &mut sink)?;

    Ok(sink)
}
