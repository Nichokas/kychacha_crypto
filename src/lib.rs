// lib.rs

//! Post-quantum hybrid encryption using ML-KEM (Kyber) + ChaCha20-Poly1305 with optional Dilithium signatures.
//! Features choose KEM level and buffer size; defaults aim for balanced security and performance.
//!
//! Quick example:
//! ```
//! use std::io::Cursor;
//! use kychacha_crypto::{generate_keypair, encrypt_stream, decrypt_stream};
//! let kp = generate_keypair().unwrap();
//! let mut ct = Vec::new();
//! encrypt_stream(kp.public_key.clone(), &mut Cursor::new(b"hi"), &mut ct).unwrap();
//! let mut pt = Vec::new();
//! decrypt_stream(&kp.private_key, &mut Cursor::new(ct), &mut pt).unwrap();
//! assert_eq!(&pt, b"hi");
//! ```
//! Multi-recipient encrypts once for many recipients (each gets a wrapped content key) and is O(n) only in header size.
//!
//! # Security notes
//! * Each recipient incurs one ML-KEM encapsulation (O(n)).
//! * Payload is encrypted only once (constant time w.r.t recipients) with ChaCha20-Poly1305.
//! * Unknown recipient keys simply fail to unwrap; no partial leakage.
//! * Consider size: header grows roughly (kem_ct_len + 12 + 32 + 16) per recipient.
//!
//! # When to use
//! * Broadcast to small/medium groups (tens / low hundreds) efficiently.
//! * Avoid re-encrypting large payloads per recipient.
//!
//! # When not to use
//! * Extremely large recipient lists (may become bandwidth heavy) — consider distributing the symmetric key via another channel.

use sha2::Digest;
mod encryption;
mod key_exchange;
#[cfg(test)]
mod tests;
mod types;

use anyhow::Result;
use bincode::config::Config;
use bincode::de::read::Reader;
use bincode::enc::write::Writer;
use bincode::{decode_from_reader, encode_into_writer};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use encryption::*;
use key_exchange::derive_chacha_key;
pub use key_exchange::{generate_keypair, generate_keypair_with_level};
use oqs;
use oqs::{kem, sig};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Write};
use sha2::Sha512;
pub use types::{SecurityLevel, SignSecurityLevel};
pub use types::{MlKemKeyPair, PublicKey, SecretKey};
use crate::types::{SignPublicKey, SignSecretKey};

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

pub(crate) fn given_oqs() -> Result<(SecurityLevel, Option<SignSecurityLevel>, kem::Kem, Option<sig::Sig>)> {
    #[cfg(not(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024")))]
    {
        anyhow::bail!("No ML-KEM algorithm feature selected")
    }

    oqs::init();
    let mut lkem: Option<kem::Algorithm> = None;
    let mut security: Option<SecurityLevel> = None;
    let mut lsig: Option<sig::Algorithm> = None;
    let mut signsecurity: Option<SignSecurityLevel> = None;
    let mut sig_instance: Option<sig::Sig> = None;

    #[cfg(feature = "mlkem512")]
    {
        lkem = Some(kem::Algorithm::MlKem512);
        security = Some(SecurityLevel::MlKem512);
    }
    #[cfg(feature = "mlkem768")]
    {
        lkem = Some(kem::Algorithm::MlKem768);
        security = Some(SecurityLevel::MlKem768);
    }
    #[cfg(feature = "mlkem1024")]
    {
        lkem = Some(kem::Algorithm::MlKem1024);
        security = Some(SecurityLevel::MlKem1024);
    }

    #[cfg(feature = "dilithium2")]
    {
        lsig = Some(sig::Algorithm::Dilithium2);
        signsecurity = Some(SignSecurityLevel::Dilithium2);
    }
    #[cfg(feature = "dilithium3")]
    {
        lsig = Some(sig::Algorithm::Dilithium3);
        signsecurity = Some(SignSecurityLevel::Dilithium3);
    }
    #[cfg(feature = "dilithium5")]
    {
        lsig = Some(sig::Algorithm::Dilithium5);
        signsecurity = Some(SignSecurityLevel::Dilithium5);
    }

    if let Some(alg) = lsig {
        if let Ok(s) = sig::Sig::new(alg) {
            sig_instance = Some(s);
        }
    }

    Ok((security.unwrap(), signsecurity, kem::Kem::new(lkem.unwrap()).map_err(|e| anyhow::anyhow!("Failed to initialize ML-KEM: {}", e))?, sig_instance))
}

pub(crate) fn select_oqs(sec: &SecurityLevel, sign_sec: Option<&SignSecurityLevel>) -> Result<(kem::Kem, Option<sig::Sig>)> {
    oqs::init();

    // Select KEM algorithm based on security level
    let kem = match sec {
        SecurityLevel::MlKem512 => kem::Kem::new(kem::Algorithm::MlKem512)
            .map_err(|e| anyhow::anyhow!("Failed to initialize ML-KEM-512: {}", e))?,
        SecurityLevel::MlKem768 => kem::Kem::new(kem::Algorithm::MlKem768)
            .map_err(|e| anyhow::anyhow!("Failed to initialize ML-KEM-768: {}", e))?,
        SecurityLevel::MlKem1024 => kem::Kem::new(kem::Algorithm::MlKem1024)
            .map_err(|e| anyhow::anyhow!("Failed to initialize ML-KEM-1024: {}", e))?,
    };

    let sig = if let Some(sign_level) = sign_sec {
        let sig_alg = match sign_level {
            SignSecurityLevel::Dilithium2 => sig::Algorithm::Dilithium2,
            SignSecurityLevel::Dilithium3 => sig::Algorithm::Dilithium3,
            SignSecurityLevel::Dilithium5 => sig::Algorithm::Dilithium5,
        };

        Some(sig::Sig::new(sig_alg)
            .map_err(|e| anyhow::anyhow!("Failed to initialize signature algorithm: {}", e))?)
    } else {
        None
    };

    Ok((kem, sig))
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

/// Hybrid encryption (KEM encapsulation + streaming AEAD). See crate docs for an example.
pub fn encrypt_stream<R: Read, W: Write>(
    server_pubkey: PublicKey,
    reader: &mut R,
    io_writer: &mut W,
) -> Result<()> {
    let (kem,_) = select_oqs(&server_pubkey.security, None)?;

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

pub fn encrypt_multiple_recipient<R: Read, W: Write>(
    server_pubkeys: Vec<PublicKey>,
    reader: &mut R,
    io_writer: &mut W,
) -> Result<()> {
    let mut ckt = [0u8; 32];
    getrandom::fill(&mut ckt).unwrap();
    let mut writer = IoWWrapper(io_writer);

    let mut for_all_k: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for pubk in server_pubkeys {
        let (kem,_) = select_oqs(&pubk.security, None)?;

        let (ct, ss) = kem
            .encapsulate(&pubk.key)
            .map_err(|e| anyhow::anyhow!("Failed to encapsulate with public key: {}", e))?;

        let chacha_key = derive_chacha_key(ss)?;
        // One-shot AEAD encrypt of the content key (ckt)
        let cipher = ChaCha20Poly1305::new_from_slice(&chacha_key)
            .map_err(|e| anyhow::anyhow!("Invalid key length: {}", e))?;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut sink = Vec::with_capacity(12 + 32 + 16);
        sink.extend_from_slice(&nonce);
        let encrypted_ckt = cipher
            .encrypt(&nonce, ckt.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to encrypt content key: {}", e))?;
        sink.extend_from_slice(&encrypted_ckt);

        for_all_k.push((ct.into_vec(), sink));
    }

    let config = match select_bincode_config() {
        Ok(config) => config,
        Err(_) => anyhow::bail!(
            "The bincode (kychacha_crypto crate) configuration feature flag is not properly configured."
        ),
    };

    encode_into_writer(for_all_k, &mut writer, config)?;

    encrypt_with_key_stream(&ckt, reader, &mut writer.0)?;

    Ok(())
}

/// Decrypt counterpart to `encrypt_stream`.
pub fn decrypt_stream<R: Read, W: Write>(
    private_key: &SecretKey,
    io_reader: &mut R,
    writer: &mut W,
) -> Result<()> {
    let (kem,_) = select_oqs(&private_key.security, None)?;

    let mut reader = IoRWrapper(io_reader);

    let config = match select_bincode_config() {
        Ok(config) => config,
        Err(_) => anyhow::bail!(
            "The bincode (kychacha_crypto crate) configuration feature flag is not properly configured."
        ),
    };

    let ct_bytes: Vec<u8> = bincode::decode_from_reader(&mut reader, config)?;
    let ct = kem
        .ciphertext_from_bytes(&ct_bytes)
        .ok_or_else(|| anyhow::anyhow!("Error while retreating the ciphertext from bytes"))?;

    let ss = kem
        .decapsulate(&private_key.key, &ct)
        .map_err(|e| anyhow::anyhow!("Error decapsulating KEM: {}", e))?;
    let chacha_key = derive_chacha_key(ss)?;

    let mut nonce_bytes = [0u8; 12];
    reader.0.read_exact(&mut nonce_bytes)?;

    decrypt_with_key_stream(&chacha_key, &nonce_bytes, reader, writer)?;

    Ok(())
}

pub fn decrypt_multiple_recipient<R: Read, W: Write>(
    private_key: &SecretKey,
    io_reader: &mut R,
    writer: &mut W,
) -> Result<()> {
    let (kem,_) = select_oqs(&private_key.security, None)?;
    let mut reader = IoRWrapper(io_reader);

    let config = match select_bincode_config() {
        Ok(config) => config,
        Err(_) => anyhow::bail!(
            "The bincode (kychacha_crypto crate) configuration feature flag is not properly configured."
        ),
    };

    let all_keys: Vec<(Vec<u8>, Vec<u8>)> = decode_from_reader(&mut reader, config)?;
    let mut ckt_opt: Option<[u8; 32]> = None;

    for (ciph, encr) in all_keys {
        let ct = kem
            .ciphertext_from_bytes(&ciph)
            .ok_or_else(|| anyhow::anyhow!("Error while retreating the ciphertext from bytes"))?;

        if let Ok(ss) = kem.decapsulate(&private_key.key, &ct) {
            let key = derive_chacha_key(ss)?;
            if encr.len() < 12 + 16 {
                // nonce + minimum tag
                continue;
            }
            let nonce = &encr[0..12];
            let ct_ckt = &encr[12..];
            let cipher = ChaCha20Poly1305::new_from_slice(&key)
                .map_err(|e| anyhow::anyhow!("Invalid key length: {}", e))?;
            if let Ok(plain_ckt) = cipher.decrypt(nonce.into(), ct_ckt) {
                if plain_ckt.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&plain_ckt);
                    ckt_opt = Some(arr);
                    break;
                }
            }
        }
    }

    if ckt_opt.is_none() {
        anyhow::bail!("Your key is not included on the recipients of this message/file")
    }

    // Decrypt the actual data with the recovered content key
    let mut nonce_bytes = [0u8; 12];
    reader.0.read_exact(&mut nonce_bytes)?;

    decrypt_with_key_stream(&ckt_opt.unwrap(), &nonce_bytes, reader, writer)?;

    Ok(())
}

/// Stream-sign data (SHA-512 digest then Dilithium signature) writing a bincode-serialized signature.
pub fn sign_stream<R: Read, W: Write>(private_sign_key: &SignSecretKey, reader: &mut R, writer: &mut W) -> Result<()>{
    let (_, sig_opt) = select_oqs(&SecurityLevel::MlKem768, Some(&private_sign_key.security))?;
    let sig = sig_opt.ok_or_else(|| anyhow::anyhow!("No signature algorithm available"))?;

    let mut hasher = Sha512::new();

    // Read and hash data in chunks
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    // Get the final hash
    let hash = hasher.finalize();

    // Sign the hash
    let signature = sig.sign(hash.as_ref(), &private_sign_key.key)
        .map_err(|e| anyhow::anyhow!("Failed to sign data: {}", e))?;

    // Use bincode for structured serialization
    let config = select_bincode_config()?;
    let mut io_writer = IoWWrapper(writer);
    encode_into_writer(signature.into_vec(), &mut io_writer, config)?;

    Ok(())
}

/// Verify a detached stream signature created by `sign_stream`.
pub fn verify_stream<R: Read, S: Read>(
    public_sign_key: &SignPublicKey,
    data_reader: &mut R,
    signature_reader: &mut S
) -> Result<bool> {
    let (_, sig_opt) = select_oqs(&SecurityLevel::MlKem768, Some(&public_sign_key.security))?;
    let sig = sig_opt.ok_or_else(|| anyhow::anyhow!("No signature algorithm available"))?;

    let mut hasher = Sha512::new();

    // Read and hash data in chunks
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let bytes_read = data_reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    // Get the final hash
    let hash = hasher.finalize();

    // Deserialize signature using bincode
    let config = select_bincode_config()?;
    let mut io_reader = IoRWrapper(signature_reader);
    let signature_bytes: Vec<u8> = decode_from_reader(&mut io_reader, config)?;

    // Create signature from bytes
    let signature = sig.signature_from_bytes(&signature_bytes)
        .ok_or_else(|| anyhow::anyhow!("Invalid signature format"))?;

    // Verify the signature
    match sig.verify(hash.as_ref(), &signature, &public_sign_key.key) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Deprecated: use `decrypt_stream`.
#[deprecated(
    since = "4.2.0",
    note = "This function is deprecated because it's susceptible to OOM attacks. Use `decrypt_from_stream` instead."
)]
pub fn decrypt(encrypted_data: &[u8], private_key: &SecretKey) -> Result<String> {
    let mut buf = Vec::new();
    decrypt_stream(private_key, &mut Cursor::new(encrypted_data), &mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into())
}

/// Deprecated: use `encrypt_stream`.
#[deprecated(
    since = "4.2.0",
    note = "This function is deprecated because it's susceptible to OOM attacks. Use `decrypt_from_stream` instead."
)]
pub fn encrypt(server_pubkey: PublicKey, message: &[u8]) -> Result<Vec<u8>> {
    let mut sink = Vec::new();
    encrypt_stream(server_pubkey, &mut Cursor::new(message), &mut sink)?;

    Ok(sink)
}
