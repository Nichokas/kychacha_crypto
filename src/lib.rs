mod key_exchange;
mod encryption;
mod tests;

pub use key_exchange::*;
pub use encryption::*;
pub use x25519_dalek::{PublicKey, StaticSecret};

use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use anyhow::{Context, Result};

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData {
    pub ephemeral_public: String,
    pub nonce: String,
    pub ciphertext: String,
}

pub fn encrypt(static_public: PublicKey, message: &[u8]) -> Result<String> {
    let (eph_secret, eph_public) = generate_ephemeral_keypair();
    let shared_secret = derive_shared_secret(eph_secret, &static_public);
    let chacha_key = derive_chacha_key(shared_secret, None);

    let (nonce, ciphertext) = encrypt_with_key(&chacha_key, message)?;

    let data = EncryptedData {
        ephemeral_public: general_purpose::STANDARD.encode(eph_public.as_bytes()),
        nonce: general_purpose::STANDARD.encode(nonce),
        ciphertext: general_purpose::STANDARD.encode(ciphertext),
    };

    serde_json::to_string(&data).context("Serialization failed")
}

pub fn decrypt(encrypted_data: &str, static_secret: StaticSecret) -> Result<String> {
    let data: EncryptedData = serde_json::from_str(encrypted_data)
        .context("Invalid JSON")?;

    let eph_public = general_purpose::STANDARD.decode(&data.ephemeral_public)
        .context("Invalid ephemeral public key")?;
    let eph_public = PublicKey::from(<[u8; 32]>::try_from(eph_public.as_slice())?);

    let nonce = general_purpose::STANDARD.decode(&data.nonce)
        .context("Invalid nonce")?;
    let ciphertext = general_purpose::STANDARD.decode(&data.ciphertext)
        .context("Invalid ciphertext")?;

    let shared_secret = static_secret.diffie_hellman(&eph_public);
    let chacha_key = derive_chacha_key(shared_secret, None);

    let plaintext = decrypt_with_key(&chacha_key, &nonce, &ciphertext)?;

    String::from_utf8(plaintext).context("Invalid UTF-8")
}