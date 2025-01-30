mod key_exchange;
mod encryption;
mod tests;

pub use key_exchange::*;
pub use encryption::*;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use kyberlib::{Keypair, PublicKey, encapsulate, decapsulate, KYBER_CIPHERTEXT_BYTES};
use serde::{Deserialize, Serialize};
use zerocopy::AsBytes;

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData {
    pub ciphertext: String,    // Ciphertext of Kyber (encapsulation)
    pub nonce: String,         // Nonce for ChaCha20Poly1305
    pub encrypted_msg: String, // Encrypted message
}

pub fn encrypt(server_pubkey: &PublicKey, message: &[u8]) -> Result<String> {
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
        ciphertext: general_purpose::STANDARD.encode(kyber_ciphertext.as_bytes()),
        nonce: general_purpose::STANDARD.encode(nonce),
        encrypted_msg: general_purpose::STANDARD.encode(ciphertext),
    };

    serde_json::to_string(&data).context("Error while serializing data")
}

pub fn decrypt(encrypted_data: &str, server_kp: &Keypair) -> Result<String> {
    let data: EncryptedData = serde_json::from_str(encrypted_data)?;

    // Decode components
    let kyber_ciphertext = general_purpose::STANDARD.decode(&data.ciphertext)?;
    let nonce = general_purpose::STANDARD.decode(&data.nonce)?;
    let encrypted_msg = general_purpose::STANDARD.decode(&data.encrypted_msg)?;

    let kyber_ciphertext_array: [u8; KYBER_CIPHERTEXT_BYTES] = kyber_ciphertext
        .try_into()
        .map_err(|_| anyhow!("Invalid size of ciphertext"))?;
    
    // Uncapsulate shared secret
    let shared_secret = decapsulate(&kyber_ciphertext_array, &server_kp.secret)
        .map_err(|e| anyhow!("Uncapsulation failed: {}", e))?;

    // Derivate key and decode
    let chacha_key = derive_chacha_key(&shared_secret);
    let plaintext = decrypt_with_key(&chacha_key, &nonce, &encrypted_msg)?;

    String::from_utf8(plaintext).context("Invalid UTF-8")
}