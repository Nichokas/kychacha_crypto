mod key_exchange;
mod encryption;
mod tests;

pub use encryption::*;
pub use key_exchange::*;

use anyhow::{anyhow, Context, Error, Result};
use base64::Engine as _;
use bincode::serialize;
use kyberlib::{decapsulate, encapsulate, Keypair, PublicKey, SecretKey, KYBER_CIPHERTEXT_BYTES};
use serde::{Deserialize, Serialize};
use zerocopy::AsBytes;

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData {
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,    // Kyber ciphertext
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,         // ChaCha20 nonce
    #[serde(with = "serde_bytes")]
    pub encrypted_msg: Vec<u8>, // Encrypted message
}

pub fn secret_key_to_bytes(sk: &SecretKey) -> Vec<u8> {
    sk.as_bytes().to_vec()
}

pub fn public_key_to_bytes(pk: &PublicKey) -> Vec<u8> {
    pk.as_bytes().to_vec()
}

pub fn bytes_to_secret_key(bytes: &[u8]) -> Result<SecretKey> {
    let array: [u8; KYBER_SECRET_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid secret key length"))?;
    Ok(SecretKey::from(array))
}

pub fn bytes_to_public_key(bytes: &[u8]) -> Result<PublicKey> {
    let array: [u8; KYBER_PUBLIC_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid public key length"))?;
    Ok(PublicKey::from(array))
}

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

    serialize(&data).context("Serialization error")
}

pub fn decrypt(encrypted_data: &[u8], server_kp: &Keypair) -> Result<String> {
    let data: EncryptedData = bincode::deserialize(encrypted_data)?;

    let kyber_ciphertext_array: [u8; KYBER_CIPHERTEXT_BYTES] = data.ciphertext
        .try_into()
        .map_err(|_| anyhow!("Tamaño de ciphertext inválido"))?;

    let shared_secret = decapsulate(&kyber_ciphertext_array, &server_kp.secret)
        .map_err(|e| anyhow!("Encapsulation failed: {}", e))?;
    let chacha_key = derive_chacha_key(&shared_secret);

    let plaintext = decrypt_with_key(&chacha_key, &data.nonce, &data.encrypted_msg)?;
    String::from_utf8(plaintext).context("UTF-8 inválido")
}