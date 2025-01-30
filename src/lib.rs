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
    pub ciphertext: String,    // Ciphertext de Kyber (encapsulación)
    pub nonce: String,         // Nonce para ChaCha20Poly1305
    pub encrypted_msg: String, // Mensaje cifrado
}

pub fn encrypt(server_pubkey: &PublicKey, message: &[u8]) -> Result<String> {
    // 1. Cliente encapsula un secreto compartido
    let (kyber_ciphertext, shared_secret) = encapsulate(server_pubkey, &mut rand::thread_rng())
        .map_err(|e| anyhow!("Encapsulación fallida: {}", e))?;

    debug_assert_eq!(kyber_ciphertext.as_bytes().len(), KYBER_CIPHERTEXT_BYTES);

    // 2. Derivar clave para ChaCha20Poly1305
    let chacha_key = derive_chacha_key(&shared_secret);

    // 3. Cifrar el mensaje
    let (nonce, ciphertext) = encrypt_with_key(&chacha_key, message)?;

    // 4. Serializar datos
    let data = EncryptedData {
        ciphertext: general_purpose::STANDARD.encode(kyber_ciphertext.as_bytes()),
        nonce: general_purpose::STANDARD.encode(nonce),
        encrypted_msg: general_purpose::STANDARD.encode(ciphertext),
    };

    serde_json::to_string(&data).context("Error al serializar")
}

pub fn decrypt(encrypted_data: &str, server_kp: &Keypair) -> Result<String> {
    let data: EncryptedData = serde_json::from_str(encrypted_data)?;

    // Decodificar componentes
    let kyber_ciphertext = general_purpose::STANDARD.decode(&data.ciphertext)?;
    let nonce = general_purpose::STANDARD.decode(&data.nonce)?;
    let encrypted_msg = general_purpose::STANDARD.decode(&data.encrypted_msg)?;

    let kyber_ciphertext_array: [u8; KYBER_CIPHERTEXT_BYTES] = kyber_ciphertext
        .try_into()
        .map_err(|_| anyhow!("Tamaño de ciphertext inválido"))?;
    
    // Desencapsular el secreto compartido
    let shared_secret = decapsulate(&kyber_ciphertext_array, &server_kp.secret)
        .map_err(|e| anyhow!("Desencapsulación fallida: {}", e))?;

    // Derivar clave y descifrar
    let chacha_key = derive_chacha_key(&shared_secret);
    let plaintext = decrypt_with_key(&chacha_key, &nonce, &encrypted_msg)?;

    String::from_utf8(plaintext).context("UTF-8 inválido")
}