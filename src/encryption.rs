use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{AeadCore, AeadMutInPlace, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce
};

pub fn encrypt_with_key(
    key: &[u8; 32],
    plaintext: &[u8]
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut cipher = ChaCha20Poly1305::new_from_slice(key)  // Remover mut
        .context("Invalid key length")?;

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut buffer = plaintext.to_vec();

    cipher.encrypt_in_place(&nonce, b"", &mut buffer)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    Ok((nonce.to_vec(), buffer))
}
pub fn decrypt_with_key(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8]
) -> Result<Vec<u8>> {
    let mut cipher = ChaCha20Poly1305::new_from_slice(key)
        .context("Invalid key length")?;

    let nonce = Nonce::from_slice(nonce);
    let mut buffer = ciphertext.to_vec();

    cipher.decrypt_in_place(nonce, b"", &mut buffer)
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;

    Ok(buffer)
}