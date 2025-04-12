//! Symmetric cypher using ChaCha20Poly1305 (AEAD).

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{AeadCore, AeadMutInPlace, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};

/// Encrypt a message with ChaCha20Poly1305.
///
/// # Example
/// ```
/// use kychacha_crypto::encrypt_with_key;
///
/// // do not use this on your code, instead use encrypt fn
/// let key = [0u8; 32];
/// let (nonce, cifrado) = encrypt_with_key(&key, b"mensaje").unwrap();
/// ```
///
/// # Errores
/// - key ≠ 32 bytes
/// - Error while encrypting
pub fn encrypt_with_key(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut cipher = ChaCha20Poly1305::new_from_slice(key) // Remover mut
        .context("Invalid key length")?;

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut buffer = plaintext.to_vec();

    cipher
        .encrypt_in_place(&nonce, b"", &mut buffer)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    Ok((nonce.to_vec(), buffer))
}

/// Decrypt a message with ChaCha20Poly1305.
///
/// # Example
/// ```
/// use kychacha_crypto::{decrypt_with_key, encrypt_with_key};
///
/// let key = [0u8; 32];
/// // do not use this on your code, instead use encrypt fn
/// let (nonce, encrypted) = encrypt_with_key(&key, b"mensaje").unwrap();
/// // do not use this on your code, instead use decrypt fn
/// let decrypted_text = decrypt_with_key(&key, &nonce, &encrypted).unwrap();
/// ```
///
/// # Errores
/// - Key ≠ 32 bytes or nonce ≠ 12 bytes
/// - Failed auth or corruption on the data
pub fn decrypt_with_key(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut cipher = ChaCha20Poly1305::new_from_slice(key).context("Invalid key length")?;

    let nonce = Nonce::from_slice(nonce);
    let mut buffer = ciphertext.to_vec();

    cipher
        .decrypt_in_place(nonce, b"", &mut buffer)
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;

    Ok(buffer)
}
