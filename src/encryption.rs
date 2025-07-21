//! Symmetric cypher using ChaCha20Poly1305 (AEAD).

use std::io::{Read, Write};
use anyhow::{anyhow, Context, Result};
use chacha20poly1305::{
    aead::{AeadCore, AeadMutInPlace, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use chacha20poly1305::aead::{Aead, Payload};
use crate::IoRWrapper;

pub(crate) fn encrypt_with_key_stream<R: Read, W: Write> (
    key: &[u8; 32],
    reader: &mut R,
    writer: &mut W,
) -> Result<()> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .context("Invalid key length")?;

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    writer
        .write_all(&nonce)
        .context("Error writing nonce")?;

    let mut buf = [0u8; 4096]; // 4KB Buffer

    while let Ok(n) = reader.read(&mut buf) {
        if n == 0 { break; }
        let ct_chunk = cipher
            .encrypt(&nonce, Payload::from(&buf[..n]))
            .map_err(|e| anyhow::anyhow!("Error while encrypting the chunk: {}", e))?;
        let len = ct_chunk.len() as u64;
        writer
            .write_all(&len.to_le_bytes())
            .context("Error while writing len")?;
        writer
            .write_all(&ct_chunk)
            .context("Error while writing chunk")?;
    }
    Ok(())
}

pub(crate) fn decrypt_with_key_stream<R: Read, W: Write>(key: &[u8; 32], nonce: &[u8], mut reader: IoRWrapper<R>, mut writer: W) -> Result<()> {
    let mut cipher = ChaCha20Poly1305::new_from_slice(key).context("Invalid key length")?;

    let nonce = Nonce::from_slice(nonce);
    loop {
        let mut len_bytes = [0u8; 8];
        match reader.0.read_exact(&mut len_bytes) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("Fallo al leer la longitud del fragmento"),
        }

        let len = u64::from_le_bytes(len_bytes) as usize;
        let mut ct_chunk = vec![0u8; len];
        reader.0.read_exact(&mut ct_chunk)?;

        cipher
            .decrypt_in_place(nonce, b"", &mut ct_chunk)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        writer.write_all(&ct_chunk)?;
    }


    Ok(())
}