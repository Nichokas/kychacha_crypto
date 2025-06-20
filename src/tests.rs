// tests/test.rs
use crate::{MlKemKeyPair, TestData};
use crate::{
    bytes_to_public_key, bytes_to_secret_key, decrypt, encrypt, generate_keypair, EncryptedData,
};
use anyhow::{Context, Result};
use bincode::serde::{decode_from_slice, encode_to_vec};

#[test]
fn test_round_trip() -> Result<()> {
    let server_kp = generate_keypair();
    let msg = "Message for testing!!!";

    let encrypted = encrypt(server_kp.public_key, msg.as_bytes())?;
    let decrypted = decrypt(&encrypted, &server_kp.private_key)?;

    assert_eq!(decrypted, msg);
    Ok(())
}

#[test]
fn test_tampered_ciphertext() {
    let server_kp = generate_keypair();
    let encrypted = encrypt(server_kp.public_key, "test".as_bytes()).unwrap();

    // Configuración estándar para bincode
    let config = bincode::config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    let (mut data, _): (EncryptedData, usize) = decode_from_slice(&encrypted, config).unwrap();

    // Corrupt Kyber ciphertext
    data.ciphertext[0] ^= 0x01;

    let tampered_data = encode_to_vec(&data, config).unwrap();
    let result = decrypt(&tampered_data, &server_kp.private_key);
    assert!(result.is_err());
}

#[test]
fn test_tampered_nonce() {
    let server_kp = generate_keypair();
    let encrypted = encrypt(server_kp.public_key, "test".as_bytes()).unwrap();

    // Standard configuration for bincode
    let config = bincode::config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    let (mut data, _): (EncryptedData, usize) = decode_from_slice(&encrypted, config).unwrap();

    // Corrupt nonce
    data.nonce[0] ^= 0x01;

    let tampered_data = encode_to_vec(&data, config).unwrap();
    let result = decrypt(&tampered_data, &server_kp.private_key);
    assert!(result.is_err());
}

#[test]
fn test_empty_message() -> Result<()> {
    let server_kp = generate_keypair();
    let msg = "";

    let encrypted = encrypt(server_kp.public_key, msg.as_bytes())?;
    let decrypted = decrypt(&encrypted, &server_kp.private_key)?;

    assert_eq!(decrypted, msg);
    Ok(())
}

#[test]
fn test_large_message() -> Result<()> {
    let server_kp = generate_keypair();
    let msg = "A".repeat(10_000);

    let encrypted = encrypt(server_kp.public_key, msg.as_bytes())?;
    let decrypted = decrypt(&encrypted, &server_kp.private_key)?;

    assert_eq!(decrypted, msg);
    Ok(())
}

#[test]
fn test_wrong_key_decryption() {
    let server_kp = generate_keypair();
    let attacker_kp = generate_keypair();
    let msg = "Confidential message.";

    let encrypted = encrypt(server_kp.public_key, msg.as_bytes()).unwrap();
    let result = decrypt(&encrypted, &attacker_kp.private_key);

    assert!(result.is_err());
}

#[test]
fn test_known_vector() -> Result<()> {
    let path = "tests.bin";

    let config = bincode::config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    let metadata = std::fs::metadata(path).context(format!(
        "File '{}' not found. Run `cargo run --bin main` first",
        path
    ))?;

    let min_size = 100;

    if metadata.len() < min_size {
        anyhow::bail!(
            "Corrupted file: size {} < minimum expected {}",
            metadata.len(),
            min_size
        );
    }

    let bytes = std::fs::read(path)?;

    let (_empty, _): ((), usize) = decode_from_slice(&bytes, config)?;

    let (test_data, _): (TestData, usize) = decode_from_slice(&bytes, config)?;

    let secret_key = bytes_to_secret_key(&test_data.secret_key);
    let public_key = bytes_to_public_key(&test_data.public_key);
    
    // Crear keypair directamente con las claves cargadas
    let server_kp:MlKemKeyPair = MlKemKeyPair {
        public_key: public_key.clone(),
        private_key: secret_key.clone()
    };

    let decrypted = decrypt(&test_data.encrypted_data, &server_kp.private_key)?;
    assert_eq!(decrypted, "Testing... 1234; quantum??? :3");
    Ok(())
}