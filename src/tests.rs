// tests/test.rs
use crate::{MlKemKeyPair, TestData};
use crate::{
    bytes_to_public_key, bytes_to_secret_key, decrypt_from_stream, encrypt, generate_keypair, EncryptedData, decrypt_from_reader
};
use anyhow::{Context, Result};
use bincode::serde::{decode_from_slice, encode_to_vec};
use std::fs::File;
use std::io::{BufReader, Write};
use std::error::Error;
use bincode::de::read::SliceReader;

#[test]
fn test_round_trip() -> Result<(), Box<dyn Error>> {
    let keypair = generate_keypair()?;
    let encrypted_data = encrypt(keypair.public_key, b"secret message")?;
    let reader = SliceReader::new(&encrypted_data);
    let decrypted = decrypt_from_reader(reader, &keypair.private_key)?;
    assert_eq!(decrypted, "secret message");
    Ok(())
}

#[test]
fn test_tampered_ciphertext() {
    let server_kp = generate_keypair().unwrap();
    let encrypted = encrypt(server_kp.public_key, "test".as_bytes()).unwrap();

    // Configuración estándar para bincode
    let config = bincode::config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    let (mut data, _): (EncryptedData, usize) = decode_from_slice(&encrypted, config).unwrap();

    // Corrupt Kyber ciphertext
    data.ciphertext[0] ^= 0x01;

    let tampered_data = encode_to_vec(&data, config).unwrap();
    let reader = SliceReader::new(&tampered_data);
    let result = decrypt_from_reader(reader, &server_kp.private_key);
    assert!(result.is_err());
}

#[test]
fn test_tampered_nonce() {
    let server_kp = generate_keypair().unwrap();
    let encrypted = encrypt(server_kp.public_key, "test".as_bytes()).unwrap();

    // Standard configuration for bincode
    let config = bincode::config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    let (mut data, _): (EncryptedData, usize) = decode_from_slice(&encrypted, config).unwrap();

    // Corrupt nonce
    data.nonce[0] ^= 0x01;

    let tampered_data = encode_to_vec(&data, config).unwrap();
    let reader = SliceReader::new(&tampered_data);
    let result = decrypt_from_reader(reader, &server_kp.private_key);
    assert!(result.is_err());
}

#[test]
fn test_empty_message() -> Result<()> {
    let server_kp = generate_keypair()?;
    let msg = "";

    let encrypted = encrypt(server_kp.public_key, msg.as_bytes())?;
    let reader = SliceReader::new(&encrypted);
    let decrypted = decrypt_from_reader(reader, &server_kp.private_key)?;

    assert_eq!(decrypted, msg);
    Ok(())
}

#[test]
fn test_large_message() -> Result<()> {
    let server_kp = generate_keypair()?;
    let msg = "A".repeat(10_000);

    let encrypted = encrypt(server_kp.public_key, msg.as_bytes())?;
    let reader = SliceReader::new(&encrypted);
    let decrypted = decrypt_from_reader(reader, &server_kp.private_key)?;

    assert_eq!(decrypted, msg);
    Ok(())
}

#[test]
fn test_wrong_key_decryption() {
    let server_kp = generate_keypair().unwrap();
    let attacker_kp = generate_keypair().unwrap();
    let msg = "Confidential message.";

    let encrypted = encrypt(server_kp.public_key, msg.as_bytes()).unwrap();
    let reader = SliceReader::new(&encrypted);
    let result = decrypt_from_reader(reader, &attacker_kp.private_key);

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

    let secret_key = bytes_to_secret_key(&test_data.secret_key)?;
    let public_key = bytes_to_public_key(&test_data.public_key)?;
    
    // Crear keypair directamente con las claves cargadas
    let server_kp:MlKemKeyPair = MlKemKeyPair {
        public_key: public_key.clone(),
        private_key: secret_key.clone()
    };

    let reader = SliceReader::new(&test_data.encrypted_data);
    let decrypted = decrypt_from_reader(reader, &server_kp.private_key)?;
    assert_eq!(decrypted, "Testing... 1234; quantum??? :3");
    Ok(())
}

#[test]
fn file_round_trip() -> Result<(), Box<dyn Error>> {
        let keypair = generate_keypair()?;
        let encrypted_data = encrypt(keypair.public_key, b"file content example")?;
        {
            let mut file = File::create("encrypted.bin")?;
            file.write_all(&encrypted_data)?;
        }
        let file = File::open("encrypted.bin")?;
        let reader = BufReader::new(file);
        let decrypted = decrypt_from_stream(reader, &keypair.private_key)?;
        assert_eq!(decrypted, "file content example");
        Ok(())

}