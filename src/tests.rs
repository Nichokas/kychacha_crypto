// tests/test.rs
use crate::TestData;
use crate::{bytes_to_public_key, bytes_to_secret_key, decrypt, encrypt, generate_keypair, EncryptedData, Keypair};
use anyhow::{Context, Result};

#[test]
fn test_round_trip() -> Result<()> {
    let server_kp = generate_keypair()?;
    let msg = "Message for testing!!!";

    let encrypted = encrypt(&server_kp.public, msg.as_bytes())?;
    let decrypted = decrypt(&encrypted, &server_kp)?;

    assert_eq!(decrypted, msg);
    Ok(())
}

#[test]
fn test_tampered_ciphertext() {
    let server_kp = generate_keypair().unwrap();
    let encrypted = encrypt(&server_kp.public, "test".as_bytes()).unwrap();
    let mut data: EncryptedData = bincode::deserialize(&encrypted).unwrap();

    // Corrupt Kyber ciphertext
    data.ciphertext[0] ^= 0x01;

    let tampered_data = bincode::serialize(&data).unwrap();
    let result = decrypt(&tampered_data, &server_kp);
    assert!(result.is_err());
}

#[test]
fn test_tampered_nonce() {
    let server_kp = generate_keypair().unwrap();
    let encrypted = encrypt(&server_kp.public, "test".as_bytes()).unwrap();
    let mut data: EncryptedData = bincode::deserialize(&encrypted).unwrap();

    // Corrupt nonce
    data.nonce[0] ^= 0x01;

    let tampered_data = bincode::serialize(&data).unwrap();
    let result = decrypt(&tampered_data, &server_kp);
    assert!(result.is_err());
}

#[test]
fn test_empty_message() -> Result<()> {
    let server_kp = generate_keypair()?;
    let msg = "";

    let encrypted = encrypt(&server_kp.public, msg.as_bytes())?;
    let decrypted = decrypt(&encrypted, &server_kp)?;

    assert_eq!(decrypted, msg);
    Ok(())
}

#[test]
fn test_large_message() -> Result<()> {
    let server_kp = generate_keypair()?;
    let msg = "A".repeat(10_000);

    let encrypted = encrypt(&server_kp.public, msg.as_bytes())?;
    let decrypted = decrypt(&encrypted, &server_kp)?;

    assert_eq!(decrypted, msg);
    Ok(())
}

#[test]
fn test_wrong_key_decryption() {
    let sender_kp = generate_keypair().unwrap();
    let attacker_kp = generate_keypair().unwrap();
    let msg = "Confidential message.";

    let encrypted = encrypt(&sender_kp.public, msg.as_bytes()).unwrap();
    let result = decrypt(&encrypted, &attacker_kp);

    assert!(result.is_err());
}

#[test]
fn test_known_vector() -> Result<()> {
    let path = "tests.bin";

    // Verificar existencia del archivo
    let metadata = std::fs::metadata(path)
        .context(format!("Archivo '{}' no encontrado. Ejecuta `cargo run --bin main` primero", path))?;

    // Verificar tamaño mínimo
    let min_size = bincode::serialized_size(&TestData {
        secret_key: vec![],
        public_key: vec![],
        encrypted_data: vec![],
    })?;

    if metadata.len() < min_size {
        anyhow::bail!(
            "Archivo corrupto: tamaño {} < mínimo esperado {}",
            metadata.len(),
            min_size
        );
    }

    // Leer y deserializar
    let bytes = std::fs::read(path)?;
    bincode::deserialize::<()>(&bytes)?;
    let test_data: TestData = bincode::deserialize(&bytes)?;

    let server_kp = Keypair {
        secret: bytes_to_secret_key(&test_data.secret_key)?,
        public: bytes_to_public_key(&test_data.public_key)?,
    };

    let decrypted = decrypt(&test_data.encrypted_data, &server_kp)?;
    assert_eq!(decrypted, "Testing... 1234; Bytedream? :3");
    Ok(())
}