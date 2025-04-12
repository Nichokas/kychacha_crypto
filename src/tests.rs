// tests/test.rs
use crate::TestData;
use crate::{
    bytes_to_public_key, bytes_to_secret_key, decrypt, encrypt, generate_keypair, EncryptedData,
    Keypair,
};
use anyhow::{Context, Result};
use bincode::serde::{decode_from_slice, encode_to_vec};

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

    // Configuración estándar para bincode
    let config = bincode::config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    let (mut data, _): (EncryptedData, usize) = decode_from_slice(&encrypted, config).unwrap();

    // Corrupt Kyber ciphertext
    data.ciphertext[0] ^= 0x01;

    let tampered_data = encode_to_vec(&data, config).unwrap();
    let result = decrypt(&tampered_data, &server_kp);
    assert!(result.is_err());
}

#[test]
fn test_tampered_nonce() {
    let server_kp = generate_keypair().unwrap();
    let encrypted = encrypt(&server_kp.public, "test".as_bytes()).unwrap();

    // Configuración estándar para bincode
    let config = bincode::config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    let (mut data, _): (EncryptedData, usize) = decode_from_slice(&encrypted, config).unwrap();

    // Corrupt nonce
    data.nonce[0] ^= 0x01;

    let tampered_data = encode_to_vec(&data, config).unwrap();
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

    // Configuración estándar para bincode
    let config = bincode::config::standard()
        .with_big_endian()
        .with_variable_int_encoding();

    // Verificar existencia del archivo
    let metadata = std::fs::metadata(path).context(format!(
        "Archivo '{}' no encontrado. Ejecuta `cargo run --bin main` primero",
        path
    ))?;

    // En bincode 2.0 no existe serialized_size de la misma forma
    // Por lo que vamos a estimar un tamaño mínimo razonable
    let min_size = 100; // Tamaño mínimo estimado

    if metadata.len() < min_size {
        anyhow::bail!(
            "Archivo corrupto: tamaño {} < mínimo esperado {}",
            metadata.len(),
            min_size
        );
    }

    // Leer y deserializar
    let bytes = std::fs::read(path)?;

    // Verificar que se puede deserializar como vacío primero
    let (_empty, _): ((), usize) = decode_from_slice(&bytes, config)?;

    // Deserializar los datos de prueba
    let (test_data, _): (TestData, usize) = decode_from_slice(&bytes, config)?;

    let server_kp = Keypair {
        secret: bytes_to_secret_key(&test_data.secret_key)?,
        public: bytes_to_public_key(&test_data.public_key)?,
    };

    let decrypted = decrypt(&test_data.encrypted_data, &server_kp)?;
    assert_eq!(decrypted, "Testing... 1234; Bytedream? :3");
    Ok(())
}
