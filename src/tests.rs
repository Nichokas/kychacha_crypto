// tests/test.rs
use crate::{bytes_to_public_key, bytes_to_secret_key, decrypt, encrypt, generate_keypair, EncryptedData};
use anyhow::Result;
use kyberlib::{Keypair, PublicKey, SecretKey};

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
    let data = std::fs::read("tests.bin")?;

    // Deserializar claves
    let sk_bytes: Vec<u8> = bincode::deserialize(&data[0..bincode::serialized_size(&Vec::<u8>::new())? as usize])?;
    let pk_bytes: Vec<u8> = bincode::deserialize(&data[sk_bytes.len()..sk_bytes.len() + bincode::serialized_size(&Vec::<u8>::new())? as usize])?;

    let server_kp = Keypair {
        secret: bytes_to_secret_key(&sk_bytes)?,
        public: bytes_to_public_key(&pk_bytes)?,
    };

    // Obtener datos cifrados
    let encrypted_data = &data[sk_bytes.len() + pk_bytes.len()..];

    let decrypted = decrypt(encrypted_data, &server_kp)?;
    assert_eq!(decrypted, "Testing... 1234; Bytedream? :3");
    Ok(())
}