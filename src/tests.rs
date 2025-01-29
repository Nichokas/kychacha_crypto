use crate::{decrypt, encrypt, EncryptedData, generate_keypair};
use base64::{engine::general_purpose, Engine as _};
use anyhow::{Result, anyhow, Context};
use kyberlib::{Keypair, SecretKey, PublicKey};

#[test]
fn test_round_trip() -> Result<()> {
    let server_kp = generate_keypair()?;
    let msg = "Mensaje de prueba segura 98765!";

    let encrypted = encrypt(&server_kp.public, msg.as_bytes())?;
    let decrypted = decrypt(&encrypted, &server_kp)?;

    assert_eq!(decrypted, msg);
    Ok(())
}

#[test]
fn test_tampered_ciphertext() {
    let server_kp = generate_keypair().unwrap();
    let encrypted = encrypt(&server_kp.public, "test".as_bytes()).unwrap();
    let mut data: EncryptedData = serde_json::from_str(&encrypted).unwrap();

    // Alterar ciphertext de Kyber
    let mut ciphertext = general_purpose::STANDARD.decode(&data.ciphertext).unwrap();
    ciphertext[0] ^= 0x01;
    data.ciphertext = general_purpose::STANDARD.encode(ciphertext);

    let result = decrypt(&serde_json::to_string(&data).unwrap(), &server_kp);
    assert!(result.is_err());
}

#[test]
fn test_tampered_nonce() {
    let server_kp = generate_keypair().unwrap();
    let encrypted = encrypt(&server_kp.public, "test".as_bytes()).unwrap();
    let mut data: EncryptedData = serde_json::from_str(&encrypted).unwrap();

    // Alterar nonce de ChaCha
    let mut nonce = general_purpose::STANDARD.decode(&data.nonce).unwrap();
    nonce[0] ^= 0x01;
    data.nonce = general_purpose::STANDARD.encode(nonce);

    let result = decrypt(&serde_json::to_string(&data).unwrap(), &server_kp);
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
    let msg = "A".repeat(10_000); // Mensaje de 10KB

    let encrypted = encrypt(&server_kp.public, msg.as_bytes())?;
    let decrypted = decrypt(&encrypted, &server_kp)?;

    assert_eq!(decrypted, msg);
    Ok(())
}

#[test]
fn test_wrong_key_decryption() {
    let sender_kp = generate_keypair().unwrap();
    let attacker_kp = generate_keypair().unwrap();
    let msg = "Mensaje confidencial";

    let encrypted = encrypt(&sender_kp.public, msg.as_bytes()).unwrap();
    let result = decrypt(&encrypted, &attacker_kp);

    assert!(result.is_err());
}

// Test de vector conocido (requiere generar nuevos datos de prueba)
#[test]
fn test_known_vector() -> Result<()> {


    let server_secret = SecretKey::try_from(
        general_purpose::STANDARD.decode(server_sk_b64)?.as_slice()
    )?;

    let server_public = PublicKey::try_from(
        general_purpose::STANDARD.decode(server_pk_b64)?.as_slice()
    )?;

    let server_kp = Keypair {
        public: server_public,
        secret: server_secret
    };

    let decrypted = decrypt(encrypted_json, &server_kp)?;
    assert_eq!(decrypted, "Testing... 1234; Bytedream? :3");
    Ok(())
}

