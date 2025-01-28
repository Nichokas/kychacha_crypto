use crate::{decrypt, encrypt, EncryptedData, PublicKey, StaticSecret};
use base64::{engine::general_purpose, Engine as _};
use anyhow::Result;

#[test]
fn test_round_trip() -> Result<()> {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);
    let msg = "Mensaje de prueba segura 98765!";

    let encrypted = encrypt(public, msg.as_bytes())?;
    let decrypted = decrypt(&encrypted, secret)?;

    assert_eq!(decrypted, msg);
    Ok(())
}

#[test]
fn test_tampered_data() {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);
    let mut encrypted_data: EncryptedData = serde_json::from_str(
        &encrypt(public, "test".as_bytes()).unwrap()
    ).unwrap();

    // Corromper el nonce
    let mut nonce = general_purpose::STANDARD.decode(&encrypted_data.nonce).unwrap();
    nonce[0] ^= 0x01;
    encrypted_data.nonce = general_purpose::STANDARD.encode(nonce);

    let result = decrypt(&serde_json::to_string(&encrypted_data).unwrap(), secret);
    assert!(result.is_err());
}

#[test]
fn test_known_vector() -> Result<()> {
    let static_secret_b64 = "pLeW1AMChvWUlbiax187/gy/9jy6g9dGfDaNJOalQVE=";
    let message = "Test vector con valor conocido 12345!@#$%";
    let encrypted_json = r#"{"ephemeral_public":"MqrTf8umHpsfVeZ8eRQc44FeiUyBiZrFVujiQ8u3sXs=","nonce":"vILGnes9x26cPwu9","ciphertext":"c6F+dS/3JAv+3uLNEX3FyJgKOoeXhofy7WFZc3usI+bFJH7xCTa077fIfUr8rff9kFQk8Fg6buN7"}"#;

    let secret_bytes = general_purpose::STANDARD.decode(static_secret_b64)?;
    let secret = StaticSecret::from(<[u8; 32]>::try_from(secret_bytes.as_slice())?);

    let decrypted = decrypt(encrypted_json, secret)?;
    assert_eq!(decrypted, message);
    Ok(())
}