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


#[test]
fn test_known_vector() -> Result<()> {
    let server_sk_b64 = r#"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"#;
    let server_pk_b64 = r#"xhM/tOGggjcZHCZPLkRkgrk+4/BuwgAiYzGvzKFFAehNaAqTfwdMA7sW+AeknRU4FCQO1oDGw4NREMswCEQdbNe549wNxxQFVtqxlQqkjCm+vig7OfpQYCNsDaMF3HxV7syOHZRLS1OypnptfHg260PFZzsRc7KGULcGP1abTLEhwiPIsqVk2GKUefHMbtqvgyQIaMaNGvlTP4uxMpiS6JiOU/Rj1mxEZFpaJJkG3YCtl+IO0hjB6ARDGFQNtfxBitdV2WsLxMcUORadifYusCJfM9dtN0tE4SFxy8cgqTkJ5SyG3Vg5/wCvrdWfdwDAdNkgBgSjvxk15bgmt8yqCecV46c9ZxMMdljKHVppNVNa1naQfJQ51gcnZhsYy+BjlzjKCTaMweGA81sOBYoiZGcyIlYEHXCSz0W4poq2iSZTSYxvZYLBI/t+BKGRQmcJYWRz6kC7nvYcgQh/wCpmveRTCuhXP2YDdrcbf8J01sGfTOq5OEEA8xjE5BaJ9tpNPuPD51SKQVGINWR2vRgz2KscKnTAC+c43BqD3hqg54C96ifEwTppZDxSgAytY2HM2XVtcXAK96mh57Rtq8dXXrssCLMX4Vys4slZcEGpc1wyYcqQxgkTfXOppjoyNpQjuVSbGZNvqhE9DXl7ouCJcVm8TfxDXEc6vkNNx2CQQewLSlNgjygrpSWNL6M/DssMNUS4OmKPOaiddsEmbAJ3Fat3++lRjssbVfArFKConQCttUmV11xjaxiSxxh8h8AEOWcnzWYhxbClsVRoaqJpbfge7pdt+SUi23sJfZfDZVscW7QC8qMw88bPhnl3bum9PMuO66A8N6AYHgpryWldZmYyvrm4Wylm8FcUpfyfgfaJPulpVCIf+FQbpXjN6sKJKtUFvxNr8FxfMWK6gDUNwOkIPqmAuGGUoxwLsRFFezNFXgjGlLExXOcWQgtf9AoERLoHTjMQokceu0kc4dYgunIEfwGUNfgrd4WwYsWGPnKwRPEDeiQ0v8DJCJVrT1VsyECNChFjeqZjziN/hVHIYcC2M0BrhayFlDaH6OQOftVVofCGvjldzwgfivm3n1FkbgQWiJIPJnOftZXDv7mdOsNg1IFt2Qe6ZgwQ6laFU2i1l9ywM7h6T0Y1JjpR7cI2z6G5afWshYm4XDs4clq28Qa4j3tn93Jig2wlrMgqB1ATMLMGU1YHF3Ylg8uMVDuWAzXLTVBOmJUvYHRYwxpG9ve4zzCD/VOBvMGenXkFXtkNpLi7i+e+gzYVHce9psB615xYAWuMJAAEyigcrriasszGvmodrGdb8EFWj7dgDYB78wtsazAQrlGAzLiUf7yydlBb0QVNQ7Nwbnw5MtkCr3il4/w9jvZK8WfFnmu08RSCtmVfztN4GhFaejRhaAAO/IOv+qcKidk9a2RBtyOLDGu3klJjX9wJVHUU7lNCqvZa1+l9I2VD5uWWMgKeVpuWdFdD2sxo5juRScuOB3Jp9riiWrvI8PaP2iygZmDMKiudqJWhlZC3KMdM9wEPURlAq3qa0mAOJnclt+XTAueIkUOEzz2xLttnsdxC5kPsGpw="#;
    let encrypted_json= r#"{"ciphertext":"BE2WKsnC3cyJCHQrnMvMnkpo9BMG5bU8zyCLCQXHjdshuagTLXwCURK7z3bf8uQ1O2itSHs8jyWl+XDZOsLH9zFD+69AvRld0dJX1cSskkalCZ35uWqHuQAMIgndgp7A0eF+dE5ri15CxDhURXEHbYHSLDWKheXaorfp5dSebDi/5TyqthOjB6Zmbx7LhTDWZB/7XFVDiM//yakbBQTLx/QCS6ts1ny/Zs+v/dQgX/Qk4pq1zSSOSmRnbCBbOrkV8siQ3EDmf4ykdJM6yJMNYSxP4FrPUCR95iIDjAL5vJD1OyRQv3qILXtZbOrCxk5SaC4++yCKghKx5gADtgrYLmGVPsqxOCvns9Ahe+ebscJkvFi95qL9xyxEIuR6f0LPfG7Q3wWgeXtv7gyuF5Km0hC55OdYdMvqioL6KLYnwtszYnn1s4GsjXBVilBWodM6CTmqiAxBW+e9W8uZ+9zXXT+7iOAnNBuMpepUMj52TG1Udk3ZnuvSpQ162GGf8UL2J3sTWla8TDa/WFHyLcjZUhBUxt6DrCI33obWEyJmyBI+eGuPK8tiM5hn0GMAlUdQgcQnVvowpYyDdiKdvFxX6ZHx1c7B8p/g+Ux+efzvFd6L3jrga6LW9opDIU9kjnjFaF4eeFqSmQBl7HTiPZxMM6ErYHRAKyxRgQAFlD3VWDTiCbgFmfM1IUHbRIcJXM1SV80t48IjWA6NeHdMWDP3q6+3LcR16ywKu8HVf0pgAh34UVio3vCI2Y/V7EfbzT9OO5VsYYsAqrrX7nbfjyjEjyAGgbZs6u8N/Obj2WfCyaiVWS0RYWSQrb85IOnQyDJdHCa5N++d5np/lezEKMMtbGqFonFUU+JSwGtv+fZerl7E5TBsRAJ2Y6gmP182BUTGonw2LQz51oLKDh0/0OjW+Fu0eYrwIlqDQoRAKRQSShi9JauN/+gcvGo5wmuumtyW3t4Ce0wBdTngj6xPX8Knl925/D4yDMV0/RnG/sy7V3bY1pB/u7H30E1a29WrkMUFsceMVV6q9rs8i+TWkGG+9+IIXmAGoV01KZbgvHK+djAb0QCU4N5TJDCOJzCY/TDwXTqZJiupw3aVKPm3Ai5mBnKw6Cl9jKpQnNQ3jg2VkQWXKk4zuwgY14vWlKm2G/BJ7pTVu8EGkETTfVgn+fEEJnNMTuyqVdADpbC7ZHiTWYsZT50NXCjhj00Ntrt1kjOaXG8r7bjfRpEZvUsqOfJj45VwczxhhfWloc4o+I1cRYl+N6WdFjkjo0aIOgbkdSuPdPHvcBkrqr4uG8NQWl3gHW8b+2N7qBB55jgL6Kbkq6nCUa6dZgjmOwE74OG8oTWLYMyYrc1qoOxZfT+/IR7roy1Yug2OXpVPK16Uujz7oHov3TQwArT4bxgmR2TuWOAk3Zs3Nj9aUicd73BF1wVrsb3ItZcvWyDN235YzoLNdkQ=","nonce":"E8DdCcunH4e1rOAZ","encrypted_msg":"7oW4xgPMHchy6/zg8QGhs9QHOFMaxlRJ5fZNcBGW1PdX/XXZ9xHG3c6QGHUp2A=="}"#;
    
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