// tests/test.rs
use crate::{decrypt, decrypt_stream, encrypt, encrypt_stream};
use crate::{decrypt_multiple_recipient, encrypt_multiple_recipient, generate_keypair_with_level};
use crate::{SecurityLevel, SignSecurityLevel};
use anyhow::Result;
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::OsRng;
use hex;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Write};
use tempfile::tempfile;

// Función auxiliar para tests que asegura el uso de Dilithium3
#[cfg(any(feature = "dilithium2", feature = "dilithium3", feature = "dilithium5"))]
fn generate_test_keypair() -> Result<crate::MlKemKeyPair> {
    // Usamos Dilithium3 específicamente como nivel de seguridad para firmas
    generate_keypair_with_level(&SecurityLevel::MlKem768, Some(&SignSecurityLevel::Dilithium3))
}

#[cfg(not(any(feature = "dilithium2", feature = "dilithium3", feature = "dilithium5")))]
fn generate_test_keypair() -> Result<crate::MlKemKeyPair> {
    generate_keypair()
}

#[test]
fn test_round_trip() -> Result<(), Box<dyn Error>> {
    let keypair = generate_test_keypair()?;
    let mut sink = Vec::new();
    encrypt_stream(
        keypair.public_key,
        &mut Cursor::new(b"secret message"),
        &mut sink,
    )?;
    let mut ciphertext_bytes = Vec::new();
    decrypt_stream(
        &keypair.private_key,
        &mut Cursor::new(sink),
        &mut ciphertext_bytes,
    )?;
    assert_eq!(String::from_utf8_lossy(&ciphertext_bytes), "secret message");
    Ok(())
}

#[test]
fn test_big_round_trip() -> Result<(), Box<dyn Error>> {
    let mut file = tempfile()?;
    const TOTAL_SIZE: usize = 10 * 1024 * 1024; // 10MB instead of 2GB
    const BUFFER_SIZE: usize = 1024 * 1024; // 1MB buffer instead of 100MB
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut remaining_bytes = TOTAL_SIZE;

    while remaining_bytes > 0 {
        let bytes_to_write = BUFFER_SIZE.min(remaining_bytes);
        OsRng.fill_bytes(&mut buffer[0..bytes_to_write]);
        file.write_all(&buffer[0..bytes_to_write])?;
        remaining_bytes -= bytes_to_write;
    }
    file.flush()?;

    // Reset file position to beginning for reading
    use std::io::Seek;
    file.seek(std::io::SeekFrom::Start(0))?;

    let keypair = generate_test_keypair()?;
    let mut encrypted_file = tempfile()?;
    encrypt_stream(keypair.public_key, &mut file, &mut encrypted_file)?;

    // Reset encrypted file position to beginning for reading
    encrypted_file.seek(std::io::SeekFrom::Start(0))?;

    let mut decrypted_file = tempfile()?;
    decrypt_stream(
        &keypair.private_key,
        &mut encrypted_file,
        &mut decrypted_file,
    )?;

    // Reset both files to beginning for comparison
    file.seek(std::io::SeekFrom::Start(0))?;
    decrypted_file.seek(std::io::SeekFrom::Start(0))?;

    // comparison
    let mut buffer1 = vec![0u8; BUFFER_SIZE];
    let mut buffer2 = vec![0u8; BUFFER_SIZE];
    let mut reader1 = BufReader::new(file);
    let mut reader2 = BufReader::new(decrypted_file);

    let mut comp = true;

    loop {
        let bytes1 = reader1.read(&mut buffer1)?;
        let bytes2 = reader2.read(&mut buffer2)?;

        if bytes1 != bytes2 {
            comp = false;
            break;
        }

        if bytes1 == 0 {
            break;
        }

        if buffer1[..bytes1] != buffer2[..bytes2] {
            comp = false;
            break;
        }
    }

    assert!(comp);
    Ok(())
}

#[test]
fn legacy_functions() -> Result<(), Box<dyn Error>> {
    let keypair = generate_test_keypair()?;
    let ciphertext = encrypt(keypair.public_key, b"secret message")?;
    let plaintext = decrypt(&ciphertext, &keypair.private_key)?;
    assert_eq!(plaintext, "secret message");
    Ok(())
}

#[test]
fn test_key_hashes() -> Result<(), Box<dyn Error>> {
    let keypair = generate_test_keypair()?;

    // Test public key hash
    let mut hasher = Sha256::new();
    hasher.update(keypair.public_key.key.as_ref());
    let digest = hasher.finalize();
    let expected_hex = hex::encode(&digest);
    let expected_dec = BigUint::from_bytes_be(&digest).to_str_radix(10);
    assert_eq!(keypair.public_key.hash_hex(), expected_hex);
    assert_eq!(keypair.public_key.hash_decimal(), expected_dec);

    // Test private key hash
    let mut hasher = Sha256::new();
    hasher.update(keypair.private_key.key.as_ref());
    let digest = hasher.finalize();
    let expected_hex = hex::encode(&digest);
    let expected_dec = BigUint::from_bytes_be(&digest).to_str_radix(10);
    assert_eq!(keypair.private_key.hash_hex(), expected_hex);
    assert_eq!(keypair.private_key.hash_decimal(), expected_dec);

    // Test full keypair hash (combines public KEM key and public sign key if available)
    let mut hasher = Sha256::new();
    let mut combined = Vec::new();
    combined.extend_from_slice(keypair.public_key.key.as_ref());

    #[cfg(any(feature = "dilithium2", feature = "dilithium3", feature = "dilithium5"))]
    {
        combined.extend_from_slice(keypair.public_sign_key.key.as_ref());
    }

    hasher.update(&combined);
    let digest = hasher.finalize();
    let expected_hex = hex::encode(&digest);
    let expected_dec = BigUint::from_bytes_be(&digest).to_str_radix(10);

    assert_eq!(keypair.hash_hex(), expected_hex);
    assert_eq!(keypair.hash_decimal(), expected_dec);

    Ok(())
}

#[test]
fn test_tampered_ciphertext() {
    let server_kp = generate_test_keypair().unwrap();
    let mut encrypted = Vec::new();
    encrypt_stream(
        server_kp.public_key,
        &mut Cursor::new("test".as_bytes()),
        &mut encrypted,
    )
    .unwrap();

    let mut corrupted = encrypted.clone();
    if corrupted.len() > 10 {
        corrupted[10] ^= 0x01; // Corrupt a byte likely to be in the KEM ciphertext
    }

    let mut output = Vec::new();
    let result = decrypt_stream(
        &server_kp.private_key,
        &mut Cursor::new(corrupted),
        &mut output,
    );
    assert!(result.is_err());
}

#[test]
fn test_tampered_nonce() {
    let server_kp = generate_test_keypair().unwrap();
    let mut encrypted = Vec::new();
    encrypt_stream(
        server_kp.public_key,
        &mut Cursor::new("test".as_bytes()),
        &mut encrypted,
    )
    .unwrap();

    let mut corrupted = encrypted.clone();
    if corrupted.len() > 50 {
        // Try to find where the nonce likely starts and corrupt it
        let nonce_start = corrupted.len().saturating_sub(50); // Approximate location
        corrupted[nonce_start] ^= 0x01;
    }

    let mut output = Vec::new();
    let result = decrypt_stream(
        &server_kp.private_key,
        &mut Cursor::new(corrupted),
        &mut output,
    );
    assert!(result.is_err());
}

#[test]
fn test_empty_message() -> Result<()> {
    let server_kp = generate_test_keypair()?;
    let msg = "";

    let mut encrypted = Vec::new();
    encrypt_stream(
        server_kp.public_key,
        &mut Cursor::new(msg.as_bytes()),
        &mut encrypted,
    )?;

    let mut decrypted = Vec::new();
    decrypt_stream(
        &server_kp.private_key,
        &mut Cursor::new(encrypted),
        &mut decrypted,
    )?;

    assert_eq!(String::from_utf8_lossy(&decrypted), msg);
    Ok(())
}

#[test]
fn test_large_message() -> Result<()> {
    let server_kp = generate_test_keypair()?;
    let msg = "A".repeat(10_000);

    let mut encrypted = Vec::new();
    encrypt_stream(
        server_kp.public_key,
        &mut Cursor::new(msg.as_bytes()),
        &mut encrypted,
    )?;

    let mut decrypted = Vec::new();
    decrypt_stream(
        &server_kp.private_key,
        &mut Cursor::new(encrypted),
        &mut decrypted,
    )?;

    assert_eq!(String::from_utf8_lossy(&decrypted), msg);
    Ok(())
}

#[test]
fn test_wrong_key_decryption() {
    let server_kp = generate_test_keypair().unwrap();
    let attacker_kp = generate_test_keypair().unwrap();
    let msg = "Confidential message.";

    let mut encrypted = Vec::new();
    encrypt_stream(
        server_kp.public_key,
        &mut Cursor::new(msg.as_bytes()),
        &mut encrypted,
    )
    .unwrap();

    let mut output = Vec::new();
    let result = decrypt_stream(
        &attacker_kp.private_key,
        &mut Cursor::new(encrypted),
        &mut output,
    );

    assert!(result.is_err());
}

#[test]
fn file_round_trip() -> Result<(), Box<dyn Error>> {
    let keypair = generate_test_keypair()?;
    let mut encrypted_data = Vec::new();
    encrypt_stream(
        keypair.public_key,
        &mut Cursor::new(b"file content example"),
        &mut encrypted_data,
    )?;

    {
        let mut file = File::create("encrypted.bin")?;
        file.write_all(&encrypted_data)?;
    }

    let mut file = File::open("encrypted.bin")?;
    let mut decrypted = Vec::new();
    decrypt_stream(&keypair.private_key, &mut file, &mut decrypted)?;

    assert_eq!(String::from_utf8_lossy(&decrypted), "file content example");
    Ok(())
}

#[test]
fn test_multi_recipient_round_trip() -> Result<(), Box<dyn Error>> {
    // Generate three recipient keypairs
    let kp1 = generate_test_keypair()?;
    let kp2 = generate_test_keypair()?;
    let kp3 = generate_test_keypair()?;

    let message = b"multi recipient secret data";
    let mut encrypted = Vec::new();
    encrypt_multiple_recipient(
        vec![kp1.public_key, kp2.public_key, kp3.public_key],
        &mut Cursor::new(message.as_slice()),
        &mut encrypted,
    )?;

    // Each recipient should be able to decrypt
    for privk in [&kp1.private_key, &kp2.private_key, &kp3.private_key] {
        let mut out = Vec::new();
        decrypt_multiple_recipient(privk, &mut Cursor::new(encrypted.clone()), &mut out)?;
        assert_eq!(out, message);
    }
    Ok(())
}

#[test]
fn test_multi_recipient_wrong_key() -> Result<(), Box<dyn Error>> {
    let kp1 = generate_test_keypair()?;
    let kp2 = generate_test_keypair()?;
    let kp3 = generate_test_keypair()?;
    let outsider = generate_test_keypair()?; // not included

    let message = b"top secret";
    let mut encrypted = Vec::new();
    encrypt_multiple_recipient(
        vec![kp1.public_key, kp2.public_key, kp3.public_key],
        &mut Cursor::new(message.as_slice()),
        &mut encrypted,
    )?;

    // Outsider should fail
    let mut out = Vec::new();
    let res = decrypt_multiple_recipient(
        &outsider.private_key,
        &mut Cursor::new(encrypted.clone()),
        &mut out,
    );
    assert!(res.is_err());

    // Ensure a valid recipient still works after failure attempt
    let mut out_ok = Vec::new();
    decrypt_multiple_recipient(&kp2.private_key, &mut Cursor::new(encrypted), &mut out_ok)?;
    assert_eq!(out_ok, message);
    Ok(())
}


#[cfg(any(feature = "dilithium2", feature = "dilithium3", feature = "dilithium5"))]
#[test]
fn test_keypair_serialization_with_signatures() -> Result<(), Box<dyn Error>> {
    // Generate a keypair with signature keys
    let keypair = generate_test_keypair()?;

    // Serialize the keypair
    let serialized = keypair.to_vec()?;

    // Deserialize the keypair
    let deserialized = crate::MlKemKeyPair::from_bytes(&serialized)?;

    // Verify both KEM and signature components match
    assert_eq!(keypair.public_key, deserialized.public_key);
    assert_eq!(keypair.private_key, deserialized.private_key);
    assert_eq!(keypair.public_sign_key, deserialized.public_sign_key);
    assert_eq!(keypair.private_sign_key, deserialized.private_sign_key);

    // Additional test: verify hashes match
    assert_eq!(keypair.hash_hex(), deserialized.hash_hex());
    assert_eq!(keypair.hash_decimal(), deserialized.hash_decimal());

    Ok(())
}
