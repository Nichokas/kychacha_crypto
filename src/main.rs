// main.rs - Script to generate tests.bin
use anyhow::Result;
use bincode::serde::encode_to_vec;
use kychacha_crypto::{encrypt_stream, generate_keypair, public_key_to_bytes, secret_key_to_bytes};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Write, Cursor};

#[derive(Serialize, Deserialize)]
struct TestData {
    #[serde(with = "serde_bytes")]
    pub secret_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    pub encrypted_data: Vec<u8>,
}

fn main() -> Result<()> {
    // Generate a new keypair
    let keypair = generate_keypair()?;
    
    // Test message that matches the expected one in test_known_vector
    let message = "Testing... 1234; quantum??? :3";
    
    // Encrypt the message using the streaming API
    let mut encrypted_data = Vec::new();
    encrypt_stream(keypair.public_key.clone(), &mut Cursor::new(message.as_bytes()), &mut encrypted_data)?;

    // Create the TestData structure
    let test_data = TestData {
        secret_key: secret_key_to_bytes(keypair.private_key),
        public_key: public_key_to_bytes(keypair.public_key),
        encrypted_data,
    };
    
    // Bincode configuration
    let config = bincode::config::standard()
        .with_big_endian()
        .with_variable_int_encoding();
    
    // Encode an empty tuple first (as expected in test_known_vector)
    let empty_bytes = encode_to_vec(&(), config)?;
    
    // Encode the test data
    let test_data_bytes = encode_to_vec(&test_data, config)?;
    
    // Write to file
    let mut file = File::create("tests.bin")?;
    file.write_all(&empty_bytes)?;
    file.write_all(&test_data_bytes)?;
    
    println!("File tests.bin generated successfully.");
    println!("Size: {} bytes", empty_bytes.len() + test_data_bytes.len());
    
    Ok(())
}