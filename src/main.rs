// src/main.rs
use curve_msg::{encrypt, PublicKey, StaticSecret};
use base64::{engine::general_purpose, Engine as _};

fn main() -> anyhow::Result<()> {
    // Generar par de claves estáticas
    let static_secret = StaticSecret::random();
    let static_public = PublicKey::from(&static_secret);

    // Mensaje de prueba
    let message = "Test vector con valor conocido 12345!@#$%";

    // Encriptar
    let encrypted_json = encrypt(static_public, message.as_bytes())?;

    // Imprimir valores para los tests
    println!("=== Valores para tests ===");
    println!("Static secret (base64): {}", general_purpose::STANDARD.encode(static_secret.to_bytes()));
    println!("Mensaje original: {:?}", message);
    println!("JSON encriptado: {}", encrypted_json);

    Ok(())
}