use curve_msg::{encrypt, generate_keypair};
use base64::{engine::general_purpose, Engine as _};
use anyhow::Result;
use zerocopy::AsBytes;

fn main() -> Result<()> {
    // Generar par de claves del servidor
    let server_kp = generate_keypair()?;

    // Mensaje de prueba conocido
    let message = "Testing... 1234; Bytedream? :3";

    // Generar datos cifrados
    let encrypted = encrypt(&server_kp.public, message.as_bytes())?;

    // Imprimir datos para el test de vector conocido
    println!("=== DATOS PARA tests.rs ===");
    println!("// Secret key en Base64:");
    println!("static SERVER_SK_B64: &str = \"{}\";",
             general_purpose::STANDARD.encode(server_kp.secret.as_bytes()));

    println!("\n// Public key en Base64:");
    println!("static SERVER_PK_B64: &str = \"{}\";",
             general_purpose::STANDARD.encode(server_kp.public.as_bytes()));

    println!("\n// JSON cifrado:");
    println!("static ENCRYPTED_JSON: &str = r#\"{}\"#;", encrypted);

    // Verificación adicional
    let decrypted = curve_msg::decrypt(&encrypted, &server_kp)?;
    assert_eq!(decrypted, message);

    println!("\n=== VERIFICACIÓN EXITOSA ===");
    Ok(())
}