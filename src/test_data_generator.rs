use std::fs::File;
use std::io::Write;
use kychacha_crypto::{encrypt, generate_keypair}; // Reemplaza your_crate_name
use base64::{engine::general_purpose, Engine as _};
use zerocopy::AsBytes;

fn main() {
    // Generar claves
    let server_kp = generate_keypair().expect("Error generando keypair");

    // Codificar en Base64
    let server_sk_b64 = general_purpose::STANDARD.encode(server_kp.secret.as_bytes());
    let server_pk_b64 = general_purpose::STANDARD.encode(server_kp.public.as_bytes());

    // Cifrar mensaje
    let test_message = "Testing... 1234; Bytedream? :3";
    let encrypted_json = encrypt(&server_kp.public, test_message.as_bytes())
        .expect("Error en el cifrado");

    // Guardar en archivo
    let mut file = File::create("tests.txt").expect("Error creando archivo");
    writeln!(file, "{}", server_sk_b64).expect("Escritura fallida");
    writeln!(file, "{}", server_pk_b64).expect("Escritura fallida");
    writeln!(file, "{}", encrypted_json).expect("Escritura fallida");

    println!("Datos de test generados en tests.txt");
}