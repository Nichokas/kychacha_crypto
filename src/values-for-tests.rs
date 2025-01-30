// values-for-tests
use std::fs::File;
use std::io::Write;
use kychacha_crypto::{encrypt, generate_keypair, public_key_to_bytes, secret_key_to_bytes};

fn main() {
    // Generar claves
    let server_kp = generate_keypair().expect("Error generando keypair");

    // Convertir claves a bytes
    let sk_bytes = secret_key_to_bytes(&server_kp.secret);
    let pk_bytes = public_key_to_bytes(&server_kp.public);

    // Cifrar mensaje
    let test_message = "Testing... 1234; Bytedream? :3";
    let encrypted_data = encrypt(&server_kp.public, test_message.as_bytes())
        .expect("Error en el cifrado");

    // Guardar en archivo binario
    let mut file = File::create("tests.bin").expect("Error creando archivo");

    // Escribir claves y datos cifrados usando bincode
    let sk_serialized = bincode::serialize(&sk_bytes).unwrap();
    let pk_serialized = bincode::serialize(&pk_bytes).unwrap();

    file.write_all(&sk_serialized).unwrap();
    file.write_all(&pk_serialized).unwrap();
    file.write_all(&encrypted_data).unwrap();

    println!("Datos de test generados en tests.bin");
}