use zerocopy::AsBytes;
// values-for-tests
use kychacha_crypto::{encrypt, generate_keypair, public_key_to_bytes, secret_key_to_bytes, TestData};


fn main() -> anyhow::Result<()> {
    let server_kp = generate_keypair()?;

    let test_data = TestData {
        secret_key: server_kp.secret.as_bytes().to_vec(),
        public_key: server_kp.public.as_bytes().to_vec(),
        encrypted_data: encrypt(&server_kp.public, "Testing... 1234; Bytedream? :3".as_bytes())?,
    };

    let path = "tests.bin";
    let bytes = bincode::serialize(&test_data)?;
    std::fs::write(path, &bytes)?;

    println!(
        "Archivo generado: {} ({})",
        path,
        humansize::format_size(bytes.len(), humansize::DECIMAL)
    );

    Ok(())
}