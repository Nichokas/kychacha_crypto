use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::{
    aead::{AeadCore, AeadMutInPlace, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use chacha20poly1305::aead::Nonce;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

#[derive(Serialize, Deserialize)]
struct EncryptedData {
    ephemeral_public: String,
    nonce: String,
    ciphertext: String,
}

fn derive_chacha_key(shared_secret:SharedSecret, salt:Option<&[u8]>) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(salt, shared_secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"chacha-encryption-v1", &mut okm)
        .expect("sos");
    okm
}

fn encrypt(static_public: PublicKey, message: &[u8]) -> String {
    let ephemeral_secret = EphemeralSecret::random();
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(&static_public);
    let okm = derive_chacha_key(shared_secret, None);

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut cipher = ChaCha20Poly1305::new_from_slice(&okm).expect("Invalid key length");

    let mut buffer = message.to_vec();
    cipher.encrypt_in_place(&nonce, b"", &mut buffer).expect("Encryption failed");

    let encrypted_data = EncryptedData {
        ephemeral_public: general_purpose::STANDARD.encode(ephemeral_public.as_bytes()),
        nonce: general_purpose::STANDARD.encode(nonce),
        ciphertext: general_purpose::STANDARD.encode(buffer),
    };

    serde_json::to_string(&encrypted_data).unwrap()
}


fn decrypt(encrypted_data: &str, static_secret: StaticSecret) -> String {
    let data: EncryptedData = serde_json::from_str(encrypted_data).expect("Invalid JSON");

    let ephemeral_public = general_purpose::STANDARD.decode(&data.ephemeral_public).expect("Invalid base64");
    let nonce_bytes = general_purpose::STANDARD.decode(&data.nonce).expect("Invalid base64");
    let ciphertext = general_purpose::STANDARD.decode(&data.ciphertext).expect("Invalid base64");

    let ephemeral_public = PublicKey::from(<[u8; 32]>::try_from(ephemeral_public.as_slice()).unwrap());
    let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&nonce_bytes);

    let shared_secret = static_secret.diffie_hellman(&ephemeral_public);
    let okm = derive_chacha_key(shared_secret, None);
    let mut cipher = ChaCha20Poly1305::new_from_slice(&okm).expect("Invalid key length");

    let mut buffer = ciphertext.to_vec();
    cipher.decrypt_in_place(nonce, b"", &mut buffer).expect("Decryption failed");

    String::from_utf8(buffer).expect("Invalid UTF-8")
}

fn main() {
    let static_secret = StaticSecret::random_from_rng(OsRng);
    let static_public:PublicKey=PublicKey::from(&static_secret);

    let encrypted_message = encrypt(static_public, b"Hii! bytedream :3");
    println!("{}", encrypted_message);

    let decrypted = decrypt(&encrypted_message, static_secret);
    println!("Decrypted: {}", decrypted);
}