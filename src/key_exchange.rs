use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use hkdf::Hkdf;
use sha2::Sha256;

pub fn generate_ephemeral_keypair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random();
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn derive_shared_secret(
    ephemeral_secret: EphemeralSecret,
    static_public: &PublicKey
) -> SharedSecret {
    ephemeral_secret.diffie_hellman(static_public)
}

pub fn derive_chacha_key(shared_secret: SharedSecret, salt: Option<&[u8]>) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(salt, shared_secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"chacha-encryption-v1", &mut okm)
        .expect("HKDF expansion failed");
    okm
}