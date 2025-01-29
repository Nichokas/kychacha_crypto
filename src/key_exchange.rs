use hkdf::Hkdf;
use sha2::Sha256;
use anyhow::{Context, Result};
use kyberlib::{keypair, keypairfrom, KyberLibError};

pub fn generate_ephemeral_keypair() -> Result<(kyberlib::kex::SecretKey, kyberlib::kex::PublicKey)> {
    let mut rng = rand::thread_rng();
    let keys = keypair(&mut rng).map_err(|e| anyhow::anyhow!("Keypair generation failed: {}", e))?;;
    let mut public = keys.public;
    let mut secret = keys.secret;
    Ok((secret, public))
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