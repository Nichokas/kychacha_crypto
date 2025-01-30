use anyhow::{anyhow, Error, Result};
use hkdf::Hkdf;
use kyberlib::{Uake, PublicKey, SecretKey, SharedSecret, UakeSendInit, UakeSendResponse, keypair};
use rand::thread_rng;
use sha2::Sha256;
use zerocopy::AsBytes;

// Sizes for Kyber1024
pub const KYBER_PUBLIC_KEY_BYTES: usize = 1184;
pub const KYBER_SECRET_KEY_BYTES: usize = 2400;

#[derive(Clone)]
pub struct ClientHandshake {
    pub(crate) instance: Uake,
    pub send_init: UakeSendInit,
}

pub struct ServerHandshake {
    instance: Uake,
    pub send_response: UakeSendResponse,
}

impl ClientHandshake {
    pub fn new(server_pubkey: &PublicKey) -> Result<Self> {
        let mut rng = thread_rng();
        let mut instance = Uake::new();

        let send_init = instance.client_init(server_pubkey, &mut rng)
            .map_err(|e| anyhow!("Client init failed: {}", e))?;

        Ok(Self { instance, send_init })
    }

    pub fn finalize(mut self, server_response: UakeSendResponse) -> Result<SharedSecret> {
        self.instance.client_confirm(server_response)
            .map_err(|e| anyhow!("Client confirm failed: {}", e))?;
        Ok(self.instance.shared_secret)
    }
}

impl ServerHandshake {
    pub fn new(client_init: UakeSendInit, server_secret: &SecretKey) -> Result<Self> {
        let mut rng = thread_rng();
        let mut instance = Uake::new();

        let send_response = instance.server_receive(client_init, server_secret, &mut rng)
            .map_err(|e| anyhow!("Server receive failed: {}", e))?;

        Ok(Self { instance, send_response })
    }

    pub fn get_secret(&self) -> SharedSecret {
        self.instance.shared_secret
    }
    pub fn get_shared_secret(&self) -> SharedSecret {
        self.instance.shared_secret
    }
}

pub fn derive_chacha_key(shared_secret: &SharedSecret) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"chacha-encryption-v1", &mut okm)
        .expect("HKDF failed");
    okm
}

pub fn generate_keypair() -> std::result::Result<kyberlib::Keypair, Error> {
    let mut rng = thread_rng();
    keypair(&mut rng).map_err(|e| anyhow!("Key generation failed: {}", e))
}