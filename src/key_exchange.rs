//! Kyber-1024 key exchange implementation (NIST PQC Round 3)
//!
//! Provides Unilateral Authentication Key Exchange (UAKE) protocol
//!
//! ## Basic Flow
//! 1. Client: `ClientHandshake::new()` -> `send_init`
//! 2. Server: `ServerHandshake::new()` -> `send_response`
//! 3. Client: `finalize()` -> Shared secret
//! 4. Derive keys: `derive_chacha_key()`

use anyhow::{anyhow, Error, Result};
use hkdf::Hkdf;
use kyberlib::{Uake, PublicKey, SecretKey, SharedSecret, UakeSendInit, UakeSendResponse, keypair};
use rand::thread_rng;
use sha2::Sha256;
use zerocopy::IntoBytes;

/// Kyber-1024 key sizes
pub const KYBER_PUBLIC_KEY_BYTES: usize = 1184;
/// Kyber-1024 key sizes
pub const KYBER_SECRET_KEY_BYTES: usize = 2400;

/// Client-side handshake state
#[derive(Clone)]
pub struct ClientHandshake {
    pub(crate) instance: Uake,
    pub send_init: UakeSendInit,
}

/// Server-side handshake state
pub struct ServerHandshake {
    instance: Uake,
    pub send_response: UakeSendResponse,
}

impl ClientHandshake {
    /// Initiates key exchange with recipient public key
    pub fn new(server_pubkey: &PublicKey) -> Result<Self> {
        let mut rng = thread_rng();
        let mut instance = Uake::new();

        let send_init = instance.client_init(server_pubkey, &mut rng)
            .map_err(|e| anyhow!("Client init failed: {}", e))?;

        Ok(Self { instance, send_init })
    }

    /// Completes handshake with recipient response
    ///
    /// # Returns
    /// Shared secret for key derivation
    pub fn finalize(mut self, server_response: UakeSendResponse) -> Result<SharedSecret> {
        self.instance.client_confirm(server_response)
            .map_err(|e| anyhow!("Client confirm failed: {}", e))?;
        Ok(self.instance.shared_secret)
    }
}

impl ServerHandshake {
    /// Processes sender initiation and generates response
    pub fn new(client_init: UakeSendInit, server_secret: &SecretKey) -> Result<Self> {
        let mut rng = thread_rng();
        let mut instance = Uake::new();

        let send_response = instance.server_receive(client_init, server_secret, &mut rng)
            .map_err(|e| anyhow!("Server receive failed: {}", e))?;

        Ok(Self { instance, send_response })
    }

    /// Retrieves established shared secret
    pub fn get_secret(&self) -> SharedSecret {
        self.instance.shared_secret
    }
}

/// Derives 256-bit ChaCha20 key from Kyber shared secret
///
/// Uses HKDF-SHA256 with protocol-specific context
///
/// # Security
/// Context string prevents key reuse in different protocol components
pub fn derive_chacha_key(shared_secret: &SharedSecret) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"chacha-encryption-v1", &mut okm)
        .expect("HKDF failed");
    okm
}

/// Generates CPA-secure Kyber-1024 keypair
///
/// # Example
/// ```
/// # use std::error::Error;
/// # fn main() -> Result<(), Box<dyn Error>> {
/// use kychacha_crypto::generate_keypair;
///
/// let keypair = generate_keypair()?;
/// Ok(())
/// # }
/// ```
pub fn generate_keypair() -> std::result::Result<kyberlib::Keypair, Error> {
    let mut rng = thread_rng();
    keypair(&mut rng).map_err(|e| anyhow!("Key generation failed: {}", e))
}