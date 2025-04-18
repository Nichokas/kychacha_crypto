# Kychacha-crypto: Post-Quantum Secure Encryption Protocol
## A post-quantum simple to use implementation for Kyber and ChaCha20
[![CI](https://github.com/Nichokas/kychacha_crypto/actions/workflows/build.yaml/badge.svg)](https://github.com/Nichokas/kychacha_crypto/actions/workflows/build.yaml)
[![Security audit](https://github.com/Nichokas/kychacha_crypto/actions/workflows/rustsec.yaml/badge.svg)](https://github.com/Nichokas/kychacha_crypto/actions/workflows/rustsec.yaml)
[![CodSpeed Badge](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://codspeed.io/Nichokas/kychacha_crypto)
![Crates.io Version](https://img.shields.io/crates/v/kychacha_crypto)

Hybrid cryptographic implementation using:
- **Crystals-Kyber**: Post-Quantum secure Key Encapsulation Mechanism (KEM) for key exchange.
- **ChaCha20-Poly1305**: Authenticated symmetric encryption.

## Architecture

The following diagram describes the protocol flow between the "Sender" and the "Recipient":

```mermaid
sequenceDiagram
    participant Sender
    participant Recipient

    Recipient-->>Sender: Recipient public key (Kyber pub key 1184 bytes)
    
    Sender->>Sender: Encapsulate secret (Kyber)
    Note right of Sender: Generates ephemeral keypair and derives shared secret
    Sender->>Sender: Derive ChaCha key (HKDF-SHA256)
    Note right of Sender: Uses shared secret to derive symmetric key
    Sender->>Sender: Encrypt message (ChaCha20-Poly1305)
    
    Sender->>Recipient: Send {ciphertext, nonce, encrypted message}
    
    Recipient->>Recipient: Decapsulate secret (Kyber)
    Note right of Recipient: Recovers shared secret
    Recipient->>Recipient: Derive ChaCha key (HKDF-SHA256)
    Note right of Recipient: Derives the same symmetric key
    Recipient->>Recipient: Decrypt message
```

> *Note*: During the encapsulation process on the sender's side, an ephemeral keypair is generated.

## Technical Specifications

### 1. Key Exchange Protocol
- **Algorithm**: Kyber-1024 (NIST PQC Round 3)
- **Key Parameters**:
  ```rust
    pub const KYBER_PUBLIC_KEY_BYTES: usize = 1184;
    pub const KYBER_SECRET_KEY_BYTES: usize = 2400;
    pub const KYBER_CIPHERTEXT_BYTES: usize = 1568;
  ```
- **Key Derivation**: HKDF-SHA256 with specific context
### 2. Symetric Encryption
- **Algorithm**: ChaCha20-Poly1305 (IETF variant)
- **Key** Size: 256 bits
- **Nonce**: 96 bits (randomly generated per message)

### 3. Encrypted Data Format
The encrypted data is a serialized binary structure containing:

- **Ciphertext**: Kyber ciphertext (1568 bytes).
- **Nonce**: ChaCha20 nonce (12 bytes).
- **Encrypted Message**: Encrypted message with authentication tag.
```rust
    #[derive(Serialize, Deserialize, Debug)]
    pub struct EncryptedData {
        #[serde(with = "serde_bytes")]
        pub ciphertext: Vec<u8>,    // Kyber ciphertext (1568 bytes)
        #[serde(with = "serde_bytes")]
        pub nonce: Vec<u8>,         // ChaCha20 nonce (12 bytes)
        #[serde(with = "serde_bytes")]
        pub encrypted_msg: Vec<u8>, // Encrypted message with authentication tag
    }
```

## Basic Usage
### Key Generation and encryption
```rust
use kychacha_crypto::{generate_keypair, Keypair, decrypt, encrypt, PublicKey};

// Generate a Kyber-1024 keypair
let server_kp: Keypair = generate_keypair()?;

let message = b"Secret message";
// Encrypt the message using the server's public key
let encrypted_data: Vec<u8> = encrypt(&server_kp.public, message)?;

// Receive encrypted_data as &[u8] from the client
let decrypted_message = decrypt(&encrypted_data, &server_kp)?;
assert_eq!(decrypted_message, "Secret message");
```
> **Note**: The decrypt function assumes the original message is a valid UTF-8 string and returns a String. If the message contains non-UTF-8 binary data, decryption will fail.

### Key Serialization (for storage/transmission)
```rust
use kychacha_crypto::{public_key_to_bytes, secret_key_to_bytes};

// Convert keys to byte vectors
let pk_bytes: Vec<u8> = public_key_to_bytes(&server_kp.public);
let sk_bytes: Vec<u8> = secret_key_to_bytes(&server_kp.secret);

// Reconstruct keys from bytes
let public_key = PublicKey::from(pk_bytes.as_slice());
let secret_key = SecretKey::from(sk_bytes.as_slice());
```
## Safety Considerations

2. **Randomness**: Depends on the secure generator of the system.
3. **HKDF context**: Used for protocol binding.
4. **Nonces**: Generated with CSPRNG for each message.
