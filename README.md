# Kychacha-crypto: Post-Quantum Secure Encryption Protocol
## A post-quantum simple to use implementation for ML-KEM and ChaCha20
[![CI](https://github.com/Nichokas/kychacha_crypto/actions/workflows/build.yaml/badge.svg)](https://github.com/Nichokas/kychacha_crypto/actions/workflows/build.yaml)
[![Security audit](https://github.com/Nichokas/kychacha_crypto/actions/workflows/rustsec.yaml/badge.svg)](https://github.com/Nichokas/kychacha_crypto/actions/workflows/rustsec.yaml)
[![CodSpeed Badge](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://codspeed.io/Nichokas/kychacha_crypto)
![Crates.io Version](https://img.shields.io/crates/v/kychacha_crypto)
[![DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Nichokas/kychacha_crypto)

Hybrid cryptographic implementation using:
- **ML-KEM** (formerly Crystals-Kyber): Post-Quantum secure Key Encapsulation Mechanism (KEM) for key exchange, standardized by NIST.
- **ChaCha20-Poly1305**: Authenticated symmetric encryption.

## Language Bindings

### Ruby Gem

A Ruby gem binding is available that leverages the FFI interface to provide Kychacha functionality in Ruby applications: [kychacha_gem](https://github.com/Nichokas/kychacha_gem)

## Architecture

The following diagram describes the protocol flow between the "Sender" and the "Recipient":

```mermaid
sequenceDiagram
    participant Sender
    participant Recipient

    Recipient-->>Sender: Recipient public key (ML-KEM pub key 1184 bytes)
    
    Sender->>Sender: Encapsulate secret (ML-KEM)
    Note right of Sender: Generates ephemeral keypair and derives shared secret
    Sender->>Sender: Derive ChaCha key (HKDF-SHA256)
    Note right of Sender: Uses shared secret to derive symmetric key
    Sender->>Sender: Encrypt message (ChaCha20-Poly1305)
    
    Sender->>Recipient: Send {ciphertext, nonce, encrypted message}
    
    Recipient->>Recipient: Decapsulate secret (ML-KEM)
    Note right of Recipient: Recovers shared secret
    Recipient->>Recipient: Derive ChaCha key (HKDF-SHA256)
    Note right of Recipient: Derives the same symmetric key
    Recipient->>Recipient: Decrypt message
```

> *Note*: During the encapsulation process on the sender's side, an ephemeral keypair is generated.

## Usage and documentation
https://docs.rs/kychacha_crypto

## Safety Considerations

2. **Randomness**: Depends on the secure generator of the system.
3. **HKDF context**: Used for protocol binding.
4. **Nonces**: Generated with CSPRNG for each message.
