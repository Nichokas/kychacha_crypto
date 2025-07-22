use oqs::kem::{PublicKey as libPublicKey, SecretKey as libSecretKey};
use serde::{Deserialize, Serialize};
use bincode::serde::{encode_to_vec,borrow_decode_from_slice};
use crate::select_bincode_config;
use anyhow::Result;

#[repr(u16)]
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum SecurityLevel {
    MlKem512 = 512,
    MlKem768 = 768,
    MlKem1024 = 1024,
}

#[derive(Clone,Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretKey {
    pub security: SecurityLevel,
    pub key: libSecretKey,
}

impl SecretKey {
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(encode_to_vec(self,select_bincode_config()?)?)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(borrow_decode_from_slice(bytes,select_bincode_config()?)?.0)
    }
}

#[derive(Clone,Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKey {
    pub security: SecurityLevel,
    pub key: libPublicKey,
}

impl PublicKey {
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(encode_to_vec(self,select_bincode_config()?)?)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(borrow_decode_from_slice(bytes,select_bincode_config()?)?.0)
    }
}

#[derive(Clone,Eq, PartialEq, Serialize, Deserialize)]
pub struct MlKemKeyPair {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
}

impl MlKemKeyPair {
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        Ok(encode_to_vec(self,select_bincode_config()?)?)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(borrow_decode_from_slice(bytes,select_bincode_config()?)?.0)
    }
}