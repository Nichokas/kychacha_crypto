use std::ffi::{c_char, CStr, CString};
use crate::{bytes_to_public_key, bytes_to_secret_key, generate_keypair as kgk, public_key_to_bytes, secret_key_to_bytes, encrypt as kencrypt, decrypt as kdecript, MlKem768PublicKey, MlKem768PrivateKey};

#[unsafe(no_mangle)]
pub extern "C" fn ffi_generate_keypair() -> *mut c_char {
    let keypair = kgk();
    let hex = hex::encode([public_key_to_bytes(keypair.public_key()).as_ref(),secret_key_to_bytes(keypair.private_key()).as_ref()].concat());
    CString::new(hex).unwrap_or_default().into_raw()
}

#[unsafe(no_mangle)]
pub extern "C" fn ffi_get_pub_key(keypair:*mut c_char) -> *mut c_char {
    unsafe {
        // Early returns for validation checks
        if keypair.is_null() {
            return error_msg("Error: Null pointer provided");
        }

        let hex_s = match CStr::from_ptr(keypair).to_str() {
            Ok(s) => s,
            Err(_) => return error_msg("Error: Invalid UTF-8 in keypair string"),
        };

        let comb = match hex::decode(hex_s) {
            Ok(bytes) => bytes,
            Err(_) => return error_msg("Error: Invalid hex format in keypair"),
        };

        if comb.len() < 3584 {
            return error_msg("Failed to reassemble keys: Keypair must be at least 3584 bytes");
        }
        match <&[u8; 1184]>::try_from(&comb[..1184]) {
            Ok(pub_key_bytes) => CString::new(hex::encode(pub_key_bytes))
                .unwrap_or_default()
                .into_raw(),
            Err(_) => error_msg("Error: Private key has incorrect length"),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ffi_get_priv_key(keypair: *mut c_char) -> *mut c_char {
    unsafe {
        // Early returns for validation checks
        if keypair.is_null() {
            return error_msg("Error: Null pointer provided");
        }

        // Chain operations with early return on errors
        let hex_s = match CStr::from_ptr(keypair).to_str() {
            Ok(s) => s,
            Err(_) => return error_msg("Error: Invalid UTF-8 in keypair string"),
        };

        let comb = match hex::decode(hex_s) {
            Ok(bytes) => bytes,
            Err(_) => return error_msg("Error: Invalid hex format in keypair"),
        };

        if comb.len() <= 1184 {
            return error_msg("Failed to reassemble keys: Invalid keypair");
        }

        match <&[u8; 2400]>::try_from(&comb[1184..]) {
            Ok(priv_key_bytes) => CString::new(hex::encode(priv_key_bytes))
                .unwrap_or_default()
                .into_raw(),
            Err(_) => error_msg("Error: Private key has incorrect length"),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ffi_encrypt(pubkey: *mut c_char, message: *mut c_char) -> *mut c_char {
    unsafe {
        // Check for null pointer
        if pubkey.is_null() || message.is_null(){
            return error_msg("Error: Null pointer provided");
        }

        let (hex_s, msg_s) = match (
            CStr::from_ptr(pubkey).to_str(),
            CStr::from_ptr(message).to_str()
        ) {
            (Ok(p), Ok(m)) => (p, m),
            (Err(_), _) => return error_msg("Error: Invalid UTF-8 in pubkey string"),
            (_, Err(_)) => return error_msg("Error: Invalid UTF-8 in message string")
        };

        let pubkey_bytes = match hex::decode(hex_s) {
            Ok(p) => p,
            Err(_) => return error_msg("Error: Failed to decode the message")
        };

        let pubkey_array: [u8; 1184] = match pubkey_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return error_msg("Invalid public key format"),
        };

        let pubkey = match bytes_to_public_key(&pubkey_array) {
            Ok(pk) => pk,
            Err(_) => return error_msg("Failed to create public key from bytes"),
        };

        match kencrypt(&pubkey, msg_s.as_bytes()) {
            Ok(encrypted_data) => CString::new(hex::encode(encrypted_data))
                .unwrap_or_default()
                .into_raw(),
            Err(_) => error_msg("Error: Encryption failed"),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ffi_decrypt(cprivkey: *mut c_char,encrypted_data: *mut c_char) -> *mut c_char {
    unsafe {
        // Check for null pointer
        if cprivkey.is_null() || encrypted_data.is_null(){
            return error_msg("Error: Null pointer provided");
        }
        let (privatekey_cs,data_cs) = match (
            CStr::from_ptr(cprivkey).to_str(),
            CStr::from_ptr(encrypted_data).to_str()
        ){
            (Ok(p),Ok(ed)) => (p,ed),
            (Err(_),_) => return error_msg("Error: Invalid UTF-8 in private key"),
            (_,Err(_)) => return error_msg("Error: Invalid UTF-8 in encrypted data")
        };

        let (privatekey_bytes,data_vec) = match (
            hex::decode(privatekey_cs),
            hex::decode(data_cs)
        ) {
            (Ok(p),Ok(ed)) => (p,ed),
            (Err(_),_) => return error_msg("Error: Invalid Hex in private key"),
            (_,Err(_)) => return error_msg("Error: Invalid Hex in encrypted data")
        };

        let private_key_array: [u8; 2400] = match privatekey_bytes.try_into(){
            Ok(pk) => pk,
            Err(_) => return error_msg("Error while reconstructing the private key to a array")
        };

        let private_key: MlKem768PrivateKey = match bytes_to_secret_key(&private_key_array) {
            Ok(pk) => pk,
            Err(_) => return error_msg("Error: Invalid private key")
        };

        match kdecript(data_vec.as_slice(), &private_key) {
            Ok(decrypted_data) => CString::new(decrypted_data).unwrap_or_default().into_raw(),
            Err(_) => error_msg("Error: Decryption failed"),
        }
    }
}

fn error_msg(msg:&str) -> *mut c_char {
    return CString::new(format!("*/üuüuüu/-/ {msg} /-/üuüuüu/*"))
        .unwrap_or_default()
        .into_raw();
}


#[unsafe(no_mangle)]
pub extern "C" fn ffi_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}
