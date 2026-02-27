use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, aead::{Aead, OsRng}};
use blake3::Hash;
use crate::{lib::GeneralError};

pub fn get_length_of_slice_as_bytes(slice: &[u8]) -> Vec<u8> {
    let mut length = slice.len().to_string().as_bytes().to_vec();
    while length.len() != 20 {length.push(0)}
    length
}

pub fn try_slice_into_usize(slice: &[u8]) -> Result<usize, GeneralError> {
    let mut slice_vec = slice.to_vec();
    loop {
        match slice_vec.last() {
            Some(b) => {if b == &0 {let _ = slice_vec.pop();} else {break;}}
            None => {return Err(GeneralError::InvalidFormat);}
        }
    }
    let string = match String::from_utf8(slice_vec) {
        Ok(s) => {s}
        Err(_) => {return Err(GeneralError::InvalidFormat);}
    };
    let number = match string.parse::<usize>() {
        Ok(n) => {n}
        Err(_) => {return Err(GeneralError::InvalidFormat);}
    };
    Ok(number)
}

pub fn encrypt_bytes(bytes: Vec<u8>, pwd_hash: Hash) -> Result<Vec<u8>, GeneralError> {

    let key: &Key<Aes256Gcm> = pwd_hash.as_bytes().into();
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    let mut enc_bytes = match cipher.encrypt(&nonce, bytes.as_slice()) {
        Ok(b) => {drop(bytes); b}
        Err(_) => {return Err(GeneralError::EncryptionError);}
    };
    let mut total = nonce.to_vec();
    total.append(&mut enc_bytes);

    Ok(total)
}

pub fn decrypt_bytes(bytes: Vec<u8>, pwd_hash: Hash) -> Result<Vec<u8>, GeneralError> {
    
    let enc_bytes = match bytes.get(12..) {
        Some(b) => {b}
        None => {return Err(GeneralError::InvalidFormat);}
    };
    let nonce_bytes = match bytes.get(0..12) {
        Some(b) => {b}
        None => {return Err(GeneralError::InvalidFormat);}
    };
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    let key: &Key<Aes256Gcm> = pwd_hash.as_bytes().into();
    let cipher = Aes256Gcm::new(key);
    
    match cipher.decrypt(&nonce, enc_bytes) {
        Ok(b) => {return Ok(b);}
        Err(_) => {return Err(GeneralError::DecryptionError);}
    };
}