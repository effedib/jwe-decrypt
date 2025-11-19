use aes_gcm::{
    Aes128Gcm, Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use std::error::Error;

use crate::jwe::JweHeader;

pub type CryptoResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub trait KeyDecryptor {
    fn decrypt_cek(
        &self,
        input_key: &[u8],
        encrypted_key: &[u8],
        header: JweHeader,
    ) -> CryptoResult<Vec<u8>>;
}

pub trait ContentDecryptor {
    fn decrypt_payload(
        &self,
        cek: &[u8],
        aad: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> CryptoResult<Vec<u8>>;
}

pub struct AesGcmContentDecryptor {
    key_len: usize,
}

impl AesGcmContentDecryptor {
    pub fn new(key_len: usize) -> Self {
        Self { key_len }
    }
}

impl ContentDecryptor for AesGcmContentDecryptor {
    fn decrypt_payload(
        &self,
        cek: &[u8],
        aad: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if cek.len() != self.key_len {
            return Err("Cek length mismatch".into());
        }
        let payload_concat = [ciphertext, tag].concat();
        let payload = Payload {
            msg: &payload_concat,
            aad,
        };

        let iv_array: [u8; 12] = iv
            .try_into()
            .map_err(|_| "IV length invalid: must be 12 bytes")?;
        let nonce = Nonce::from(iv_array);

        match self.key_len {
            16 => {
                let key_array: [u8; 16] = cek
                    .try_into()
                    .map_err(|_| "CEK length mismatch: expected 16 bytes (A128GCM)")?;
                let key = Key::<Aes128Gcm>::from(key_array);
                Aes128Gcm::new(&key)
                    .decrypt(&nonce, payload)
                    .map_err(|e| format!("Decryption failed (A128): {}", e).into())
            }
            32 => {
                let key_array: [u8; 32] = cek
                    .try_into()
                    .map_err(|_| "CEK length mismatch: expected 32 bytes (A256GCM)")?;
                let key = Key::<Aes256Gcm>::from(key_array);
                Aes256Gcm::new(&key)
                    .decrypt(&nonce, payload)
                    .map_err(|e| format!("Decryption failed (A256): {}", e).into())
            }
            _ => Err(format!("Unsupported key length: {}", self.key_len).into()),
        }
    }
}
