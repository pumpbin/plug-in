use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use extism_pdk::*;
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Input {
    pub shellcode: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Pass {
    pub holder: Vec<u8>,
    pub replace_by: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Output {
    pub encrypted: Vec<u8>,
    pub pass: Vec<Pass>,
}

#[plugin_fn]
pub fn encrypt_shellcode(input: Vec<u8>) -> FnResult<Vec<u8>> {
    const KEY: &[u8; 32] = b"$$KKKKKKKKKKKKKKKKKKKKKKKKKKKK$$";
    const NONCE: &[u8; 12] = b"$$NNNNNNNN$$";

    let input = serde_json::from_slice::<Input>(input.as_slice())?;

    let mut key = vec![0; 32];
    let mut nonce = vec![0; 12];
    rand::thread_rng().fill_bytes(&mut key);
    rand::thread_rng().fill_bytes(&mut nonce);

    let aes = Aes256Gcm::new_from_slice(key.as_slice()).unwrap();
    let aes_nonce = Nonce::from_slice(nonce.as_slice());
    let encrypted = aes.encrypt(aes_nonce, input.shellcode.as_slice()).unwrap();

    let output = Output {
        encrypted,
        pass: vec![
            Pass {
                holder: KEY.to_vec(),
                replace_by: key,
            },
            Pass {
                holder: NONCE.to_vec(),
                replace_by: nonce,
            },
        ],
    };

    Ok(serde_json::to_vec(&output)?)
}
