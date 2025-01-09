use crate::encoding::{decode_from_mandelbrot, encode_to_mandelbrot};
use crate::keys::{derive_aes_key, KYBER_CIPHERTEXT_LENGTH, NONCE_SIZE};
use crate::types::MandelbrotPoint;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use pqc_kyber::*;
use rand_chacha::ChaChaRng;
use sha2::Sha256;

const HMAC_SIZE: usize = 32;
use crate::padding::BLOCK_SIZE;

pub fn encrypt(
    data: &[u8],
    password: &str,
    pk: &PublicKey,
    salt: &[u8],
    rng: &mut ChaChaRng,
) -> Vec<u8> {
    // Derive AES key
    let aes_key = derive_aes_key(password, salt);
    let nonce = generate_nonce(rng);

    let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
    let aes_encrypted_data = cipher.encrypt(Nonce::from_slice(&nonce), data).unwrap();

    let mandelbrot_encoded = encode_to_mandelbrot(&aes_encrypted_data);

    let (kyber_encrypted_key, shared_secret_alice) = encapsulate(pk, rng).unwrap();

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&shared_secret_alice).unwrap();
    mac.update(&aes_encrypted_data);
    let hmac = mac.finalize().into_bytes();

    let mut combined_data = Vec::with_capacity(
        KYBER_CIPHERTEXT_LENGTH + NONCE_SIZE + mandelbrot_encoded.len() * 16 + HMAC_SIZE,
    );
    combined_data.extend_from_slice(&kyber_encrypted_key);
    combined_data.extend_from_slice(&nonce);

    for p in mandelbrot_encoded.iter() {
        combined_data.extend_from_slice(&p.real.to_le_bytes());
        combined_data.extend_from_slice(&p.imag.to_le_bytes());
    }

    combined_data.extend_from_slice(&hmac);

    combined_data
}

pub fn decrypt(encrypted_data: &[u8], password: &str, sk: &SecretKey, salt: &[u8]) -> Vec<u8> {
    let aes_key = derive_aes_key(password, salt);

    if encrypted_data.len() < KYBER_CIPHERTEXT_LENGTH + NONCE_SIZE + HMAC_SIZE + BLOCK_SIZE {
        panic!("Encrypted data length is insufficient.");
    }

    let encrypted_key = &encrypted_data[..KYBER_CIPHERTEXT_LENGTH];

    let nonce_start = KYBER_CIPHERTEXT_LENGTH;
    let nonce_end = nonce_start + NONCE_SIZE;
    let nonce = Nonce::from_slice(&encrypted_data[nonce_start..nonce_end]);

    let hmac_start = encrypted_data.len() - HMAC_SIZE;
    let hmac = &encrypted_data[hmac_start..];

    let mandelbrot_data_start = nonce_end;
    let mandelbrot_data_end = hmac_start;
    let mandelbrot_data = &encrypted_data[mandelbrot_data_start..mandelbrot_data_end];

    let mut points = Vec::with_capacity(mandelbrot_data.len() / 16);
    for chunk in mandelbrot_data.chunks_exact(16) {
        let real = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let imag = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        points.push(MandelbrotPoint { real, imag });
    }

    let aes_encrypted_data = decode_from_mandelbrot(&mut points);

    let shared_secret_bob = match decapsulate(encrypted_key, sk) {
        Ok(secret) => secret,
        Err(_) => {
            panic!("Decapsulation failed.");
        }
    };

    let mut mac_calc = <Hmac<Sha256> as Mac>::new_from_slice(&shared_secret_bob).unwrap();
    mac_calc.update(&aes_encrypted_data);
    let computed_hmac = mac_calc.finalize().into_bytes();

    if computed_hmac.as_slice() != hmac {
        panic!("Data integrity check failed: HMAC does not match.");
    }

    let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
    cipher.decrypt(nonce, aes_encrypted_data.as_ref()).unwrap()
}

fn generate_nonce(rng: &mut ChaChaRng) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut nonce);
    nonce
}
