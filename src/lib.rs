#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
// Clippy allows
#![allow(clippy::needless_doctest_main)]
#![allow(clippy::new_without_default)]

extern crate alloc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use alloc::vec::Vec;
use argon2::Argon2;
use core::convert::TryInto;
use core::str;
use hmac::{Hmac, Mac};
use pqc_kyber::*;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use sha2::Sha256;

// Define clear constants for each component's size
const KYBER_CIPHERTEXT_LENGTH: usize = 1568; // Length of Kyber ciphertext
const NONCE_SIZE: usize = 12; // Nonce size for AES-GCM
const HMAC_SIZE: usize = 32; // HMAC-SHA256 size
const SALT_SIZE: usize = 32; // Salt size for Argon2
const BLOCK_SIZE: usize = 16; // Block size for padding

struct MandelbrotPoint {
    real: u64,
    imag: u64,
}

/**
    # Laqf2
    Laqf2 is a hybrid encryption scheme that combines Kyber and AES-GCM with Argon2 and HMAC-SHA256.
    It is the second version of the LAQ-Fort (Lattice Authenticated Quantum Fortress) encryption scheme.
    It also employs encoding data to Mandelbrot points for more secure encryption.

    ## Methods
    - `new()`: Create a new Laqf2 instance.
    - `generate_salt() -> Vec<u8>`: Generate a salt.
    - `generate_kyber_keypair() -> (PublicKey, SecretKey)`: Generate a Kyber keypair.
    - `encrypt(data: &[u8], password: &str, pk: &PublicKey, salt: &[u8]) -> Vec<u8>`: Encrypt data using Kyber and AES-GCM.
    - `decrypt(encrypted_data: &[u8], password: &str, sk: &SecretKey, salt: &[u8]) -> Vec<u8>`: Decrypt data using Kyber and AES-GCM.

    ## Example
    ```rust
    use laqf2::Laqf2;

    fn main() {
        let laqf = Laqf2::new();
        let (pk, sk) = laqf.generate_kyber_keypair();

        let data = b"Hello, world!";
        let password = "password";
        let salt = laqf.generate_salt();

        let encrypted_data = laqf.encrypt(data, password, &pk, &salt);
        let decrypted_data = laqf.decrypt(&encrypted_data, password, &sk, &salt);

        assert_eq!(data, decrypted_data.as_slice());
    }
    ```
*/
#[allow(dead_code)]
pub struct Laqf2 {
    salt_size: usize,
    nonce_size: usize,
    ciphertext_length: usize,
}

impl Laqf2 {
    /// Create a new Laqf2 instance.
    pub fn new() -> Self {
        Laqf2 {
            salt_size: SALT_SIZE,
            nonce_size: NONCE_SIZE,
            ciphertext_length: KYBER_CIPHERTEXT_LENGTH,
        }
    }

    /// Generate a salt
    pub fn generate_salt(&self) -> Vec<u8> {
        let mut rng = ChaChaRng::from_entropy();
        let mut salt = [0u8; SALT_SIZE];
        rng.fill_bytes(&mut salt);
        (salt).to_vec()
    }

    /// Generate a Kyber keypair.
    pub fn generate_kyber_keypair(&self) -> (PublicKey, SecretKey) {
        let mut rng = ChaChaRng::from_entropy();
        let Keypair { public, secret } = keypair(&mut rng).unwrap();
        (public, secret)
    }

    // Derive AES key using Argon2
    fn derive_aes_key(&self, password: &str, salt: &[u8]) -> [u8; 32] {
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .unwrap();
        key
    }

    fn generate_nonce(&self) -> [u8; NONCE_SIZE] {
        let mut rng = ChaChaRng::from_entropy();
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        nonce
    }

    // Apply PKCS#7 padding
    fn pad(&self, data: &[u8]) -> Vec<u8> {
        let padding_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
        let mut padded = data.to_vec();
        padded.extend(core::iter::repeat(padding_len as u8).take(padding_len));
        padded
    }

    // Remove PKCS#7 padding
    fn unpad(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if data.is_empty() {
            return Err("Data is empty, cannot unpad.");
        }
        let padding_len = *data.last().unwrap() as usize;
        if padding_len == 0 || padding_len > BLOCK_SIZE {
            return Err("Invalid padding length.");
        }
        if data.len() < padding_len {
            return Err("Padding length exceeds data length.");
        }
        for &byte in &data[data.len() - padding_len..] {
            if byte as usize != padding_len {
                return Err("Invalid padding byte found.");
            }
        }
        Ok(data[..data.len() - padding_len].to_vec())
    }

    // Encode data to Mandelbrot points without loss, with padding
    fn encode_to_mandelbrot(&self, data: &[u8]) -> Vec<MandelbrotPoint> {
        let padded_data = self.pad(data);
        let data_length = data.len() as u64;
        let mut encoded = Vec::new();

        // Encode the original data length first
        encoded.push(MandelbrotPoint {
            real: data_length,
            imag: 0,
        });

        // Encode the padded data
        padded_data.chunks(BLOCK_SIZE).for_each(|chunk| {
            let real_bytes: [u8; 8] = chunk
                .get(0..8)
                .unwrap_or(&[])
                .iter()
                .cloned()
                .chain(core::iter::repeat(0))
                .take(8)
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap();
            let imag_bytes: [u8; 8] = chunk
                .get(8..16)
                .unwrap_or(&[])
                .iter()
                .cloned()
                .chain(core::iter::repeat(0))
                .take(8)
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap();
            encoded.push(MandelbrotPoint {
                real: u64::from_le_bytes(real_bytes),
                imag: u64::from_le_bytes(imag_bytes),
            });
        });

        encoded
    }

    // Decode Mandelbrot points back to data without loss, removing padding
    fn decode_from_mandelbrot(&self, points: &[MandelbrotPoint]) -> Vec<u8> {
        if points.is_empty() {
            return Vec::new();
        }

        // First point contains the original data length
        let data_length = points[0].real as usize;
        let mut data = Vec::with_capacity(data_length);

        // Decode the actual padded data
        let mut padded_data = Vec::new();
        for point in &points[1..] {
            padded_data.extend_from_slice(&point.real.to_le_bytes());
            padded_data.extend_from_slice(&point.imag.to_le_bytes());
        }

        // Remove padding
        match self.unpad(&padded_data) {
            Ok(unpadded) => {
                // Trim the data to the original length
                data.extend_from_slice(&unpadded[..data_length.min(unpadded.len())]);
            }
            Err(_) => {
                // If padding is invalid, return empty data
                return Vec::new();
            }
        }

        data
    }

    fn check_key(&self, pk: Option<&PublicKey>, sk: Option<&SecretKey>) {
        match (pk, sk) {
            (Some(_), Some(_)) => {
                // Do nothing
            }
            (None, Some(sk)) => {
                if sk.is_empty() {
                    panic!("Secret key is empty.");
                }
            }
            (Some(pk), None) => {
                if pk.is_empty() {
                    panic!("Public key is empty.");
                }
            }
            (None, None) => {
                panic!("Both keys are missing.");
            }
        }
    }

    fn check_bounds(&self, data: &[u8], password: &str, salt: &[u8]) {
        if data.is_empty() {
            panic!("Data is empty.");
        }
        if password.is_empty() {
            panic!("Password is empty.");
        }
        if salt.is_empty() {
            panic!("Salt is empty.");
        }
    }

    /// Encrypt using Laqf2 hybrid encryption scheme.
    pub fn encrypt(&self, data: &[u8], password: &str, pk: &PublicKey, salt: &[u8]) -> Vec<u8> {
        self.check_bounds(data, password, salt);
        self.check_key(Some(pk), None);

        let aes_key = self.derive_aes_key(password, salt);
        let nonce = self.generate_nonce();

        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let aes_encrypted_data = cipher.encrypt(Nonce::from_slice(&nonce), data).unwrap();

        let mandelbrot_encoded = self.encode_to_mandelbrot(&aes_encrypted_data);

        let mut rng = ChaChaRng::from_entropy();
        let (kyber_encrypted_key, shared_secret_alice) = encapsulate(pk, &mut rng).unwrap();

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&shared_secret_alice).unwrap();
        mac.update(&aes_encrypted_data);
        let hmac = mac.finalize().into_bytes();

        let mut combined_data = kyber_encrypted_key.to_vec();
        combined_data.extend_from_slice(nonce.as_slice());
        combined_data.extend(
            mandelbrot_encoded
                .iter()
                .flat_map(|p| {
                    p.real
                        .to_le_bytes()
                        .iter()
                        .cloned()
                        .chain(p.imag.to_le_bytes().iter().cloned())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<u8>>(),
        );
        combined_data.extend_from_slice(&hmac);

        combined_data
    }

    /// Decrypt using Laqf2 hybrid encryption scheme.
    pub fn decrypt(
        &self,
        encrypted_data: &[u8],
        password: &str,
        sk: &SecretKey,
        salt: &[u8],
    ) -> Vec<u8> {
        self.check_bounds(encrypted_data, password, salt);
        self.check_key(None, Some(sk));

        let aes_key = self.derive_aes_key(password, salt);

        // Ensure the encrypted_data has at least the minimum required length
        if encrypted_data.len() < KYBER_CIPHERTEXT_LENGTH + NONCE_SIZE + HMAC_SIZE + BLOCK_SIZE {
            panic!("Encrypted data length is insufficient.");
        }

        // Extract the Kyber encrypted key
        let encrypted_key = &encrypted_data[..KYBER_CIPHERTEXT_LENGTH];

        // Extract the nonce
        let nonce_start = KYBER_CIPHERTEXT_LENGTH;
        let nonce_end = nonce_start + NONCE_SIZE;
        let nonce = Nonce::from_slice(&encrypted_data[nonce_start..nonce_end]);

        // Extract the HMAC
        let hmac_start = encrypted_data.len() - HMAC_SIZE;
        let hmac = &encrypted_data[hmac_start..];

        // Extract the mandelbrot_encoded data
        let mandelbrot_data_start = nonce_end;
        let mandelbrot_data_end = hmac_start;
        let mandelbrot_data = &encrypted_data[mandelbrot_data_start..mandelbrot_data_end];

        // Decode mandelbrot data to get the AES encrypted data
        let points = mandelbrot_data
            .chunks(BLOCK_SIZE)
            .map(|chunk| {
                let real_bytes: [u8; 8] = chunk
                    .get(0..8)
                    .unwrap_or(&[])
                    .iter()
                    .cloned()
                    .chain(core::iter::repeat(0))
                    .take(8)
                    .collect::<Vec<u8>>()
                    .try_into()
                    .unwrap();
                let imag_bytes: [u8; 8] = chunk
                    .get(8..16)
                    .unwrap_or(&[])
                    .iter()
                    .cloned()
                    .chain(core::iter::repeat(0))
                    .take(8)
                    .collect::<Vec<u8>>()
                    .try_into()
                    .unwrap();
                MandelbrotPoint {
                    real: u64::from_le_bytes(real_bytes),
                    imag: u64::from_le_bytes(imag_bytes),
                }
            })
            .collect::<Vec<MandelbrotPoint>>();

        let aes_encrypted_data = self.decode_from_mandelbrot(&points);

        // Decapsulate to get the shared secret
        let shared_secret_bob = match decapsulate(encrypted_key, sk) {
            Ok(secret) => secret,
            Err(_) => {
                panic!("Decapsulation failed.");
            }
        };

        // Verify HMAC
        let mut mac_calc = <Hmac<Sha256> as Mac>::new_from_slice(&shared_secret_bob).unwrap();
        mac_calc.update(&aes_encrypted_data);
        let computed_hmac = mac_calc.finalize().into_bytes();

        if computed_hmac.as_slice() != hmac {
            panic!("Data integrity check failed: HMAC does not match.");
        }

        // Decrypt the data
        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        cipher.decrypt(nonce, aes_encrypted_data.as_ref()).unwrap()
    }
}
