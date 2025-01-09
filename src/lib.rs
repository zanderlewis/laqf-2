#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![allow(clippy::needless_doctest_main)]
#![allow(clippy::new_without_default)]

extern crate alloc;

pub mod encoding;
pub mod encryption;
pub mod keys;
pub mod padding;
pub mod types;
pub mod utils;

use alloc::vec::Vec;
use encryption::{decrypt, encrypt};
use keys::{generate_kyber_keypair, generate_salt, KYBER_CIPHERTEXT_LENGTH, NONCE_SIZE, SALT_SIZE};
use pqc_kyber::{PublicKey, SecretKey};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use utils::check_for_empty;

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
        let mut laqf = Laqf2::new();
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
    pub salt_size: usize,
    pub nonce_size: usize,
    pub ciphertext_length: usize,
    rng: ChaChaRng,
}

impl Laqf2 {
    /// Create a new Laqf2 instance.
    pub fn new() -> Self {
        Laqf2 {
            salt_size: SALT_SIZE,
            nonce_size: NONCE_SIZE,
            ciphertext_length: KYBER_CIPHERTEXT_LENGTH,
            rng: ChaChaRng::from_entropy(),
        }
    }

    /// Generate a salt
    pub fn generate_salt(&self) -> Vec<u8> {
        generate_salt()
    }

    /// Generate a Kyber keypair.
    pub fn generate_kyber_keypair(&self) -> (PublicKey, SecretKey) {
        generate_kyber_keypair()
    }

    /// Encrypt data
    pub fn encrypt(&mut self, data: &[u8], password: &str, pk: &PublicKey, salt: &[u8]) -> Vec<u8> {
        check_for_empty(data, password);
        encrypt(data, password, pk, salt, &mut self.rng)
    }

    /// Decrypt data
    pub fn decrypt(
        &self,
        encrypted_data: &[u8],
        password: &str,
        sk: &SecretKey,
        salt: &[u8],
    ) -> Vec<u8> {
        decrypt(encrypted_data, password, sk, salt)
    }
}
