use alloc::vec::Vec;
use argon2::Argon2;
use pqc_kyber::*;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

pub const SALT_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const KYBER_CIPHERTEXT_LENGTH: usize = 1568;

pub fn generate_salt() -> Vec<u8> {
    let mut salt = [0u8; SALT_SIZE];
    ChaChaRng::from_entropy().fill_bytes(&mut salt);
    salt.to_vec()
}

pub fn generate_kyber_keypair() -> (PublicKey, SecretKey) {
    let mut rng = ChaChaRng::from_entropy();
    let Keypair { public, secret } = keypair(&mut rng).unwrap();
    (public, secret)
}

pub fn derive_aes_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .unwrap();
    key
}
