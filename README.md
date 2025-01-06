# LAQ-Fort v2
## Description
Laqf2 is a hybrid encryption scheme that combines Kyber and AES-GCM with Argon2 and HMAC-SHA256. It also employs encoding data to Mandelbrot points for more secure encryption.


It is also the second version of the LAQ-Fort (Lattice Authenticated Quantum Fortress, an originally messy crate) encryption scheme.

## Methods
- `new()`: Create a new Laqf2 instance.
- `generate_salt() -> Vec<u8>`: Generate a random salt.
- `generate_kyber_keypair()`: Generate a Kyber keypair.
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