use laqf2::Laqf2;

#[test]
fn test_correct() {
    let laqf = Laqf2::new();
    let (pk, sk) = laqf.generate_kyber_keypair();

    let data = b"Hello, world!";
    let password = "password";
    let salt = laqf.generate_salt();

    let encrypted_data = laqf.encrypt(data, password, &pk, &salt);
    let decrypted_data = laqf.decrypt(&encrypted_data, password, &sk, &salt);

    // Should be the same
    assert_eq!(data, decrypted_data.as_slice());
}

#[test]
fn test_wrong_password() {
    let result = std::panic::catch_unwind(|| {
        let laqf = Laqf2::new();
        let (pk, sk) = laqf.generate_kyber_keypair();

        let data = b"Hello, world!";
        let password = "password";
        let salt = laqf.generate_salt();

        let encrypted_data = laqf.encrypt(data, password, &pk, &salt);
        let decrypted_data = laqf.decrypt(&encrypted_data, "wrong_password", &sk, &salt);

        // Should not be the same
        assert_ne!(data, decrypted_data.as_slice());
    });

    assert!(result.is_err());
}

#[test]
fn test_wrong_key() {
    let result = std::panic::catch_unwind(|| {
        let laqf = Laqf2::new();
        let (pk, _) = laqf.generate_kyber_keypair();
        let (_, sk) = laqf.generate_kyber_keypair();

        let data = b"Hello, world!";
        let password = "password";
        let salt = laqf.generate_salt();

        let encrypted_data = laqf.encrypt(data, password, &pk, &salt);
        let decrypted_data = laqf.decrypt(&encrypted_data, password, &sk, &salt);

        // Should not be the same
        assert_ne!(data, decrypted_data.as_slice());
    });

    assert!(result.is_err());
}

#[test]
fn test_wrong_salt() {
    let result = std::panic::catch_unwind(|| {
        let laqf = Laqf2::new();
        let (pk, sk) = laqf.generate_kyber_keypair();

        let data = b"Hello, world!";
        let password = "password";
        let salt = laqf.generate_salt();
        let wrong_salt = laqf.generate_salt();

        let encrypted_data = laqf.encrypt(data, password, &pk, &salt);
        let decrypted_data = laqf.decrypt(&encrypted_data, password, &sk, &wrong_salt);

        // Should not be the same
        assert_ne!(data, decrypted_data.as_slice());
    });

    assert!(result.is_err());
}

#[test]
fn test_wrong_data() {
    let result = std::panic::catch_unwind(|| {
        let laqf = Laqf2::new();
        let (_, sk) = laqf.generate_kyber_keypair();

        let data = b"Hello, world!";
        let password = "password";
        let salt = laqf.generate_salt();

        let decrypted_data = laqf.decrypt(b"wrong_data", password, &sk, &salt);

        // Should not be the same
        assert_ne!(data, decrypted_data.as_slice());
    });

    assert!(result.is_err());
}

#[test]
fn test_empty_data() {
    let result = std::panic::catch_unwind(|| {
        let laqf = Laqf2::new();
        let (pk, sk) = laqf.generate_kyber_keypair();

        let data = b"";
        let password = "password";
        let salt = laqf.generate_salt();

        let encrypted_data = laqf.encrypt(data, password, &pk, &salt);
        let decrypted_data = laqf.decrypt(&encrypted_data, password, &sk, &salt);

        // Should be the same
        assert_eq!(data, decrypted_data.as_slice());
    });

    assert!(result.is_err());
}

#[test]
fn test_empty_password() {
    let result = std::panic::catch_unwind(|| {
        let laqf = Laqf2::new();
        let (pk, sk) = laqf.generate_kyber_keypair();

        let data = b"Hello, world!";
        let password = "";
        let salt = laqf.generate_salt();

        let encrypted_data = laqf.encrypt(data, password, &pk, &salt);
        let decrypted_data = laqf.decrypt(&encrypted_data, password, &sk, &salt);

        // Should be the same
        assert_eq!(data, decrypted_data.as_slice());
    });

    assert!(result.is_err());
}

#[test]
fn test_empty_salt() {
    let result = std::panic::catch_unwind(|| {
        let laqf = Laqf2::new();
        let (pk, sk) = laqf.generate_kyber_keypair();

        let data = b"Hello, world!";
        let password = "password";
        let salt = vec![];

        let encrypted_data = laqf.encrypt(data, password, &pk, &salt);
        let decrypted_data = laqf.decrypt(&encrypted_data, password, &sk, &salt);

        // Should be the same
        assert_eq!(data, decrypted_data.as_slice());
    });

    assert!(result.is_err());
}

#[test]
fn test_empty_keypair() {
    let result = std::panic::catch_unwind(|| {
        let laqf = Laqf2::new();
        let empty_pk = [0u8; 1568];
        let empty_sk = [0u8; 3168];

        let data = b"Hello, world!";
        let password = "password";
        let salt = laqf.generate_salt();

        let encrypted_data = laqf.encrypt(data, password, &empty_pk, &salt);
        let decrypted_data = laqf.decrypt(&encrypted_data, password, &empty_sk, &salt);

        // Should not be the same
        assert_ne!(data, decrypted_data.as_slice());
    });

    assert!(result.is_err());
}

#[test]
fn test_empty_pubkey() {
    let result = std::panic::catch_unwind(|| {
        let laqf = Laqf2::new();
        let (_, sk) = laqf.generate_kyber_keypair();
        let empty_pk = [0u8; 1568];

        let data = b"Hello, world!";
        let password = "password";
        let salt = laqf.generate_salt();

        let encrypted_data = laqf.encrypt(data, password, &empty_pk, &salt);
        let decrypted_data = laqf.decrypt(&encrypted_data, password, &sk, &salt);

        // Should not be the same
        assert_ne!(data, decrypted_data.as_slice());
    });

    assert!(result.is_err());
}

#[test]
fn test_empty_privkey() {
    let result = std::panic::catch_unwind(|| {
        let laqf = Laqf2::new();
        let (pk, _) = laqf.generate_kyber_keypair();
        let empty_sk = [0u8; 3168];

        let data = b"Hello, world!";
        let password = "password";
        let salt = laqf.generate_salt();

        let encrypted_data = laqf.encrypt(data, password, &pk, &salt);
        let decrypted_data = laqf.decrypt(&encrypted_data, password, &empty_sk, &salt);

        // Should not be the same
        assert_ne!(data, decrypted_data.as_slice());
    });

    assert!(result.is_err());
}
