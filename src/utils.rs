pub fn check_for_empty(data: &[u8], password: &str) {
    if data.is_empty() {
        panic!("Data is empty, cannot encrypt.");
    }
    if password.is_empty() {
        panic!("Password is empty, cannot encrypt.");
    }
}
