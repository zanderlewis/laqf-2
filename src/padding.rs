use alloc::vec::Vec;

pub const BLOCK_SIZE: usize = 16;

/// Apply PKCS#7 padding
pub fn pad(data: &[u8]) -> Vec<u8> {
    let padding_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
    let mut padded = data.to_vec();

    padded.extend(core::iter::repeat(padding_len as u8).take(padding_len));

    padded
}

/// Remove PKCS#7 padding
pub fn unpad(data: &[u8]) -> Result<Vec<u8>, &'static str> {
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
