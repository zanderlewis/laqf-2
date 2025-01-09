use crate::padding::{pad, unpad, BLOCK_SIZE};
use crate::types::MandelbrotPoint;
use alloc::vec::Vec;

pub fn encode_to_mandelbrot(data: &[u8]) -> Vec<MandelbrotPoint> {
    let padded_data = pad(data);
    let data_length = data.len() as u64;
    let mut encoded = Vec::with_capacity(1 + padded_data.len() / BLOCK_SIZE);

    encoded.push(MandelbrotPoint {
        real: data_length,
        imag: 0,
    });

    for chunk in padded_data.chunks_exact(BLOCK_SIZE) {
        let real = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let imag = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        encoded.push(MandelbrotPoint { real, imag });
    }

    encoded
}

pub fn decode_from_mandelbrot(points: &mut [MandelbrotPoint]) -> Vec<u8> {
    if points.is_empty() {
        return Vec::new();
    }

    let data_length = points[0].real as usize;
    let mut padded_data = Vec::with_capacity((points.len() - 1) * BLOCK_SIZE);

    for point in &points[1..] {
        padded_data.extend_from_slice(&point.real.to_le_bytes());
        padded_data.extend_from_slice(&point.imag.to_le_bytes());
    }

    if let Ok(unpadded) = unpad(&padded_data) {
        unpadded.into_iter().take(data_length).collect()
    } else {
        Vec::new()
    }
}
