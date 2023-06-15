use crate::gf256;

use rand::{CryptoRng, Rng, RngCore};

/// Pick a random non-zero element of GF(256)
pub fn random_gf256<R: CryptoRng + RngCore>(rng: &mut R) -> gf256 {
    gf256(rng.gen_range(1..=255))
}

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
        .collect()
}

pub fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    bits.chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0, |acc, (i, &b)| acc | (b as u8) << (7 - i))
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_bytes_to_bits() {
        assert_eq!(
            bytes_to_bits(&[0b0000_0000, 0b1111_1111]),
            vec![
                false, false, false, false, false, false, false, false, true, true, true, true,
                true, true, true, true
            ]
        );
        assert_eq!(
            bytes_to_bits(&[0b1010_1010]),
            vec![true, false, true, false, true, false, true, false]
        );
    }

    #[test]
    fn test_bits_to_bytes() {
        assert_eq!(
            bits_to_bytes(&[
                false, false, false, false, false, false, false, false, true, true, true, true,
                true, true, true, true
            ]),
            vec![0b0000_0000, 0b1111_1111]
        );
        assert_eq!(
            bits_to_bytes(&[true, false, true, false, true, false, true, false]),
            vec![0b1010_1010]
        );
    }
}