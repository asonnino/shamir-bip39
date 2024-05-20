// Copyright (c) Alberto Sonnino
// SPDX-License-Identifier: Apache-2.0

/// Convert an iterator of bytes into a vector of bits.
pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
        .collect()
}

/// Convert an iterator of bits into a vector of bytes.
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
