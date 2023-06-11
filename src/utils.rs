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
