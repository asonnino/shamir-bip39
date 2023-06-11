// This module is inspired from the `shamir.rs` example of the `gf256` crate:
// <https://github.com/asonnino/gf256/blob/master/examples/shamir.rs>
use crate::{
    gf256,
    shamir::{ShamirMasterSecret, ShamirShare},
};
use fastcrypto::hash::{HashFunction, Sha256};
use std::{collections::HashMap, fs::read_to_string, path::Path};

pub const BIT39_BITS_GROUP_SIZE: usize = 11;

type Entropy = [bool; 256];
type Checksum = [bool; 8];

fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
        .collect()
}

fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    bits.chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0, |acc, (i, &b)| acc | (b as u8) << (7 - i))
        })
        .collect()
}

pub struct Bip39Dictionary {
    words: [String; 2 << BIT39_BITS_GROUP_SIZE],
}

impl Bip39Dictionary {
    pub fn load<P: AsRef<Path>>(dictionary_path: P) -> Result<Self, std::io::Error> {
        let words = read_to_string(dictionary_path)?
            .lines()
            .map(Into::into)
            .collect::<Vec<_>>()
            .try_into()
            .expect("Invalid bip-39 dictionary");
        Ok(Self { words })
    }

    pub fn bits_from_word(&self, word: &str) -> Vec<bool> {
        let index = self
            .words
            .iter()
            .position(|w| w == word)
            .expect("Invalid word in mnemonic");
        let bits = bytes_to_bits(&index.to_le_bytes());
        bits[bits.len() - BIT39_BITS_GROUP_SIZE..].to_vec()
    }

    pub fn word_from_bits(&self, bits: &[bool; BIT39_BITS_GROUP_SIZE]) -> String {
        let bytes = bits_to_bytes(bits).try_into().unwrap();
        let index = usize::from_le_bytes(bytes);
        self.words[index].clone()
    }
}

pub struct Bip39Secret {
    entropy: Entropy,
    checksum: Checksum,
}

impl Bip39Secret {
    pub fn from_mnemonic(
        mnemonic: &str,
        dictionary: &Bip39Dictionary,
    ) -> Result<Self, std::io::Error> {
        let words: [&str; 24] = mnemonic
            .split(' ')
            .collect::<Vec<_>>()
            .try_into()
            .expect("Invalid mnemonic length");
        let bits = words
            .iter()
            .map(|word| dictionary.bits_from_word(word))
            .flatten()
            .collect::<Vec<_>>();
        Ok(Self {
            entropy: bits[..256].try_into().unwrap(),
            checksum: bits[256..].try_into().unwrap(),
        })
    }

    pub fn into_mnemonic(&self, dictionary: &Bip39Dictionary) -> String {
        let words: Vec<_> = self
            .entropy
            .into_iter()
            .chain(self.checksum.into_iter())
            .collect::<Vec<_>>()
            .chunks(BIT39_BITS_GROUP_SIZE)
            .map(|chunk| dictionary.word_from_bits(chunk.try_into().unwrap()))
            .collect();
        words.join(" ")
    }

    pub fn split(&self, n: u8, t: u8) -> Vec<Bip39Share> {
        assert!(n > 0, "There must be at least one share");
        assert!(t > 0, "The threshold must be at least one");
        assert!(
            t <= n,
            "The threshold cannot be higher than the number of shares"
        );

        let mut secrets = HashMap::new();

        let entropy = bits_to_bytes(&self.entropy).into_iter().map(gf256);
        for element in entropy {
            let shamir_master_secret = ShamirMasterSecret::from(element);
            let shamir_shares = shamir_master_secret.split(n, t);
            for share in shamir_shares {
                let (id, secret) = share.into_inner();
                secrets.entry(id).or_insert_with(Vec::new).push(secret);
            }
        }

        secrets
            .into_iter()
            .map(|(id, secret)| {
                let bytes = secret.into_iter().map(|s| s.into()).collect::<Vec<_>>();
                let bits: Entropy = bytes_to_bits(&bytes).try_into().unwrap();
                let secret = Bip39Secret::from(bits);
                Bip39Share::new(id, secret)
            })
            .collect()
    }

    /// Reconstruct a secret
    pub fn reconstruct(shares: &[Bip39Share]) -> Self {
        assert!(!shares.is_empty(), "There must be at least one share");

        let mut entropy = Vec::new();

        let length = 256 / 8;
        for i in 0..length {
            let shamir_shares = shares
                .iter()
                .map(|s| {
                    let share_entropy = bits_to_bytes(&s.secret.entropy).into_iter().map(gf256);
                    ShamirShare::new(s.id, share_entropy.collect::<Vec<_>>()[i])
                })
                .collect::<Vec<_>>();
            let shamir_master_secret = ShamirMasterSecret::reconstruct(&shamir_shares);
            entropy.push(shamir_master_secret.into());
        }

        let bits: Entropy = bytes_to_bits(&entropy).try_into().unwrap();
        Self::from(bits)
    }
}

impl From<Entropy> for Bip39Secret {
    fn from(entropy: Entropy) -> Self {
        let digest = Sha256::digest(bits_to_bytes(&entropy));
        let bits = bytes_to_bits(digest.as_ref());
        let checksum = bits[..8].try_into().unwrap();
        Self { entropy, checksum }
    }
}

pub struct Bip39Share {
    id: u8,
    secret: Bip39Secret,
}

impl Bip39Share {
    pub fn new(id: u8, secret: Bip39Secret) -> Self {
        Self { id, secret }
    }
}
