use crate::{
    gf256,
    shamir::{ShamirMasterSecret, ShamirShare},
    utils::{bits_to_bytes, bytes_to_bits},
};

use eyre::{ensure, eyre, Result};
use fastcrypto::hash::{HashFunction, Sha256};
use rand::{CryptoRng, RngCore};
use std::{array::TryFromSliceError, collections::HashMap, fs::read_to_string, path::Path};

const BTS: usize = 11;
const WORDS: usize = 2 << BTS - 1;
const MS: usize = 24;
const CS: usize = (MS * BTS) / 33;
const ENT: usize = CS * 32;

pub struct Bip39Dictionary {
    words: [String; WORDS],
}

impl Bip39Dictionary {
    pub fn load<P: AsRef<Path>>(dictionary_path: P) -> Result<Self> {
        let words = read_to_string(dictionary_path)?
            .lines()
            .map(Into::into)
            .collect::<Vec<_>>();
        let length = words.len();

        Ok(Self {
            words: words
                .try_into()
                .map_err(|_| eyre!("Invalid BIP-39 dictionary length {length} != {WORDS}"))?,
        })
    }

    pub fn bits_from_word(&self, word: &str) -> Result<[bool; BTS]> {
        let index = self
            .words
            .iter()
            .position(|w| w == word)
            .ok_or(eyre!("Invalid BIP-39 word '{word}' in mnemonic"))?;
        let bits = bytes_to_bits(&index.to_be_bytes());
        Ok(bits[bits.len() - BTS..]
            .try_into()
            .expect("BTS should be always smaller than `usize` bit length"))
    }

    pub fn word_from_bits(&self, bits: &[bool; BTS]) -> String {
        let mut extended = bytes_to_bits(&usize::to_be_bytes(0));
        let length = extended.len();
        extended[length - BTS..].copy_from_slice(bits);
        let bytes = bits_to_bytes(&extended)
            .try_into()
            .expect("BTS should be always smaller than `usize` bit length");
        let index = usize::from_be_bytes(bytes);
        self.words[index].clone()
    }
}

struct Entropy([bool; ENT]);

impl Entropy {
    pub fn as_bits(&self) -> &[bool] {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bits_to_bytes(&self.0)
    }
}

impl TryFrom<&[bool]> for Entropy {
    type Error = TryFromSliceError;

    fn try_from(value: &[bool]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl TryFrom<&[u8]> for Entropy {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(bytes_to_bits(value).as_slice())
    }
}

struct Checksum([bool; CS]);

impl TryFrom<&[bool]> for Checksum {
    type Error = TryFromSliceError;

    fn try_from(value: &[bool]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl Checksum {
    pub fn as_bits(&self) -> &[bool] {
        &self.0
    }
}

pub struct Bip39Secret {
    entropy: Entropy,
    checksum: Checksum,
}

impl Bip39Secret {
    pub fn from_mnemonic(mnemonic: &str, dictionary: &Bip39Dictionary) -> Result<Self> {
        let words = mnemonic.split(' ').collect::<Vec<_>>();
        let length = words.len();

        let bits = TryInto::<[&str; MS]>::try_into(words)
            .map_err(|_| eyre!("Invalid mnemonic length {length} != {MS}"))?
            .into_iter()
            .map(|word| dictionary.bits_from_word(word))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        Ok(Self {
            entropy: bits[..ENT]
                .try_into()
                .expect("Valid mnemonic should be longer than ENT bits"),
            checksum: bits[ENT..]
                .try_into()
                .expect("Valid mnemonic should be ENT+CS bit long"),
        })
    }

    pub fn to_mnemonic(&self, dictionary: &Bip39Dictionary) -> String {
        self.entropy
            .as_bits()
            .into_iter()
            .cloned()
            .chain(self.checksum.as_bits().into_iter().cloned())
            .collect::<Vec<_>>()
            .chunks(BTS)
            .map(|chunk| {
                let bits = chunk.try_into().expect("ENT+CS should be divisible by BTS");
                dictionary.word_from_bits(bits)
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn split<R: RngCore + CryptoRng>(
        &self,
        n: u8,
        t: u8,
        rng: &mut R,
    ) -> Result<Vec<Bip39Share>> {
        ensure!(n > 0, "There must be at least one share");
        ensure!(t > 0, "The threshold must be at least one");
        ensure!(
            t <= n,
            "The threshold cannot be higher than the number of shares"
        );

        let mut secrets = HashMap::new();

        let entropy = self.entropy.to_bytes().into_iter().map(gf256);
        for element in entropy {
            let shamir_master_secret = ShamirMasterSecret::from(element);
            let shamir_shares = shamir_master_secret.split(n, t, rng);
            for share in shamir_shares {
                let (id, secret) = share.into_inner();
                secrets.entry(id).or_insert_with(Vec::new).push(secret);
            }
        }

        let mut shares = secrets
            .into_iter()
            .map(|(id, secret)| {
                let bytes = secret.into_iter().map(|s| s.into()).collect::<Vec<u8>>();
                let share_entropy: Entropy = bytes
                    .as_slice()
                    .try_into()
                    .expect("Shamir secret sharing should preserve length");
                let secret = Bip39Secret::from(share_entropy);
                Bip39Share::new(id, secret)
            })
            .collect::<Vec<_>>();

        shares.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(shares)
    }

    /// Reconstruct a secret
    pub fn reconstruct(shares: &[Bip39Share]) -> Result<Self> {
        ensure!(!shares.is_empty(), "There must be at least one share");

        let mut entropy: Vec<u8> = Vec::new();
        for i in 0..ENT / 8 {
            let shamir_shares = shares
                .iter()
                .map(|s| {
                    let share_entropy = s.secret.entropy.to_bytes().into_iter().map(gf256);
                    ShamirShare::new(s.id, share_entropy.collect::<Vec<_>>()[i])
                })
                .collect::<Vec<_>>();
            let shamir_master_secret = ShamirMasterSecret::reconstruct(&shamir_shares);
            entropy.push(shamir_master_secret.into());
        }

        let bits: Entropy = entropy
            .as_slice()
            .try_into()
            .expect("Shamir secret sharing should preserve length");
        Ok(Self::from(bits))
    }
}

impl From<Entropy> for Bip39Secret {
    fn from(entropy: Entropy) -> Self {
        let digest = Sha256::digest(entropy.to_bytes());
        let bits = bytes_to_bits(digest.as_ref());
        let checksum = bits[..CS]
            .try_into()
            .expect("SHA-256 digest should be longer than CS");
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

    pub fn from_mnemonic(id: u8, mnemonic: &str, dictionary: &Bip39Dictionary) -> Result<Self> {
        let secret = Bip39Secret::from_mnemonic(mnemonic, dictionary)?;
        Ok(Self::new(id, secret))
    }

    pub fn to_mnemonic(&self, dictionary: &Bip39Dictionary) -> String {
        let secret = self.secret.to_mnemonic(dictionary);
        format!("share {}: {}", self.id, secret)
    }
}

#[cfg(test)]
mod tests {
    use crate::bip39::Bip39Dictionary;

    #[test]
    fn bits_from_word() {
        let dictionary = Bip39Dictionary::load("assets/bip39-en.txt").unwrap();

        let bits = dictionary.bits_from_word("abandon").unwrap();
        assert_eq!(bits, [false; 11]);

        let bits = dictionary.bits_from_word("hold").unwrap();
        assert_eq!(
            bits,
            [false, true, true, false, true, true, false, false, true, false, false]
        );
    }

    #[test]
    fn word_from_bits() {
        let dictionary = Bip39Dictionary::load("assets/bip39-en.txt").unwrap();

        let bits = [false; 11];
        let word = dictionary.word_from_bits(&bits);
        assert_eq!(word, "abandon");

        let bits = [
            false, true, true, false, true, true, false, false, true, false, false,
        ];
        let word = dictionary.word_from_bits(&bits);
        assert_eq!(word, "hold");
    }
}
