use crate::{
    gf256,
    shamir::{ShamirMasterSecret, ShamirShare},
    utils::{bits_to_bytes, bytes_to_bits},
};
use fastcrypto::hash::{HashFunction, Sha256};
use std::{array::TryFromSliceError, collections::HashMap, fs::read_to_string, path::Path};

pub const BTS: usize = 11;
pub const MS: usize = 24;
pub const ENT: usize = (MS * BTS) / 33;
pub const CS: usize = ENT / 32;

pub struct Bip39Dictionary {
    words: [String; 2 << BTS],
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
        bits[bits.len() - BTS..].to_vec()
    }

    pub fn word_from_bits(&self, bits: &[bool; BTS]) -> String {
        let bytes = bits_to_bytes(bits).try_into().unwrap();
        let index = usize::from_le_bytes(bytes);
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
    pub fn from_mnemonic(
        mnemonic: &str,
        dictionary: &Bip39Dictionary,
    ) -> Result<Self, std::io::Error> {
        let words: [&str; MS] = mnemonic
            .split(' ')
            .collect::<Vec<_>>()
            .try_into()
            .expect("Invalid mnemonic length");
        let bits = words
            .into_iter()
            .map(|word| dictionary.bits_from_word(word))
            .flatten()
            .collect::<Vec<_>>();
        Ok(Self {
            entropy: bits[..ENT].try_into().unwrap(),
            checksum: bits[CS..].try_into().unwrap(),
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
            .map(|chunk| dictionary.word_from_bits(chunk.try_into().unwrap()))
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn split(&self, n: u8, t: u8) -> Vec<Bip39Share> {
        assert!(n > 0, "There must be at least one share");
        assert!(t > 0, "The threshold must be at least one");
        assert!(
            t <= n,
            "The threshold cannot be higher than the number of shares"
        );

        let mut secrets = HashMap::new();

        let entropy = self.entropy.to_bytes().into_iter().map(gf256);
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
                let bytes = secret.into_iter().map(|s| s.into()).collect::<Vec<u8>>();
                let share_entropy: Entropy = bytes.as_slice().try_into().unwrap();
                let secret = Bip39Secret::from(share_entropy);
                Bip39Share::new(id, secret)
            })
            .collect()
    }

    /// Reconstruct a secret
    pub fn reconstruct(shares: &[Bip39Share]) -> Self {
        assert!(!shares.is_empty(), "There must be at least one share");

        let mut entropy: Vec<u8> = Vec::new();

        let length = ENT / 8;
        for i in 0..length {
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

        let bits: Entropy = entropy.as_slice().try_into().unwrap();
        Self::from(bits)
    }
}

impl From<Entropy> for Bip39Secret {
    fn from(entropy: Entropy) -> Self {
        let digest = Sha256::digest(entropy.to_bytes());
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

    pub fn from_mnemonic(
        id: u8,
        mnemonic: &str,
        dictionary: &Bip39Dictionary,
    ) -> Result<Self, std::io::Error> {
        let secret = Bip39Secret::from_mnemonic(mnemonic, dictionary)?;
        Ok(Self::new(id, secret))
    }

    pub fn to_mnemonic(&self, dictionary: &Bip39Dictionary) -> String {
        self.secret.to_mnemonic(dictionary)
    }
}
