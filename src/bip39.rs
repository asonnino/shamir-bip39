use crate::{
    traits::{FieldArray, ShamirSecretSharing, ShamirShare},
    utils::{bits_to_bytes, bytes_to_bits},
};

use eyre::{ensure, eyre, Result};
use fastcrypto::hash::{HashFunction, Sha256};
use gf256::gf256;
use rand::{CryptoRng, RngCore};
use std::{array::TryFromSliceError, fmt::Debug, fs::read_to_string, path::Path};

/// Parameters of the BIP-39 specification
const BTS: usize = 11;
const WORDS: usize = 2 << BTS - 1;
const MS: usize = 24;
const CS: usize = (MS * BTS) / 33;
const ENT: usize = CS * 32;
const ENT_BYTES: usize = ENT / 8;

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
        let bits = bytes_to_bits(index.to_be_bytes().into_iter());
        Ok(bits[bits.len() - BTS..]
            .try_into()
            .expect("BTS should be always smaller than `usize` bit length"))
    }

    pub fn word_from_bits(&self, bits: &[bool; BTS]) -> String {
        let mut extended = bytes_to_bits(usize::to_be_bytes(0).into_iter());
        let length = extended.len();
        extended[length - BTS..].copy_from_slice(bits);
        let bytes = bits_to_bytes(extended.into_iter())
            .try_into()
            .expect("BTS should be always smaller than `usize` bit length");
        let index = usize::from_be_bytes(bytes);
        self.words[index].clone()
    }
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
struct Entropy([bool; ENT]);

impl Entropy {
    pub fn as_bits(&self) -> &[bool] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; ENT_BYTES] {
        bits_to_bytes(self.0.into_iter()).try_into().unwrap()
    }

    #[cfg(test)]
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        use rand::Rng;

        Self(std::array::from_fn(|_| rng.gen()))
    }
}

impl TryFrom<&[bool]> for Entropy {
    type Error = TryFromSliceError;

    fn try_from(value: &[bool]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl<T> From<FieldArray<T, ENT_BYTES>> for Entropy
where
    u8: From<T>,
{
    fn from(value: FieldArray<T, ENT_BYTES>) -> Self {
        let bytes = value.into_iter().map(From::from);
        bytes_to_bits(bytes).as_slice().try_into().unwrap()
    }
}

impl<T> From<&Entropy> for FieldArray<T, ENT_BYTES>
where
    T: From<u8> + Debug,
{
    fn from(value: &Entropy) -> Self {
        value.to_bytes().map(From::from).into()
    }
}

#[derive(PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
struct Checksum([bool; CS]);

impl TryFrom<&[bool]> for Checksum {
    type Error = TryFromSliceError;

    fn try_from(value: &[bool]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl From<&Entropy> for Checksum {
    fn from(entropy: &Entropy) -> Self {
        let digest = Sha256::digest(entropy.to_bytes());
        let bits = bytes_to_bits(digest.to_vec().into_iter());
        let checksum = bits[..CS]
            .try_into()
            .expect("SHA-256 digest should be longer than CS");
        Self(checksum)
    }
}

impl Checksum {
    pub fn as_bits(&self) -> &[bool] {
        &self.0
    }
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Bip39Secret {
    entropy: Entropy,
    checksum: Checksum,
}

impl ShamirSecretSharing for Bip39Secret {
    fn split<R: CryptoRng + RngCore>(self, n: u8, t: u8, rng: &mut R) -> Vec<Bip39Share> {
        FieldArray::<gf256, ENT_BYTES>::from(&self.entropy)
            .split(n, t, rng)
            .into_iter()
            .map(|share| {
                let (id, secret) = share.into_inner();
                let entropy = Entropy::from(secret);
                Bip39Share::new(id, Self::from(entropy))
            })
            .collect()
    }

    fn reconstruct(shares: &[Bip39Share]) -> Self {
        let array_shares = shares
            .into_iter()
            .map(|share| {
                let (id, secret) = share.as_coordinates();
                let array = From::from(&secret.entropy);
                ShamirShare::new(*id, array)
            })
            .collect::<Vec<_>>();

        let array = FieldArray::<gf256, ENT_BYTES>::reconstruct(&array_shares);
        let entropy = Entropy::from(array);
        Self::from(entropy)
    }
}

impl Bip39Secret {
    pub fn is_valid(&self) -> Result<()> {
        let checksum = Checksum::from(&self.entropy);
        ensure!(self.checksum == checksum, "Invalid checksum");
        Ok(())
    }

    pub fn from_mnemonic(mnemonic: &str, dictionary: &Bip39Dictionary) -> Result<Self> {
        let words = mnemonic.split_whitespace().collect::<Vec<_>>();
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

    #[cfg(test)]
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self::from(Entropy::random(rng))
    }
}

impl From<Entropy> for Bip39Secret {
    fn from(entropy: Entropy) -> Self {
        let checksum = Checksum::from(&entropy);
        Self { entropy, checksum }
    }
}

pub type Bip39Share = ShamirShare<Bip39Secret>;

// #[cfg_attr(test, derive(Debug, PartialEq, Eq))]
// pub struct Bip39Share {
//     id: u8,
//     secret: Bip39Secret,
// }

impl Bip39Share {
    pub fn is_valid(&self) -> Result<()> {
        self.secret().is_valid()
    }

    pub fn from_mnemonic(id: u8, mnemonic: &str, dictionary: &Bip39Dictionary) -> Result<Self> {
        let secret = Bip39Secret::from_mnemonic(mnemonic, dictionary)?;
        Ok(Self::new(id, secret))
    }

    pub fn to_mnemonic(&self, dictionary: &Bip39Dictionary) -> String {
        self.secret().to_mnemonic(dictionary)
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

    use crate::{
        bip39::{Bip39Dictionary, Bip39Share, ENT},
        traits::ShamirSecretSharing,
    };

    use super::Bip39Secret;

    fn test_dictionary() -> Bip39Dictionary {
        Bip39Dictionary::load("assets/bip39-en.txt").unwrap()
    }

    fn test_mnemonic() -> &'static str {
        "motion domain employ liberty priority moral \
        boil property urge error chunk pave \
        bullet blanket bind adapt local enroll \
        bullet permit theory vibrant initial venue"
    }

    #[test]
    fn load_dictionary() {
        let dictionary = test_dictionary();
        assert_eq!(dictionary.words.len(), 2048);
    }

    #[test]
    fn bits_from_word() {
        let dictionary = test_dictionary();

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
        let dictionary = test_dictionary();

        let bits = [false; 11];
        let word = dictionary.word_from_bits(&bits);
        assert_eq!(word, "abandon");

        let bits = [
            false, true, true, false, true, true, false, false, true, false, false,
        ];
        let word = dictionary.word_from_bits(&bits);
        assert_eq!(word, "hold");
    }

    #[test]
    fn valid() {
        let dictionary = test_dictionary();
        let mnemonic = test_mnemonic();

        let secret = Bip39Secret::from_mnemonic(mnemonic, &dictionary).unwrap();
        assert!(secret.is_valid().is_ok());
    }

    #[test]
    fn from_mnemonic() {
        let dictionary = test_dictionary();
        let mnemonic = test_mnemonic();

        let secret = Bip39Secret::from_mnemonic(mnemonic, &dictionary).unwrap();

        let expected = mnemonic
            .split_whitespace()
            .flat_map(|word| dictionary.bits_from_word(word).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(secret.entropy, expected[..ENT].try_into().unwrap());
        assert_eq!(secret.checksum, expected[ENT..].try_into().unwrap());
        assert!(secret.is_valid().is_ok());
    }

    #[test]
    fn to_mnemonic() {
        let dictionary = test_dictionary();
        let mnemonic = test_mnemonic();

        let secret = Bip39Secret::from_mnemonic(mnemonic, &dictionary).unwrap();
        assert_eq!(secret.to_mnemonic(&dictionary), mnemonic);
    }

    // #[test]
    // fn valid_shares() {
    //     let dictionary = test_dictionary();

    //     let mut rng = StdRng::seed_from_u64(0);
    //     let secret = Bip39Secret::random(&mut rng);

    //     let n = 5;
    //     let t = 3;
    //     let shares = secret.split(n, t, &mut rng);

    //     assert_eq!(shares.len(), n as usize);
    //     for i in 0..t {
    //         let share = &shares[i as usize];
    //         let id = i + 1;

    //         assert_eq!(share.id, id);
    //         assert!(share.is_valid().is_ok());

    //         let share_mnemonic = share.to_mnemonic(&dictionary);
    //         assert_eq!(
    //             share,
    //             &Bip39Share::from_mnemonic(id, &share_mnemonic, &dictionary).unwrap()
    //         );
    //     }
    // }

    // #[test]
    // fn reconstruct() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let secret = Bip39Secret::random(&mut rng);

    //     let n = 5;
    //     let t = 3;
    //     let shares = secret.split(n, t, &mut rng).unwrap();

    //     let reconstructed = Bip39Secret::reconstruct(&shares[..t as usize]).unwrap();
    //     assert_eq!(secret, reconstructed);
    // }

    // #[test]
    // fn reconstruct_sparse() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let secret = Bip39Secret::random(&mut rng);
    //     let mut shares = secret.split(5, 3, &mut rng).unwrap();
    //     let share_4 = shares.pop().unwrap();
    //     let _share_3 = shares.pop().unwrap();
    //     let share_2 = shares.pop().unwrap();
    //     let share_1 = shares.pop().unwrap();
    //     let reconstructed = Bip39Secret::reconstruct(&vec![share_1, share_2, share_4]).unwrap();
    //     assert_eq!(secret, reconstructed);
    // }

    // #[test]
    // fn reconstruct_missing_shares() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let secret = Bip39Secret::random(&mut rng);

    //     let n = 5;
    //     let t = 3;
    //     let shares = secret.split(n, t, &mut rng).unwrap();
    //     let reconstructed = Bip39Secret::reconstruct(&shares[0..(t - 1) as usize]).unwrap();

    //     assert!(reconstructed.is_valid().is_ok());
    //     assert_ne!(secret, reconstructed);
    // }

    // #[test]
    // fn chaos() {
    //     let dictionary = test_dictionary();

    //     let mut rng = StdRng::seed_from_u64(0);
    //     for n in 1..=15 {
    //         for t in 1..=n {
    //             let secret = Bip39Secret::random(&mut rng);

    //             let mut shares = secret.split(n, t, &mut rng).unwrap();
    //             shares.shuffle(&mut rng);

    //             for share in &shares {
    //                 assert!(share.is_valid().is_ok());
    //                 let mnemonic = share.to_mnemonic(&dictionary);
    //                 let id = share.id;
    //                 let loaded = Bip39Share::from_mnemonic(id, &mnemonic, &dictionary).unwrap();
    //                 assert_eq!(share, &loaded);
    //             }

    //             let reconstructed = Bip39Secret::reconstruct(&shares[0..t as usize]).unwrap();
    //             assert!(reconstructed.is_valid().is_ok());
    //             assert_eq!(secret, reconstructed);
    //             let mnemonic = reconstructed.to_mnemonic(&dictionary);
    //             let loaded = Bip39Secret::from_mnemonic(&mnemonic, &dictionary).unwrap();
    //             assert_eq!(secret, loaded);
    //         }
    //     }
    // }
}
