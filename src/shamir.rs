// Copyright (c) Alberto Sonnino
// SPDX-License-Identifier: Apache-2.0

use std::{
    array,
    collections::HashMap,
    fmt::Debug,
    ops::{Add, Mul},
};

use rand::{CryptoRng, RngCore};

pub trait Zero {
    fn zero() -> Self;
}

pub trait Random {
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self;
}

/// A share of a secret.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct ShamirShare<T> {
    /// The share's ID (the x-coordinate).
    id: u8,
    /// The share's secret (the y-coordinate).
    secret: T,
}

impl<T> ShamirShare<T> {
    /// Create a new share with the given ID and secret.
    pub fn new(id: u8, secret: T) -> Self {
        Self { id, secret }
    }

    /// Get the share's ID.
    #[cfg(test)]
    pub fn id(&self) -> &u8 {
        &self.id
    }

    /// Get the share's secret.
    pub fn secret(&self) -> &T {
        &self.secret
    }

    /// Convert the share into a tuple of ID and secret.
    pub fn into_inner(self) -> (u8, T) {
        (self.id, self.secret)
    }

    /// Get the share's ID and secret.
    pub fn as_coordinates(&self) -> (&u8, &T) {
        (&self.id, &self.secret)
    }
}

impl<T> AsRef<ShamirShare<T>> for ShamirShare<T> {
    fn as_ref(&self) -> &ShamirShare<T> {
        self
    }
}

/// A secret sharing scheme based on Shamir's secret sharing.
pub trait ShamirSecretSharing {
    /// Split a secret into `n` shares, of which any `t` can be used to reconstruct the secret.
    /// Panic if `n` or `t` are zero, or if `t` is greater than `n`.
    fn split<R: CryptoRng + RngCore>(&self, n: u8, t: u8, rng: &mut R) -> Vec<ShamirShare<Self>>
    where
        Self: Sized;

    /// Reconstruct a secret from `t` shares.
    fn reconstruct<S>(shares: &[S]) -> Self
    where
        S: AsRef<ShamirShare<Self>>,
        Self: Sized;
}

/// A polynomial with random coefficients and hiding a secret at its origin.
pub struct ShamirPolynomial<T>(Vec<T>);

impl<T> ShamirPolynomial<T>
where
    T: Mul<T, Output = T> + Add<T, Output = T> + Clone + Zero + Random,
{
    /// Generate a random polynomial of a given degree, fixing f(0) = secret.
    pub fn random<R: CryptoRng + RngCore>(secret: T, degree: u8, rng: &mut R) -> Self {
        let mut f = vec![secret];
        for _ in 0..degree {
            f.push(T::random(rng));
        }
        Self(f)
    }

    /// Evaluate a polynomial at x using Horner's method.
    pub fn evaluate(&self, x: T) -> T {
        let mut y = T::zero();
        for c in self.0.iter().cloned().rev() {
            y = y * x.clone() + c;
        }
        y
    }
}

/// An array of field elements that can be used in Shamir's secret sharing scheme.
#[cfg_attr(test, derive(Clone, Debug, PartialEq, Eq))]
pub struct FieldArray<T, const N: usize>([T; N]);

impl<T, const N: usize> ShamirSecretSharing for FieldArray<T, N>
where
    T: ShamirSecretSharing + Clone + Debug,
{
    fn split<R: CryptoRng + RngCore>(&self, n: u8, t: u8, rng: &mut R) -> Vec<ShamirShare<Self>> {
        let mut secrets = HashMap::new();

        for element in &self.0 {
            for share in element.split(n, t, rng) {
                let (id, secret) = share.into_inner();
                secrets.entry(id).or_insert_with(Vec::new).push(secret);
            }
        }

        let mut shares = secrets
            .into_iter()
            .map(|(id, share)| {
                let share = share
                    .try_into()
                    .expect("Shamir secret sharing should preserve length");
                ShamirShare::new(id, Self(share))
            })
            .collect::<Vec<_>>();

        shares.sort_by(|a, b| a.id.cmp(&b.id));
        shares
    }

    fn reconstruct<S: AsRef<ShamirShare<Self>>>(shares: &[S]) -> Self {
        Self(array::from_fn(|i| {
            let element_shares = shares
                .iter()
                .map(|share| {
                    let (id, secret) = share.as_ref().as_coordinates();
                    ShamirShare::new(*id, secret.0[i].clone())
                })
                .collect::<Vec<_>>();
            T::reconstruct(&element_shares)
        }))
    }
}

impl<T, const N: usize> IntoIterator for FieldArray<T, N> {
    type Item = T;
    type IntoIter = std::array::IntoIter<Self::Item, N>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T, const N: usize> From<[T; N]> for FieldArray<T, N> {
    fn from(value: [T; N]) -> Self {
        Self(value)
    }
}

#[cfg(test)]
impl<T: Random, const N: usize> Random for FieldArray<T, N> {
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        Self(array::from_fn(|_| T::random(rng)))
    }
}

#[cfg(test)]
pub mod test {
    use std::fmt::Debug;

    use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

    use super::{FieldArray, Random, ShamirSecretSharing};

    pub fn test_reconstruct<T>() -> T
    where
        T: ShamirSecretSharing + Random + PartialEq + Eq + Debug + Clone,
    {
        let mut rng = StdRng::seed_from_u64(0);
        let secret = T::random(&mut rng);

        let n = 5;
        let t = 3;
        let shares = secret.clone().split(n, t, &mut rng);

        let reconstructed = T::reconstruct(&shares[..t as usize]);
        assert_eq!(secret, reconstructed);
        secret
    }

    pub fn test_reconstruct_sparse<T>() -> T
    where
        T: ShamirSecretSharing + Random + PartialEq + Eq + Debug + Clone,
    {
        let mut rng = StdRng::seed_from_u64(0);
        let secret = T::random(&mut rng);
        let mut shares = secret.clone().split(5, 3, &mut rng);
        let share_4 = shares.pop().unwrap();
        let _share_3 = shares.pop().unwrap();
        let share_2 = shares.pop().unwrap();
        let share_1 = shares.pop().unwrap();
        let reconstructed = T::reconstruct(&[share_1, share_2, share_4]);
        assert_eq!(secret, reconstructed);
        secret
    }

    pub fn test_reconstruct_missing_shares<T>() -> (T, T)
    where
        T: ShamirSecretSharing + Random + PartialEq + Eq + Debug + Clone,
    {
        let mut rng = StdRng::seed_from_u64(0);
        let secret = T::random(&mut rng);

        let n = 5;
        let t = 3;
        let shares = secret.clone().split(n, t, &mut rng);
        let reconstructed = T::reconstruct(&shares[0..(t - 1) as usize]);

        assert_ne!(secret, reconstructed);
        (secret, reconstructed)
    }

    pub fn chaos_test<T>()
    where
        T: ShamirSecretSharing + Random + PartialEq + Eq + Debug + Clone,
    {
        let mut rng = StdRng::seed_from_u64(0);
        for n in 1..=15 {
            for t in 1..=n {
                let secret = T::random(&mut rng);

                let mut shares = secret.clone().split(n, t, &mut rng);
                shares.shuffle(&mut rng);

                for i in 1..=t {
                    let reconstructed = T::reconstruct(&shares[0..i as usize]);
                    if i == t {
                        assert_eq!(secret, reconstructed);
                    } else {
                        assert_ne!(secret, reconstructed);
                    }
                }
            }
        }
    }

    #[test]
    fn reconstruct() {
        test_reconstruct::<FieldArray<gf256::gf256, 16>>();
        test_reconstruct::<FieldArray<gf256::gf256, 20>>();
        test_reconstruct::<FieldArray<gf256::gf256, 24>>();
        test_reconstruct::<FieldArray<gf256::gf256, 28>>();
        test_reconstruct::<FieldArray<gf256::gf256, 32>>();
    }

    #[test]
    fn reconstruct_sparse() {
        test_reconstruct_sparse::<FieldArray<gf256::gf256, 16>>();
        test_reconstruct_sparse::<FieldArray<gf256::gf256, 20>>();
        test_reconstruct_sparse::<FieldArray<gf256::gf256, 28>>();
        test_reconstruct_sparse::<FieldArray<gf256::gf256, 24>>();
        test_reconstruct_sparse::<FieldArray<gf256::gf256, 32>>();
    }

    #[test]
    fn reconstruct_missing_shares() {
        test_reconstruct_missing_shares::<FieldArray<gf256::gf256, 16>>();
        test_reconstruct_missing_shares::<FieldArray<gf256::gf256, 20>>();
        test_reconstruct_missing_shares::<FieldArray<gf256::gf256, 24>>();
        test_reconstruct_missing_shares::<FieldArray<gf256::gf256, 28>>();
        test_reconstruct_missing_shares::<FieldArray<gf256::gf256, 32>>();
    }

    #[test]
    fn chaos() {
        chaos_test::<FieldArray<gf256::gf256, 16>>();
        chaos_test::<FieldArray<gf256::gf256, 20>>();
        chaos_test::<FieldArray<gf256::gf256, 24>>();
        chaos_test::<FieldArray<gf256::gf256, 28>>();
        chaos_test::<FieldArray<gf256::gf256, 32>>();
    }
}
