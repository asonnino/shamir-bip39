use std::{
    array,
    collections::HashMap,
    fmt::Debug,
    ops::{Add, AddAssign, Div, Mul, MulAssign},
};

use rand::{distributions::Standard, prelude::Distribution, CryptoRng, Rng, RngCore};

use crate::utils;

pub trait Zero {
    fn zero() -> Self;
}

pub trait One {
    fn one() -> Self;
}

pub struct ShamirPolynomial<T>(Vec<T>);

impl<T> ShamirPolynomial<T>
where
    T: Mul<T, Output = T> + Add<T, Output = T> + Clone + Zero,
    Standard: Distribution<T>,
{
    /// Generate a random polynomial of a given degree, fixing f(0) = secret
    pub fn random<R: CryptoRng + RngCore>(secret: T, degree: u8, rng: &mut R) -> Self {
        let mut f = vec![secret];
        for _ in 0..degree {
            f.push(rng.gen());
        }
        Self(f)
    }

    /// Evaluate a polynomial at x using Horner's method
    pub fn evaluate(&self, x: T) -> T {
        let mut y = T::zero();
        for c in self.0.iter().cloned().rev() {
            y = y * x.clone() + c;
        }
        y
    }
}

pub trait ShamirSecretSharing {
    fn split<R: CryptoRng + RngCore>(&self, n: u8, t: u8, rng: &mut R) -> Vec<(u8, Self)>
    where
        Self: Sized;

    fn reconstruct(shares: &[(u8, Self)]) -> Self
    where
        Self: Sized;
}

#[derive(Clone)]
pub struct FieldElement<T>(T);

impl<T> ShamirSecretSharing for FieldElement<T>
where
    T: Mul<T, Output = T>
        + Div<T, Output = T>
        + Add<T, Output = T>
        + MulAssign<T>
        + AddAssign<T>
        + From<u8>
        + Clone
        + Zero
        + One,
    Standard: Distribution<T>,
{
    fn split<R: CryptoRng + RngCore>(&self, n: u8, t: u8, rng: &mut R) -> Vec<(u8, Self)> {
        assert!(n > 0, "There must be at least one share");
        assert!(t > 0, "The threshold must be at least one");
        assert!(
            t <= n,
            "The threshold cannot be higher than the number of shares"
        );

        let polynomial = ShamirPolynomial::random(self.0.clone(), t - 1, rng);

        (1..=n)
            .map(|id| {
                let secret = polynomial.evaluate(T::from(id));
                (id, Self(secret))
            })
            .collect()
    }

    fn reconstruct(shares: &[(u8, Self)]) -> Self {
        let mut y = T::zero();
        for (i, (x0, y0)) in shares.iter().cloned().enumerate() {
            let mut li = T::one();
            for (j, (x1, _y1)) in shares.iter().cloned().enumerate() {
                if i != j {
                    li *= T::from(x1) / (T::from(x0) + T::from(x1));
                }
            }
            y += li * y0.0;
        }
        Self(y)
    }
}

pub struct FieldArray<T, const N: usize>([T; N]);

impl<T, const N: usize> ShamirSecretSharing for FieldArray<T, N>
where
    T: ShamirSecretSharing + Clone + Debug,
{
    fn split<R: CryptoRng + RngCore>(&self, n: u8, t: u8, rng: &mut R) -> Vec<(u8, Self)> {
        let mut secrets = HashMap::new();

        for element in &self.0 {
            for (id, share) in element.split(n, t, rng) {
                secrets.entry(id).or_insert_with(Vec::new).push(share);
            }
        }

        let mut shares = secrets
            .into_iter()
            .map(|(id, share)| {
                let share = share
                    .try_into()
                    .expect("Shamir secret sharing should preserve length");
                (id, Self(share))
            })
            .collect::<Vec<_>>();

        shares.sort_by(|a, b| a.0.cmp(&b.0));
        shares
    }

    fn reconstruct(shares: &[(u8, Self)]) -> Self {
        Self(array::from_fn(|i| {
            let element_shares = shares
                .iter()
                .map(|s| (s.0, s.1 .0[i].clone()))
                .collect::<Vec<_>>();
            T::reconstruct(&element_shares)
        }))
    }
}
