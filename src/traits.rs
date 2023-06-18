use std::{
    array,
    collections::HashMap,
    fmt::Debug,
    ops::{Add, Mul},
};

use gf256::gf256;
use rand::{CryptoRng, Rng, RngCore};

pub trait Zero {
    fn zero() -> Self;
}

pub trait Random {
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self;
}

pub struct ShamirPolynomial<T>(Vec<T>);

impl<T> ShamirPolynomial<T>
where
    T: Mul<T, Output = T> + Add<T, Output = T> + Clone + Zero + Random,
{
    /// Generate a random polynomial of a given degree, fixing f(0) = secret
    pub fn random<R: CryptoRng + RngCore>(secret: T, degree: u8, rng: &mut R) -> Self {
        let mut f = vec![secret];
        for _ in 0..degree {
            f.push(T::random(rng));
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
    fn split<R: CryptoRng + RngCore>(self, n: u8, t: u8, rng: &mut R) -> Vec<(u8, Self)>
    where
        Self: Sized;

    fn reconstruct(shares: &[(u8, Self)]) -> Self
    where
        Self: Sized;
}

impl Zero for gf256 {
    fn zero() -> Self {
        gf256(0)
    }
}

impl Random for gf256 {
    fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        gf256(rng.gen_range(1..=255))
    }
}

impl ShamirSecretSharing for gf256 {
    fn split<R: CryptoRng + RngCore>(self, n: u8, t: u8, rng: &mut R) -> Vec<(u8, Self)> {
        assert!(n > 0, "There must be at least one share");
        assert!(t > 0, "The threshold must be at least one");
        assert!(
            t <= n,
            "The threshold cannot be higher than the number of shares"
        );

        let polynomial = ShamirPolynomial::random(self, t - 1, rng);

        (1..=n)
            .map(|id| {
                let secret = polynomial.evaluate(gf256(id));
                (id, secret)
            })
            .collect()
    }

    fn reconstruct(shares: &[(u8, Self)]) -> Self
    where
        Self: Sized,
    {
        let mut y = gf256(0);
        for (i, (x0, y0)) in shares.iter().enumerate() {
            let mut li = gf256(1);
            for (j, (x1, _y1)) in shares.iter().enumerate() {
                if i != j {
                    li *= gf256(*x1) / (gf256(*x0) + gf256(*x1));
                }
            }
            y += li * y0;
        }
        y
    }
}

pub struct FieldArray<T, const N: usize>([T; N]);

impl<T, const N: usize> ShamirSecretSharing for FieldArray<T, N>
where
    T: ShamirSecretSharing + Clone + Debug,
{
    fn split<R: CryptoRng + RngCore>(self, n: u8, t: u8, rng: &mut R) -> Vec<(u8, Self)> {
        assert!(n > 0, "There must be at least one share");
        assert!(t > 0, "The threshold must be at least one");
        assert!(
            t <= n,
            "The threshold cannot be higher than the number of shares"
        );

        let mut secrets = HashMap::new();

        for element in self.0 {
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
                .map(|(id, secret)| (*id, secret.0[i].clone()))
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
