// This module is inspired from the `shamir.rs` example of the `gf256` crate:
// <https://github.com/asonnino/gf256/blob/master/examples/shamir.rs>
use crate::gf256;
use rand;
use rand::Rng;
use std::convert::TryFrom;

pub struct ShamirPolynomial(Vec<gf256>);

impl ShamirPolynomial {
    /// Generate a random polynomial of a given degree, fixing f(0) = secret
    pub fn random(secret: gf256, degree: u8) -> Self {
        let mut rng = rand::thread_rng();
        let mut f = vec![secret];
        for _ in 0..degree {
            f.push(gf256(rng.gen_range(1..=255)));
        }
        Self(f)
    }

    /// Evaluate a polynomial at x using Horner's method
    pub fn evaluate(&self, x: gf256) -> gf256 {
        let mut y = gf256(0);
        for c in self.0.iter().rev() {
            y = y * x + c;
        }
        y
    }
}

pub struct ShamirShare {
    id: u8,
    secret: gf256,
}

impl ShamirShare {
    pub fn new(id: u8, secret: gf256) -> Self {
        Self { id, secret }
    }

    pub fn into_inner(self) -> (u8, gf256) {
        (self.id, self.secret)
    }
}

pub struct ShamirMasterSecret(gf256);

impl From<gf256> for ShamirMasterSecret {
    fn from(secret: gf256) -> Self {
        Self(secret)
    }
}

impl From<ShamirMasterSecret> for u8 {
    fn from(value: ShamirMasterSecret) -> Self {
        value.0.try_into().unwrap()
    }
}

impl ShamirMasterSecret {
    /// Split the master secret into n shares requiring at least t shares to reconstruct
    pub fn split(&self, n: u8, t: u8) -> Vec<ShamirShare> {
        assert!(n > 0, "There must be at least one share");
        assert!(t > 0, "The threshold must be at least one");
        assert!(
            t <= n,
            "The threshold cannot be higher than the number of shares"
        );

        let polynomial = ShamirPolynomial::random(self.0, t - 1);

        (1..=n)
            .map(|id| {
                let secret = polynomial.evaluate(gf256::try_from(id).unwrap());
                ShamirShare::new(id, secret)
            })
            .collect()
    }

    /// Find f(0) using Lagrange interpolation
    pub fn reconstruct(shares: &[ShamirShare]) -> Self {
        let mut y = gf256(0);
        for (i, (x0, y0)) in shares.iter().map(|s| (s.id, s.secret)).enumerate() {
            let mut li = gf256(1);
            for (j, (x1, _y1)) in shares.iter().map(|s| (s.id, s.secret)).enumerate() {
                if i != j {
                    li *= gf256(x1) / (gf256(x0) + gf256(x1));
                }
            }

            y += li * y0;
        }

        Self(y)
    }
}
