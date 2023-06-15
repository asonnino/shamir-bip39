use crate::{gf256, utils};

use rand::RngCore;
use rand::{self, CryptoRng};
use std::convert::TryFrom;

pub struct ShamirPolynomial(Vec<gf256>);

impl ShamirPolynomial {
    /// Generate a random polynomial of a given degree, fixing f(0) = secret
    pub fn random<R: CryptoRng + RngCore>(secret: gf256, degree: u8, rng: &mut R) -> Self {
        let mut f = vec![secret];
        for _ in 0..degree {
            f.push(utils::random_gf256(rng));
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

#[derive(PartialEq, Eq, Debug)]
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
    pub fn split<R: RngCore + CryptoRng>(&self, n: u8, t: u8, rng: &mut R) -> Vec<ShamirShare> {
        assert!(n > 0, "There must be at least one share");
        assert!(t > 0, "The threshold must be at least one");
        assert!(
            t <= n,
            "The threshold cannot be higher than the number of shares"
        );

        let polynomial = ShamirPolynomial::random(self.0, t - 1, rng);

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

#[cfg(test)]
mod test {

    use rand::{rngs::StdRng, SeedableRng};

    use crate::{gf256, shamir::ShamirMasterSecret, utils};

    #[test]
    fn random_polynomial() {
        let mut rng = StdRng::seed_from_u64(0);
        for i in 1..=100 {
            let secret = utils::random_gf256(&mut rng);
            let degree = i;
            let f = super::ShamirPolynomial::random(secret, degree - 1, &mut rng);
            assert_eq!(f.0.len(), degree as usize);
            assert_eq!(f.0[0], secret);
        }
    }

    #[test]
    fn evaluate_polynomial() {
        let f = super::ShamirPolynomial(vec![gf256(42), gf256(1), gf256(2)]);
        for i in 0..u8::MAX {
            assert_eq!(
                f.evaluate(gf256(i)),
                gf256(42) + gf256(1) * gf256(i) + gf256(2) * gf256(i) * gf256(i)
            );
        }
    }

    #[test]
    fn reconstruct() {
        let mut rng = StdRng::seed_from_u64(0);
        let secret = gf256(42);
        let shares = ShamirMasterSecret(secret).split(5, 3, &mut rng);
        let reconstructed = ShamirMasterSecret::reconstruct(&shares[0..3]);
        assert_eq!(ShamirMasterSecret(secret), reconstructed);
    }

    #[test]
    fn reconstruct_many() {
        let mut rng = StdRng::seed_from_u64(0);
        for n in 1..=30 {
            for t in 1..=n {
                let secret = utils::random_gf256(&mut rng);
                let shares = ShamirMasterSecret(secret).split(n, t, &mut rng);
                let reconstructed = ShamirMasterSecret::reconstruct(&shares[0..t as usize]);
                assert_eq!(ShamirMasterSecret(secret), reconstructed);
            }
        }
    }

    #[test]
    fn reconstruct_sparse() {
        let mut rng = StdRng::seed_from_u64(0);
        let secret = gf256(42);
        let mut shares = ShamirMasterSecret(secret).split(5, 3, &mut rng);
        let share_4 = shares.pop().unwrap();
        let _share_3 = shares.pop().unwrap();
        let share_2 = shares.pop().unwrap();
        let share_1 = shares.pop().unwrap();
        let reconstructed = ShamirMasterSecret::reconstruct(&vec![share_1, share_2, share_4]);
        assert_eq!(ShamirMasterSecret(secret), reconstructed);
    }

    #[test]
    fn reconstruct_missing_shares() {
        let mut rng = StdRng::seed_from_u64(0);
        let secret = gf256(42);
        let shares = ShamirMasterSecret(secret).split(5, 3, &mut rng);
        let reconstructed = ShamirMasterSecret::reconstruct(&shares[0..2]);
        assert_ne!(ShamirMasterSecret(secret), reconstructed);
    }
}
