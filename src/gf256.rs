use gf256::gf256;
use rand::{CryptoRng, Rng, RngCore};

use crate::shamir::{Random, ShamirPolynomial, ShamirSecretSharing, ShamirShare, Zero};

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
    fn split<R: CryptoRng + RngCore>(&self, n: u8, t: u8, rng: &mut R) -> Vec<ShamirShare<Self>> {
        assert!(n > 0, "There must be at least one share");
        assert!(t > 0, "The threshold must be at least one");
        assert!(t <= n, "The threshold must be lower than the total shares");

        let polynomial = ShamirPolynomial::random(*self, t - 1, rng);

        (1..=n)
            .map(|id| {
                let secret = polynomial.evaluate(gf256(id));
                ShamirShare::new(id, secret)
            })
            .collect()
    }

    fn reconstruct<S: AsRef<ShamirShare<Self>>>(shares: &[S]) -> Self {
        let mut y = gf256(0);
        for (i, share) in shares.iter().enumerate() {
            let mut li = gf256(1);
            let (x0, y0) = share.as_ref().as_coordinates();
            for (j, share) in shares.iter().enumerate() {
                let (x1, _y1) = share.as_ref().as_coordinates();
                if i != j {
                    li *= gf256(*x1) / (gf256(*x0) + gf256(*x1));
                }
            }
            y += li * y0;
        }
        y
    }
}

/// NOTE: Chaos test is not implemented for GF(256) because the field is too small to prevent collisions.
#[cfg(test)]
mod test {
    use gf256::gf256;

    use crate::shamir;

    #[test]
    fn reconstruct() {
        shamir::test::test_reconstruct::<gf256>();
    }

    #[test]
    fn reconstruct_sparse() {
        shamir::test::test_reconstruct_sparse::<gf256>();
    }

    #[test]
    fn reconstruct_missing_shares() {
        shamir::test::test_reconstruct_missing_shares::<gf256>();
    }
}
