use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto:: RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
///this module implements the Pedersen commitment scheme using Ristretto points which serves 
/// as the commitment as leaves to the merkle tree.
pub struct PedersenCommitment {
    // G (base point)
    g: RistrettoPoint,
    // H (base point with no discrete log relation with G)
    h: RistrettoPoint,
}

impl PedersenCommitment {
    //uses hash-to-curve 
    pub fn new() -> Self {
        
        let g = RISTRETTO_BASEPOINT_POINT;

        let mut hasher = Sha512::new();
        hasher.update(b"Pedersen Commitment Generator H");
        let h_bytes = hasher.finalize();
        let mut h_bytes_array = [0u8; 64];
        h_bytes_array.copy_from_slice(&h_bytes[..64]);
        let h = RistrettoPoint::from_uniform_bytes(&h_bytes_array);
        PedersenCommitment { g, h }
    }

    /// Commit to a value with a random blinding factor
    pub fn commit(&self, value: u64, blinding: &Scalar) -> RistrettoPoint {
        let v = Scalar::from(value);
        self.g * v + self.h * blinding
    }
    #[allow(dead_code)]
    /// Generate a random blinding factor
    pub fn random_blinding(&self) -> Scalar {
        let mut rng = OsRng;
        let mut random_bytes = [0u8; 32];
        let _u=rng.try_fill_bytes(&mut random_bytes);
        Scalar::from_bytes_mod_order(random_bytes)
    }
    #[allow(dead_code)]
    /// Verify a commitment
    pub fn verify(&self, commitment: &RistrettoPoint, value: u64, blinding: &Scalar) -> bool {
        let expected = self.commit(value, blinding);
        *commitment == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen_commitment() {
        let pc = PedersenCommitment::new();

        let value = 42u64;
        let blinding = pc.random_blinding();

        let commitment = pc.commit(value, &blinding);

      
        assert!(pc.verify(&commitment, value, &blinding));

       
        assert!(!pc.verify(&commitment, value + 1, &blinding));
        assert!(!pc.verify(&commitment, value, &pc.random_blinding()));
    }

    #[test]
    fn test_homomorphic_property() {
        let pc = PedersenCommitment::new();

        let v1 = 10u64;
        let r1 = pc.random_blinding();
        let c1 = pc.commit(v1, &r1);

        let v2 = 20u64;
        let r2 = pc.random_blinding();
        let c2 = pc.commit(v2, &r2);

       
        let v_sum = v1 + v2;
        let r_sum = r1 + r2;
        let c_sum = c1 + c2;

        assert!(pc.verify(&c_sum, v_sum, &r_sum));
    }
}