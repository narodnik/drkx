use bls12_381 as bls;
use itertools::izip;
use sha2::{Digest, Sha256};
#[allow(unused_imports)]
use crate::bls_extensions::*;
#[allow(unused_imports)]
use crate::parameters::*;

pub struct ProofHasher {
    g1_datas: Vec<[u8; 48]>,
    g2_datas: Vec<[u8; 96]>,
}

impl ProofHasher {
    pub fn new() -> Self {
        Self {
            g1_datas: Vec::new(),
            g2_datas: Vec::new(),
        }
    }

    pub fn add_g1(&mut self, point: &bls::G1Projective) {
        let point = bls::G1Affine::from(point);
        self.add_g1_affine(&point);
    }

    pub fn add_g2(&mut self, point: &bls::G2Projective) {
        let point = bls::G2Affine::from(point);
        self.add_g2_affine(&point);
    }

    pub fn add_g1_affine(&mut self, point: &bls::G1Affine) {
        let data = point.to_compressed();
        self.g1_datas.push(data);
    }

    pub fn add_g2_affine(&mut self, point: &bls::G2Affine) {
        let data = point.to_compressed();
        self.g2_datas.push(data);
    }

    pub fn finish(&self) -> bls::Scalar {
        for i in 0u32.. {
            let mut hasher = Sha256::new();

            let i_data = i.to_le_bytes();
            hasher.input(&i_data);

            for data in &self.g1_datas {
                hasher.input(&data[0..32]);
                hasher.input(&data[32..]);
            }
            for data in &self.g2_datas {
                hasher.input(&data[0..32]);
                hasher.input(&data[32..64]);
                hasher.input(&data[64..]);
            }
            let hash_result = hasher.result();

            // TODO: how can I fix this? Why not &hash_result[0...32]??
            let mut hash_data = [0u8; 32];
            hash_data.copy_from_slice(hash_result.as_slice());

            let challenge = bls::Scalar::from_bytes(&hash_data);
            if challenge.is_some().unwrap_u8() == 1 {
                return challenge.unwrap();
            }
        }
        unreachable!();
    }
}

pub trait ProofBuilder {
    fn finish(&self, challenge: &bls::Scalar);
}

pub trait ProofCommitments {
    fn commit(&self, hasher: &mut ProofHasher);
}

struct Witness {
    secret: bls::Scalar,
    witness: bls::Scalar,
}

impl Witness {
    fn new<R: RngInstance>(params: &Parameters<R>, secret: bls::Scalar) -> Self {
        Self {
            secret,
            witness: params.random_scalar(),
        }
    }

    fn derive(&self, challenge: &bls::Scalar) -> bls::Scalar {
        self.witness - challenge * self.secret
    }
}

struct WitnessVec {
    secrets: Vec<bls::Scalar>,
    witness: Vec<bls::Scalar>,
}

impl WitnessVec {
    fn new<R: RngInstance>(params: &Parameters<R>, secrets: Vec<bls::Scalar>) -> Self {
        let secrets_len = secrets.len();
        Self {
            secrets,
            witness: params.random_scalars(secrets_len),
        }
    }

    fn derive(&self, challenge: &bls::Scalar) -> Vec<bls::Scalar> {
        izip!(&self.witness, &self.secrets)
            .map(|(witness, secret)| witness - challenge * secret)
            .collect()
    }
}

