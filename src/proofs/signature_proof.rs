use bls12_381 as bls;
use itertools::{chain, izip};

use crate::bls_extensions::*;
use crate::elgamal::*;
use crate::parameters::*;
use crate::proofs::proof::*;

pub struct BuilderValues {
    pub commit_hash: bls::G1Projective,
    pub attribute_keys: Vec<bls::Scalar>,
    pub blinding_factor: bls::Scalar,
}

pub struct Builder<'a, R: RngInstance> {
    params: &'a Parameters<R>,

    // Secrets
    private_attributes: &'a Vec<bls::Scalar>,
    public_attributes: &'a Vec<bls::Scalar>,
    attribute_keys: Vec<bls::Scalar>,
    blinding_factor: bls::Scalar,

    // Witnesses
    witness_blind: bls::Scalar,
    witness_attributes: Vec<bls::Scalar>,
    witness_keys: Vec<bls::Scalar>,
}

pub struct Commitments<'a, R: RngInstance> {
    // Base points
    params: &'a Parameters<R>,
    gamma: &'a ElGamalPublicKey,
    commit_hash: &'a bls::G1Projective,

    // This value is hashed in the challenge in coconut ref impl. We do the same here.
    attribute_commit: &'a bls::G1Projective,

    // Commitments
    commit_attributes: bls::G1Projective,
    commit_keys: Vec<(bls::G1Projective, bls::G1Projective)>,
}

pub struct Proof {
    // Responses
    response_blind: bls::Scalar,
    response_attributes: Vec<bls::Scalar>,
    response_keys: Vec<bls::Scalar>,
}

impl<'a, R: RngInstance> Builder<'a, R> {
    pub fn new(
        params: &'a Parameters<R>,
        private_attributes: &'a Vec<bls::Scalar>,
        public_attributes: &'a Vec<bls::Scalar>,
        attribute_keys: Vec<bls::Scalar>,
        blinding_factor: bls::Scalar,
    ) -> Self {
        assert_eq!(
            params.hs.len(),
            private_attributes.len() + public_attributes.len()
        );

        let attribute_keys_len = attribute_keys.len();

        Self {
            params,

            private_attributes,
            public_attributes,
            attribute_keys,
            blinding_factor,

            witness_blind: params.random_scalar(),
            witness_attributes: params
                .random_scalars(private_attributes.len() + public_attributes.len()),
            witness_keys: params.random_scalars(attribute_keys_len),
        }
    }

    pub fn commitments(
        &self,
        gamma: &'a ElGamalPublicKey,
        commit_hash: &'a bls::G1Projective,
        attribute_commit: &'a bls::G1Projective,
    ) -> Box<Commitments<'a, R>> {
        assert_eq!(self.witness_attributes.len(), self.params.hs.len());

        // w_o G_1 + sum(w_m H_i)
        let mut commit_attributes = self.params.g1 * self.witness_blind;
        for (h, witness) in izip!(&self.params.hs, &self.witness_attributes) {
            commit_attributes += h * witness;
        }

        Box::new(Commitments {
            params: self.params,
            gamma,
            commit_hash,
            attribute_commit,

            commit_attributes,

            commit_keys: izip!(&self.witness_attributes, &self.witness_keys)
                .map(|(witness_attribute, witness_key)| {
                    (
                        // w_k_i G_1
                        self.params.g1 * witness_key,
                        // w_m_i h + w_k_i Y
                        commit_hash * witness_attribute + gamma.public_key * witness_key,
                    )
                })
                .collect(),
        })
    }

    pub fn finish(&self, challenge: &bls::Scalar) -> Proof {
        assert_eq!(
            self.witness_attributes.len(),
            self.private_attributes.len() + self.public_attributes.len()
        );
        assert_eq!(self.witness_keys.len(), self.attribute_keys.len());

        Proof {
            response_blind: self.witness_blind - challenge * self.blinding_factor,

            response_attributes: izip!(
                chain(self.private_attributes, self.public_attributes),
                &self.witness_attributes
            )
            .map(|(attribute, witness)| witness - challenge * attribute)
            .collect(),

            response_keys: izip!(&self.attribute_keys, &self.witness_keys)
                .map(|(key, witness)| witness - challenge * key)
                .collect(),
        }
    }
}

impl<'a, R: RngInstance> ProofCommitments for Commitments<'a, R> {
    fn commit(&self, hasher: &mut ProofHasher) {
        // Add base points we use
        hasher.add_g1_affine(&self.params.g1);
        hasher.add_g2_affine(&self.params.g2);
        for h in &self.params.hs {
            hasher.add_g1_affine(h);
        }
        hasher.add_g1(&self.gamma.public_key);
        hasher.add_g1(self.commit_hash);
        hasher.add_g1(self.attribute_commit);

        hasher.add_g1(&self.commit_attributes);

        for (commit_a, commit_b) in &self.commit_keys {
            hasher.add_g1(&commit_a);
            hasher.add_g1(&commit_b);
        }
    }
}

impl Proof {
    pub fn commitments<'a, R: RngInstance>(
        &self,
        params: &'a Parameters<R>,
        challenge: &bls::Scalar,
        gamma: &'a ElGamalPublicKey,
        commit_hash: &'a bls::G1Projective,
        attribute_commit: &'a bls::G1Projective,
        ciphertexts: &Vec<EncryptedValue>,
    ) -> Box<Commitments<'a, R>> {
        // c c_m + r_r G_1 + sum(r_m H)
        let mut commit_attributes = attribute_commit * challenge + params.g1 * self.response_blind;
        for (h, response) in izip!(&params.hs, &self.response_attributes) {
            commit_attributes += h * response;
        }

        Box::new(Commitments {
            params,

            gamma,
            commit_hash,
            attribute_commit,

            commit_attributes,

            commit_keys: izip!(&self.response_attributes, &self.response_keys, ciphertexts)
                .map(|(response_attribute, response_key, ciphertext)| {
                    (
                        // c A_i + r_k_i G1
                        ciphertext.0 * challenge + params.g1 * response_key,
                        // c B_i + r_k_i Y + r_m_i h
                        ciphertext.1 * challenge
                            + gamma.public_key * response_key
                            + commit_hash * response_attribute,
                    )
                })
                .collect(),
        })
    }
}
