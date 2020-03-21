use bls12_381 as bls;
use itertools::izip;

use crate::bls_extensions::*;
use crate::coconut::coconut::*;
use crate::parameters::*;
use crate::proofs::proof::*;

pub struct BuilderValues {
    pub blind: bls::Scalar,
}

pub struct Builder<'a, R: RngInstance> {
    params: &'a Parameters<R>,

    // Secrets
    attributes: &'a Vec<bls::Scalar>,
    blind: bls::Scalar,

    // Witnesses
    witness_kappa: Vec<bls::Scalar>,
    witness_blind: bls::Scalar,
}

pub struct Commitments<'a, R: RngInstance> {
    // Base points
    params: &'a Parameters<R>,
    verify_key: &'a VerifyKey,
    blind_commit_hash: &'a bls::G1Projective,

    // Commitments
    commit_kappa: bls::G2Projective,
    commit_blind: bls::G1Projective,
}

pub struct Proof {
    response_kappa: Vec<bls::Scalar>,
    response_blind: bls::Scalar,
}

impl<'a, R: RngInstance> Builder<'a, R> {
    pub fn new(
        params: &'a Parameters<R>,
        attributes: &'a Vec<bls::Scalar>,
        blind: bls::Scalar,
    ) -> Self {
        Self {
            params,

            attributes,
            blind,

            witness_kappa: params.random_scalars(attributes.len()),
            witness_blind: params.random_scalar(),
        }
    }

    pub fn commitments(
        &self,
        verify_key: &'a VerifyKey,
        blind_commit_hash: &'a bls::G1Projective,
    ) -> Box<dyn ProofCommitments + 'a> {
        assert!(self.witness_kappa.len() <= verify_key.beta.len());

        //  w_o G_2 + A + sum(w_k_i B_i)
        let mut commit_kappa = self.params.g2 * self.witness_blind + verify_key.alpha;
        for (beta_i, witness) in izip!(&verify_key.beta, &self.witness_kappa) {
            commit_kappa += beta_i * witness;
        }

        Box::new(Commitments {
            params: self.params,
            verify_key,
            blind_commit_hash,

            commit_kappa,

            commit_blind: blind_commit_hash * self.witness_blind,
        })
    }

    pub fn finish(&self, challenge: &bls::Scalar) -> Proof {
        assert_eq!(self.witness_kappa.len(), self.attributes.len());

        Proof {
            response_kappa: izip!(&self.witness_kappa, self.attributes)
                .map(|(witness, attribute)| witness - challenge * attribute)
                .collect(),

            response_blind: self.witness_blind - challenge * self.blind,
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

        hasher.add_g2(&self.verify_key.alpha);
        for beta in &self.verify_key.beta {
            hasher.add_g2(beta);
        }
        hasher.add_g1(self.blind_commit_hash);

        hasher.add_g2(&self.commit_kappa);
        hasher.add_g1(&self.commit_blind);
    }
}

impl Proof {
    pub fn commitments<'a, R: RngInstance>(
        &self,
        params: &'a Parameters<R>,
        challenge: &bls::Scalar,
        verify_key: &'a VerifyKey,
        blind_commit_hash: &'a bls::G1Projective,
        kappa: &bls::G2Projective,
        v: &bls::G1Projective,
    ) -> Box<dyn ProofCommitments + 'a> {
        // c K + r_t G2 + (1 - c) A + sum(r_m_i B_i)
        let mut commit_kappa = kappa * challenge
            + params.g2 * self.response_blind
            + verify_key.alpha * (bls::Scalar::one() - challenge);
        for (beta_i, response) in izip!(&verify_key.beta, &self.response_kappa) {
            commit_kappa += beta_i * response;
        }

        Box::new(Commitments {
            params,

            verify_key,
            blind_commit_hash,

            commit_kappa,

            commit_blind: v * challenge + blind_commit_hash * self.response_blind,
        })
    }
}
