use bls12_381 as bls;
use itertools::{chain, izip};

use crate::bls_extensions::*;
use crate::elgamal::*;
use crate::parameters::*;
use crate::proofs::credential_proof;
use crate::proofs::proof::*;
use crate::proofs::signature_proof;
use crate::utility::*;

pub struct SecretKey {
    pub x: bls::Scalar,
    pub y: Vec<bls::Scalar>,
}

#[derive(Clone)]
pub struct VerifyKey {
    pub alpha: bls::G2Projective,
    pub beta: Vec<bls::G2Projective>,
}

pub type Attribute = bls::Scalar;

type SignatureShare = bls::G1Projective;
type CombinedSignatureShares = bls::G1Projective;

pub type CommitHash = bls::G1Projective;

pub struct PartialSignature {
    encrypted_value: EncryptedValue,
}

impl PartialSignature {
    pub fn unblind(&self, private_key: &ElGamalPrivateKey) -> SignatureShare {
        private_key.decrypt(&self.encrypted_value)
    }
}

pub struct Signature {
    pub commit_hash: CommitHash,
    pub sigma: bls::G1Projective,
}

pub struct Coconut<R: RngInstance> {
    pub params: Parameters<R>,
    threshold: u32,
    authorities_total: u32,
}

impl<R: RngInstance> Coconut<R> {
    pub fn new(attributes_size: u32, authorities_threshold: u32, authorities_total: u32) -> Self {
        Self {
            params: Parameters::<R>::new(attributes_size),
            threshold: authorities_threshold,
            authorities_total: authorities_total,
        }
    }

    pub fn multiparty_keygen(&self) -> (Vec<SecretKey>, Vec<VerifyKey>) {
        let attributes_size = self.params.hs.len();
        assert!(self.authorities_total >= self.threshold);
        assert!(attributes_size > 0);

        let n_random_scalars = |n| (0..n).map(|_| self.params.random_scalar()).collect();
        let v_poly: Vec<_> = n_random_scalars(self.threshold);
        let w_poly: Vec<Vec<_>> = (0..attributes_size)
            .map(|_| n_random_scalars(self.threshold))
            .collect();

        //// Generate shares
        let x_shares =
            (1..=self.authorities_total).map(|i| compute_polynomial(v_poly.iter(), i as u64));
        let y_shares = (1..=self.authorities_total).map(|i| {
            w_poly
                .iter()
                .map(move |w_coefficients| compute_polynomial(w_coefficients.iter(), i as u64))
        });

        // Set the keys
        // sk_i = (x, (y_1, y_2, ..., y_q))
        // vk_i = (g2^x, (g2^y_1, g2^y_2, ..., g2^y_q)) = (a, (B_1, B_2, ..., B_q))
        let verify_keys: Vec<VerifyKey> = x_shares
            .clone()
            .zip(y_shares.clone())
            .map(|(x, y_share_parts)| VerifyKey {
                alpha: self.params.g2 * x,
                beta: y_share_parts.map(|y| self.params.g2 * y).collect(),
            })
            .collect();
        // We are moving out of x_shares into SecretKey, so this line happens
        // after creating verify_keys to avoid triggering borrow checker.
        let secret_keys: Vec<SecretKey> = x_shares
            .zip(y_shares)
            .map(|(x, y)| SecretKey {
                x: x,
                y: y.collect(),
            })
            .collect();

        (secret_keys, verify_keys)
    }

    pub fn aggregate_keys(&self, verify_keys: &Vec<VerifyKey>) -> VerifyKey {
        let lagrange = lagrange_basis_from_range(verify_keys.len() as u64);

        let (alpha, beta): (Vec<&_>, Vec<&Vec<_>>) = verify_keys
            .iter()
            .map(|key| (&key.alpha, &key.beta))
            .unzip();

        assert!(beta.len() > 0);
        let attributes_size = beta[0].len();

        assert_eq!(lagrange.len(), alpha.len());

        let mut aggregate_alpha = bls::G2Projective::identity();
        for (alpha_i, lagrange_i) in izip!(alpha, &lagrange) {
            aggregate_alpha += alpha_i * lagrange_i;
        }

        let aggregate_beta: Vec<_> = (0..attributes_size)
            .map(|i| {
                let mut result = bls::G2Projective::identity();
                for (beta_j, lagrange_i) in izip!(&beta, &lagrange) {
                    result += beta_j[i] * lagrange_i;
                }
                result
            })
            .collect();

        return VerifyKey {
            alpha: aggregate_alpha,
            beta: aggregate_beta,
        };
    }

    pub fn make_blind_sign_request(
        &self,
        shared_attribute_key: &ElGamalPublicKey,
        private_attributes: &Vec<Attribute>,
        public_attributes: &Vec<Attribute>,
    ) -> (BlindSignatureRequest, signature_proof::BuilderValues) {
        let blinding_factor = self.params.random_scalar();

        assert_eq!(
            self.params.hs.len(),
            private_attributes.len() + public_attributes.len()
        );

        let mut attribute_commit = self.params.g1 * blinding_factor;
        for (h, attribute) in izip!(
            &self.params.hs,
            chain(private_attributes, public_attributes)
        ) {
            attribute_commit += h * attribute;
        }

        let commit_hash = compute_commit_hash(&attribute_commit);

        let attribute_keys: Vec<_> = (0..private_attributes.len())
            .map(|_| self.params.random_scalar())
            .collect();

        let encrypted_attributes: Vec<(_, _)> = izip!(private_attributes, &attribute_keys)
            .map(|(attribute, key)| {
                shared_attribute_key.encrypt(&self.params, &attribute, &key, &commit_hash)
            })
            .collect();

        // Construct proof
        // Witness
        /*
        // Commits
        let commitments =
            proof_builder.commitments(shared_attribute_key, &commit_hash, &attribute_commit);

        let mut proof_assembly = ProofAssembly::new();
        proof_assembly.add(commitments);
        for commit in external_commitments {
            proof_assembly.add(commit);
        }

        // Challenge
        let challenge = proof_assembly.compute_challenge();
        //Responses
        let proof = proof_builder.finish(&challenge);
        */

        (
            BlindSignatureRequest {
                attribute_commit,
                encrypted_attributes,
                //challenge,
                //proof,
            },
            signature_proof::BuilderValues {
                commit_hash,
                attribute_keys,
                blinding_factor,
            },
        )
    }

    pub fn aggregate(
        &self,
        signature_shares: &Vec<SignatureShare>,
        indexes: Vec<u64>,
    ) -> CombinedSignatureShares {
        let lagrange = lagrange_basis(indexes.iter());

        let mut signature = bls::G1Projective::identity();
        for (share, lagrange_i) in izip!(signature_shares, lagrange) {
            signature += share * lagrange_i;
        }
        signature
    }

    pub fn make_credential(
        &self,
        verify_key: &VerifyKey,
        signature: &Signature,
        attributes: &Vec<Attribute>,
    ) -> (Credential, credential_proof::BuilderValues) {
        assert!(attributes.len() <= verify_key.beta.len());

        let blind_prime = self.params.random_scalar();
        let (blind_commit_hash, blind_sigma) = (
            signature.commit_hash * blind_prime,
            signature.sigma * blind_prime,
        );

        let blind = self.params.random_scalar();

        // K = o G2 + A + sum(m_i B_i)
        let mut kappa = self.params.g2 * blind + verify_key.alpha;
        for (beta_i, attribute) in izip!(&verify_key.beta, attributes) {
            kappa += beta_i * attribute;
        }
        // v = r H_p(C_m)
        let v = blind_commit_hash * blind;

        /*
        // Construct proof
        // Witness
        let proof_builder = CredentialProofBuilder::new(&self.params, attributes, &blind);
        // Commits
        let commitments = proof_builder.commitments(verify_key, &blind_commit_hash);

        let mut proof_assembly = ProofAssembly::new();
        proof_assembly.add(commitments);
        for commit in external_commitments {
            proof_assembly.add(commit);
        }

        // Challenge
        let challenge = proof_assembly.compute_challenge();
        //Responses
        let proof = proof_builder.finish(&challenge);
        */

        (
            Credential {
                kappa: kappa,
                v: v,
                blind_commit_hash,
                blind_sigma,
            },
            credential_proof::BuilderValues { blind },
        )
    }
}

pub struct BlindSignatureRequest {
    pub attribute_commit: bls::G1Projective,
    pub encrypted_attributes: Vec<EncryptedValue>,
    //challenge: bls::Scalar,
    //proof: SignatureProof,
}

impl BlindSignatureRequest {
    pub fn compute_commit_hash(&self) -> CommitHash {
        compute_commit_hash(&self.attribute_commit)
    }

    pub fn blind_sign<R: RngInstance>(
        &self,
        params: &Parameters<R>,
        secret_key: &SecretKey,
        shared_attribute_key: &ElGamalPublicKey,
        public_attributes: &Vec<Attribute>,
    ) -> PartialSignature {
        assert_eq!(
            self.encrypted_attributes.len() + public_attributes.len(),
            params.hs.len()
        );
        let (a_factors, b_factors): (Vec<&_>, Vec<&_>) = self
            .encrypted_attributes
            .iter()
            .map(|value| (&value.0, &value.1))
            .unzip();

        // Issue signature
        let commit_hash = self.compute_commit_hash();

        /*
        // Verify proof
        let commitments = self.proof.commitments(
            params,
            &self.challenge,
            shared_attribute_key,
            &commit_hash,
            &self.attribute_commit,
            &self.encrypted_attributes,
        );
        let mut proof_assembly = ProofAssembly::new();
        proof_assembly.add(commitments);
        for commit in external_commitments {
            proof_assembly.add(commit);
        }

        // Challenge
        let challenge = proof_assembly.compute_challenge();

        if challenge != self.challenge {
            return Err("verify proof failed");
        }
        */

        let mut signature_a = bls::G1Projective::identity();
        for (y_j, a) in izip!(&secret_key.y, a_factors) {
            signature_a += a * y_j;
        }

        let public_terms: Vec<_> = public_attributes
            .iter()
            .map(|attribute| commit_hash * attribute)
            .collect();

        let mut signature_b = commit_hash * secret_key.x;
        for (y_j, b) in izip!(&secret_key.y, chain(b_factors, &public_terms)) {
            signature_b += b * y_j;
        }

        PartialSignature {
            encrypted_value: (signature_a, signature_b),
        }
    }
}

pub struct Credential {
    pub kappa: bls::G2Projective,
    pub v: bls::G1Projective,
    pub blind_commit_hash: CommitHash,
    pub blind_sigma: bls::G1Projective,
}

impl Credential {
    pub fn verify<'a, R: RngInstance>(
        &self,
        params: &Parameters<R>,
        verify_key: &VerifyKey,
        public_attributes: &Vec<Attribute>,
    ) -> bool {
        /*let commitments = self.proof.commitments(
            params,
            &self.challenge,
            verify_key,
            &self.blind_commit_hash,
            &self.kappa,
            &self.v,
        );

        let mut proof_assembly = ProofAssembly::new();
        proof_assembly.add(commitments);
        for commit in external_commitments {
            proof_assembly.add(commit);
        }

        // Challenge
        let challenge = proof_assembly.compute_challenge();

        if challenge != self.challenge {
            return false;
        }*/

        let mut public_aggregates = bls::G2Projective::identity();
        let start_index = verify_key.beta.len() - public_attributes.len();
        for (beta_i, attribute) in izip!(&verify_key.beta[start_index..], public_attributes) {
            public_aggregates += beta_i * attribute;
        }

        let kappa = bls::G2Affine::from(self.kappa + public_aggregates);
        let blind_commit = bls::G1Affine::from(self.blind_commit_hash);
        let sigma_nu = bls::G1Affine::from(self.blind_sigma + self.v);
        bls::pairing(&blind_commit, &kappa) == bls::pairing(&sigma_nu, &params.g2)
    }
}
