#[allow(unused_imports)]
use bls12_381 as bls;
#[allow(unused_imports)]
use itertools::izip;

#[allow(unused_imports)]
use crate::bls_extensions::*;
#[allow(unused_imports)]
use crate::coconut::coconut::*;
#[allow(unused_imports)]
use crate::elgamal::*;
#[allow(unused_imports)]
use crate::proofs::credential_proof;
#[allow(unused_imports)]
use crate::proofs::proof::*;
#[allow(unused_imports)]
use crate::proofs::signature_proof;
#[allow(unused_imports)]
use crate::utility::*;

#[test]
fn test_multiparty_keygen() {
    let attributes_size = 2;
    let (threshold, number_authorities) = (5, 7);

    let coconut = Coconut::<OsRngInstance>::new(attributes_size, threshold, number_authorities);

    let (secret_keys, verify_keys) = coconut.multiparty_keygen();

    let verify_key = coconut.aggregate_keys(&verify_keys);

    let sigs_x: Vec<bls::G1Projective> = secret_keys
        .iter()
        .map(|secret_key| coconut.params.g1 * secret_key.x)
        .collect();
    let l = lagrange_basis_from_range(6);

    let mut sig = bls::G1Projective::identity();
    for (s_i, l_i) in izip!(&sigs_x, &l) {
        sig += s_i * l_i;
    }

    let ppair_1 = bls::pairing(&bls::G1Affine::from(sig), &coconut.params.g2);
    let ppair_2 = bls::pairing(&coconut.params.g1, &bls::G2Affine::from(verify_key.alpha));
    assert_eq!(ppair_1, ppair_2);
}

#[test]
fn test_multiparty_coconut() {
    let attributes_size = 3;
    let (threshold, number_authorities) = (5, 7);

    let coconut = Coconut::<OsRngInstance>::new(attributes_size, threshold, number_authorities);

    let (secret_keys, verify_keys) = coconut.multiparty_keygen();

    let verify_key = coconut.aggregate_keys(&verify_keys);

    let d = ElGamalPrivateKey::new(&coconut.params);
    let gamma = d.to_public(&coconut.params);

    //let private_attributes = vec![bls::Scalar::from(110), bls::Scalar::from(4)];
    //let public_attributes = vec![bls::Scalar::from(256)];
    let private_attributes = vec![bls::Scalar::from(110)];
    let public_attributes = vec![bls::Scalar::from(4), bls::Scalar::from(256)];

    let (sign_request, sign_proof_values) =
        coconut.make_blind_sign_request(&gamma, &private_attributes, &public_attributes);

    let sign_proof_builder = signature_proof::Builder::new(
        &coconut.params,
        &private_attributes,
        &public_attributes,
        sign_proof_values.attribute_keys,
        sign_proof_values.blinding_factor,
    );

    let sign_commitments = sign_proof_builder.commitments(
        &gamma,
        &sign_proof_values.commit_hash,
        &sign_request.attribute_commit,
    );

    let mut sign_hasher = ProofHasher::new();
    sign_commitments.commit(&mut sign_hasher);
    let sign_challenge = sign_hasher.finish();

    let sign_proof = sign_proof_builder.finish(&sign_challenge);

    let blind_signatures: Vec<_> = secret_keys
        .iter()
        .map(|secret_key| {
            let commit_hash = sign_request.compute_commit_hash();
            let commits = sign_proof.commitments(
                &coconut.params,
                &sign_challenge,
                &gamma,
                &commit_hash,
                &sign_request.attribute_commit,
                &sign_request.encrypted_attributes,
            );
            let mut hasher = ProofHasher::new();
            commits.commit(&mut hasher);
            let challenge = hasher.finish();

            assert_eq!(challenge, sign_challenge);

            sign_request.blind_sign(&coconut.params, secret_key, &gamma, &public_attributes)
        })
        .collect();

    // Signatures should be a struct, with an authority ID inside them
    let mut signature_shares: Vec<_> = blind_signatures
        .iter()
        .map(|blind_signature| blind_signature.unblind(&d))
        .collect();
    let mut indexes: Vec<u64> = (1u64..=signature_shares.len() as u64).collect();

    signature_shares.remove(0);
    indexes.remove(0);
    signature_shares.remove(4);
    indexes.remove(4);

    let commit_hash = sign_request.compute_commit_hash();
    let signature = Signature {
        commit_hash,
        sigma: coconut.aggregate(&signature_shares, indexes),
    };

    //let private_attributes2 = vec![bls::Scalar::from(110)];
    //let public_attributes2 = vec![bls::Scalar::from(4), bls::Scalar::from(256)];
    let private_attributes2 = vec![bls::Scalar::from(110), bls::Scalar::from(4)];
    let public_attributes2 = vec![bls::Scalar::from(256)];

    let (credential, credential_proof_values) =
        coconut.make_credential(&verify_key, &signature, &private_attributes2);

    let credential_proof_builder = credential_proof::Builder::new(
        &coconut.params,
        &private_attributes2,
        credential_proof_values.blind,
    );

    // Commits
    let credential_commitments =
        credential_proof_builder.commitments(&verify_key, &credential.blind_commit_hash);

    let mut hasher = ProofHasher::new();
    credential_commitments.commit(&mut hasher);
    let challenge = hasher.finish();

    //Responses
    let credential_proof = credential_proof_builder.finish(&challenge);

    let is_verify = credential.verify(&coconut.params, &verify_key, &public_attributes2);
    assert!(is_verify);

    let credential_verify_commitments = credential_proof.commitments(
        &coconut.params,
        &challenge,
        &verify_key,
        &credential.blind_commit_hash,
        &credential.kappa,
        &credential.v,
    );

    let mut verify_hasher = ProofHasher::new();
    credential_verify_commitments.commit(&mut verify_hasher);
    let verify_challenge = verify_hasher.finish();
    assert_eq!(verify_challenge, challenge);
}
