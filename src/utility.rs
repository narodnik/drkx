use bls12_381 as bls;
use std::borrow::Borrow;

use crate::hashable::*;

pub fn compute_polynomial<'a, I>(coefficients: I, x_primitive: u64) -> bls::Scalar
where
    I: Iterator<Item = &'a bls::Scalar>,
{
    let x = bls::Scalar::from(x_primitive);
    coefficients
        .enumerate()
        .map(|(i, coefficient)| coefficient * x.pow(&[i as u64, 0, 0, 0]))
        .fold(bls::Scalar::zero(), |result, x| result + x)
}

pub fn lagrange_basis<I>(indexes: I) -> Vec<bls::Scalar>
where
    I: Iterator + Clone,
    I::Item: Borrow<u64>,
{
    let x = bls::Scalar::zero();
    let mut lagrange_result = Vec::new();

    for i_value in indexes.clone() {
        let mut numerator = bls::Scalar::one();
        let mut denominator = bls::Scalar::one();

        let i_integer = *i_value.borrow();
        let i = bls::Scalar::from(i_integer);

        for j_value in indexes.clone() {
            let j_integer = *j_value.borrow();

            if j_integer == i_integer {
                continue;
            }

            let j = bls::Scalar::from(j_integer);
            numerator = numerator * (x - j);
            denominator = denominator * (i - j);
        }

        let result = numerator * denominator.invert().unwrap();
        lagrange_result.push(result);
    }

    lagrange_result
}

pub fn lagrange_basis_from_range(range_len: u64) -> Vec<bls::Scalar> {
    lagrange_basis(1..=range_len)
}

// TODO: This should just be hash to point
pub fn compute_commit_hash(attribute_commit: &bls::G1Projective) -> bls::G1Projective {
    let commit_data = bls::G1Affine::from(attribute_commit).to_compressed();
    let commit_hash = bls::G1Projective::hash_to_point(&commit_data);
    commit_hash
}

pub fn izip<A, B>(
    first: impl IntoIterator<Item = A>,
    second: impl IntoIterator<Item = B>,
) -> impl Iterator<Item = (A, B)> {
    first.into_iter().zip(second.into_iter())
}
