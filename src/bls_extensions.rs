use bls12_381 as bls;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

// This code provides the ability to create a random scalar using a trait
pub trait RngInstance {
    fn fill_bytes(dest: &mut [u8]);
}

pub struct OsRngInstance;

impl RngInstance for OsRngInstance {
    fn fill_bytes(dest: &mut [u8]) {
        OsRng.fill_bytes(dest);
    }
}

pub trait RandomScalar {
    fn new_random<R: RngInstance>() -> Self;
}

// Extend bls::Scalar with a new_random() method.
impl RandomScalar for bls::Scalar {
    fn new_random<R: RngInstance>() -> Self {
        loop {
            let mut random_bytes = [0u8; 32];
            R::fill_bytes(&mut random_bytes);
            let scalar = bls::Scalar::from_bytes(&random_bytes);
            if scalar.is_some().unwrap_u8() == 1 {
                break scalar.unwrap();
            }
        }
    }
}

macro_rules! from_slice {
    ($data:expr, $len:literal) => {{
        let mut array = [0; $len];
        // panics if not enough data
        let bytes = &$data[..array.len()];
        array.copy_from_slice(bytes);
        array
    }};
}

trait BlsStringConversion {
    fn to_string(&self) -> String;
    fn from_string(object: &str) -> Self;
}

impl BlsStringConversion for bls::Scalar {
    fn to_string(&self) -> String {
        hex::encode(self.to_bytes())
    }
    fn from_string(object: &str) -> Self {
        let bytes = from_slice!(&hex::decode(object).unwrap(), 32);
        bls::Scalar::from_bytes(&bytes).unwrap()
    }
}

impl BlsStringConversion for bls::G1Affine {
    fn to_string(&self) -> String {
        hex::encode(self.to_compressed().to_vec())
    }
    fn from_string(object: &str) -> Self {
        let bytes = from_slice!(&hex::decode(object).unwrap(), 48);
        bls::G1Affine::from_compressed(&bytes).unwrap()
    }
}

impl BlsStringConversion for bls::G2Affine {
    fn to_string(&self) -> String {
        hex::encode(self.to_compressed().to_vec())
    }
    fn from_string(object: &str) -> Self {
        let bytes = from_slice!(&hex::decode(object).unwrap(), 96);
        bls::G2Affine::from_compressed(&bytes).unwrap()
    }
}

impl BlsStringConversion for bls::G1Projective {
    fn to_string(&self) -> String {
        bls::G1Affine::from(self).to_string()
    }
    fn from_string(object: &str) -> Self {
        bls::G1Affine::from_string(object).into()
    }
}

impl BlsStringConversion for bls::G2Projective {
    fn to_string(&self) -> String {
        bls::G2Affine::from(self).to_string()
    }
    fn from_string(object: &str) -> Self {
        bls::G2Affine::from_string(object).into()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "bls::Scalar")]
struct ScalarDef(#[serde(getter = "bls::Scalar::to_string")] String);

#[derive(Serialize, Deserialize)]
#[serde(remote = "bls::G1Affine")]
struct G1AffineDef(#[serde(getter = "bls::G1Affine::to_string")] String);

#[derive(Serialize, Deserialize)]
#[serde(remote = "bls::G2Affine")]
struct G2AffineDef(#[serde(getter = "bls::G2Affine::to_string")] String);

#[derive(Serialize, Deserialize)]
#[serde(remote = "bls::G1Projective")]
struct G1ProjectiveDef(#[serde(getter = "bls::G1Projective::to_string")] String);

#[derive(Serialize, Deserialize)]
#[serde(remote = "bls::G2Projective")]
struct G2ProjectiveDef(#[serde(getter = "bls::G2Projective::to_string")] String);

// Provide a conversion to construct the remote type.

impl From<ScalarDef> for bls::Scalar {
    fn from(def: ScalarDef) -> Self {
        Self::from_string(&def.0)
    }
}

impl From<G1AffineDef> for bls::G1Affine {
    fn from(def: G1AffineDef) -> Self {
        Self::from_string(&def.0)
    }
}

impl From<G2AffineDef> for bls::G2Affine {
    fn from(def: G2AffineDef) -> Self {
        Self::from_string(&def.0)
    }
}

impl From<G1ProjectiveDef> for bls::G1Projective {
    fn from(def: G1ProjectiveDef) -> Self {
        Self::from_string(&def.0)
    }
}

impl From<G2ProjectiveDef> for bls::G2Projective {
    fn from(def: G2ProjectiveDef) -> Self {
        Self::from_string(&def.0)
    }
}

#[test]
fn serialize_deserialize_bls_g1_affine() {
    #[derive(Serialize, Deserialize)]
    struct Object {
        #[serde(with = "G1AffineDef")]
        identity: bls::G1Affine,
    }

    let object = Object {
        identity: bls::G1Affine::identity(),
    };

    let json = serde_json::to_string(&object).unwrap();

    let object1: Object = serde_json::from_str(&json).unwrap();

    println!("{}", json);
    assert_eq!(object.identity, object1.identity);
}

#[test]
fn serialize_deserialize_bls_g1_projective() {
    #[derive(Serialize, Deserialize)]
    struct Object {
        #[serde(with = "G1ProjectiveDef")]
        identity: bls::G1Projective,
    }

    let object = Object {
        identity: bls::G1Affine::identity().into(),
    };

    let json = serde_json::to_string(&object).unwrap();

    let object1: Object = serde_json::from_str(&json).unwrap();

    println!("{}", json);
    assert_eq!(object.identity, object1.identity);
}
