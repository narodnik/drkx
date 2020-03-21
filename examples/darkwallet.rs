#[macro_use]
extern crate clap;
extern crate darkwallet;
use bls12_381 as bls;
use clap::{App, Arg, SubCommand};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use simplelog::*;
use std::fs;
use std::path::Path;

struct CoconutSettings {
    attributes: u32,
    threshold: u32,
    total: u32,
}

struct Authority {
    index: u64,
    secret_key: darkwallet::SecretKey,
    coconut: darkwallet::Coconut<darkwallet::OsRngInstance>,
}

impl Authority {
    fn new(index: u64, secret_key: darkwallet::SecretKey, settings: &CoconutSettings) -> Self {
        Self {
            index,
            secret_key,

            coconut: darkwallet::Coconut::<darkwallet::OsRngInstance>::new(
                settings.attributes,
                settings.threshold,
                settings.total,
            ),
        }
    }

    fn blind_sign(
        &self,
        sign_request: &darkwallet::BlindSignatureRequest,
        public_key: &darkwallet::ElGamalPublicKey,
        public_attributes: &Vec<bls::Scalar>,
    ) -> darkwallet::PartialSignature {
        sign_request.blind_sign(
            &self.coconut.params,
            &self.secret_key,
            &public_key,
            &public_attributes,
        )
    }
}

fn generate_keys(
    settings: &CoconutSettings,
) -> (Vec<darkwallet::SecretKey>, darkwallet::VerifyKey) {
    let coconut = darkwallet::Coconut::<darkwallet::OsRngInstance>::new(
        settings.attributes,
        settings.threshold,
        settings.total,
    );

    let (secret_keys, verify_keys) = coconut.multiparty_keygen();

    let verify_key = coconut.aggregate_keys(&verify_keys);

    (secret_keys, verify_key)
}

struct Token {
    value: u64,
    serial: bls::Scalar,
    signature: darkwallet::Signature,
    private_key: darkwallet::ElGamalPrivateKey,
}

impl Token {
    fn id_string(&self) -> String {
        let bytes = self.serial.to_bytes();
        let hash = sha2::Sha256::digest(&bytes);
        hex::encode(&hash)
    }
}

struct Wallet<'a> {
    coconut: darkwallet::Coconut<darkwallet::OsRngInstance>,
    verify_key: &'a darkwallet::VerifyKey,
}

struct WithdrawRequest {
    burn_value: bls::G1Projective,
    //burn_proof: BurnProof,
    credential: darkwallet::Credential,
}

impl<'a> Wallet<'a> {
    fn new(settings: &CoconutSettings, verify_key: &'a darkwallet::VerifyKey) -> Self {
        Self {
            coconut: darkwallet::Coconut::<darkwallet::OsRngInstance>::new(
                settings.attributes,
                settings.threshold,
                settings.total,
            ),
            verify_key,
        }
    }

    fn deposit_new(&self, value: u64) {
        // Assuming we can deposit the money
        let private_attributes = vec![self.coconut.params.random_scalar()];
        let public_attributes = vec![bls::Scalar::from(value)];

        let private_key = darkwallet::ElGamalPrivateKey::new(&self.coconut.params);
        let public_key = private_key.to_public(&self.coconut.params);

        let sign_request = self.coconut.make_blind_sign_request(
            &public_key,
            &private_attributes,
            &public_attributes,
        );

        // Issue a new token
        // Create token file
        // Status = "process_deposit"

        // /deposit_requests/<id>/request
        //   sign_request
        //   public_key
        //   public_attributes
        // /deposit_requests/<id>/secret
        //   private_attributes
    }

    fn deposit(&self, value: u64, authorities: &Vec<Authority>) -> Token {
        // Assuming we can deposit the money
        let private_attributes = vec![self.coconut.params.random_scalar()];
        let public_attributes = vec![bls::Scalar::from(value)];

        let private_key = darkwallet::ElGamalPrivateKey::new(&self.coconut.params);
        let public_key = private_key.to_public(&self.coconut.params);

        let sign_request = self
            .coconut
            .make_blind_sign_request(&public_key, &private_attributes, &public_attributes)
            .0;

        let mut indexed_shares: Vec<_> = authorities
            .iter()
            .map(|authority| {
                (
                    authority.index,
                    authority
                        .blind_sign(&sign_request, &public_key, &public_attributes)
                        .unblind(&private_key),
                )
            })
            .collect();

        // Lets remove 2 of them since this is 5 of 7
        // For testing purposes...
        indexed_shares.remove(0);
        indexed_shares.remove(4);

        let (indexes, shares): (Vec<_>, Vec<_>) = indexed_shares.into_iter().unzip();

        let commit_hash = sign_request.compute_commit_hash();
        let signature = darkwallet::Signature {
            commit_hash,
            sigma: self.coconut.aggregate(&shares, indexes),
        };

        Token {
            value,
            serial: private_attributes[0],
            signature,
            private_key,
        }
    }

    fn withdraw(&self, token: Token) -> WithdrawRequest {
        let burn_value = self.coconut.params.g1 * token.serial;

        let proof_builder = BurnProofBuilder::new(&self.coconut.params, &token.serial);
        let commitments = proof_builder.commitments();

        let private_attributes = vec![token.serial, bls::Scalar::from(token.value)];

        let (credential, credential_proof_builder) =
            self.coconut
                .make_credential(self.verify_key, &token.signature, &private_attributes);

        assert!(credential.verify(&self.coconut.params, &self.verify_key, &Vec::new(),));

        //let burn_proof = proof_builder.finish(&credential.challenge);

        WithdrawRequest {
            burn_value,
            //burn_proof,
            credential,
        }
    }

    fn token_commit(&self, value: u64, blind: &bls::Scalar) -> bls::G1Projective {
        assert!(self.coconut.params.hs.len() >= 1);

        self.coconut.params.g1 * bls::Scalar::from(value) + self.coconut.params.hs[0] * blind
    }

    fn split(
        &self,
        token: Token,
        value1: u64,
        value2: u64,
        authorities: &Vec<Authority>,
    ) -> Result<(Token, Token), &'static str> {
        assert_eq!(token.value, value1 + value2);

        let burn_value = self.coconut.params.g1 * token.serial;

        let blind1 = self.coconut.params.random_scalar();
        let blind2 = self.coconut.params.random_scalar();
        let blind = blind1 + blind2;

        let commit = self.token_commit(token.value, &blind);
        let commit1 = self.token_commit(value1, &blind1);
        let commit2 = self.token_commit(value2, &blind2);

        assert_eq!(commit, commit1 + commit2);

        /*
        let commit_proof_builder = CommitProofBuilder::new(
            &self.coconut.params,
            &bls::Scalar::from(token.value),
            &blind,
        );
        let commit1_proof_builder = CommitProofBuilder::new(
            &self.coconut.params,
            &bls::Scalar::from(value1),
            &blind1,
        );
        let commit2_proof_builder = CommitProofBuilder::new(
            &self.coconut.params,
            &bls::Scalar::from(value2),
            &blind2,
        );

        let commit_commitments = commit_proof_builder.commitments();
        let commit1_commitments = commit1_proof_builder.commitments();
        let commit2_commitments = commit2_proof_builder.commitments();
        */

        // Burn a coin ... This code is nearly identical to withdraw()
        //let proof_builder = BurnProofBuilder::new(&self.coconut.params, &token.serial);
        //let commitments = proof_builder.commitments();

        let private_attributes = vec![token.serial, bls::Scalar::from(token.value)];

        let (credential, credential_proof_builder) = self.coconut.make_credential(
            self.verify_key,
            &token.signature,
            &private_attributes,
            //vec![commitments, commit_commitments, commit1_commitments, commit2_commitments],
            //vec![commitments],
        );

        // Construct proof
        // Witness
        //let proof_builder =
        //    darkwallet::CredentialProofBuilder::new(&self.params, &private_attributes, &blind);
        //// Commits
        //let commitments = proof_builder.commitments(verify_key, &blind_commit_hash);

        // Challenge
        //let challenge = proof_assembly.compute_challenge();
        //Responses
        //let proof = proof_builder.finish(&challenge);

        //let burn_proof = proof_builder.finish(&credential.challenge);
        //let commit_proof = commit_proof_builder.finish(&credential.challenge);
        //let commit1_proof = commit1_proof_builder.finish(&credential.challenge);
        //let commit2_proof = commit2_proof_builder.finish(&credential.challenge);

        // Mint a coin ... Code is nearly identical to deposit()
        // these functions call BlindSign()
        let token1 = self.deposit(value1, authorities);
        let token2 = self.deposit(value2, authorities);

        // Now authorities process the tokens
        // TODO: spent burns list contains burn_value
        if commit != commit1 + commit2 {
            return Err("commits don't add up");
        }
        // pretty similar to process_withdraw()
        //let burn_commitments =
        //    burn_proof.commitments(&self.coconut.params, &credential.challenge, &burn_value);
        if !credential.verify(
            &self.coconut.params,
            &self.verify_key,
            &Vec::new(),
            //vec![burn_commitments],
        ) {
            return Err("verify failed");
        }

        // Unblind token1, token2 and aggregate (already done in call to deposit())
        Ok((token1, token2))
    }
}

struct BurnProofBuilder<'a, R: darkwallet::RngInstance> {
    params: &'a darkwallet::Parameters<R>,

    // Secrets
    serial: &'a bls::Scalar,

    witness: bls::Scalar,
}

struct BurnProofCommitments<'a, R: darkwallet::RngInstance> {
    params: &'a darkwallet::Parameters<R>,

    // Commitments
    commit: bls::G1Projective,
}

struct BurnProof {
    response: bls::Scalar,
}

impl<'a, R: darkwallet::RngInstance> BurnProofBuilder<'a, R> {
    fn new(params: &'a darkwallet::Parameters<R>, serial: &'a bls::Scalar) -> Self {
        Self {
            params,
            serial,
            witness: params.random_scalar(),
        }
    }

    fn commitments(&self) -> Box<dyn darkwallet::ProofCommitments + 'a> {
        Box::new(BurnProofCommitments {
            params: self.params,
            commit: self.params.g1 * self.witness,
        })
    }

    fn finish(&self, challenge: &bls::Scalar) -> BurnProof {
        BurnProof {
            response: self.witness - challenge * self.serial,
        }
    }
}

impl<'a, R: darkwallet::RngInstance> darkwallet::ProofCommitments
    for BurnProofCommitments<'a, R>
{
    fn commit(&self, hasher: &mut darkwallet::ProofHasher) {
        hasher.add_g1_affine(&self.params.g1);
        hasher.add_g1(&self.commit);
    }
}

impl BurnProof {
    fn commitments<'a, R: darkwallet::RngInstance>(
        &self,
        params: &'a darkwallet::Parameters<R>,
        challenge: &bls::Scalar,
        burn_value: &bls::G1Projective,
    ) -> Box<dyn darkwallet::ProofCommitments + 'a> {
        Box::new(BurnProofCommitments {
            params,
            commit: burn_value * challenge + params.g1 * self.response,
        })
    }
}
struct CommitProofBuilder<'a, R: darkwallet::RngInstance> {
    params: &'a darkwallet::Parameters<R>,

    // Secrets
    value: &'a bls::Scalar,
    blind: &'a bls::Scalar,

    witness_value: bls::Scalar,
    witness_blind: bls::Scalar,
}

struct CommitProofCommitments<'a, R: darkwallet::RngInstance> {
    params: &'a darkwallet::Parameters<R>,

    // Commitments
    commit: bls::G1Projective,
}

struct CommitProof {
    response_value: bls::Scalar,
    response_blind: bls::Scalar,
}

impl<'a, R: darkwallet::RngInstance> CommitProofBuilder<'a, R> {
    fn new(
        params: &'a darkwallet::Parameters<R>,
        value: &'a bls::Scalar,
        blind: &'a bls::Scalar,
    ) -> Self {
        Self {
            params,
            value,
            blind,
            witness_value: params.random_scalar(),
            witness_blind: params.random_scalar(),
        }
    }

    fn commitments(&self) -> Box<dyn darkwallet::ProofCommitments + 'a> {
        assert!(self.params.hs.len() > 0);
        let h1 = self.params.hs[0];

        Box::new(CommitProofCommitments {
            params: self.params,
            commit: self.params.g1 * self.witness_value + h1 * self.witness_blind,
        })
    }

    fn finish(&self, challenge: &bls::Scalar) -> CommitProof {
        CommitProof {
            response_value: self.witness_value - challenge * self.value,
            response_blind: self.witness_blind - challenge * self.blind,
        }
    }
}

impl<'a, R: darkwallet::RngInstance> darkwallet::ProofCommitments
    for CommitProofCommitments<'a, R>
{
    fn commit(&self, hasher: &mut darkwallet::ProofHasher) {
        hasher.add_g1_affine(&self.params.g1);
        assert!(self.params.hs.len() > 0);
        let h1 = self.params.hs[0];
        hasher.add_g1_affine(&h1);
        hasher.add_g1(&self.commit);
    }
}

impl CommitProof {
    fn commitments<'a, R: darkwallet::RngInstance>(
        &self,
        params: &'a darkwallet::Parameters<R>,
        challenge: &bls::Scalar,
        token_commit: &bls::G1Projective,
    ) -> Box<dyn darkwallet::ProofCommitments + 'a> {
        assert!(params.hs.len() > 0);
        let h1 = params.hs[0];

        Box::new(CommitProofCommitments {
            params,
            commit: token_commit * challenge
                + params.g1 * self.response_value
                + h1 * self.response_blind,
        })
    }
}

struct Bank<'a> {
    coconut: darkwallet::Coconut<darkwallet::OsRngInstance>,
    verify_key: &'a darkwallet::VerifyKey,
    spent_burns: Vec<bls::G1Projective>,
}

impl<'a> Bank<'a> {
    fn new(settings: &CoconutSettings, verify_key: &'a darkwallet::VerifyKey) -> Self {
        Self {
            coconut: darkwallet::Coconut::<darkwallet::OsRngInstance>::new(
                settings.attributes,
                settings.threshold,
                settings.total,
            ),
            verify_key,
            spent_burns: Vec::new(),
        }
    }

    fn process_withdraw(&mut self, withdraw: WithdrawRequest) -> bool {
        if self.spent_burns.contains(&withdraw.burn_value) {
            return false;
        }
        // To avoid double spends of the same coin
        self.spent_burns.push(withdraw.burn_value);

        /*
        let burn_commits = withdraw.burn_proof.commitments(
            &self.coconut.params,
            &withdraw.credential.challenge,
            &withdraw.burn_value,
        );
        */

        withdraw.credential.verify(
            &self.coconut.params,
            &self.verify_key,
            &Vec::new(),
            //vec![burn_commits],
        )
    }
}

trait BlsStringConversion {
    fn to_string(&self) -> String;
    fn from_string(object: &str) -> Self;
}

fn from_slice_32(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

impl BlsStringConversion for bls::Scalar {
    fn to_string(&self) -> String {
        hex::encode(self.to_bytes())
    }

    fn from_string(object: &str) -> Self {
        let bytes = from_slice_32(&hex::decode(object).unwrap());
        Self::from_bytes(&bytes).unwrap()
    }
}

fn from_slice_48(bytes: &[u8]) -> [u8; 48] {
    let mut array = [0; 48];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

impl BlsStringConversion for bls::G1Projective {
    fn to_string(&self) -> String {
        hex::encode(&bls::G1Affine::from(self).to_compressed().to_vec())
    }

    fn from_string(object: &str) -> Self {
        let bytes = from_slice_48(&hex::decode(object).unwrap());
        bls::G1Affine::from_compressed(&bytes).unwrap().into()
    }
}

fn from_slice_96(bytes: &[u8]) -> [u8; 96] {
    let mut array = [0; 96];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

impl BlsStringConversion for bls::G2Projective {
    fn to_string(&self) -> String {
        hex::encode(&bls::G2Affine::from(self).to_compressed().to_vec())
    }

    fn from_string(object: &str) -> Self {
        let bytes = from_slice_96(&hex::decode(object).unwrap());
        bls::G2Affine::from_compressed(&bytes).unwrap().into()
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct CoinSettings {
    attributes: u32,
    threshold: u32,
    total: u32,
    verify_key: (String, Vec<String>),
}

#[derive(Serialize, Deserialize, Debug)]
struct SecretKeyObject {
    x: String,
    y: Vec<String>,
}

fn initialize(config_dir: &Path, coin_name: &str, threshold: u32, total: u32) {
    let settings = CoconutSettings {
        attributes: 2,
        threshold,
        total,
    };
    let (secret_keys, verify_key) = generate_keys(&settings);

    let verify_key_data = (
        verify_key.alpha.to_string(),
        verify_key
            .beta
            .iter()
            .map(|beta_i| beta_i.to_string())
            .collect(),
    );

    // /coins/<name>
    //   attributes
    //   threshold
    //   total
    //   verify_key
    let coin_settings = CoinSettings {
        attributes: settings.attributes,
        threshold: settings.threshold,
        total: settings.total,
        verify_key: verify_key_data,
    };

    let coin_settings_data = serde_json::to_string(&coin_settings).unwrap();

    let coin_path = config_dir.join("coins").join(coin_name);
    std::fs::create_dir(&coin_path).unwrap();

    fs::write(coin_path.join("config"), coin_settings_data).unwrap();

    let authority_path = coin_path.join("authority");
    std::fs::create_dir(&authority_path).unwrap();

    let tokens_path = coin_path.join("tokens");
    std::fs::create_dir(&tokens_path).unwrap();

    // /coins/authority/n
    //   secret_key
    for (i, secret_key) in secret_keys.iter().enumerate() {
        let object = SecretKeyObject {
            x: secret_key.x.to_string(),
            y: secret_key.y.iter().map(|y_i| y_i.to_string()).collect(),
        };

        let secret_key_data = serde_json::to_string(&object).unwrap();
        fs::write(authority_path.join(i.to_string()), secret_key_data).unwrap();
    }

    println!("Created: {}", coin_name);
}

fn load_settings(config_dir: &Path, coin_name: &str) -> (CoconutSettings, darkwallet::VerifyKey) {
    let config_path = config_dir.join("coins").join(coin_name).join("config");

    let config_data = fs::read_to_string(config_path).unwrap();

    let object: CoinSettings = serde_json::from_str(&config_data).unwrap();

    let settings = CoconutSettings {
        attributes: object.attributes,
        threshold: object.threshold,
        total: object.total,
    };

    let verify_key = darkwallet::VerifyKey {
        alpha: bls::G2Projective::from_string(&object.verify_key.0),
        beta: object
            .verify_key
            .1
            .iter()
            .map(|beta_i| bls::G2Projective::from_string(beta_i))
            .collect(),
    };

    (settings, verify_key)
}

fn load_authority(
    config_dir: &Path,
    coin_name: &str,
    authority_index: u32,
    settings: &CoconutSettings,
) -> Authority {
    let authority_path = config_dir
        .join("coins")
        .join(coin_name)
        .join("authority")
        .join(authority_index.to_string());

    let authority_data = fs::read_to_string(authority_path).unwrap();

    let object: SecretKeyObject = serde_json::from_str(&authority_data).unwrap();

    let secret_key = darkwallet::SecretKey {
        x: bls::Scalar::from_string(&object.x),
        y: object
            .y
            .iter()
            .map(|y_i| bls::Scalar::from_string(y_i))
            .collect(),
    };

    Authority::new((authority_index + 1) as u64, secret_key, &settings)
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenObject {
    value: u64,
    serial: String,
    signature: (String, String),
    private_key: String,
}

fn save_token(config_dir: &Path, coin_name: &str, token: &Token) {
    let object = TokenObject {
        value: token.value,
        serial: token.serial.to_string(),
        signature: (
            token.signature.commit_hash.to_string(),
            token.signature.sigma.to_string(),
        ),
        private_key: token.private_key.private_key.to_string(),
    };

    let token_id = token.id_string();
    let token_path = config_dir
        .join("coins")
        .join(coin_name)
        .join("tokens")
        .join(&token_id);

    let token_data = serde_json::to_string(&object).unwrap();
    fs::write(token_path, token_data).unwrap();

    println!("Issued new token {}", token_id);
}

fn deposit(config_dir: &Path, coin_name: &str, value: u64) {
    let (settings, verify_key) = load_settings(config_dir, coin_name);
    let wallet = Wallet::new(&settings, &verify_key);
    println!("Deposit: {:?}", value);

    let authorities: Vec<_> = (0..settings.total)
        .map(|i| load_authority(config_dir, coin_name, i, &settings))
        .collect();

    let token = wallet.deposit(value, &authorities);

    save_token(config_dir, coin_name, &token);
}

fn load_token(token_path: &Path) -> Token {
    let token_data = fs::read_to_string(&token_path).unwrap();
    let object: TokenObject = serde_json::from_str(&token_data).unwrap();

    let signature = darkwallet::Signature {
        commit_hash: bls::G1Projective::from_string(&object.signature.0),
        sigma: bls::G1Projective::from_string(&object.signature.1),
    };

    let private_key = darkwallet::ElGamalPrivateKey {
        private_key: bls::Scalar::from_string(&object.private_key),
    };

    Token {
        value: object.value,
        serial: bls::Scalar::from_string(&object.serial),
        signature,
        private_key,
    }
}

fn withdraw(config_dir: &Path, coin_name: &str, token_id: &str) {
    let (settings, verify_key) = load_settings(config_dir, coin_name);
    let mut bank = Bank::new(&settings, &verify_key);
    let wallet = Wallet::new(&settings, &verify_key);

    let token_path = config_dir
        .join("coins")
        .join(coin_name)
        .join("tokens")
        .join(&token_id);
    let token = load_token(&token_path);

    let withdraw_request = wallet.withdraw(token);
    let withdraw_success = bank.process_withdraw(withdraw_request);
    let withdraw_status = if withdraw_success {
        "success"
    } else {
        "failed"
    };

    println!("Withdraw status: {}", withdraw_status);

    if withdraw_success {
        println!("Token burnt.");
        fs::remove_file(&token_path).unwrap();
    }
}

fn split(config_dir: &Path, coin_name: &str, token_id: &str, value1: u64, value2: u64) {
    let (settings, verify_key) = load_settings(config_dir, coin_name);
    let wallet = Wallet::new(&settings, &verify_key);

    let authorities: Vec<_> = (0..settings.total)
        .map(|i| load_authority(config_dir, coin_name, i, &settings))
        .collect();

    let token_path = config_dir
        .join("coins")
        .join(coin_name)
        .join("tokens")
        .join(&token_id);
    let token = load_token(&token_path);

    if token.value != value1 + value2 {
        eprintln!("error: split amounts do not equal token value.");
        return;
    }

    let token_id = token.id_string();
    match wallet.split(token, value1, value2, &authorities) {
        Err(err) => eprintln!("error: split failed: {}", err),
        Ok((token1, token2)) => {
            fs::remove_file(&token_path).unwrap();
            println!("Burnt token {}", token_id);
            save_token(config_dir, coin_name, &token1);
            save_token(config_dir, coin_name, &token2);
        }
    }
}

fn token_info(config_dir: &Path, coin_name: &str, token_id: &str) {
    let (settings, verify_key) = load_settings(config_dir, coin_name);
    let wallet = Wallet::new(&settings, &verify_key);

    let token_path = config_dir
        .join("coins")
        .join(coin_name)
        .join("tokens")
        .join(&token_id);
    let token = load_token(&token_path);

    println!("Token value: {}", token.value);
}

fn list_tokens(config_dir: &Path, coin_name: &str) {
    let (settings, verify_key) = load_settings(config_dir, coin_name);
    let wallet = Wallet::new(&settings, &verify_key);

    let tokens_path = config_dir.join("coins").join(coin_name).join("tokens");

    let paths = fs::read_dir(tokens_path).unwrap();
    for path in paths {
        let token_path = path.unwrap().path();
        println!("{}", token_path.file_name().unwrap().to_str().unwrap());
        let token = load_token(&token_path);
        println!("  Token value: {}", token.value);
    }

    //println!("Token value: {}", token.value);
}

fn main() {
    let matches = clap_app!(darkwallet =>
        (version: "0.1.0")
        (author: "Amir Taaki <amir@dyne.org>")
        (about: "Make anonymous payments with any cryptocurrency")
        (@arg CONFIG: -c --config +takes_value "Sets the config directory")
        (@subcommand init =>
            (about: "Initialize")
            (@arg NAME: +required "Name of the coin")
            (@arg THRESHOLD: +required "Threshold out of N")
            (@arg TOTAL: +required "N total authorities")
        )
        (@subcommand deposit =>
            (about: "Deposit money")
            (@arg NAME: +required "Name of the coin")
            (@arg VALUE: +required "Amount to deposit")
        )
        (@subcommand withdraw =>
            (about: "Withdraw token")
            (@arg NAME: +required "Name of the coin")
            (@arg TOKEN_ID: +required "Token ID")
        )
        (@subcommand split =>
            (about: "Split token")
            (@arg NAME: +required "Name of the coin")
            (@arg TOKEN_ID: +required "Token ID")
            (@arg VALUE1: +required "Amount 1")
            (@arg VALUE2: +required "Amount 2")
        )
        (@subcommand token_info =>
            (about: "Show info about a token")
            (@arg NAME: +required "Name of the coin")
            (@arg TOKEN_ID: +required "Token ID")
        )
        (@subcommand list_tokens =>
            (about: "Show list of issued tokens")
            (@arg NAME: +required "Name of the coin")
        )
    )
    .get_matches();

    let default_dir = dirs::home_dir().unwrap().as_path().join(".darkwallet/");

    let config_dir = match matches.value_of("CONFIG") {
        None => default_dir.as_path(),
        Some(path_str) => Path::new(path_str),
    };

    if !config_dir.exists() {
        let _ = std::fs::create_dir(config_dir).unwrap();
        let _ = std::fs::create_dir(config_dir.join("coins")).unwrap();
        println!("Initialized new config directory: {}", config_dir.display());
    }

    let log_path = config_dir.join("darkwallet.log");

    CombinedLogger::init(vec![
        TermLogger::new(LevelFilter::Debug, Config::default(), TerminalMode::Mixed).unwrap(),
        //WriteLogger::new(LevelFilter::Info, Config::default(), std::fs::File::create(log_path).unwrap()),
    ])
    .unwrap();

    match matches.subcommand() {
        ("init", Some(matches)) => {
            let coin_name = matches.value_of("NAME").unwrap();
            let threshold = matches
                .value_of("THRESHOLD")
                .unwrap()
                .parse::<u32>()
                .unwrap();
            let total = matches.value_of("TOTAL").unwrap().parse::<u32>().unwrap();
            initialize(&config_dir, &coin_name, threshold, total);
        }
        ("deposit", Some(matches)) => {
            //let matches = matches.
            let coin_name = matches.value_of("NAME").unwrap();
            let value = matches.value_of("VALUE").unwrap().parse::<u64>().unwrap();
            deposit(&config_dir, &coin_name, value);
        }
        ("withdraw", Some(matches)) => {
            let coin_name = matches.value_of("NAME").unwrap();
            let token_id = matches.value_of("TOKEN_ID").unwrap();
            withdraw(&config_dir, &coin_name, &token_id);
        }
        ("split", Some(matches)) => {
            let coin_name = matches.value_of("NAME").unwrap();
            let token_id = matches.value_of("TOKEN_ID").unwrap();
            let value1 = matches.value_of("VALUE1").unwrap().parse::<u64>().unwrap();
            let value2 = matches.value_of("VALUE2").unwrap().parse::<u64>().unwrap();
            split(&config_dir, &coin_name, &token_id, value1, value2);
        }
        ("token_info", Some(matches)) => {
            let coin_name = matches.value_of("NAME").unwrap();
            let token_id = matches.value_of("TOKEN_ID").unwrap();
            token_info(&config_dir, &coin_name, &token_id);
        }
        ("list_tokens", Some(matches)) => {
            let coin_name = matches.value_of("NAME").unwrap();
            list_tokens(&config_dir, &coin_name);
        }
        _ => {
            eprintln!("Invalid subcommand invoked");
            return;
        }
    }

    // /coins/token

    return;

    let settings = CoconutSettings {
        attributes: 2,

        threshold: 5,
        total: 7,
    };
    let (secret_keys, verify_key) = generate_keys(&settings);

    let authorities: Vec<_> = (0..settings.total)
        .zip(secret_keys.into_iter())
        .map(|(i, secret_key)| Authority::new((i + 1) as u64, secret_key, &settings))
        .collect();

    // Normally the authorities, bank and wallet have some form of network protocol
    // between themselves.
    let mut bank = Bank::new(&settings, &verify_key);

    let wallet = Wallet::new(&settings, &verify_key);
    let coin_value = 110;
    let token = wallet.deposit(coin_value, &authorities);

    let withdraw_request = wallet.withdraw(token);

    // Now we serialize withdraw_request ...
    // ... Send it to the guy holding the money
    // ... They validate the request. If it works, they process our payout.

    let withdraw_success = bank.process_withdraw(withdraw_request);
    assert_eq!(withdraw_success, true);
    info!("Successfully withdrew our token of {} $", coin_value);

    // Lets now make a new coin and split it
    let token = wallet.deposit(coin_value, &authorities);
    match wallet.split(token, 100, 10, &authorities) {
        Err(err) => eprintln!("error: split failed: {}", err),
        Ok((token1, token2)) => info!("split worked."),
    }
}
