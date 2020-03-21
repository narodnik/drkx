use crate::bls_extensions::*;
use crate::coconut::coconut::*;
use crate::elgamal::*;
use crate::error;
use bls12_381 as bls;

struct Schema<'a, R: RngInstance> {
    coconut: &'a Coconut<R>,
    verify_key: VerifyKey,
}

impl<'a, R: RngInstance> Schema<'a, R> {
    fn start_deposit(&self, partial_token: &Token) -> DepositRequest {
        let private_attributes = vec![partial_token.serial.clone()];
        let public_attributes = vec![bls::Scalar::from(partial_token.value)];

        let public_key = partial_token.private_key.to_public(&self.coconut.params);

        let (sign_request, sign_proof_values) = self.coconut.make_blind_sign_request(
            &public_key,
            &private_attributes,
            &public_attributes,
        );

        DepositRequest {
            sign_request,
            public_key,
            public_attributes,
        }
    }

    fn end_deposit(
        &self,
        partial_token: &mut Token,
        responses: Vec<DepositResponse>,
        commit_hash: CommitHash,
    ) {
        let shares: Vec<_> = responses
            .iter()
            .map(|response| {
                (
                    response.index,
                    response.signature_share.unblind(&partial_token.private_key),
                )
            })
            .collect();

        let (indexes, shares): (Vec<_>, Vec<_>) = shares.into_iter().unzip();

        let signature = Signature {
            commit_hash,
            sigma: self.coconut.aggregate(&shares, indexes),
        };

        partial_token.signature = Some(signature);
    }

    fn start_split(&self, token: &Token, token1: &Token, token2: &Token) -> SplitRequest {
        assert_eq!(token.value, token1.value + token2.value);

        let blind1 = self.coconut.params.random_scalar();
        let blind2 = self.coconut.params.random_scalar();
        let blind = blind1 + blind2;

        let commit = self.token_commit(token.value, &blind);
        let commit1 = self.token_commit(token1.value, &blind1);
        let commit2 = self.token_commit(token2.value, &blind2);

        assert_eq!(commit, commit1 + commit2);

        SplitRequest {
            commit,
            commit1,
            commit2,

            burn_request: self.withdraw(&token),

            deposit_request1: self.start_deposit(&token1),
            deposit_request2: self.start_deposit(&token2),
        }
    }

    fn token_commit(&self, value: u64, blind: &bls::Scalar) -> bls::G1Projective {
        assert!(self.coconut.params.hs.len() >= 1);

        self.coconut.params.g1 * bls::Scalar::from(value) + self.coconut.params.hs[0] * blind
    }

    fn end_split(
        &self,
        token: &mut Token,
        token1: &mut Token,
        token2: &mut Token,
        responses: Vec<SplitResponse>,
        commit_hashes: (CommitHash, CommitHash),
    ) {
        let (deposit_responses1, deposit_responses2): (Vec<_>, Vec<_>) = responses
            .into_iter()
            .map(|response| (response.deposit_response1, response.deposit_response2))
            .unzip();

        let (commit_hash1, commit_hash2) = commit_hashes;

        self.end_deposit(token1, deposit_responses1, commit_hash1);
        self.end_deposit(token2, deposit_responses2, commit_hash2);
    }

    fn start_merge(&self, token1: &Token, token2: &Token, token: &Token) -> MergeRequest {
        assert_eq!(token1.value + token2.value, token.value);

        let blind1 = self.coconut.params.random_scalar();
        let blind2 = self.coconut.params.random_scalar();
        let blind = blind1 + blind2;

        let commit1 = self.token_commit(token1.value, &blind1);
        let commit2 = self.token_commit(token2.value, &blind2);
        let commit = self.token_commit(token.value, &blind);

        assert_eq!(commit, commit1 + commit2);

        MergeRequest {
            commit1,
            commit2,
            commit,

            burn_request1: self.withdraw(&token1),
            burn_request2: self.withdraw(&token2),

            deposit_request: self.start_deposit(&token),
        }
    }

    fn end_merge(
        &self,
        token1: &mut Token,
        token2: &mut Token,
        token: &mut Token,
        responses: Vec<MergeResponse>,
        commit_hash: CommitHash,
    ) {
        let deposit_responses: Vec<_> = responses
            .into_iter()
            .map(|response| response.deposit_response)
            .collect();

        self.end_deposit(token, deposit_responses, commit_hash);
    }

    fn withdraw(&self, token: &Token) -> WithdrawRequest {
        let burn_value = self.coconut.params.g1 * token.serial;

        let private_attributes = vec![token.serial, bls::Scalar::from(token.value)];

        let token_signature = &token.signature.as_ref().unwrap();
        let (credential, credential_proof_values) =
            self.coconut
                .make_credential(&self.verify_key, token_signature, &private_attributes);

        assert!(credential.verify(&self.coconut.params, &self.verify_key, &Vec::new(),));

        WithdrawRequest {
            burn_value,
            credential,
        }
    }
}

type SpentBurns = Vec<bls::G1Projective>;

struct Service<'a, R: RngInstance> {
    coconut: &'a Coconut<R>,
    secret: SecretKey,
    verify_key: VerifyKey,
    index: u64,
    spent: SpentBurns,
}

impl<'a, R: RngInstance> Service<'a, R> {
    fn from_secret(
        coconut: &'a Coconut<R>,
        secret: SecretKey,
        verify_key: VerifyKey,
        index: u64,
    ) -> Self {
        Self {
            coconut,
            secret,
            verify_key,
            index,
            spent: SpentBurns::new(),
        }
    }

    fn process_deposit(&self, request: &DepositRequest) -> DepositResponse {
        let signature_share = request.sign_request.blind_sign(
            &self.coconut.params,
            &self.secret,
            &request.public_key,
            &request.public_attributes,
        );
        DepositResponse {
            index: self.index,
            signature_share,
        }
    }

    fn process_split(&mut self, request: &SplitRequest) -> error::Result<SplitResponse> {
        if request.commit != request.commit1 + request.commit2 {
            return Err(error::Error::CommitsDontAdd);
        }

        if !self.execute_withdraw(&request.burn_request) {
            return Err(error::Error::InvalidCredential);
        }

        Ok(SplitResponse {
            deposit_response1: self.process_deposit(&request.deposit_request1),
            deposit_response2: self.process_deposit(&request.deposit_request2),
        })
    }

    fn process_merge(&mut self, request: &MergeRequest) -> error::Result<MergeResponse> {
        if request.commit1 + request.commit2 != request.commit {
            return Err(error::Error::CommitsDontAdd);
        }

        if !self.execute_withdraw(&request.burn_request1)
            || !self.execute_withdraw(&request.burn_request2)
        {
            return Err(error::Error::InvalidCredential);
        }

        Ok(MergeResponse {
            deposit_response: self.process_deposit(&request.deposit_request),
        })
    }

    // Maybe should be called burn
    fn execute_withdraw(&mut self, request: &WithdrawRequest) -> bool {
        if self.spent.contains(&request.burn_value) {
            return false;
        }

        if !request.credential.verify(
            &self.coconut.params,
            &self.verify_key,
            &Vec::new(),
            //vec![burn_commits],
        ) {
            return false;
        }

        // To avoid double spends of the same coin
        self.spent.push(request.burn_value);

        true
    }
}

struct DepositRequest {
    sign_request: BlindSignatureRequest,
    public_key: ElGamalPublicKey,
    public_attributes: Vec<bls::Scalar>,
}
struct DepositResponse {
    index: u64,
    signature_share: PartialSignature,
}

impl DepositRequest {
    fn get_hash(&self) -> CommitHash {
        self.sign_request.compute_commit_hash()
    }
}

type PedersenCommit = bls::G1Projective;

struct SplitRequest {
    commit: PedersenCommit,
    commit1: PedersenCommit,
    commit2: PedersenCommit,

    burn_request: WithdrawRequest,

    deposit_request1: DepositRequest,
    deposit_request2: DepositRequest,
}
struct SplitResponse {
    deposit_response1: DepositResponse,
    deposit_response2: DepositResponse,
}

impl SplitRequest {
    fn get_hashes(&self) -> (CommitHash, CommitHash) {
        (
            self.deposit_request1.get_hash(),
            self.deposit_request2.get_hash(),
        )
    }
}

struct MergeRequest {
    commit1: PedersenCommit,
    commit2: PedersenCommit,
    commit: PedersenCommit,

    burn_request1: WithdrawRequest,
    burn_request2: WithdrawRequest,

    deposit_request: DepositRequest,
}
struct MergeResponse {
    deposit_response: DepositResponse,
}

impl MergeRequest {
    fn get_hash(&self) -> CommitHash {
        self.deposit_request.get_hash()
    }
}

struct WithdrawRequest {
    burn_value: bls::G1Projective,
    credential: Credential,
}

struct Token {
    value: u64,
    serial: bls::Scalar,
    private_key: ElGamalPrivateKey,
    signature: Option<Signature>,
}

impl Token {
    fn mint<R: RngInstance>(value: u64, coconut: &Coconut<R>) -> Self {
        Self {
            value,
            serial: coconut.params.random_scalar(),
            private_key: ElGamalPrivateKey::new(&coconut.params),
            signature: None,
        }
    }
}

// Temporary function
fn generate_keys(attributes: u32, threshold: u32, total: u32) -> (Vec<SecretKey>, VerifyKey) {
    let coconut = Coconut::<OsRngInstance>::new(attributes, threshold, total);

    let (secret_keys, verify_keys) = coconut.multiparty_keygen();
    let verify_key = coconut.aggregate_keys(&verify_keys);

    (secret_keys, verify_key)
}

#[test]
fn test_perpetual_contract() {
    //
    // Initialization
    //

    let (mut secret_keys, verify_key) = generate_keys(2, 5, 7);
    let coconut = Coconut::<OsRngInstance>::new(2, 5, 7);

    let mut services: Vec<_> = secret_keys
        .into_iter()
        .enumerate()
        .map(|(index, secret)| {
            Service::from_secret(&coconut, secret, verify_key.clone(), (index + 1) as u64)
        })
        .collect();

    let schema = Schema {
        coconut: &coconut,
        verify_key: verify_key,
    };

    //
    // Deposit
    //

    // Wallet
    let mut token = Token::mint(110, &coconut);
    {
        let deposit_request = schema.start_deposit(&token);
        let commit_hash = deposit_request.get_hash();

        // Service
        let deposit_responses: Vec<_> = services
            .iter()
            .map(|service| service.process_deposit(&deposit_request))
            .collect();

        // Wallet
        schema.end_deposit(&mut token, deposit_responses, commit_hash);
    }

    //
    // Split
    //

    // Wallet
    let mut token1 = Token::mint(10, &coconut);
    let mut token2 = Token::mint(100, &coconut);
    {
        let split_request = schema.start_split(&token, &token1, &token2);
        let commit_hashes = split_request.get_hashes();

        // Service
        let split_responses: Vec<_> = services
            .iter_mut()
            .map(|service| {
                let response = service.process_split(&split_request);
                assert!(response.is_ok());
                response.ok().unwrap()
            })
            .collect();

        // Wallet
        schema.end_split(
            &mut token,
            &mut token1,
            &mut token2,
            split_responses,
            commit_hashes,
        );
    }

    //
    // Merge
    //

    // Wallet
    let mut token_x = Token::mint(110, &coconut);
    {
        let merge_request = schema.start_merge(&token1, &token2, &token_x);
        let commit_hash = merge_request.get_hash();

        // Service
        let merge_responses: Vec<_> = services
            .iter_mut()
            .map(|service| {
                let response = service.process_merge(&merge_request);
                assert!(response.is_ok());
                response.ok().unwrap()
            })
            .collect();

        // Wallet
        schema.end_merge(
            &mut token1,
            &mut token2,
            &mut token_x,
            merge_responses,
            commit_hash,
        );
    }

    //
    // Withdraw
    //

    {
        // Wallet
        let withdraw_request = schema.withdraw(&token_x);
        let withdraw_success = services[0].execute_withdraw(&withdraw_request);
        assert!(withdraw_success);
        token.signature = None;
    }
}
