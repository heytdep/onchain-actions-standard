#![no_std]

use extension_macro::StandardActions;
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    symbol_short, vec, Address, BytesN, Env, Map, Symbol, Val, Vec,
};

#[contract]
#[derive(StandardActions)]
struct AccountContract;

#[contracttype]
#[derive(Clone)]
pub struct Signature {
    pub public_key: BytesN<32>,
    pub signature: BytesN<64>,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Signer(BytesN<32>),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AccError {
    UnknownSigner = 1,
    InvalidContext = 2,
}

#[contractimpl]
impl AccountContract {
    // Add other init params here.
    pub fn init(env: Env, master_signer: BytesN<32>, standard_signer: BytesN<32>) {
        env.storage()
            .instance()
            .set(&DataKey::Signer(master_signer), &true);
        env.storage()
            .instance()
            .set(&DataKey::Signer(standard_signer), &false);
    }
}

#[contractimpl]
impl CustomAccountInterface for AccountContract {
    type Signature = Signature;
    type Error = AccError;

    #[allow(non_snake_case)]
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature: Signature,
        auth_contexts: Vec<Context>,
    ) -> Result<(), AccError> {
        let is_master = authenticate(&env, &signature_payload, &signature)?;
        let mut result = Err(AccError::InvalidContext);

        if is_master {
            result = Ok(())
        } else {
            if is_standard_allowed_action(&env, auth_contexts) {
                result = Ok(())
            };
        }

        result
    }
}

fn authenticate(
    env: &Env,
    signature_payload: &Hash<32>,
    signature: &Signature,
) -> Result<bool, AccError> {
    let is_master = if let Some(is_master) = env
        .storage()
        .instance()
        .get(&DataKey::Signer(signature.public_key.clone()))
    {
        is_master
    } else {
        return Err(AccError::UnknownSigner);
    };

    env.crypto().ed25519_verify(
        &signature.public_key,
        &signature_payload.clone().into(),
        &signature.signature,
    );

    Ok(is_master)
}

mod test;
