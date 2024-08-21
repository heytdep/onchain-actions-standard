#![cfg(test)]
extern crate std;

use ed25519_dalek::Keypair;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use ed25519_dalek::Signer;
use rand::thread_rng;
use soroban_sdk::auth::ContractContext;
use soroban_sdk::contract;
use soroban_sdk::contractimpl;
use soroban_sdk::contracttype;
use soroban_sdk::map;
use soroban_sdk::symbol_short;
use soroban_sdk::Map;
use soroban_sdk::Val;
use soroban_sdk::{
    auth::Context, testutils::BytesN as _, vec, Address, BytesN, Env, IntoVal, Vec, Symbol,
};

use crate::AccError;
use crate::StandardAction;
use crate::{AccountContract, AccountContractClient, Signature};

fn generate_keypair() -> Keypair {
    Keypair::generate(&mut thread_rng())
}

fn signer_public_key(e: &Env, signer: &Keypair) -> BytesN<32> {
    signer.public.to_bytes().into_val(e)
}

fn create_account_contract(e: &Env) -> (Address, AccountContractClient) {
    let address = e.register_contract(None, AccountContract {});
    (address.clone(), AccountContractClient::new(e, &address))
}

fn sign(e: &Env, signer: &Keypair, payload: &BytesN<32>) -> Val {
    Signature {
        public_key: signer_public_key(e, signer),
        signature: signer
            .sign(payload.to_array().as_slice())
            .to_bytes()
            .into_val(e),
    }
    .into_val(e)
}

fn blend_valid_auth_context(e: &Env, blend_id: &Address, fn_name: Symbol, source: Address) -> Context {
    Context::Contract(ContractContext {
        contract: blend_id.clone(),
        fn_name,
        args: (source.clone(), source.clone(), source).into_val(e),
    })
}

fn blend_invalid_auth_context(e: &Env, blend_id: &Address, fn_name: Symbol, source: Address) -> Context {
    Context::Contract(ContractContext {
        contract: blend_id.clone(),
        fn_name,
        args: (source.clone(), source.clone(), blend_id).into_val(e),
    })
}

#[contract]
pub struct BlendMock;

#[contractimpl]
impl BlendMock {
    pub fn submit(env: Env, from: Address,
        spender: Address,
        to: Address,
        requests: Vec<Request>,) {
        std::println!("Submit called")
    }
}

#[derive(Clone)]
#[contracttype]
pub struct Request {
    pub request_type: u32,
    pub address: Address, // asset address or liquidatee
    pub amount: i128,
}

#[test]
fn test_valid_blend_auth() {
    let env = Env::default();
    env.mock_all_auths();

    let blend = env.register_contract(None, BlendMock);

    let (smart_account_id, account_contract) = create_account_contract(&env);

    let signer = generate_keypair();
    let standard_signer = generate_keypair();
    let smart_account_val: Val = smart_account_id.into_val(&env);
    
    account_contract.init(
        &signer_public_key(&env, &signer),
        &signer_public_key(&env, &standard_signer),
    );

    account_contract.set_standard_allowed_actions(&crate::StandardAllowedActions {
        contracts: map![&env, (1, blend.clone()), (2, smart_account_id.clone())],
        actions: map![
            &env,
            (
                symbol_short!("submit"),
                StandardAction {
                    allowed_contracts: vec![&env, 1],
                    allowed_args: map![
                        &env,
                        (0_u32, vec![&env, smart_account_val]),
                        (1_u32, vec![&env, smart_account_val]),
                        (2_u32, vec![&env, smart_account_val])
                    ]
                }
            ),
            (
                symbol_short!("saa"),
                StandardAction {
                    allowed_contracts: vec![&env, 2],
                    allowed_args: map![&env]
                }
            )
        ],
        deploy: false,
    });

    let payload = BytesN::random(&env);

    env.try_invoke_contract_check_auth::<AccError>(
        &account_contract.address,
        &payload,
        sign(&env, &standard_signer, &payload),
        &vec![
            &env,
            blend_valid_auth_context(&env, &blend, Symbol::new(&env, "submit"), smart_account_id.clone()),
        ],
    ).unwrap();

    let args = {
        let map: Map<Symbol, Val> = map![
            &env,
            (
                Symbol::new(&env, "request_type"),
                2_u32.into_val(&env),
            ),
            (
                Symbol::new(&env, "address"),
                Address::from_string(&soroban_sdk::String::from_str(
                    &env,
                    "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
                ))
                .into_val(&env),
            ),
            (
                Symbol::new(&env, "amount"),
                100_000_000_i128.into_val(&env),
            )
        ];
        
        let args: soroban_sdk::Vec<Val> = vec![
            &env,
            smart_account_id.clone().into_val(&env),
            smart_account_id.clone().into_val(&env),
            smart_account_id.into_val(&env),
            vec![&env, map].into_val(&env),
        ];

        args
    };

    let args = vec![&env, (blend, Symbol::new(&env, "submit"), args)];
    env.invoke_contract(&smart_account_id, &Symbol::new(&env, "saa_invoke"), vec![&env, args.into_val(&env)])

    //account_contract.saa_invoke(&args)
}

#[test]
#[should_panic(expected="Ok(InvalidContext)")]
fn test_invalid_blend_auth() {
    let env = Env::default();
    env.mock_all_auths();

    let blend = env.register_contract(None, BlendMock);

    let (smart_account_id, account_contract) = create_account_contract(&env);

    let signer = generate_keypair();
    let standard_signer = generate_keypair();
    let smart_account_val: Val = smart_account_id.into_val(&env);
    
    account_contract.init(
        &signer_public_key(&env, &signer),
        &signer_public_key(&env, &standard_signer),
    );

    account_contract.set_standard_allowed_actions(&crate::StandardAllowedActions {
        contracts: map![&env, (1, blend.clone())],
        actions: map![
            &env,
            (
                symbol_short!("submit"),
                StandardAction {
                    allowed_contracts: vec![&env, 1],
                    allowed_args: map![
                        &env,
                        (0_u32, vec![&env, smart_account_val]),
                        (1_u32, vec![&env, smart_account_val]),
                        (2_u32, vec![&env, smart_account_val])
                    ]
                }
            )
        ],
        deploy: false,
    });

    let payload = BytesN::random(&env);

    env.try_invoke_contract_check_auth::<AccError>(
        &account_contract.address,
        &payload,
        sign(&env, &standard_signer, &payload),
        &vec![
            &env,
            blend_invalid_auth_context(&env, &blend, Symbol::new(&env, "submit"), smart_account_id),
        ],
    ).unwrap();
}

#[test]
fn get_signer() {
    let secret = SecretKey::from_bytes(
        &stellar_strkey::ed25519::PrivateKey::from_string(
            "SDD7ZVTGRP2A5PX3G6FZ56HVCFPBWPGM3XMYYE5EEOEV5FM5KIJGGWOS",
        )
        .unwrap()
        .0,
    )
    .unwrap();
    let public: PublicKey = (&secret).into();
    std::println!("{:?}", public.as_bytes());
}
