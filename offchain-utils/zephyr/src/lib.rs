//use stellar_xdr::next::{Limits as NLimits, ScVal};
use urlencoding::encode;
use zephyr_sdk::{
    prelude::*,
    soroban_sdk::{
        self, map, vec,
        xdr::{
            self, Limits, ToXdr, Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, WriteXdr, ScVal
        },
        Address, BytesN, IntoVal, Map, String as SorobanString, Symbol, Val,
    },
    utils::{
        add_contract_to_footprint, address_from_str, build_authorization_preimage, ed25519_sign, sha256, sign_transaction
    },
    AgnosticRequest, EnvClient,
};

// Note: these small fee adjustements are needed because:
// 1. The ZVM is using a newer version of the RPC.
// 2. We are only simulating once, thus need to account for
// signature verification too.
const INSTRUCTIONS_FIX: u32 = 4000292;
const WRITE_BYTES_FIX: u32 = 200;
const READ_BYTES_FIX: u32 = 100000;
const RESOURCE_FEE_FIX: i64 = 9000965;
const FEE_FIX: u32 = 9950000;

// Signature's ledgers to live.
const SIGNATURE_DURATION: u32 = 100;
const NETWORK: &'static str = "Test SDF Network ; September 2015";

const YBX_CONTRACT: &'static str = "CDWCIQMI3EHKGK32SVICLUBFVBT5VKNG72O3G7KNJOLSIVA4WDVQ2IYX";

const MERCURY_SECRET: &'static str = "SADOELF6HB54HS2LJ5VWBDYMB72XIHD53SFQ2KXAVS5SXEUB7FUFAXSH";

const SOURCE_ACCOUNT: &'static str = "GDQ47JRRX2SQ7YHM6FAMMDC4K5EXFZOYPWZCFAILKEE3IYTZAQEFGR3M";
const SOUCRE_SECRET: &'static str = "SDD7ZVTGRP2A5PX3G6FZ56HVCFPBWPGM3XMYYE5EEOEV5FM5KIJGGWOS";

const SMART_ACCOUNT: &'static str = "CCMJ32EN7E4AKK6K6MGKSVRZPER6RWU3RKDM4VS43T2KC365AMLW3MI2";
const SMART_ACCOUNT_HASH: &'static str =
    "5ff7fff8a3abadcc1630c92c7df556e0cf9614f278e28096ca85bbf6d996ca28";


fn build_sig(env: &EnvClient, public: [u8; 32], signature: [u8; 64]) -> ScVal {
    let signature: Map<Val, Val> = map![
        &env.soroban(),
        (
            Symbol::new(&env.soroban(), "signature").into_val(env.soroban()),
            BytesN::from_array(&env.soroban(), &signature).into_val(env.soroban())
        ),
        (
            Symbol::new(&env.soroban(), "public_key").into_val(env.soroban()),
            BytesN::from_array(&env.soroban(), &public).into_val(env.soroban())
        ),
    ];

    env.to_scval(signature)
}

#[no_mangle]
pub extern "C" fn do_action() {
    let env = EnvClient::empty();
    let wallet_address = address_from_str(&env, SMART_ACCOUNT);
    let ybx_address = address_from_str(&env, &YBX_CONTRACT);
    
    let action: (Address, Symbol, soroban_sdk::Vec<Val>) = {
        let fname = "submit";
        let map: Map<Symbol, Val> = map![
            &env.soroban(),
            (
                Symbol::new(&env.soroban(), "request_type"),
                2_u32.into_val(env.soroban()),
            ),
            (
                Symbol::new(&env.soroban(), "address"),
                Address::from_string(&zephyr_sdk::soroban_sdk::String::from_str(
                    &env.soroban(),
                    "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
                ))
                .into_val(env.soroban()),
            ),
            (
                Symbol::new(&env.soroban(), "amount"),
                100_000_000_i128.into_val(env.soroban()),
            )
        ];
        
        let args: soroban_sdk::Vec<Val> = vec![
            &env.soroban(),
            wallet_address.into_val(env.soroban()),
            wallet_address.into_val(env.soroban()),
            wallet_address.into_val(env.soroban()),
            vec![&env.soroban(), map].into_val(env.soroban()),
        ];
        
        (ybx_address, Symbol::new(&env.soroban(), fname), args)
    };

    let saa_actions: soroban_sdk::Vec<(Address, Symbol, soroban_sdk::Vec<Val>)> = vec![&env.soroban(), action];
    //let bytes = env.to_scval(saa_actions.clone()).to_xdr_base64(Limits::none()).unwrap();
    //env.log().debug(format!("{:?}", bytes), None);

    env.log().debug("Executing smart account transaction", None);
    execute_smart_account_transaction(
        &env,
        &NETWORK,
        "https://horizon-testnet.stellar.org/transactions",
        &SOURCE_ACCOUNT,
        &SOUCRE_SECRET,
        &SMART_ACCOUNT,
        "saa_invoke",
        vec![&env.soroban(), saa_actions.into_val(env.soroban())],
        SIGNATURE_DURATION,
        &MERCURY_SECRET,
        &SMART_ACCOUNT,
        &SMART_ACCOUNT_HASH,
        false,
        INSTRUCTIONS_FIX,
        WRITE_BYTES_FIX,
        READ_BYTES_FIX,
        RESOURCE_FEE_FIX,
        FEE_FIX,
        build_sig
    );

    env.conclude("Successfully sent transaction")
}

fn add_allowed_action(
    env: &EnvClient,
    actions: &mut Map<Symbol, Map<Symbol, Val>>,
    fname: &str,
    contracts: soroban_sdk::Vec<u32>,
    args: Map<u32, soroban_sdk::Vec<Val>>,
) {
    let mut action: Map<Symbol, Val> = Map::new(&env.soroban());
    action.set(
        Symbol::new(&env.soroban(), "allowed_contracts"),
        contracts.into_val(env.soroban()),
    );
    action.set(
        Symbol::new(&env.soroban(), "allowed_args"),
        args.into_val(env.soroban()),
    );

    actions.set(Symbol::new(&env.soroban(), fname), action)
}

fn build_standard_actions(env: &EnvClient, contracts: Map<u32, Address>, actions: Map<Symbol, Map<Symbol, Val>>, deploy: bool) -> Map<Symbol, Val> {
    let mut standard_allowed_actions: Map<Symbol, Val> = Map::new(&env.soroban());
    standard_allowed_actions.set(
        Symbol::new(&env.soroban(), "contracts"),
        contracts.into_val(env.soroban()),
    );
    standard_allowed_actions.set(
        Symbol::new(&env.soroban(), "actions"),
        actions.into_val(env.soroban()),
    );
    standard_allowed_actions.set(
        Symbol::new(&env.soroban(), "deploy"),
        deploy.into_val(env.soroban()),
    );

    standard_allowed_actions
}

#[no_mangle]
pub extern "C" fn add_signer() {
    let env = EnvClient::empty();
    env.log().debug("Function invoked", None);

    let fname = "set_standard_allowed_actions";
    let wallet_address =
        Address::from_string(&SorobanString::from_str(&env.soroban(), &SMART_ACCOUNT));

    let mut allowed_contracts = Map::new(&env.soroban());
    allowed_contracts.set(
        1_u32,
        Address::from_string(&SorobanString::from_str(&env.soroban(), &YBX_CONTRACT)),
    );
    allowed_contracts.set(2_u32, wallet_address.clone());
    allowed_contracts.set(3_u32, address_from_str(&env, "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC"));

    let mut allowed_actions = Map::new(env.soroban());
    add_allowed_action(
        &env,
        &mut allowed_actions,
        "submit",
        vec![&env.soroban(), 1_u32],
        Map::<u32, soroban_sdk::Vec<Val>>::from_array(
            &env.soroban(),
            [
                (
                    0_u32,
                    vec![
                        &env.soroban(),
                        wallet_address.clone().into_val(env.soroban()),
                    ],
                ),
                (
                    1_u32,
                    vec![
                        &env.soroban(),
                        wallet_address.clone().into_val(env.soroban()),
                    ],
                ),
                (
                    2_u32,
                    vec![
                        &env.soroban(),
                        wallet_address.clone().into_val(env.soroban()),
                    ],
                ),
            ],
        ),
    );

    add_allowed_action(
        &env,
        &mut allowed_actions,
        "saa_invoke",
        vec![&env.soroban(), 2_u32],
        Map::new(&env.soroban())
    );

    add_allowed_action(
        &env,
        &mut allowed_actions,
        "transfer",
        vec![&env.soroban(), 3_u32],
        Map::new(&env.soroban())
    );

    let standard_allowed_actions = build_standard_actions(&env, allowed_contracts, allowed_actions, false);
    
    let arguments = vec![
        &env.soroban(),
        standard_allowed_actions.into_val(env.soroban()),
    ];

    env.log().debug("Executing smart account transaction", None);
    execute_smart_account_transaction(
        &env,
        &NETWORK,
        "https://horizon-testnet.stellar.org/transactions",
        &SOURCE_ACCOUNT,
        &SOUCRE_SECRET,
        &SMART_ACCOUNT,
        &fname,
        arguments,
        SIGNATURE_DURATION,
        &SOUCRE_SECRET,
        &SMART_ACCOUNT,
        &SMART_ACCOUNT_HASH,
        false,
        INSTRUCTIONS_FIX,
        WRITE_BYTES_FIX,
        READ_BYTES_FIX,
        RESOURCE_FEE_FIX,
        FEE_FIX,
        build_sig
    );

    env.conclude("Successfully sent transaction")
}

fn execute_smart_account_transaction<F>(
    env: &EnvClient,
    network: &str,
    horizon: &str,
    source: &str,
    source_secret: &str,
    invoked_contract: &str,
    fname: &str,
    args: soroban_sdk::Vec<Val>,
    signature_duration: u32,
    signer_secret: &str,
    smart_account_id: &str,
    smart_account_hash: &str,
    add_to_footprint: bool,
    instrs_fix: u32,
    write_bytes_fix: u32,
    read_bytes_fix: u32,
    resource_fee_fix: i64,
    fee_fix: u32,
    build_signature: F
) where 
F: Fn(&EnvClient, [u8;32], [u8;64]) -> ScVal
{
    let account = stellar_strkey::ed25519::PublicKey::from_string(&source)
        .unwrap()
        .0;
    let sequence = env
        .read_account_from_ledger(account)
        .unwrap()
        .unwrap()
        .seq_num;

    let contract = stellar_strkey::Contract::from_string(&invoked_contract)
        .unwrap()
        .0;
    let tx = env.simulate_contract_call_to_tx(
        source.into(),
        sequence as i64 + 1,
        contract,
        Symbol::new(&env.soroban(), fname),
        args,
    );

    if tx.clone().unwrap().error.is_some() {
        env.log().debug(
            format!("Failed on simulation: {:?}", tx.clone().unwrap().error),
            None,
        );
    } else {
        let b64tx = tx.unwrap().tx.unwrap();
        let mut tx_with_signed_auth = smart_account_sign_auth_entries(
            env,
            TransactionEnvelope::from_xdr_base64(b64tx, Limits::none()).unwrap(),
            signature_duration,
            signer_secret,
            build_signature
        );

        let TransactionExt::V1(mut v1ext) = tx_with_signed_auth.ext else {
            panic!()
        };
        let mut r = v1ext.resources;

        // Adding the contract code and instance to the footprint.
        // NB: this is needed since simulation doesn't currently account for the
        // contracts in the auth stack that aren't directly invoked (such as our custom account).
        if add_to_footprint {
            let mut footprint = r.footprint;
            add_contract_to_footprint(
                &mut footprint,
                &smart_account_id,
                &hex::decode(smart_account_hash).unwrap(),
            );
            r.footprint = footprint;
        }

        // Note that currently zephyr is operating on a newer simulation branch, so we need to slightly adjust
        // simulation resource parameters.
        r.instructions += instrs_fix;
        r.write_bytes += write_bytes_fix;
        r.read_bytes += read_bytes_fix;
        v1ext.resource_fee += resource_fee_fix;
        v1ext.resources = r;
        tx_with_signed_auth.ext = TransactionExt::V1(v1ext);
        tx_with_signed_auth.fee += fee_fix;

        let signed = sign_transaction(tx_with_signed_auth, &network, &source_secret);
        env.send_web_request(AgnosticRequest {
            body: Some(format!("tx={}", encode(&signed))),
            url: horizon.to_string(),
            method: zephyr_sdk::Method::Post,
            headers: std::vec![(
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string()
            )],
        });
    }
}

fn smart_account_sign_auth_entries<F>(
    env: &EnvClient,
    tx: TransactionEnvelope,
    signature_duration: u32,
    signer_secret: &str,
    build_signature: F
) -> Transaction where 
F: Fn(&EnvClient, [u8;32], [u8;64]) -> ScVal
{
    let new_sequence = env.soroban().ledger().sequence() + signature_duration;
    let TransactionEnvelope::Tx(TransactionV1Envelope { mut tx, .. }) = tx else {
        panic!()
    };
    let source = tx.operations.to_vec()[0].source_account.clone();
    let xdr::OperationBody::InvokeHostFunction(mut host_function) =
        tx.operations.to_vec()[0].body.clone()
    else {
        panic!()
    };
    let mut auth = host_function.auth.to_vec()[0].clone();
    let xdr::SorobanCredentials::Address(mut credentials) = auth.clone().credentials else {
        panic!()
    };

    let preimage = build_authorization_preimage(
        credentials.nonce,
        new_sequence,
        auth.clone().root_invocation,
    );
    let payload = sha256(&preimage.to_xdr(Limits::none()).unwrap());
    let (public, signature) = ed25519_sign(signer_secret, &payload);
    let public = public.to_bytes();

    let signature = build_signature(env, public, signature);

    credentials.signature_expiration_ledger = new_sequence;
    credentials.signature = signature;
    auth.credentials = xdr::SorobanCredentials::Address(credentials);
    host_function.auth = std::vec![auth].try_into().unwrap();

    tx.operations = std::vec![xdr::Operation {
        source_account: source,
        body: xdr::OperationBody::InvokeHostFunction(host_function)
    }]
    .try_into()
    .unwrap();

    tx
}
