use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    self, parse_macro_input, Attribute, DeriveInput, Expr, ExprLit, Ident, Lit
};

fn get_attribute(attrs: Vec<Attribute>, attr_name: &str, default_to: &str) -> Ident {
    let ident_source = get_attribute_string(attrs, attr_name, default_to);
    Ident::new(&ident_source, Span::call_site())
}

fn get_attribute_string(attrs: Vec<Attribute>, attr_name: &str, default_to: &str) -> String {
    attrs
        .iter()
        .find_map(|attr| {
            if attr.path().is_ident(attr_name) {
                let value: Expr = attr.parse_args().unwrap();
                if let Expr::Lit(ExprLit { lit, .. }) = value {
                    if let Lit::Str(value) = lit {
                        return Some(value.value());
                    } else {
                        panic!("Invalid lit type")
                    }
                } else {
                    panic!("Invalid type")
                }
            } else {
                panic!("No provided, defaulting to standard")
            }
        })
        .unwrap_or(default_to.to_string())
}

#[proc_macro_derive(
    StandardActions,
    attributes(
        actions_fname,
        invoke_fname,
        generic_typename,
        specific_typename,
        actions_storage,
    )
)]
pub fn standard_actions_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;
    let actions_fname_attr = get_attribute(
        input.attrs.clone(),
        "actions_fname",
        "set_standard_allowed_actions",
    );
    let invoke_fname_attr = get_attribute(input.attrs.clone(), "invoke_fname", "saa_invoke");
    let generic_typename_attr = get_attribute(
        input.attrs.clone(),
        "generic_typename",
        "StandardAllowedActions",
    );
    let specific_typename_attr =
        get_attribute(input.attrs.clone(), "specific_typename", "StandardAction");
    let actions_storage_attr = get_attribute_string(input.attrs.clone(), "actions_storage", "SAA");

    let expanded = quote! {
        #[contracttype]
        pub struct #generic_typename_attr {
            contracts: Map<u32, Address>,
            actions: Map<Symbol, StandardAction>,
            deploy: bool,
        }

        #[contracttype]
        pub struct #specific_typename_attr {
            allowed_contracts: Vec<u32>,
            allowed_args: Map<u32, Vec<Val>>,
        }

        impl StandardAllowedActions {
            pub fn is_allowed(&self, env: &Env, context: Context) -> bool {
                match context {
                    Context::CreateContractHostFn(_) => self.deploy,
                    Context::Contract(contract_ctx) => {
                        let args = contract_ctx.args;
                        let contract = contract_ctx.contract;
                        let fname = contract_ctx.fn_name;

                        let mut is_allowed = false;

                        if let Some(allowed) = self.actions.get(fname) {
                            for contract_idx in allowed.allowed_contracts {
                                if let Some(address) = self.contracts.get(contract_idx) {
                                    if contract == address {
                                        let mut current_args_approved = true;
                                        for (idx, allowed_args) in allowed.allowed_args.clone().into_iter() {
                                            if let Some(current_arg) = args.get(idx) {
                                                if allowed_args.iter().find(|x| vec![&env, x.clone()] == vec![&env, current_arg.clone()]).is_none() {
                                                    current_args_approved = false
                                                }
                                            } else {
                                                current_args_approved = false
                                            }
                                        }

                                        if current_args_approved {
                                            is_allowed = true
                                        }
                                    }
                                }
                            }
                        }

                        is_allowed
                    }
                }
            }
        }

        pub fn is_standard_allowed_action(env: &Env, ctxs: Vec<Context>) -> bool {
            let actions: StandardAllowedActions = env.storage().instance().get(&symbol_short!(#actions_storage_attr)).unwrap();
            let mut allowed = true;

            for ctx in ctxs {
                if !actions.is_allowed(env, ctx) {
                    allowed = false
                }
            }

            allowed
        }

        #[contractimpl]
        impl #struct_name {
            /// Set the contract's allowed on-chain actions.
            pub fn #actions_fname_attr(env: Env, actions: StandardAllowedActions) {
                env.current_contract_address().require_auth();
                env.storage().instance().set(&symbol_short!(#actions_storage_attr), &actions);
            }

            pub fn #invoke_fname_attr(env: Env, actions: Vec<(Address, Symbol, Vec<Val>)>) {
                env.current_contract_address().require_auth();
                for action in actions {
                    let contract = action.0;
                    let fname = action.1;
                    let args = action.2;

                    let _: Val = env.invoke_contract(&contract, &fname, args);
                }

                ()
            }
        }
    };

    TokenStream::from(expanded)
}
