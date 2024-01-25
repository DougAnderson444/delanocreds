mod bindgen {
    wasmtime::component::bindgen!("delanocreds"); // name of the world in the .wit file
}

use bindgen::delano::wallet::types::{OfferConfig, Provables, Verifiables};
use delanocreds::{Attribute, CBORCodec, Credential, MaxEntries, Nonce, NymProof};
use std::{
    env,
    path::{Path, PathBuf},
};
use thiserror::Error;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::preview2::{Table, WasiCtx, WasiCtxBuilder, WasiView};

use crate::bindgen::{delano::wallet, exports::delano::wallet::actions::IssueOptions};

struct MyCtx {
    wasi_ctx: Context,
}

struct Context {
    table: Table,
    wasi: WasiCtx,
}
impl WasiView for MyCtx {
    fn table(&self) -> &Table {
        &self.wasi_ctx.table
    }
    fn table_mut(&mut self) -> &mut Table {
        &mut self.wasi_ctx.table
    }
    fn ctx(&self) -> &WasiCtx {
        &self.wasi_ctx.wasi
    }
    fn ctx_mut(&mut self) -> &mut WasiCtx {
        &mut self.wasi_ctx.wasi
    }
}

impl bindgen::seed_keeper::wallet::config::Host for MyCtx {
    /// Stub a seed gen fn
    fn get_seed(&mut self) -> Result<Result<Vec<u8>, String>, wasmtime::Error> {
        Ok(Ok(vec![69u8; 32]))
    }
}

impl bindgen::delano::wallet::types::Host for MyCtx {}

#[derive(Error, Debug)]
pub enum TestError {
    /// From String
    #[error("Error message {0}")]
    Stringified(String),

    /// From Wasmtime
    #[error("Wasmtime: {0}")]
    Wasmtime(#[from] wasmtime::Error),

    /// From VarError
    #[error("VarError: {0}")]
    VarError(#[from] std::env::VarError),

    /// From DelanoCreds
    #[error("DelanoCreds: {0}")]
    DelanoCreds(#[from] delanocreds::error::Error),

    /// From io
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
}

/// Utility function to get the workspace dir
pub fn workspace_dir() -> PathBuf {
    let output = std::process::Command::new(env!("CARGO"))
        .arg("locate-project")
        .arg("--workspace")
        .arg("--message-format=plain")
        .output()
        .unwrap()
        .stdout;
    let cargo_path = Path::new(std::str::from_utf8(&output).unwrap().trim());
    cargo_path.parent().unwrap().to_path_buf()
}

#[test]
fn main() -> wasmtime::Result<(), TestError> {
    // get the target/wasm32-wasi/debug/CARGO_PKG_NAME.wasm file
    let pkg_name = std::env::var("CARGO_PKG_NAME")?.replace('-', "_");
    let workspace = workspace_dir();
    let wasm_path = format!("target/wasm32-wasi/debug/{}.wasm", pkg_name);
    let wasm_path = workspace.join(wasm_path);

    let mut config = Config::new();
    config.cache_config_load_default()?;
    config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Enable);
    config.wasm_component_model(true);

    let engine = Engine::new(&config)?;
    let component = Component::from_file(&engine, &wasm_path)?;

    let mut linker = Linker::new(&engine);
    // link imports like get_seed to our instantiation
    bindgen::Delanocreds::add_to_linker(&mut linker, |state: &mut MyCtx| state)?;
    // link the WASI imports to our instantiation
    wasmtime_wasi::preview2::command::sync::add_to_linker(&mut linker)?;

    let table = Table::new();
    let wasi: WasiCtx = WasiCtxBuilder::new().inherit_stdout().args(&[""]).build();
    let state = MyCtx {
        wasi_ctx: Context { table, wasi },
    };
    let mut store = Store::new(&engine, state);

    let (bindings, _) = bindgen::Delanocreds::instantiate(&mut store, &component, &linker)?;
    // World

    // Now let's make some credentials!
    let doug = Attribute::new("name = DougAnderson444").to_bytes();
    let root_entry = vec![doug.clone()];

    // We should be able to leave Issue Options as None, and we will issue Root to own Nym
    let max_entries = MaxEntries::default();

    let cred = bindings
        .delano_wallet_actions()
        .call_issue(&mut store, &root_entry.clone(), max_entries.into(), None)?
        .map_err(|e| TestError::Stringified(e))?;

    // There should be an update key in the cred
    let cred_native = Credential::from_bytes(&cred)?;
    assert!(cred_native.update_key.is_some());

    let nonce = Nonce::default();
    let nonce_bytes: Vec<u8> = nonce.clone().into();
    let nym_proof_bytes = bindings
        .delano_wallet_actions()
        .call_get_nym_proof(&mut store, &nonce_bytes)?
        .map_err(|e| TestError::Stringified(format!("Get Nym: {:?}", e)))?;

    let nym_proof = NymProof::from_bytes(&nym_proof_bytes)?;

    // nym_proof.pedersen_open.open_randomness should equal the nonce value
    assert_eq!(nym_proof.pedersen_open.open_randomness, nonce);

    let cred_native = Credential::from_bytes(&cred)?;

    // The self-issued cred should be provable by our nym's proof
    let provables = Provables {
        credential: cred.clone(),
        entries: vec![root_entry.clone()],
        selected: vec![doug.clone()],
        nonce: nonce_bytes.clone(),
    };

    let wallet::types::Proven { proof, selected } = bindings
        .delano_wallet_actions()
        .call_prove(&mut store, &provables)?
        .map_err(|e| TestError::Stringified(e))?;

    // The self-issued cred should be verifiable againsy our nym's proof
    let verifiables = Verifiables {
        proof: proof.clone(),
        issuer_public: cred_native.issuer_public.to_bytes()?,
        nonce: Some(nonce_bytes.clone()),
        selected: selected.clone(),
    };
    assert!(bindings
        .delano_wallet_actions()
        .call_verify(&mut store, &verifiables)?
        .map_err(|e| TestError::Stringified(e))?);

    let max_entries = MaxEntries::default();

    // We can also explicitly issue the Root Cred to our own Nym, using IssueOptions, so we need to retreive the Nym's public key
    let cred = bindings
        .delano_wallet_actions()
        .call_issue(
            &mut store,
            &root_entry,
            max_entries.into(),
            Some(&IssueOptions {
                nymproof: nym_proof.to_bytes()?,
                nonce: Some(nonce_bytes.clone()),
            }),
        )?
        .map_err(|e| TestError::Stringified(e))?;

    let cred_native = Credential::from_bytes(&cred)?;

    // Create an offer for this cred
    let offer_config = OfferConfig {
        redact: None,
        additional_entry: None,
        max_entries: None,
    };

    let offer = bindings
        .delano_wallet_actions()
        .call_offer(&mut store, &cred, &offer_config)?
        .map_err(|e| TestError::Stringified(format!("Error calling offer: {:?}", e)))?;

    // Accept the offer
    let accepted_cred = bindings
        .delano_wallet_actions()
        .call_accept(&mut store, &offer)?
        .map_err(|e| TestError::Stringified(e))?;

    // Normally we would get these optional nonce bytes from the Verifier at their discretion
    let verifiers_nonce_bytes: Vec<u8> = Nonce::default().into();

    // generate a proof for the accepted cred
    let provables = Provables {
        credential: accepted_cred.clone(),
        entries: vec![vec![doug.clone()]],
        selected: vec![doug.clone()],
        nonce: verifiers_nonce_bytes.clone(),
    };

    let wallet::types::Proven { proof, selected } = bindings
        .delano_wallet_actions()
        .call_prove(&mut store, &provables)?
        .map_err(|e| TestError::Stringified(e))?;

    // verify the proof
    let verifiables = Verifiables {
        proof: proof.clone(),
        issuer_public: cred_native.issuer_public.to_bytes()?,
        nonce: Some(verifiers_nonce_bytes.clone()),
        selected: selected.clone(),
    };

    let verified = bindings
        .delano_wallet_actions()
        .call_verify(&mut store, &verifiables)?
        .map_err(|e| TestError::Stringified(e))?;

    assert!(verified);

    //
    // Begin Extend
    //
    // extend the given credential with another Entry
    //
    //
    let another_attr = Attribute::new("Doug = cool").to_bytes();
    let another_entry = vec![another_attr.clone()];

    let extended_cred = bindings
        .delano_wallet_actions()
        .call_extend(&mut store, &accepted_cred, &another_entry)?
        .map_err(|e| TestError::Stringified(e))?;

    // assert that we can make a proof of the another_attr with the extended cred
    let provables = Provables {
        credential: extended_cred.clone(),
        entries: vec![root_entry.clone(), another_entry.clone()],
        selected: vec![another_attr.clone()],
        nonce: nonce_bytes.clone(),
    };

    let wallet::types::Proven { proof, selected } = bindings
        .delano_wallet_actions()
        .call_prove(&mut store, &provables)?
        .map_err(|e| TestError::Stringified(e))?;

    // verify the proof
    let verifiables = Verifiables {
        proof: proof.clone(),
        issuer_public: cred_native.issuer_public.to_bytes()?,
        nonce: Some(nonce_bytes.clone()),
        selected: selected.clone(),
    };

    let verified = bindings
        .delano_wallet_actions()
        .call_verify(&mut store, &verifiables)?
        .map_err(|e| TestError::Stringified(e))?;

    assert!(verified);

    //
    // End Extend
    //
    Ok(())
}
