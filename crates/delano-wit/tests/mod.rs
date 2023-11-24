use component::delano_wit::types::{OfferConfig, Provables, Verifiables};
use delanocreds::*;
use std::{
    env,
    path::{Path, PathBuf},
};
use thiserror::Error;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::preview2::{Table, WasiCtx, WasiCtxBuilder, WasiView};

wasmtime::component::bindgen!("delanocreds");

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

impl component::delano_wit::deps::Host for MyCtx {
    /// Stub a seed gen fn
    fn get_seed(&mut self) -> Result<Vec<u8>, wasmtime::Error> {
        Ok(vec![69u8; 32])
    }
}

impl component::delano_wit::types::Host for MyCtx {}

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
    Delanocreds::add_to_linker(&mut linker, |state: &mut MyCtx| state)?;
    wasmtime_wasi::preview2::command::sync::add_to_linker(&mut linker)?;

    let table = Table::new();
    let wasi: WasiCtx = WasiCtxBuilder::new().inherit_stdout().args(&[""]).build();
    let state = MyCtx {
        wasi_ctx: Context { table, wasi },
    };
    let mut store = Store::new(&engine, state);

    let (bindings, _) = Delanocreds::instantiate(&mut store, &component, &linker)?;

    // Now let's make some credentials!
    // First, we issue the Root Cred to our own Nym, so we need to retreive the Nym's public key
    let nonce = Nonce::default();
    let nonce_bytes: Vec<u8> = nonce.clone().into();
    let nym_proof_bytes = bindings
        .component_delano_wit_actions()
        .call_get_nym_proof(&mut store, &nonce_bytes)?
        .map_err(|e| TestError::Stringified(format!("Get Nym: {:?}", e)))?;

    let nym_proof = NymProof::from_bytes(&nym_proof_bytes)?;

    // nym_proof.pedersen_open.open_randomness should equal the nonce value
    assert_eq!(nym_proof.pedersen_open.open_randomness, nonce);

    // convert for the wasm call
    let doug = Attribute::new("name = DougAnderson444").to_bytes();
    let attrs = vec![doug.clone()];

    let max_entries = MaxEntries::default();

    let cred = bindings
        .component_delano_wit_actions()
        .call_issue(
            &mut store,
            &nym_proof.to_bytes()?,
            &attrs,
            max_entries.into(),
            Some(&nonce_bytes),
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
        .component_delano_wit_actions()
        .call_offer(&mut store, &cred, &offer_config)?
        .map_err(|e| TestError::Stringified(format!("Error calling offer: {:?}", e)))?;

    // Accept the offer
    let accepted_cred = bindings
        .component_delano_wit_actions()
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

    let proof = bindings
        .component_delano_wit_actions()
        .call_prove(&mut store, &provables)?
        .map_err(|e| TestError::Stringified(e))?;

    // verify the proof
    let verifiables = Verifiables {
        proof: proof.clone(),
        issuer_public: cred_native.issuer_public.to_bytes()?,
        nonce: Some(verifiers_nonce_bytes.clone()),
        attributes: vec![doug],
    };

    let verified = bindings
        .component_delano_wit_actions()
        .call_verify(&mut store, &verifiables)?
        .map_err(|e| TestError::Stringified(e))?;

    assert!(verified);

    Ok(())
}
