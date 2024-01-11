//! Modification note:
//!
//! This moudle is dependent on wasmtime, which takes it's dependencies from the ./wit/deps/ folder
//! If you change the dependencies, ensure you also copy the wit into the ./wit/deps/ folder
//!
mod bindgen {
    // name of the world in the .wit file
    wasmtime::component::bindgen!("delanocreds-wit-ui");
}

use bindgen::delano::wit_ui::context_types;
use bindgen::exports::delano::wit_ui;

use std::{
    env,
    path::{Path, PathBuf},
};
use thiserror::Error;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::preview2::{Table, WasiCtx, WasiCtxBuilder, WasiView};

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

impl bindgen::delano::wit_ui::context_types::Host for MyCtx {}
impl bindgen::delano::wit_ui::wurbo_types::Host for MyCtx {}
impl bindgen::delano::wallet::types::Host for MyCtx {}
impl bindgen::delano::wallet::actions::Host for MyCtx {
    // Strub the following functions with noop
    /// Gets Nym Proof
    fn get_nym_proof(
        &mut self,
        _nonce: Vec<u8>,
    ) -> Result<Result<Vec<u8>, String>, wasmtime::Error> {
        Ok(Ok(vec![69u8; 32]))
    }

    /// Issue a credential Entry to a Nym with maximum entries.
    fn issue(
        &mut self,
        _attributes: Vec<bindgen::delano::wallet::types::Attribute>,
        _maxentries: u8,
        _options: Option<bindgen::delano::wallet::types::IssueOptions>,
    ) -> Result<Result<Vec<u8>, String>, wasmtime::Error> {
        Ok(Ok(vec![105u8; 32]))
    }

    /// Create an offer for a credential with its given entries and a given configuration.
    fn offer(
        &mut self,
        _cred: Vec<u8>,
        _config: bindgen::delano::wallet::types::OfferConfig,
    ) -> Result<Result<Vec<u8>, String>, wasmtime::Error> {
        Ok(Ok(vec![69u8; 32]))
    }

    /// Accept a credential offer and return the accepte Credential bytes
    fn accept(&mut self, _offer: Vec<u8>) -> Result<Result<Vec<u8>, String>, wasmtime::Error> {
        Ok(Ok(vec![69u8; 32]))
    }

    /// Export a function that proves selected attributes in a given credential
    fn prove(
        &mut self,
        _values: bindgen::delano::wallet::types::Provables,
    ) -> Result<Result<Vec<u8>, String>, wasmtime::Error> {
        Ok(Ok(vec![69u8; 32]))
    }

    /// Export a function that verifies a proof against a public key, nonce and selected attributes
    fn verify(
        &mut self,
        _values: bindgen::delano::wallet::types::Verifiables,
    ) -> Result<Result<bool, String>, wasmtime::Error> {
        Ok(Ok(true))
    }
}

impl bindgen::delano::wit_ui::wurbo_in::Host for MyCtx {
    fn addeventlistener(
        &mut self,
        _details: bindgen::delano::wit_ui::wurbo_in::ListenDetails,
    ) -> wasmtime::Result<()> {
        Ok(())
    }
}

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

    /// From io
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
}

impl From<String> for TestError {
    fn from(s: String) -> Self {
        TestError::Stringified(s)
    }
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

#[cfg(test)]
mod delano_wit_ui_tests {

    use crate::bindgen::delano::wit_ui::context_types::Page;

    use super::*;

    #[test]
    fn test_delano_wit_ui() -> wasmtime::Result<(), TestError> {
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

        // link imports to our instantiation (such as addeventlistener())
        bindgen::DelanocredsWitUi::add_to_linker(&mut linker, |state: &mut MyCtx| state)?;

        // link the WASI imports to our instantiation
        wasmtime_wasi::preview2::command::sync::add_to_linker(&mut linker)?;

        let table = Table::new();
        let wasi: WasiCtx = WasiCtxBuilder::new().inherit_stdout().args(&[""]).build();
        let state = MyCtx {
            wasi_ctx: Context { table, wasi },
        };
        let mut store = Store::new(&engine, state);

        let (bindings, _) =
            bindgen::DelanocredsWitUi::instantiate(&mut store, &component, &linker)?; // WorldNameInCamelCase

        // Now let's make some credentials!
        // First we test the ability to issue a credential.
        // The interface for issue is:
        // issue: func(nymproof: list<u8>, attributes: list<attribute>, maxentries: u8, nonce: option<list<u8>>) -> result<list<u8>, string>;
        // We will stub the nymproof for this UI test. For the UI itself, we need to allow the user to build a State which includes:
        // - list of attributes
        // - maxentries
        // - optional nonce

        // Start with an initial context. We should be able to pass this to render and have it
        // return our HTML.
        let name = "Delano Wallet App".to_string();
        let context = wit_ui::wurbo_out::Context::AllContent(context_types::Everything {
            page: Some(Page {
                name: name.clone(),
                version: "0.0.1".to_string(),
                description: "A wallet so you can sign your credentials.".to_string(),
            }),
            issue: None,
        });

        let html = bindings.delano_wit_ui_wurbo_out().call_render(
            &mut store,
            &context,
            "index.html",
        )??;

        assert!(html.contains(&name));

        // Now if we render using a context that is Addatribute, the resulting HTML should have a
        // second <li> block with another default attribute in it.

        let add_attr_context = wit_ui::wurbo_out::Context::Addattribute;

        let _html = bindings.delano_wit_ui_wurbo_out().call_render(
            &mut store,
            &add_attr_context,
            "index.html",
        )??;

        let html = bindings.delano_wit_ui_wurbo_out().call_render(
            &mut store,
            &add_attr_context,
            "index.html",
        )??;

        // the count of <select should be 2
        assert_eq!(html.matches("<select").count(), 3);

        // We should be able to edit issuer input by passing in a context that is Editissuerinput
        let edited_value = "Edited Delano Key".to_string();
        let edit_issuer_input_ctx =
            wit_ui::wurbo_out::Context::Editissuerinput(context_types::Kvctx {
                ctx: context_types::Kovindex::Key(0),
                value: edited_value.clone(),
            });

        // render with this edited ctx,
        // use output.html as the target as we just want to update the shadow state (& display it)
        let html = bindings.delano_wit_ui_wurbo_out().call_render(
            &mut store,
            &edit_issuer_input_ctx,
            "output.html",
        )??;

        eprintln!("{}", html);

        // Now there should be a match for the edited value
        assert!(html.contains(&edited_value));

        // Next we need to test that the UI can enable a user to create an offer for a credential with its given entries and a given configuration.
        // The interface for offer is:
        // offer: func(cred: list<u8>, config: offer-config) -> result<list<u8>, string>;
        // We will use the credential created from `issue` above. For the UI itself, we need to allow the user to build a State which includes:
        // - offer-config

        // Accept a credential offer and return the accepte Credential bytes
        // accept: func(offer: list<u8>) -> result<list<u8>, string>;

        // Export a function that proves selected attributes in a given credential
        // prove: func(values: provables) -> result<list<u8>, string>;

        // Export a function that verifies a proof against a public key, nonce and selected attributes
        // verify: func(values: verifiables) -> result<bool, string>;

        Ok(())
    }
}
