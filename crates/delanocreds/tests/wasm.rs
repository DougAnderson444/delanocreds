#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

// #[cfg(test)]
#[wasm_bindgen_test]
fn wasm_scalar_tests() {
    delanocreds::test_aggregate_verify_cross();
}
