#![doc = include_str!("../README.md")]

/// The Verification Key Module
/// Requires `vk` feature
#[cfg(feature = "vk")]
pub mod vk;

/// Requires `deterministic` feature
#[cfg(feature = "deterministic")]
pub mod kdf;

/// Requires `publish` feature
#[cfg(feature = "publish")]
pub mod publish;

// Test the README.md code snippets
#[cfg(doctest)]
pub struct ReadmeDoctests;
