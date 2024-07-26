#![doc = include_str!("../README.md")]

/// The Verification Key Module
/// Requires `vk` feature
pub mod vk;

/// Requires `deterministic` feature
pub mod kdf;

/// Requires `publish` feature
#[cfg(feature = "publish")]
pub mod publish;

pub mod error;

// Test the README.md code snippets
#[cfg(doctest)]
pub struct ReadmeDoctests;
