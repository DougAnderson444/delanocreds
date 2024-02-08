#![doc = include_str!("../README.md")]

/// The Verification Key Module
pub mod vk;

// only if feature derive is enabled
// #[cfg(feature = "derive")]
pub mod kdf;

pub mod publish;

// Test the README.md code snippets
#[cfg(doctest)]
pub struct ReadmeDoctests;
