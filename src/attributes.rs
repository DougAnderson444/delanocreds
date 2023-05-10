//! A module for commitments, attributes and opening information management.
//!
//! - AttributeEntries (a Vector of attribute entries) hierarchy starts with Root Issuer entry/entries
//! - AttributeEntries can be extended up to `k_prime`
//! - AttributeEntries can be restricted by zeroizing opening information
//! - AttributeEntries can hold up to a cumulative total of `max_cardinality` attribute entries
//! - There can be up to `message_l` entries in each AttributeEntries vector
//! - Each entry in AttributeEntries is a vector holding a number of Attributes
//! - You can select subsets of AttributesVectors, by indicating which indexes you want to select, a 2D vector matix
//! - When opening information is zeroized, then the corresponding entry in AttributeEntries cannot be selected,
//! thus opening and atrributes have a relationship with each other. The opening vector is held in the credential,
//! ths the credential and the attributes have a relationship with each other.
//!
//! # API
//!
//! // create a new commitment vector
//! let mut attributes = AttributesVector::new();
//!
//! // push attributes (vectors of strings) to the vector
//! attributes.push(vec!["a".to_string(), "b".to_string(), "c".to_string()]);
//!
//! // select from the attributes
//! let selected_attrs = attributes.select(vec![vec![], vec![0, 1], vec![0, 1]]);
