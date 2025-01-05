#[allow(dead_code)]
pub mod delano {
    #[allow(dead_code)]
    pub mod wallet {
        #[allow(dead_code, clippy::all)]
        pub mod types {
            #[used]
            #[doc(hidden)]
            static __FORCE_SECTION_REF: fn() = super::super::super::__link_custom_section_describing_imports;
            use super::super::super::_rt;
            /// An attribute is a 32 bytes hash value
            pub type Attribute = _rt::Vec<u8>;
            pub type Entry = _rt::Vec<Attribute>;
            pub type Selected = _rt::Vec<Entry>;
            /// If you want to redact an Entry containing an Attribute,
            /// construct a redactable record with all Entries and the list of Attributes to redact.
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct Redactables {
                pub entries: _rt::Vec<Entry>,
                pub remove: _rt::Vec<Attribute>,
            }
            impl ::core::fmt::Debug for Redactables {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("Redactables")
                        .field("entries", &self.entries)
                        .field("remove", &self.remove)
                        .finish()
                }
            }
            /// Configuration of an Offer. Can set 3 things:
            /// 1) without-attribute: an optional redactable record of attributes to redact,
            /// 2) additional-entry: an optional single additional entry,
            /// 3) max-entries: the maximum number of entries the delegated party can add to the credential.
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct OfferConfig {
                pub redact: Option<Redactables>,
                pub additional_entry: Option<Entry>,
                /// Optionally reduces the number of entries that can be added to the credential.
                pub max_entries: Option<u8>,
            }
            impl ::core::fmt::Debug for OfferConfig {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("OfferConfig")
                        .field("redact", &self.redact)
                        .field("additional-entry", &self.additional_entry)
                        .field("max-entries", &self.max_entries)
                        .finish()
                }
            }
            /// A compressed signature
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct SignatureCompressed {
                pub z: _rt::Vec<u8>,
                pub y_g1: _rt::Vec<u8>,
                pub y_hat: _rt::Vec<u8>,
                pub t: _rt::Vec<u8>,
            }
            impl ::core::fmt::Debug for SignatureCompressed {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("SignatureCompressed")
                        .field("z", &self.z)
                        .field("y-g1", &self.y_g1)
                        .field("y-hat", &self.y_hat)
                        .field("t", &self.t)
                        .finish()
                }
            }
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct ParamSetCommitmentCompressed {
                pub pp_commit_g1: _rt::Vec<_rt::Vec<u8>>,
                pub pp_commit_g2: _rt::Vec<_rt::Vec<u8>>,
            }
            impl ::core::fmt::Debug for ParamSetCommitmentCompressed {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("ParamSetCommitmentCompressed")
                        .field("pp-commit-g1", &self.pp_commit_g1)
                        .field("pp-commit-g2", &self.pp_commit_g2)
                        .finish()
                }
            }
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub enum VkCompressed {
                G1(_rt::Vec<u8>),
                G2(_rt::Vec<u8>),
            }
            impl ::core::fmt::Debug for VkCompressed {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    match self {
                        VkCompressed::G1(e) => {
                            f.debug_tuple("VkCompressed::G1").field(e).finish()
                        }
                        VkCompressed::G2(e) => {
                            f.debug_tuple("VkCompressed::G2").field(e).finish()
                        }
                    }
                }
            }
            /// Issuer public parameters, compressed
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct IssuerPublicCompressed {
                pub parameters: ParamSetCommitmentCompressed,
                pub vk: _rt::Vec<VkCompressed>,
            }
            impl ::core::fmt::Debug for IssuerPublicCompressed {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("IssuerPublicCompressed")
                        .field("parameters", &self.parameters)
                        .field("vk", &self.vk)
                        .finish()
                }
            }
            /// A compressed version of the Credential
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct CredentialCompressed {
                pub sigma: SignatureCompressed,
                pub update_key: Option<_rt::Vec<_rt::Vec<_rt::Vec<u8>>>>,
                pub commitment_vector: _rt::Vec<_rt::Vec<u8>>,
                pub opening_vector: _rt::Vec<_rt::Vec<u8>>,
                pub issuer_public: IssuerPublicCompressed,
            }
            impl ::core::fmt::Debug for CredentialCompressed {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("CredentialCompressed")
                        .field("sigma", &self.sigma)
                        .field("update-key", &self.update_key)
                        .field("commitment-vector", &self.commitment_vector)
                        .field("opening-vector", &self.opening_vector)
                        .field("issuer-public", &self.issuer_public)
                        .finish()
                }
            }
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct Provables {
                pub credential: CredentialCompressed,
                pub entries: _rt::Vec<Entry>,
                pub selected: _rt::Vec<Attribute>,
                pub nonce: _rt::Vec<u8>,
            }
            impl ::core::fmt::Debug for Provables {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("Provables")
                        .field("credential", &self.credential)
                        .field("entries", &self.entries)
                        .field("selected", &self.selected)
                        .field("nonce", &self.nonce)
                        .finish()
                }
            }
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct PedersenCompressed {
                pub h: _rt::Vec<u8>,
            }
            impl ::core::fmt::Debug for PedersenCompressed {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("PedersenCompressed").field("h", &self.h).finish()
                }
            }
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct DamgardTransformCompressed {
                pub pedersen: PedersenCompressed,
            }
            impl ::core::fmt::Debug for DamgardTransformCompressed {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("DamgardTransformCompressed")
                        .field("pedersen", &self.pedersen)
                        .finish()
                }
            }
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct PedersenOpenCompressed {
                pub open_randomness: _rt::Vec<u8>,
                pub announce_randomness: _rt::Vec<u8>,
                pub announce_element: Option<_rt::Vec<u8>>,
            }
            impl ::core::fmt::Debug for PedersenOpenCompressed {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("PedersenOpenCompressed")
                        .field("open-randomness", &self.open_randomness)
                        .field("announce-randomness", &self.announce_randomness)
                        .field("announce-element", &self.announce_element)
                        .finish()
                }
            }
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct NymProofCompressed {
                pub challenge: _rt::Vec<u8>,
                pub pedersen_open: PedersenOpenCompressed,
                pub pedersen_commit: _rt::Vec<u8>,
                pub public_key: _rt::Vec<u8>,
                pub response: _rt::Vec<u8>,
                pub damgard: DamgardTransformCompressed,
            }
            impl ::core::fmt::Debug for NymProofCompressed {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("NymProofCompressed")
                        .field("challenge", &self.challenge)
                        .field("pedersen-open", &self.pedersen_open)
                        .field("pedersen-commit", &self.pedersen_commit)
                        .field("public-key", &self.public_key)
                        .field("response", &self.response)
                        .field("damgard", &self.damgard)
                        .finish()
                }
            }
            /// Issuer config: Default config creates (issues) a credential to yourself.
            /// Provide a config to offer it to someone else's nym, and optionally verify it with a nonce.
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct IssueOptions {
                pub nymproof: NymProofCompressed,
                pub nonce: Option<_rt::Vec<u8>>,
            }
            impl ::core::fmt::Debug for IssueOptions {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("IssueOptions")
                        .field("nymproof", &self.nymproof)
                        .field("nonce", &self.nonce)
                        .finish()
                }
            }
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct CredProofCompressed {
                pub sigma: SignatureCompressed,
                pub commitment_vector: _rt::Vec<_rt::Vec<u8>>,
                pub witness_pi: _rt::Vec<u8>,
                pub nym_proof: NymProofCompressed,
            }
            impl ::core::fmt::Debug for CredProofCompressed {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("CredProofCompressed")
                        .field("sigma", &self.sigma)
                        .field("commitment-vector", &self.commitment_vector)
                        .field("witness-pi", &self.witness_pi)
                        .field("nym-proof", &self.nym_proof)
                        .finish()
                }
            }
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct Proven {
                pub proof: CredProofCompressed,
                pub selected: Selected,
            }
            impl ::core::fmt::Debug for Proven {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("Proven")
                        .field("proof", &self.proof)
                        .field("selected", &self.selected)
                        .finish()
                }
            }
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct Verifiables {
                pub proof: CredProofCompressed,
                pub issuer_public: IssuerPublicCompressed,
                pub nonce: Option<_rt::Vec<u8>>,
                pub selected: Selected,
            }
            impl ::core::fmt::Debug for Verifiables {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("Verifiables")
                        .field("proof", &self.proof)
                        .field("issuer-public", &self.issuer_public)
                        .field("nonce", &self.nonce)
                        .field("selected", &self.selected)
                        .finish()
                }
            }
        }
        #[allow(dead_code, clippy::all)]
        pub mod actions {
            #[used]
            #[doc(hidden)]
            static __FORCE_SECTION_REF: fn() = super::super::super::__link_custom_section_describing_imports;
            use super::super::super::_rt;
            pub type Attribute = super::super::super::delano::wallet::types::Attribute;
            pub type Provables = super::super::super::delano::wallet::types::Provables;
            pub type Verifiables = super::super::super::delano::wallet::types::Verifiables;
            pub type OfferConfig = super::super::super::delano::wallet::types::OfferConfig;
            pub type IssueOptions = super::super::super::delano::wallet::types::IssueOptions;
            pub type Entry = super::super::super::delano::wallet::types::Entry;
            pub type Proven = super::super::super::delano::wallet::types::Proven;
            pub type CredentialCompressed = super::super::super::delano::wallet::types::CredentialCompressed;
            pub type NymProofCompressed = super::super::super::delano::wallet::types::NymProofCompressed;
            pub type IssuerPublicCompressed = super::super::super::delano::wallet::types::IssuerPublicCompressed;
            #[allow(unused_unsafe, clippy::all)]
            /// Returns the active Nym of the component.
            pub fn get_nym_proof(
                nonce: &[u8],
            ) -> Result<NymProofCompressed, _rt::String> {
                unsafe {
                    #[repr(align(4))]
                    struct RetArea([::core::mem::MaybeUninit<u8>; 72]);
                    let mut ret_area = RetArea([::core::mem::MaybeUninit::uninit(); 72]);
                    let vec0 = nonce;
                    let ptr0 = vec0.as_ptr().cast::<u8>();
                    let len0 = vec0.len();
                    let ptr1 = ret_area.0.as_mut_ptr().cast::<u8>();
                    #[cfg(target_arch = "wasm32")]
                    #[link(wasm_import_module = "delano:wallet/actions@0.1.0")]
                    extern "C" {
                        #[link_name = "get-nym-proof"]
                        fn wit_import(_: *mut u8, _: usize, _: *mut u8);
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    fn wit_import(_: *mut u8, _: usize, _: *mut u8) {
                        unreachable!()
                    }
                    wit_import(ptr0.cast_mut(), len0, ptr1);
                    let l2 = i32::from(*ptr1.add(0).cast::<u8>());
                    match l2 {
                        0 => {
                            let e = {
                                let l3 = *ptr1.add(4).cast::<*mut u8>();
                                let l4 = *ptr1.add(8).cast::<usize>();
                                let len5 = l4;
                                let l6 = *ptr1.add(12).cast::<*mut u8>();
                                let l7 = *ptr1.add(16).cast::<usize>();
                                let len8 = l7;
                                let l9 = *ptr1.add(20).cast::<*mut u8>();
                                let l10 = *ptr1.add(24).cast::<usize>();
                                let len11 = l10;
                                let l12 = i32::from(*ptr1.add(28).cast::<u8>());
                                let l16 = *ptr1.add(40).cast::<*mut u8>();
                                let l17 = *ptr1.add(44).cast::<usize>();
                                let len18 = l17;
                                let l19 = *ptr1.add(48).cast::<*mut u8>();
                                let l20 = *ptr1.add(52).cast::<usize>();
                                let len21 = l20;
                                let l22 = *ptr1.add(56).cast::<*mut u8>();
                                let l23 = *ptr1.add(60).cast::<usize>();
                                let len24 = l23;
                                let l25 = *ptr1.add(64).cast::<*mut u8>();
                                let l26 = *ptr1.add(68).cast::<usize>();
                                let len27 = l26;
                                super::super::super::delano::wallet::types::NymProofCompressed {
                                    challenge: _rt::Vec::from_raw_parts(l3.cast(), len5, len5),
                                    pedersen_open: super::super::super::delano::wallet::types::PedersenOpenCompressed {
                                        open_randomness: _rt::Vec::from_raw_parts(
                                            l6.cast(),
                                            len8,
                                            len8,
                                        ),
                                        announce_randomness: _rt::Vec::from_raw_parts(
                                            l9.cast(),
                                            len11,
                                            len11,
                                        ),
                                        announce_element: match l12 {
                                            0 => None,
                                            1 => {
                                                let e = {
                                                    let l13 = *ptr1.add(32).cast::<*mut u8>();
                                                    let l14 = *ptr1.add(36).cast::<usize>();
                                                    let len15 = l14;
                                                    _rt::Vec::from_raw_parts(l13.cast(), len15, len15)
                                                };
                                                Some(e)
                                            }
                                            _ => _rt::invalid_enum_discriminant(),
                                        },
                                    },
                                    pedersen_commit: _rt::Vec::from_raw_parts(
                                        l16.cast(),
                                        len18,
                                        len18,
                                    ),
                                    public_key: _rt::Vec::from_raw_parts(
                                        l19.cast(),
                                        len21,
                                        len21,
                                    ),
                                    response: _rt::Vec::from_raw_parts(
                                        l22.cast(),
                                        len24,
                                        len24,
                                    ),
                                    damgard: super::super::super::delano::wallet::types::DamgardTransformCompressed {
                                        pedersen: super::super::super::delano::wallet::types::PedersenCompressed {
                                            h: _rt::Vec::from_raw_parts(l25.cast(), len27, len27),
                                        },
                                    },
                                }
                            };
                            Ok(e)
                        }
                        1 => {
                            let e = {
                                let l28 = *ptr1.add(4).cast::<*mut u8>();
                                let l29 = *ptr1.add(8).cast::<usize>();
                                let len30 = l29;
                                let bytes30 = _rt::Vec::from_raw_parts(
                                    l28.cast(),
                                    len30,
                                    len30,
                                );
                                _rt::string_lift(bytes30)
                            };
                            Err(e)
                        }
                        _ => _rt::invalid_enum_discriminant(),
                    }
                }
            }
            #[allow(unused_unsafe, clippy::all)]
            /// Issue a credential Entry to a Nym with maximum entries.
            /// By default issues a credential to your own Nym. To issue to others, set the options to their nymproof and optionally the nonce you gave them.
            pub fn issue(
                attributes: &[Attribute],
                maxentries: u8,
                options: Option<&IssueOptions>,
            ) -> Result<CredentialCompressed, _rt::String> {
                unsafe {
                    #[repr(align(4))]
                    struct RetArea([::core::mem::MaybeUninit<u8>; 96]);
                    let mut ret_area = RetArea([::core::mem::MaybeUninit::uninit(); 96]);
                    let ptr0 = ret_area.0.as_mut_ptr().cast::<u8>();
                    let vec2 = attributes;
                    let len2 = vec2.len();
                    let layout2 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec2.len() * 8,
                        4,
                    );
                    let result2 = if layout2.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout2).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout2);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec2.into_iter().enumerate() {
                        let base = result2.add(i * 8);
                        {
                            let vec1 = e;
                            let ptr1 = vec1.as_ptr().cast::<u8>();
                            let len1 = vec1.len();
                            *base.add(4).cast::<usize>() = len1;
                            *base.add(0).cast::<*mut u8>() = ptr1.cast_mut();
                        }
                    }
                    *ptr0.add(4).cast::<usize>() = len2;
                    *ptr0.add(0).cast::<*mut u8>() = result2;
                    *ptr0.add(8).cast::<u8>() = (_rt::as_i32(&maxentries)) as u8;
                    match options {
                        Some(e) => {
                            *ptr0.add(12).cast::<u8>() = (1i32) as u8;
                            let super::super::super::delano::wallet::types::IssueOptions {
                                nymproof: nymproof3,
                                nonce: nonce3,
                            } = e;
                            let super::super::super::delano::wallet::types::NymProofCompressed {
                                challenge: challenge4,
                                pedersen_open: pedersen_open4,
                                pedersen_commit: pedersen_commit4,
                                public_key: public_key4,
                                response: response4,
                                damgard: damgard4,
                            } = nymproof3;
                            let vec5 = challenge4;
                            let ptr5 = vec5.as_ptr().cast::<u8>();
                            let len5 = vec5.len();
                            *ptr0.add(20).cast::<usize>() = len5;
                            *ptr0.add(16).cast::<*mut u8>() = ptr5.cast_mut();
                            let super::super::super::delano::wallet::types::PedersenOpenCompressed {
                                open_randomness: open_randomness6,
                                announce_randomness: announce_randomness6,
                                announce_element: announce_element6,
                            } = pedersen_open4;
                            let vec7 = open_randomness6;
                            let ptr7 = vec7.as_ptr().cast::<u8>();
                            let len7 = vec7.len();
                            *ptr0.add(28).cast::<usize>() = len7;
                            *ptr0.add(24).cast::<*mut u8>() = ptr7.cast_mut();
                            let vec8 = announce_randomness6;
                            let ptr8 = vec8.as_ptr().cast::<u8>();
                            let len8 = vec8.len();
                            *ptr0.add(36).cast::<usize>() = len8;
                            *ptr0.add(32).cast::<*mut u8>() = ptr8.cast_mut();
                            match announce_element6 {
                                Some(e) => {
                                    *ptr0.add(40).cast::<u8>() = (1i32) as u8;
                                    let vec9 = e;
                                    let ptr9 = vec9.as_ptr().cast::<u8>();
                                    let len9 = vec9.len();
                                    *ptr0.add(48).cast::<usize>() = len9;
                                    *ptr0.add(44).cast::<*mut u8>() = ptr9.cast_mut();
                                }
                                None => {
                                    *ptr0.add(40).cast::<u8>() = (0i32) as u8;
                                }
                            };
                            let vec10 = pedersen_commit4;
                            let ptr10 = vec10.as_ptr().cast::<u8>();
                            let len10 = vec10.len();
                            *ptr0.add(56).cast::<usize>() = len10;
                            *ptr0.add(52).cast::<*mut u8>() = ptr10.cast_mut();
                            let vec11 = public_key4;
                            let ptr11 = vec11.as_ptr().cast::<u8>();
                            let len11 = vec11.len();
                            *ptr0.add(64).cast::<usize>() = len11;
                            *ptr0.add(60).cast::<*mut u8>() = ptr11.cast_mut();
                            let vec12 = response4;
                            let ptr12 = vec12.as_ptr().cast::<u8>();
                            let len12 = vec12.len();
                            *ptr0.add(72).cast::<usize>() = len12;
                            *ptr0.add(68).cast::<*mut u8>() = ptr12.cast_mut();
                            let super::super::super::delano::wallet::types::DamgardTransformCompressed {
                                pedersen: pedersen13,
                            } = damgard4;
                            let super::super::super::delano::wallet::types::PedersenCompressed {
                                h: h14,
                            } = pedersen13;
                            let vec15 = h14;
                            let ptr15 = vec15.as_ptr().cast::<u8>();
                            let len15 = vec15.len();
                            *ptr0.add(80).cast::<usize>() = len15;
                            *ptr0.add(76).cast::<*mut u8>() = ptr15.cast_mut();
                            match nonce3 {
                                Some(e) => {
                                    *ptr0.add(84).cast::<u8>() = (1i32) as u8;
                                    let vec16 = e;
                                    let ptr16 = vec16.as_ptr().cast::<u8>();
                                    let len16 = vec16.len();
                                    *ptr0.add(92).cast::<usize>() = len16;
                                    *ptr0.add(88).cast::<*mut u8>() = ptr16.cast_mut();
                                }
                                None => {
                                    *ptr0.add(84).cast::<u8>() = (0i32) as u8;
                                }
                            };
                        }
                        None => {
                            *ptr0.add(12).cast::<u8>() = (0i32) as u8;
                        }
                    };
                    let ptr17 = ret_area.0.as_mut_ptr().cast::<u8>();
                    #[cfg(target_arch = "wasm32")]
                    #[link(wasm_import_module = "delano:wallet/actions@0.1.0")]
                    extern "C" {
                        #[link_name = "issue"]
                        fn wit_import(_: *mut u8, _: *mut u8);
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    fn wit_import(_: *mut u8, _: *mut u8) {
                        unreachable!()
                    }
                    wit_import(ptr0, ptr17);
                    let l18 = i32::from(*ptr17.add(0).cast::<u8>());
                    if layout2.size() != 0 {
                        _rt::alloc::dealloc(result2.cast(), layout2);
                    }
                    match l18 {
                        0 => {
                            let e = {
                                let l19 = *ptr17.add(4).cast::<*mut u8>();
                                let l20 = *ptr17.add(8).cast::<usize>();
                                let len21 = l20;
                                let l22 = *ptr17.add(12).cast::<*mut u8>();
                                let l23 = *ptr17.add(16).cast::<usize>();
                                let len24 = l23;
                                let l25 = *ptr17.add(20).cast::<*mut u8>();
                                let l26 = *ptr17.add(24).cast::<usize>();
                                let len27 = l26;
                                let l28 = *ptr17.add(28).cast::<*mut u8>();
                                let l29 = *ptr17.add(32).cast::<usize>();
                                let len30 = l29;
                                let l31 = i32::from(*ptr17.add(36).cast::<u8>());
                                let l41 = *ptr17.add(48).cast::<*mut u8>();
                                let l42 = *ptr17.add(52).cast::<usize>();
                                let base46 = l41;
                                let len46 = l42;
                                let mut result46 = _rt::Vec::with_capacity(len46);
                                for i in 0..len46 {
                                    let base = base46.add(i * 8);
                                    let e46 = {
                                        let l43 = *base.add(0).cast::<*mut u8>();
                                        let l44 = *base.add(4).cast::<usize>();
                                        let len45 = l44;
                                        _rt::Vec::from_raw_parts(l43.cast(), len45, len45)
                                    };
                                    result46.push(e46);
                                }
                                _rt::cabi_dealloc(base46, len46 * 8, 4);
                                let l47 = *ptr17.add(56).cast::<*mut u8>();
                                let l48 = *ptr17.add(60).cast::<usize>();
                                let base52 = l47;
                                let len52 = l48;
                                let mut result52 = _rt::Vec::with_capacity(len52);
                                for i in 0..len52 {
                                    let base = base52.add(i * 8);
                                    let e52 = {
                                        let l49 = *base.add(0).cast::<*mut u8>();
                                        let l50 = *base.add(4).cast::<usize>();
                                        let len51 = l50;
                                        _rt::Vec::from_raw_parts(l49.cast(), len51, len51)
                                    };
                                    result52.push(e52);
                                }
                                _rt::cabi_dealloc(base52, len52 * 8, 4);
                                let l53 = *ptr17.add(64).cast::<*mut u8>();
                                let l54 = *ptr17.add(68).cast::<usize>();
                                let base58 = l53;
                                let len58 = l54;
                                let mut result58 = _rt::Vec::with_capacity(len58);
                                for i in 0..len58 {
                                    let base = base58.add(i * 8);
                                    let e58 = {
                                        let l55 = *base.add(0).cast::<*mut u8>();
                                        let l56 = *base.add(4).cast::<usize>();
                                        let len57 = l56;
                                        _rt::Vec::from_raw_parts(l55.cast(), len57, len57)
                                    };
                                    result58.push(e58);
                                }
                                _rt::cabi_dealloc(base58, len58 * 8, 4);
                                let l59 = *ptr17.add(72).cast::<*mut u8>();
                                let l60 = *ptr17.add(76).cast::<usize>();
                                let base64 = l59;
                                let len64 = l60;
                                let mut result64 = _rt::Vec::with_capacity(len64);
                                for i in 0..len64 {
                                    let base = base64.add(i * 8);
                                    let e64 = {
                                        let l61 = *base.add(0).cast::<*mut u8>();
                                        let l62 = *base.add(4).cast::<usize>();
                                        let len63 = l62;
                                        _rt::Vec::from_raw_parts(l61.cast(), len63, len63)
                                    };
                                    result64.push(e64);
                                }
                                _rt::cabi_dealloc(base64, len64 * 8, 4);
                                let l65 = *ptr17.add(80).cast::<*mut u8>();
                                let l66 = *ptr17.add(84).cast::<usize>();
                                let base75 = l65;
                                let len75 = l66;
                                let mut result75 = _rt::Vec::with_capacity(len75);
                                for i in 0..len75 {
                                    let base = base75.add(i * 12);
                                    let e75 = {
                                        let l67 = i32::from(*base.add(0).cast::<u8>());
                                        use super::super::super::delano::wallet::types::VkCompressed as V74;
                                        let v74 = match l67 {
                                            0 => {
                                                let e74 = {
                                                    let l68 = *base.add(4).cast::<*mut u8>();
                                                    let l69 = *base.add(8).cast::<usize>();
                                                    let len70 = l69;
                                                    _rt::Vec::from_raw_parts(l68.cast(), len70, len70)
                                                };
                                                V74::G1(e74)
                                            }
                                            n => {
                                                debug_assert_eq!(n, 1, "invalid enum discriminant");
                                                let e74 = {
                                                    let l71 = *base.add(4).cast::<*mut u8>();
                                                    let l72 = *base.add(8).cast::<usize>();
                                                    let len73 = l72;
                                                    _rt::Vec::from_raw_parts(l71.cast(), len73, len73)
                                                };
                                                V74::G2(e74)
                                            }
                                        };
                                        v74
                                    };
                                    result75.push(e75);
                                }
                                _rt::cabi_dealloc(base75, len75 * 12, 4);
                                super::super::super::delano::wallet::types::CredentialCompressed {
                                    sigma: super::super::super::delano::wallet::types::SignatureCompressed {
                                        z: _rt::Vec::from_raw_parts(l19.cast(), len21, len21),
                                        y_g1: _rt::Vec::from_raw_parts(l22.cast(), len24, len24),
                                        y_hat: _rt::Vec::from_raw_parts(l25.cast(), len27, len27),
                                        t: _rt::Vec::from_raw_parts(l28.cast(), len30, len30),
                                    },
                                    update_key: match l31 {
                                        0 => None,
                                        1 => {
                                            let e = {
                                                let l32 = *ptr17.add(40).cast::<*mut u8>();
                                                let l33 = *ptr17.add(44).cast::<usize>();
                                                let base40 = l32;
                                                let len40 = l33;
                                                let mut result40 = _rt::Vec::with_capacity(len40);
                                                for i in 0..len40 {
                                                    let base = base40.add(i * 8);
                                                    let e40 = {
                                                        let l34 = *base.add(0).cast::<*mut u8>();
                                                        let l35 = *base.add(4).cast::<usize>();
                                                        let base39 = l34;
                                                        let len39 = l35;
                                                        let mut result39 = _rt::Vec::with_capacity(len39);
                                                        for i in 0..len39 {
                                                            let base = base39.add(i * 8);
                                                            let e39 = {
                                                                let l36 = *base.add(0).cast::<*mut u8>();
                                                                let l37 = *base.add(4).cast::<usize>();
                                                                let len38 = l37;
                                                                _rt::Vec::from_raw_parts(l36.cast(), len38, len38)
                                                            };
                                                            result39.push(e39);
                                                        }
                                                        _rt::cabi_dealloc(base39, len39 * 8, 4);
                                                        result39
                                                    };
                                                    result40.push(e40);
                                                }
                                                _rt::cabi_dealloc(base40, len40 * 8, 4);
                                                result40
                                            };
                                            Some(e)
                                        }
                                        _ => _rt::invalid_enum_discriminant(),
                                    },
                                    commitment_vector: result46,
                                    opening_vector: result52,
                                    issuer_public: super::super::super::delano::wallet::types::IssuerPublicCompressed {
                                        parameters: super::super::super::delano::wallet::types::ParamSetCommitmentCompressed {
                                            pp_commit_g1: result58,
                                            pp_commit_g2: result64,
                                        },
                                        vk: result75,
                                    },
                                }
                            };
                            Ok(e)
                        }
                        1 => {
                            let e = {
                                let l76 = *ptr17.add(4).cast::<*mut u8>();
                                let l77 = *ptr17.add(8).cast::<usize>();
                                let len78 = l77;
                                let bytes78 = _rt::Vec::from_raw_parts(
                                    l76.cast(),
                                    len78,
                                    len78,
                                );
                                _rt::string_lift(bytes78)
                            };
                            Err(e)
                        }
                        _ => _rt::invalid_enum_discriminant(),
                    }
                }
            }
            #[allow(unused_unsafe, clippy::all)]
            /// Create an offer for a credential with its given entries and a given configuration.
            pub fn offer(
                cred: &CredentialCompressed,
                config: &OfferConfig,
            ) -> Result<CredentialCompressed, _rt::String> {
                unsafe {
                    let mut cleanup_list = _rt::Vec::new();
                    #[repr(align(4))]
                    struct RetArea([::core::mem::MaybeUninit<u8>; 120]);
                    let mut ret_area = RetArea(
                        [::core::mem::MaybeUninit::uninit(); 120],
                    );
                    let ptr0 = ret_area.0.as_mut_ptr().cast::<u8>();
                    let super::super::super::delano::wallet::types::CredentialCompressed {
                        sigma: sigma1,
                        update_key: update_key1,
                        commitment_vector: commitment_vector1,
                        opening_vector: opening_vector1,
                        issuer_public: issuer_public1,
                    } = cred;
                    let super::super::super::delano::wallet::types::SignatureCompressed {
                        z: z2,
                        y_g1: y_g12,
                        y_hat: y_hat2,
                        t: t2,
                    } = sigma1;
                    let vec3 = z2;
                    let ptr3 = vec3.as_ptr().cast::<u8>();
                    let len3 = vec3.len();
                    *ptr0.add(4).cast::<usize>() = len3;
                    *ptr0.add(0).cast::<*mut u8>() = ptr3.cast_mut();
                    let vec4 = y_g12;
                    let ptr4 = vec4.as_ptr().cast::<u8>();
                    let len4 = vec4.len();
                    *ptr0.add(12).cast::<usize>() = len4;
                    *ptr0.add(8).cast::<*mut u8>() = ptr4.cast_mut();
                    let vec5 = y_hat2;
                    let ptr5 = vec5.as_ptr().cast::<u8>();
                    let len5 = vec5.len();
                    *ptr0.add(20).cast::<usize>() = len5;
                    *ptr0.add(16).cast::<*mut u8>() = ptr5.cast_mut();
                    let vec6 = t2;
                    let ptr6 = vec6.as_ptr().cast::<u8>();
                    let len6 = vec6.len();
                    *ptr0.add(28).cast::<usize>() = len6;
                    *ptr0.add(24).cast::<*mut u8>() = ptr6.cast_mut();
                    match update_key1 {
                        Some(e) => {
                            *ptr0.add(32).cast::<u8>() = (1i32) as u8;
                            let vec9 = e;
                            let len9 = vec9.len();
                            let layout9 = _rt::alloc::Layout::from_size_align_unchecked(
                                vec9.len() * 8,
                                4,
                            );
                            let result9 = if layout9.size() != 0 {
                                let ptr = _rt::alloc::alloc(layout9).cast::<u8>();
                                if ptr.is_null() {
                                    _rt::alloc::handle_alloc_error(layout9);
                                }
                                ptr
                            } else {
                                ::core::ptr::null_mut()
                            };
                            for (i, e) in vec9.into_iter().enumerate() {
                                let base = result9.add(i * 8);
                                {
                                    let vec8 = e;
                                    let len8 = vec8.len();
                                    let layout8 = _rt::alloc::Layout::from_size_align_unchecked(
                                        vec8.len() * 8,
                                        4,
                                    );
                                    let result8 = if layout8.size() != 0 {
                                        let ptr = _rt::alloc::alloc(layout8).cast::<u8>();
                                        if ptr.is_null() {
                                            _rt::alloc::handle_alloc_error(layout8);
                                        }
                                        ptr
                                    } else {
                                        ::core::ptr::null_mut()
                                    };
                                    for (i, e) in vec8.into_iter().enumerate() {
                                        let base = result8.add(i * 8);
                                        {
                                            let vec7 = e;
                                            let ptr7 = vec7.as_ptr().cast::<u8>();
                                            let len7 = vec7.len();
                                            *base.add(4).cast::<usize>() = len7;
                                            *base.add(0).cast::<*mut u8>() = ptr7.cast_mut();
                                        }
                                    }
                                    *base.add(4).cast::<usize>() = len8;
                                    *base.add(0).cast::<*mut u8>() = result8;
                                    cleanup_list.extend_from_slice(&[(result8, layout8)]);
                                }
                            }
                            *ptr0.add(40).cast::<usize>() = len9;
                            *ptr0.add(36).cast::<*mut u8>() = result9;
                            cleanup_list.extend_from_slice(&[(result9, layout9)]);
                        }
                        None => {
                            *ptr0.add(32).cast::<u8>() = (0i32) as u8;
                        }
                    };
                    let vec11 = commitment_vector1;
                    let len11 = vec11.len();
                    let layout11 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec11.len() * 8,
                        4,
                    );
                    let result11 = if layout11.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout11).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout11);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec11.into_iter().enumerate() {
                        let base = result11.add(i * 8);
                        {
                            let vec10 = e;
                            let ptr10 = vec10.as_ptr().cast::<u8>();
                            let len10 = vec10.len();
                            *base.add(4).cast::<usize>() = len10;
                            *base.add(0).cast::<*mut u8>() = ptr10.cast_mut();
                        }
                    }
                    *ptr0.add(48).cast::<usize>() = len11;
                    *ptr0.add(44).cast::<*mut u8>() = result11;
                    let vec13 = opening_vector1;
                    let len13 = vec13.len();
                    let layout13 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec13.len() * 8,
                        4,
                    );
                    let result13 = if layout13.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout13).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout13);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec13.into_iter().enumerate() {
                        let base = result13.add(i * 8);
                        {
                            let vec12 = e;
                            let ptr12 = vec12.as_ptr().cast::<u8>();
                            let len12 = vec12.len();
                            *base.add(4).cast::<usize>() = len12;
                            *base.add(0).cast::<*mut u8>() = ptr12.cast_mut();
                        }
                    }
                    *ptr0.add(56).cast::<usize>() = len13;
                    *ptr0.add(52).cast::<*mut u8>() = result13;
                    let super::super::super::delano::wallet::types::IssuerPublicCompressed {
                        parameters: parameters14,
                        vk: vk14,
                    } = issuer_public1;
                    let super::super::super::delano::wallet::types::ParamSetCommitmentCompressed {
                        pp_commit_g1: pp_commit_g115,
                        pp_commit_g2: pp_commit_g215,
                    } = parameters14;
                    let vec17 = pp_commit_g115;
                    let len17 = vec17.len();
                    let layout17 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec17.len() * 8,
                        4,
                    );
                    let result17 = if layout17.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout17).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout17);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec17.into_iter().enumerate() {
                        let base = result17.add(i * 8);
                        {
                            let vec16 = e;
                            let ptr16 = vec16.as_ptr().cast::<u8>();
                            let len16 = vec16.len();
                            *base.add(4).cast::<usize>() = len16;
                            *base.add(0).cast::<*mut u8>() = ptr16.cast_mut();
                        }
                    }
                    *ptr0.add(64).cast::<usize>() = len17;
                    *ptr0.add(60).cast::<*mut u8>() = result17;
                    let vec19 = pp_commit_g215;
                    let len19 = vec19.len();
                    let layout19 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec19.len() * 8,
                        4,
                    );
                    let result19 = if layout19.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout19).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout19);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec19.into_iter().enumerate() {
                        let base = result19.add(i * 8);
                        {
                            let vec18 = e;
                            let ptr18 = vec18.as_ptr().cast::<u8>();
                            let len18 = vec18.len();
                            *base.add(4).cast::<usize>() = len18;
                            *base.add(0).cast::<*mut u8>() = ptr18.cast_mut();
                        }
                    }
                    *ptr0.add(72).cast::<usize>() = len19;
                    *ptr0.add(68).cast::<*mut u8>() = result19;
                    let vec23 = vk14;
                    let len23 = vec23.len();
                    let layout23 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec23.len() * 12,
                        4,
                    );
                    let result23 = if layout23.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout23).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout23);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec23.into_iter().enumerate() {
                        let base = result23.add(i * 12);
                        {
                            use super::super::super::delano::wallet::types::VkCompressed as V22;
                            match e {
                                V22::G1(e) => {
                                    *base.add(0).cast::<u8>() = (0i32) as u8;
                                    let vec20 = e;
                                    let ptr20 = vec20.as_ptr().cast::<u8>();
                                    let len20 = vec20.len();
                                    *base.add(8).cast::<usize>() = len20;
                                    *base.add(4).cast::<*mut u8>() = ptr20.cast_mut();
                                }
                                V22::G2(e) => {
                                    *base.add(0).cast::<u8>() = (1i32) as u8;
                                    let vec21 = e;
                                    let ptr21 = vec21.as_ptr().cast::<u8>();
                                    let len21 = vec21.len();
                                    *base.add(8).cast::<usize>() = len21;
                                    *base.add(4).cast::<*mut u8>() = ptr21.cast_mut();
                                }
                            }
                        }
                    }
                    *ptr0.add(80).cast::<usize>() = len23;
                    *ptr0.add(76).cast::<*mut u8>() = result23;
                    let super::super::super::delano::wallet::types::OfferConfig {
                        redact: redact24,
                        additional_entry: additional_entry24,
                        max_entries: max_entries24,
                    } = config;
                    match redact24 {
                        Some(e) => {
                            *ptr0.add(84).cast::<u8>() = (1i32) as u8;
                            let super::super::super::delano::wallet::types::Redactables {
                                entries: entries25,
                                remove: remove25,
                            } = e;
                            let vec28 = entries25;
                            let len28 = vec28.len();
                            let layout28 = _rt::alloc::Layout::from_size_align_unchecked(
                                vec28.len() * 8,
                                4,
                            );
                            let result28 = if layout28.size() != 0 {
                                let ptr = _rt::alloc::alloc(layout28).cast::<u8>();
                                if ptr.is_null() {
                                    _rt::alloc::handle_alloc_error(layout28);
                                }
                                ptr
                            } else {
                                ::core::ptr::null_mut()
                            };
                            for (i, e) in vec28.into_iter().enumerate() {
                                let base = result28.add(i * 8);
                                {
                                    let vec27 = e;
                                    let len27 = vec27.len();
                                    let layout27 = _rt::alloc::Layout::from_size_align_unchecked(
                                        vec27.len() * 8,
                                        4,
                                    );
                                    let result27 = if layout27.size() != 0 {
                                        let ptr = _rt::alloc::alloc(layout27).cast::<u8>();
                                        if ptr.is_null() {
                                            _rt::alloc::handle_alloc_error(layout27);
                                        }
                                        ptr
                                    } else {
                                        ::core::ptr::null_mut()
                                    };
                                    for (i, e) in vec27.into_iter().enumerate() {
                                        let base = result27.add(i * 8);
                                        {
                                            let vec26 = e;
                                            let ptr26 = vec26.as_ptr().cast::<u8>();
                                            let len26 = vec26.len();
                                            *base.add(4).cast::<usize>() = len26;
                                            *base.add(0).cast::<*mut u8>() = ptr26.cast_mut();
                                        }
                                    }
                                    *base.add(4).cast::<usize>() = len27;
                                    *base.add(0).cast::<*mut u8>() = result27;
                                    cleanup_list.extend_from_slice(&[(result27, layout27)]);
                                }
                            }
                            *ptr0.add(92).cast::<usize>() = len28;
                            *ptr0.add(88).cast::<*mut u8>() = result28;
                            let vec30 = remove25;
                            let len30 = vec30.len();
                            let layout30 = _rt::alloc::Layout::from_size_align_unchecked(
                                vec30.len() * 8,
                                4,
                            );
                            let result30 = if layout30.size() != 0 {
                                let ptr = _rt::alloc::alloc(layout30).cast::<u8>();
                                if ptr.is_null() {
                                    _rt::alloc::handle_alloc_error(layout30);
                                }
                                ptr
                            } else {
                                ::core::ptr::null_mut()
                            };
                            for (i, e) in vec30.into_iter().enumerate() {
                                let base = result30.add(i * 8);
                                {
                                    let vec29 = e;
                                    let ptr29 = vec29.as_ptr().cast::<u8>();
                                    let len29 = vec29.len();
                                    *base.add(4).cast::<usize>() = len29;
                                    *base.add(0).cast::<*mut u8>() = ptr29.cast_mut();
                                }
                            }
                            *ptr0.add(100).cast::<usize>() = len30;
                            *ptr0.add(96).cast::<*mut u8>() = result30;
                            cleanup_list
                                .extend_from_slice(
                                    &[(result28, layout28), (result30, layout30)],
                                );
                        }
                        None => {
                            *ptr0.add(84).cast::<u8>() = (0i32) as u8;
                        }
                    };
                    match additional_entry24 {
                        Some(e) => {
                            *ptr0.add(104).cast::<u8>() = (1i32) as u8;
                            let vec32 = e;
                            let len32 = vec32.len();
                            let layout32 = _rt::alloc::Layout::from_size_align_unchecked(
                                vec32.len() * 8,
                                4,
                            );
                            let result32 = if layout32.size() != 0 {
                                let ptr = _rt::alloc::alloc(layout32).cast::<u8>();
                                if ptr.is_null() {
                                    _rt::alloc::handle_alloc_error(layout32);
                                }
                                ptr
                            } else {
                                ::core::ptr::null_mut()
                            };
                            for (i, e) in vec32.into_iter().enumerate() {
                                let base = result32.add(i * 8);
                                {
                                    let vec31 = e;
                                    let ptr31 = vec31.as_ptr().cast::<u8>();
                                    let len31 = vec31.len();
                                    *base.add(4).cast::<usize>() = len31;
                                    *base.add(0).cast::<*mut u8>() = ptr31.cast_mut();
                                }
                            }
                            *ptr0.add(112).cast::<usize>() = len32;
                            *ptr0.add(108).cast::<*mut u8>() = result32;
                            cleanup_list.extend_from_slice(&[(result32, layout32)]);
                        }
                        None => {
                            *ptr0.add(104).cast::<u8>() = (0i32) as u8;
                        }
                    };
                    match max_entries24 {
                        Some(e) => {
                            *ptr0.add(116).cast::<u8>() = (1i32) as u8;
                            *ptr0.add(117).cast::<u8>() = (_rt::as_i32(e)) as u8;
                        }
                        None => {
                            *ptr0.add(116).cast::<u8>() = (0i32) as u8;
                        }
                    };
                    let ptr33 = ret_area.0.as_mut_ptr().cast::<u8>();
                    #[cfg(target_arch = "wasm32")]
                    #[link(wasm_import_module = "delano:wallet/actions@0.1.0")]
                    extern "C" {
                        #[link_name = "offer"]
                        fn wit_import(_: *mut u8, _: *mut u8);
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    fn wit_import(_: *mut u8, _: *mut u8) {
                        unreachable!()
                    }
                    wit_import(ptr0, ptr33);
                    let l34 = i32::from(*ptr33.add(0).cast::<u8>());
                    if layout11.size() != 0 {
                        _rt::alloc::dealloc(result11.cast(), layout11);
                    }
                    if layout13.size() != 0 {
                        _rt::alloc::dealloc(result13.cast(), layout13);
                    }
                    if layout17.size() != 0 {
                        _rt::alloc::dealloc(result17.cast(), layout17);
                    }
                    if layout19.size() != 0 {
                        _rt::alloc::dealloc(result19.cast(), layout19);
                    }
                    if layout23.size() != 0 {
                        _rt::alloc::dealloc(result23.cast(), layout23);
                    }
                    for (ptr, layout) in cleanup_list {
                        if layout.size() != 0 {
                            _rt::alloc::dealloc(ptr.cast(), layout);
                        }
                    }
                    match l34 {
                        0 => {
                            let e = {
                                let l35 = *ptr33.add(4).cast::<*mut u8>();
                                let l36 = *ptr33.add(8).cast::<usize>();
                                let len37 = l36;
                                let l38 = *ptr33.add(12).cast::<*mut u8>();
                                let l39 = *ptr33.add(16).cast::<usize>();
                                let len40 = l39;
                                let l41 = *ptr33.add(20).cast::<*mut u8>();
                                let l42 = *ptr33.add(24).cast::<usize>();
                                let len43 = l42;
                                let l44 = *ptr33.add(28).cast::<*mut u8>();
                                let l45 = *ptr33.add(32).cast::<usize>();
                                let len46 = l45;
                                let l47 = i32::from(*ptr33.add(36).cast::<u8>());
                                let l57 = *ptr33.add(48).cast::<*mut u8>();
                                let l58 = *ptr33.add(52).cast::<usize>();
                                let base62 = l57;
                                let len62 = l58;
                                let mut result62 = _rt::Vec::with_capacity(len62);
                                for i in 0..len62 {
                                    let base = base62.add(i * 8);
                                    let e62 = {
                                        let l59 = *base.add(0).cast::<*mut u8>();
                                        let l60 = *base.add(4).cast::<usize>();
                                        let len61 = l60;
                                        _rt::Vec::from_raw_parts(l59.cast(), len61, len61)
                                    };
                                    result62.push(e62);
                                }
                                _rt::cabi_dealloc(base62, len62 * 8, 4);
                                let l63 = *ptr33.add(56).cast::<*mut u8>();
                                let l64 = *ptr33.add(60).cast::<usize>();
                                let base68 = l63;
                                let len68 = l64;
                                let mut result68 = _rt::Vec::with_capacity(len68);
                                for i in 0..len68 {
                                    let base = base68.add(i * 8);
                                    let e68 = {
                                        let l65 = *base.add(0).cast::<*mut u8>();
                                        let l66 = *base.add(4).cast::<usize>();
                                        let len67 = l66;
                                        _rt::Vec::from_raw_parts(l65.cast(), len67, len67)
                                    };
                                    result68.push(e68);
                                }
                                _rt::cabi_dealloc(base68, len68 * 8, 4);
                                let l69 = *ptr33.add(64).cast::<*mut u8>();
                                let l70 = *ptr33.add(68).cast::<usize>();
                                let base74 = l69;
                                let len74 = l70;
                                let mut result74 = _rt::Vec::with_capacity(len74);
                                for i in 0..len74 {
                                    let base = base74.add(i * 8);
                                    let e74 = {
                                        let l71 = *base.add(0).cast::<*mut u8>();
                                        let l72 = *base.add(4).cast::<usize>();
                                        let len73 = l72;
                                        _rt::Vec::from_raw_parts(l71.cast(), len73, len73)
                                    };
                                    result74.push(e74);
                                }
                                _rt::cabi_dealloc(base74, len74 * 8, 4);
                                let l75 = *ptr33.add(72).cast::<*mut u8>();
                                let l76 = *ptr33.add(76).cast::<usize>();
                                let base80 = l75;
                                let len80 = l76;
                                let mut result80 = _rt::Vec::with_capacity(len80);
                                for i in 0..len80 {
                                    let base = base80.add(i * 8);
                                    let e80 = {
                                        let l77 = *base.add(0).cast::<*mut u8>();
                                        let l78 = *base.add(4).cast::<usize>();
                                        let len79 = l78;
                                        _rt::Vec::from_raw_parts(l77.cast(), len79, len79)
                                    };
                                    result80.push(e80);
                                }
                                _rt::cabi_dealloc(base80, len80 * 8, 4);
                                let l81 = *ptr33.add(80).cast::<*mut u8>();
                                let l82 = *ptr33.add(84).cast::<usize>();
                                let base91 = l81;
                                let len91 = l82;
                                let mut result91 = _rt::Vec::with_capacity(len91);
                                for i in 0..len91 {
                                    let base = base91.add(i * 12);
                                    let e91 = {
                                        let l83 = i32::from(*base.add(0).cast::<u8>());
                                        use super::super::super::delano::wallet::types::VkCompressed as V90;
                                        let v90 = match l83 {
                                            0 => {
                                                let e90 = {
                                                    let l84 = *base.add(4).cast::<*mut u8>();
                                                    let l85 = *base.add(8).cast::<usize>();
                                                    let len86 = l85;
                                                    _rt::Vec::from_raw_parts(l84.cast(), len86, len86)
                                                };
                                                V90::G1(e90)
                                            }
                                            n => {
                                                debug_assert_eq!(n, 1, "invalid enum discriminant");
                                                let e90 = {
                                                    let l87 = *base.add(4).cast::<*mut u8>();
                                                    let l88 = *base.add(8).cast::<usize>();
                                                    let len89 = l88;
                                                    _rt::Vec::from_raw_parts(l87.cast(), len89, len89)
                                                };
                                                V90::G2(e90)
                                            }
                                        };
                                        v90
                                    };
                                    result91.push(e91);
                                }
                                _rt::cabi_dealloc(base91, len91 * 12, 4);
                                super::super::super::delano::wallet::types::CredentialCompressed {
                                    sigma: super::super::super::delano::wallet::types::SignatureCompressed {
                                        z: _rt::Vec::from_raw_parts(l35.cast(), len37, len37),
                                        y_g1: _rt::Vec::from_raw_parts(l38.cast(), len40, len40),
                                        y_hat: _rt::Vec::from_raw_parts(l41.cast(), len43, len43),
                                        t: _rt::Vec::from_raw_parts(l44.cast(), len46, len46),
                                    },
                                    update_key: match l47 {
                                        0 => None,
                                        1 => {
                                            let e = {
                                                let l48 = *ptr33.add(40).cast::<*mut u8>();
                                                let l49 = *ptr33.add(44).cast::<usize>();
                                                let base56 = l48;
                                                let len56 = l49;
                                                let mut result56 = _rt::Vec::with_capacity(len56);
                                                for i in 0..len56 {
                                                    let base = base56.add(i * 8);
                                                    let e56 = {
                                                        let l50 = *base.add(0).cast::<*mut u8>();
                                                        let l51 = *base.add(4).cast::<usize>();
                                                        let base55 = l50;
                                                        let len55 = l51;
                                                        let mut result55 = _rt::Vec::with_capacity(len55);
                                                        for i in 0..len55 {
                                                            let base = base55.add(i * 8);
                                                            let e55 = {
                                                                let l52 = *base.add(0).cast::<*mut u8>();
                                                                let l53 = *base.add(4).cast::<usize>();
                                                                let len54 = l53;
                                                                _rt::Vec::from_raw_parts(l52.cast(), len54, len54)
                                                            };
                                                            result55.push(e55);
                                                        }
                                                        _rt::cabi_dealloc(base55, len55 * 8, 4);
                                                        result55
                                                    };
                                                    result56.push(e56);
                                                }
                                                _rt::cabi_dealloc(base56, len56 * 8, 4);
                                                result56
                                            };
                                            Some(e)
                                        }
                                        _ => _rt::invalid_enum_discriminant(),
                                    },
                                    commitment_vector: result62,
                                    opening_vector: result68,
                                    issuer_public: super::super::super::delano::wallet::types::IssuerPublicCompressed {
                                        parameters: super::super::super::delano::wallet::types::ParamSetCommitmentCompressed {
                                            pp_commit_g1: result74,
                                            pp_commit_g2: result80,
                                        },
                                        vk: result91,
                                    },
                                }
                            };
                            Ok(e)
                        }
                        1 => {
                            let e = {
                                let l92 = *ptr33.add(4).cast::<*mut u8>();
                                let l93 = *ptr33.add(8).cast::<usize>();
                                let len94 = l93;
                                let bytes94 = _rt::Vec::from_raw_parts(
                                    l92.cast(),
                                    len94,
                                    len94,
                                );
                                _rt::string_lift(bytes94)
                            };
                            Err(e)
                        }
                        _ => _rt::invalid_enum_discriminant(),
                    }
                }
            }
            #[allow(unused_unsafe, clippy::all)]
            /// Accept a credential offer and return the accepte Credential bytes
            pub fn accept(
                offer: &CredentialCompressed,
            ) -> Result<CredentialCompressed, _rt::String> {
                unsafe {
                    let mut cleanup_list = _rt::Vec::new();
                    #[repr(align(4))]
                    struct RetArea([::core::mem::MaybeUninit<u8>; 88]);
                    let mut ret_area = RetArea([::core::mem::MaybeUninit::uninit(); 88]);
                    let ptr0 = ret_area.0.as_mut_ptr().cast::<u8>();
                    let super::super::super::delano::wallet::types::CredentialCompressed {
                        sigma: sigma1,
                        update_key: update_key1,
                        commitment_vector: commitment_vector1,
                        opening_vector: opening_vector1,
                        issuer_public: issuer_public1,
                    } = offer;
                    let super::super::super::delano::wallet::types::SignatureCompressed {
                        z: z2,
                        y_g1: y_g12,
                        y_hat: y_hat2,
                        t: t2,
                    } = sigma1;
                    let vec3 = z2;
                    let ptr3 = vec3.as_ptr().cast::<u8>();
                    let len3 = vec3.len();
                    *ptr0.add(4).cast::<usize>() = len3;
                    *ptr0.add(0).cast::<*mut u8>() = ptr3.cast_mut();
                    let vec4 = y_g12;
                    let ptr4 = vec4.as_ptr().cast::<u8>();
                    let len4 = vec4.len();
                    *ptr0.add(12).cast::<usize>() = len4;
                    *ptr0.add(8).cast::<*mut u8>() = ptr4.cast_mut();
                    let vec5 = y_hat2;
                    let ptr5 = vec5.as_ptr().cast::<u8>();
                    let len5 = vec5.len();
                    *ptr0.add(20).cast::<usize>() = len5;
                    *ptr0.add(16).cast::<*mut u8>() = ptr5.cast_mut();
                    let vec6 = t2;
                    let ptr6 = vec6.as_ptr().cast::<u8>();
                    let len6 = vec6.len();
                    *ptr0.add(28).cast::<usize>() = len6;
                    *ptr0.add(24).cast::<*mut u8>() = ptr6.cast_mut();
                    match update_key1 {
                        Some(e) => {
                            *ptr0.add(32).cast::<u8>() = (1i32) as u8;
                            let vec9 = e;
                            let len9 = vec9.len();
                            let layout9 = _rt::alloc::Layout::from_size_align_unchecked(
                                vec9.len() * 8,
                                4,
                            );
                            let result9 = if layout9.size() != 0 {
                                let ptr = _rt::alloc::alloc(layout9).cast::<u8>();
                                if ptr.is_null() {
                                    _rt::alloc::handle_alloc_error(layout9);
                                }
                                ptr
                            } else {
                                ::core::ptr::null_mut()
                            };
                            for (i, e) in vec9.into_iter().enumerate() {
                                let base = result9.add(i * 8);
                                {
                                    let vec8 = e;
                                    let len8 = vec8.len();
                                    let layout8 = _rt::alloc::Layout::from_size_align_unchecked(
                                        vec8.len() * 8,
                                        4,
                                    );
                                    let result8 = if layout8.size() != 0 {
                                        let ptr = _rt::alloc::alloc(layout8).cast::<u8>();
                                        if ptr.is_null() {
                                            _rt::alloc::handle_alloc_error(layout8);
                                        }
                                        ptr
                                    } else {
                                        ::core::ptr::null_mut()
                                    };
                                    for (i, e) in vec8.into_iter().enumerate() {
                                        let base = result8.add(i * 8);
                                        {
                                            let vec7 = e;
                                            let ptr7 = vec7.as_ptr().cast::<u8>();
                                            let len7 = vec7.len();
                                            *base.add(4).cast::<usize>() = len7;
                                            *base.add(0).cast::<*mut u8>() = ptr7.cast_mut();
                                        }
                                    }
                                    *base.add(4).cast::<usize>() = len8;
                                    *base.add(0).cast::<*mut u8>() = result8;
                                    cleanup_list.extend_from_slice(&[(result8, layout8)]);
                                }
                            }
                            *ptr0.add(40).cast::<usize>() = len9;
                            *ptr0.add(36).cast::<*mut u8>() = result9;
                            cleanup_list.extend_from_slice(&[(result9, layout9)]);
                        }
                        None => {
                            *ptr0.add(32).cast::<u8>() = (0i32) as u8;
                        }
                    };
                    let vec11 = commitment_vector1;
                    let len11 = vec11.len();
                    let layout11 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec11.len() * 8,
                        4,
                    );
                    let result11 = if layout11.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout11).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout11);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec11.into_iter().enumerate() {
                        let base = result11.add(i * 8);
                        {
                            let vec10 = e;
                            let ptr10 = vec10.as_ptr().cast::<u8>();
                            let len10 = vec10.len();
                            *base.add(4).cast::<usize>() = len10;
                            *base.add(0).cast::<*mut u8>() = ptr10.cast_mut();
                        }
                    }
                    *ptr0.add(48).cast::<usize>() = len11;
                    *ptr0.add(44).cast::<*mut u8>() = result11;
                    let vec13 = opening_vector1;
                    let len13 = vec13.len();
                    let layout13 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec13.len() * 8,
                        4,
                    );
                    let result13 = if layout13.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout13).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout13);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec13.into_iter().enumerate() {
                        let base = result13.add(i * 8);
                        {
                            let vec12 = e;
                            let ptr12 = vec12.as_ptr().cast::<u8>();
                            let len12 = vec12.len();
                            *base.add(4).cast::<usize>() = len12;
                            *base.add(0).cast::<*mut u8>() = ptr12.cast_mut();
                        }
                    }
                    *ptr0.add(56).cast::<usize>() = len13;
                    *ptr0.add(52).cast::<*mut u8>() = result13;
                    let super::super::super::delano::wallet::types::IssuerPublicCompressed {
                        parameters: parameters14,
                        vk: vk14,
                    } = issuer_public1;
                    let super::super::super::delano::wallet::types::ParamSetCommitmentCompressed {
                        pp_commit_g1: pp_commit_g115,
                        pp_commit_g2: pp_commit_g215,
                    } = parameters14;
                    let vec17 = pp_commit_g115;
                    let len17 = vec17.len();
                    let layout17 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec17.len() * 8,
                        4,
                    );
                    let result17 = if layout17.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout17).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout17);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec17.into_iter().enumerate() {
                        let base = result17.add(i * 8);
                        {
                            let vec16 = e;
                            let ptr16 = vec16.as_ptr().cast::<u8>();
                            let len16 = vec16.len();
                            *base.add(4).cast::<usize>() = len16;
                            *base.add(0).cast::<*mut u8>() = ptr16.cast_mut();
                        }
                    }
                    *ptr0.add(64).cast::<usize>() = len17;
                    *ptr0.add(60).cast::<*mut u8>() = result17;
                    let vec19 = pp_commit_g215;
                    let len19 = vec19.len();
                    let layout19 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec19.len() * 8,
                        4,
                    );
                    let result19 = if layout19.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout19).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout19);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec19.into_iter().enumerate() {
                        let base = result19.add(i * 8);
                        {
                            let vec18 = e;
                            let ptr18 = vec18.as_ptr().cast::<u8>();
                            let len18 = vec18.len();
                            *base.add(4).cast::<usize>() = len18;
                            *base.add(0).cast::<*mut u8>() = ptr18.cast_mut();
                        }
                    }
                    *ptr0.add(72).cast::<usize>() = len19;
                    *ptr0.add(68).cast::<*mut u8>() = result19;
                    let vec23 = vk14;
                    let len23 = vec23.len();
                    let layout23 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec23.len() * 12,
                        4,
                    );
                    let result23 = if layout23.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout23).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout23);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec23.into_iter().enumerate() {
                        let base = result23.add(i * 12);
                        {
                            use super::super::super::delano::wallet::types::VkCompressed as V22;
                            match e {
                                V22::G1(e) => {
                                    *base.add(0).cast::<u8>() = (0i32) as u8;
                                    let vec20 = e;
                                    let ptr20 = vec20.as_ptr().cast::<u8>();
                                    let len20 = vec20.len();
                                    *base.add(8).cast::<usize>() = len20;
                                    *base.add(4).cast::<*mut u8>() = ptr20.cast_mut();
                                }
                                V22::G2(e) => {
                                    *base.add(0).cast::<u8>() = (1i32) as u8;
                                    let vec21 = e;
                                    let ptr21 = vec21.as_ptr().cast::<u8>();
                                    let len21 = vec21.len();
                                    *base.add(8).cast::<usize>() = len21;
                                    *base.add(4).cast::<*mut u8>() = ptr21.cast_mut();
                                }
                            }
                        }
                    }
                    *ptr0.add(80).cast::<usize>() = len23;
                    *ptr0.add(76).cast::<*mut u8>() = result23;
                    let ptr24 = ret_area.0.as_mut_ptr().cast::<u8>();
                    #[cfg(target_arch = "wasm32")]
                    #[link(wasm_import_module = "delano:wallet/actions@0.1.0")]
                    extern "C" {
                        #[link_name = "accept"]
                        fn wit_import(_: *mut u8, _: *mut u8);
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    fn wit_import(_: *mut u8, _: *mut u8) {
                        unreachable!()
                    }
                    wit_import(ptr0, ptr24);
                    let l25 = i32::from(*ptr24.add(0).cast::<u8>());
                    if layout11.size() != 0 {
                        _rt::alloc::dealloc(result11.cast(), layout11);
                    }
                    if layout13.size() != 0 {
                        _rt::alloc::dealloc(result13.cast(), layout13);
                    }
                    if layout17.size() != 0 {
                        _rt::alloc::dealloc(result17.cast(), layout17);
                    }
                    if layout19.size() != 0 {
                        _rt::alloc::dealloc(result19.cast(), layout19);
                    }
                    if layout23.size() != 0 {
                        _rt::alloc::dealloc(result23.cast(), layout23);
                    }
                    for (ptr, layout) in cleanup_list {
                        if layout.size() != 0 {
                            _rt::alloc::dealloc(ptr.cast(), layout);
                        }
                    }
                    match l25 {
                        0 => {
                            let e = {
                                let l26 = *ptr24.add(4).cast::<*mut u8>();
                                let l27 = *ptr24.add(8).cast::<usize>();
                                let len28 = l27;
                                let l29 = *ptr24.add(12).cast::<*mut u8>();
                                let l30 = *ptr24.add(16).cast::<usize>();
                                let len31 = l30;
                                let l32 = *ptr24.add(20).cast::<*mut u8>();
                                let l33 = *ptr24.add(24).cast::<usize>();
                                let len34 = l33;
                                let l35 = *ptr24.add(28).cast::<*mut u8>();
                                let l36 = *ptr24.add(32).cast::<usize>();
                                let len37 = l36;
                                let l38 = i32::from(*ptr24.add(36).cast::<u8>());
                                let l48 = *ptr24.add(48).cast::<*mut u8>();
                                let l49 = *ptr24.add(52).cast::<usize>();
                                let base53 = l48;
                                let len53 = l49;
                                let mut result53 = _rt::Vec::with_capacity(len53);
                                for i in 0..len53 {
                                    let base = base53.add(i * 8);
                                    let e53 = {
                                        let l50 = *base.add(0).cast::<*mut u8>();
                                        let l51 = *base.add(4).cast::<usize>();
                                        let len52 = l51;
                                        _rt::Vec::from_raw_parts(l50.cast(), len52, len52)
                                    };
                                    result53.push(e53);
                                }
                                _rt::cabi_dealloc(base53, len53 * 8, 4);
                                let l54 = *ptr24.add(56).cast::<*mut u8>();
                                let l55 = *ptr24.add(60).cast::<usize>();
                                let base59 = l54;
                                let len59 = l55;
                                let mut result59 = _rt::Vec::with_capacity(len59);
                                for i in 0..len59 {
                                    let base = base59.add(i * 8);
                                    let e59 = {
                                        let l56 = *base.add(0).cast::<*mut u8>();
                                        let l57 = *base.add(4).cast::<usize>();
                                        let len58 = l57;
                                        _rt::Vec::from_raw_parts(l56.cast(), len58, len58)
                                    };
                                    result59.push(e59);
                                }
                                _rt::cabi_dealloc(base59, len59 * 8, 4);
                                let l60 = *ptr24.add(64).cast::<*mut u8>();
                                let l61 = *ptr24.add(68).cast::<usize>();
                                let base65 = l60;
                                let len65 = l61;
                                let mut result65 = _rt::Vec::with_capacity(len65);
                                for i in 0..len65 {
                                    let base = base65.add(i * 8);
                                    let e65 = {
                                        let l62 = *base.add(0).cast::<*mut u8>();
                                        let l63 = *base.add(4).cast::<usize>();
                                        let len64 = l63;
                                        _rt::Vec::from_raw_parts(l62.cast(), len64, len64)
                                    };
                                    result65.push(e65);
                                }
                                _rt::cabi_dealloc(base65, len65 * 8, 4);
                                let l66 = *ptr24.add(72).cast::<*mut u8>();
                                let l67 = *ptr24.add(76).cast::<usize>();
                                let base71 = l66;
                                let len71 = l67;
                                let mut result71 = _rt::Vec::with_capacity(len71);
                                for i in 0..len71 {
                                    let base = base71.add(i * 8);
                                    let e71 = {
                                        let l68 = *base.add(0).cast::<*mut u8>();
                                        let l69 = *base.add(4).cast::<usize>();
                                        let len70 = l69;
                                        _rt::Vec::from_raw_parts(l68.cast(), len70, len70)
                                    };
                                    result71.push(e71);
                                }
                                _rt::cabi_dealloc(base71, len71 * 8, 4);
                                let l72 = *ptr24.add(80).cast::<*mut u8>();
                                let l73 = *ptr24.add(84).cast::<usize>();
                                let base82 = l72;
                                let len82 = l73;
                                let mut result82 = _rt::Vec::with_capacity(len82);
                                for i in 0..len82 {
                                    let base = base82.add(i * 12);
                                    let e82 = {
                                        let l74 = i32::from(*base.add(0).cast::<u8>());
                                        use super::super::super::delano::wallet::types::VkCompressed as V81;
                                        let v81 = match l74 {
                                            0 => {
                                                let e81 = {
                                                    let l75 = *base.add(4).cast::<*mut u8>();
                                                    let l76 = *base.add(8).cast::<usize>();
                                                    let len77 = l76;
                                                    _rt::Vec::from_raw_parts(l75.cast(), len77, len77)
                                                };
                                                V81::G1(e81)
                                            }
                                            n => {
                                                debug_assert_eq!(n, 1, "invalid enum discriminant");
                                                let e81 = {
                                                    let l78 = *base.add(4).cast::<*mut u8>();
                                                    let l79 = *base.add(8).cast::<usize>();
                                                    let len80 = l79;
                                                    _rt::Vec::from_raw_parts(l78.cast(), len80, len80)
                                                };
                                                V81::G2(e81)
                                            }
                                        };
                                        v81
                                    };
                                    result82.push(e82);
                                }
                                _rt::cabi_dealloc(base82, len82 * 12, 4);
                                super::super::super::delano::wallet::types::CredentialCompressed {
                                    sigma: super::super::super::delano::wallet::types::SignatureCompressed {
                                        z: _rt::Vec::from_raw_parts(l26.cast(), len28, len28),
                                        y_g1: _rt::Vec::from_raw_parts(l29.cast(), len31, len31),
                                        y_hat: _rt::Vec::from_raw_parts(l32.cast(), len34, len34),
                                        t: _rt::Vec::from_raw_parts(l35.cast(), len37, len37),
                                    },
                                    update_key: match l38 {
                                        0 => None,
                                        1 => {
                                            let e = {
                                                let l39 = *ptr24.add(40).cast::<*mut u8>();
                                                let l40 = *ptr24.add(44).cast::<usize>();
                                                let base47 = l39;
                                                let len47 = l40;
                                                let mut result47 = _rt::Vec::with_capacity(len47);
                                                for i in 0..len47 {
                                                    let base = base47.add(i * 8);
                                                    let e47 = {
                                                        let l41 = *base.add(0).cast::<*mut u8>();
                                                        let l42 = *base.add(4).cast::<usize>();
                                                        let base46 = l41;
                                                        let len46 = l42;
                                                        let mut result46 = _rt::Vec::with_capacity(len46);
                                                        for i in 0..len46 {
                                                            let base = base46.add(i * 8);
                                                            let e46 = {
                                                                let l43 = *base.add(0).cast::<*mut u8>();
                                                                let l44 = *base.add(4).cast::<usize>();
                                                                let len45 = l44;
                                                                _rt::Vec::from_raw_parts(l43.cast(), len45, len45)
                                                            };
                                                            result46.push(e46);
                                                        }
                                                        _rt::cabi_dealloc(base46, len46 * 8, 4);
                                                        result46
                                                    };
                                                    result47.push(e47);
                                                }
                                                _rt::cabi_dealloc(base47, len47 * 8, 4);
                                                result47
                                            };
                                            Some(e)
                                        }
                                        _ => _rt::invalid_enum_discriminant(),
                                    },
                                    commitment_vector: result53,
                                    opening_vector: result59,
                                    issuer_public: super::super::super::delano::wallet::types::IssuerPublicCompressed {
                                        parameters: super::super::super::delano::wallet::types::ParamSetCommitmentCompressed {
                                            pp_commit_g1: result65,
                                            pp_commit_g2: result71,
                                        },
                                        vk: result82,
                                    },
                                }
                            };
                            Ok(e)
                        }
                        1 => {
                            let e = {
                                let l83 = *ptr24.add(4).cast::<*mut u8>();
                                let l84 = *ptr24.add(8).cast::<usize>();
                                let len85 = l84;
                                let bytes85 = _rt::Vec::from_raw_parts(
                                    l83.cast(),
                                    len85,
                                    len85,
                                );
                                _rt::string_lift(bytes85)
                            };
                            Err(e)
                        }
                        _ => _rt::invalid_enum_discriminant(),
                    }
                }
            }
            #[allow(unused_unsafe, clippy::all)]
            /// Extend a credential with a new entry
            pub fn extend(
                cred: &CredentialCompressed,
                entry: &Entry,
            ) -> Result<CredentialCompressed, _rt::String> {
                unsafe {
                    let mut cleanup_list = _rt::Vec::new();
                    #[repr(align(4))]
                    struct RetArea([::core::mem::MaybeUninit<u8>; 92]);
                    let mut ret_area = RetArea([::core::mem::MaybeUninit::uninit(); 92]);
                    let ptr0 = ret_area.0.as_mut_ptr().cast::<u8>();
                    let super::super::super::delano::wallet::types::CredentialCompressed {
                        sigma: sigma1,
                        update_key: update_key1,
                        commitment_vector: commitment_vector1,
                        opening_vector: opening_vector1,
                        issuer_public: issuer_public1,
                    } = cred;
                    let super::super::super::delano::wallet::types::SignatureCompressed {
                        z: z2,
                        y_g1: y_g12,
                        y_hat: y_hat2,
                        t: t2,
                    } = sigma1;
                    let vec3 = z2;
                    let ptr3 = vec3.as_ptr().cast::<u8>();
                    let len3 = vec3.len();
                    *ptr0.add(4).cast::<usize>() = len3;
                    *ptr0.add(0).cast::<*mut u8>() = ptr3.cast_mut();
                    let vec4 = y_g12;
                    let ptr4 = vec4.as_ptr().cast::<u8>();
                    let len4 = vec4.len();
                    *ptr0.add(12).cast::<usize>() = len4;
                    *ptr0.add(8).cast::<*mut u8>() = ptr4.cast_mut();
                    let vec5 = y_hat2;
                    let ptr5 = vec5.as_ptr().cast::<u8>();
                    let len5 = vec5.len();
                    *ptr0.add(20).cast::<usize>() = len5;
                    *ptr0.add(16).cast::<*mut u8>() = ptr5.cast_mut();
                    let vec6 = t2;
                    let ptr6 = vec6.as_ptr().cast::<u8>();
                    let len6 = vec6.len();
                    *ptr0.add(28).cast::<usize>() = len6;
                    *ptr0.add(24).cast::<*mut u8>() = ptr6.cast_mut();
                    match update_key1 {
                        Some(e) => {
                            *ptr0.add(32).cast::<u8>() = (1i32) as u8;
                            let vec9 = e;
                            let len9 = vec9.len();
                            let layout9 = _rt::alloc::Layout::from_size_align_unchecked(
                                vec9.len() * 8,
                                4,
                            );
                            let result9 = if layout9.size() != 0 {
                                let ptr = _rt::alloc::alloc(layout9).cast::<u8>();
                                if ptr.is_null() {
                                    _rt::alloc::handle_alloc_error(layout9);
                                }
                                ptr
                            } else {
                                ::core::ptr::null_mut()
                            };
                            for (i, e) in vec9.into_iter().enumerate() {
                                let base = result9.add(i * 8);
                                {
                                    let vec8 = e;
                                    let len8 = vec8.len();
                                    let layout8 = _rt::alloc::Layout::from_size_align_unchecked(
                                        vec8.len() * 8,
                                        4,
                                    );
                                    let result8 = if layout8.size() != 0 {
                                        let ptr = _rt::alloc::alloc(layout8).cast::<u8>();
                                        if ptr.is_null() {
                                            _rt::alloc::handle_alloc_error(layout8);
                                        }
                                        ptr
                                    } else {
                                        ::core::ptr::null_mut()
                                    };
                                    for (i, e) in vec8.into_iter().enumerate() {
                                        let base = result8.add(i * 8);
                                        {
                                            let vec7 = e;
                                            let ptr7 = vec7.as_ptr().cast::<u8>();
                                            let len7 = vec7.len();
                                            *base.add(4).cast::<usize>() = len7;
                                            *base.add(0).cast::<*mut u8>() = ptr7.cast_mut();
                                        }
                                    }
                                    *base.add(4).cast::<usize>() = len8;
                                    *base.add(0).cast::<*mut u8>() = result8;
                                    cleanup_list.extend_from_slice(&[(result8, layout8)]);
                                }
                            }
                            *ptr0.add(40).cast::<usize>() = len9;
                            *ptr0.add(36).cast::<*mut u8>() = result9;
                            cleanup_list.extend_from_slice(&[(result9, layout9)]);
                        }
                        None => {
                            *ptr0.add(32).cast::<u8>() = (0i32) as u8;
                        }
                    };
                    let vec11 = commitment_vector1;
                    let len11 = vec11.len();
                    let layout11 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec11.len() * 8,
                        4,
                    );
                    let result11 = if layout11.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout11).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout11);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec11.into_iter().enumerate() {
                        let base = result11.add(i * 8);
                        {
                            let vec10 = e;
                            let ptr10 = vec10.as_ptr().cast::<u8>();
                            let len10 = vec10.len();
                            *base.add(4).cast::<usize>() = len10;
                            *base.add(0).cast::<*mut u8>() = ptr10.cast_mut();
                        }
                    }
                    *ptr0.add(48).cast::<usize>() = len11;
                    *ptr0.add(44).cast::<*mut u8>() = result11;
                    let vec13 = opening_vector1;
                    let len13 = vec13.len();
                    let layout13 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec13.len() * 8,
                        4,
                    );
                    let result13 = if layout13.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout13).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout13);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec13.into_iter().enumerate() {
                        let base = result13.add(i * 8);
                        {
                            let vec12 = e;
                            let ptr12 = vec12.as_ptr().cast::<u8>();
                            let len12 = vec12.len();
                            *base.add(4).cast::<usize>() = len12;
                            *base.add(0).cast::<*mut u8>() = ptr12.cast_mut();
                        }
                    }
                    *ptr0.add(56).cast::<usize>() = len13;
                    *ptr0.add(52).cast::<*mut u8>() = result13;
                    let super::super::super::delano::wallet::types::IssuerPublicCompressed {
                        parameters: parameters14,
                        vk: vk14,
                    } = issuer_public1;
                    let super::super::super::delano::wallet::types::ParamSetCommitmentCompressed {
                        pp_commit_g1: pp_commit_g115,
                        pp_commit_g2: pp_commit_g215,
                    } = parameters14;
                    let vec17 = pp_commit_g115;
                    let len17 = vec17.len();
                    let layout17 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec17.len() * 8,
                        4,
                    );
                    let result17 = if layout17.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout17).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout17);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec17.into_iter().enumerate() {
                        let base = result17.add(i * 8);
                        {
                            let vec16 = e;
                            let ptr16 = vec16.as_ptr().cast::<u8>();
                            let len16 = vec16.len();
                            *base.add(4).cast::<usize>() = len16;
                            *base.add(0).cast::<*mut u8>() = ptr16.cast_mut();
                        }
                    }
                    *ptr0.add(64).cast::<usize>() = len17;
                    *ptr0.add(60).cast::<*mut u8>() = result17;
                    let vec19 = pp_commit_g215;
                    let len19 = vec19.len();
                    let layout19 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec19.len() * 8,
                        4,
                    );
                    let result19 = if layout19.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout19).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout19);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec19.into_iter().enumerate() {
                        let base = result19.add(i * 8);
                        {
                            let vec18 = e;
                            let ptr18 = vec18.as_ptr().cast::<u8>();
                            let len18 = vec18.len();
                            *base.add(4).cast::<usize>() = len18;
                            *base.add(0).cast::<*mut u8>() = ptr18.cast_mut();
                        }
                    }
                    *ptr0.add(72).cast::<usize>() = len19;
                    *ptr0.add(68).cast::<*mut u8>() = result19;
                    let vec23 = vk14;
                    let len23 = vec23.len();
                    let layout23 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec23.len() * 12,
                        4,
                    );
                    let result23 = if layout23.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout23).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout23);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec23.into_iter().enumerate() {
                        let base = result23.add(i * 12);
                        {
                            use super::super::super::delano::wallet::types::VkCompressed as V22;
                            match e {
                                V22::G1(e) => {
                                    *base.add(0).cast::<u8>() = (0i32) as u8;
                                    let vec20 = e;
                                    let ptr20 = vec20.as_ptr().cast::<u8>();
                                    let len20 = vec20.len();
                                    *base.add(8).cast::<usize>() = len20;
                                    *base.add(4).cast::<*mut u8>() = ptr20.cast_mut();
                                }
                                V22::G2(e) => {
                                    *base.add(0).cast::<u8>() = (1i32) as u8;
                                    let vec21 = e;
                                    let ptr21 = vec21.as_ptr().cast::<u8>();
                                    let len21 = vec21.len();
                                    *base.add(8).cast::<usize>() = len21;
                                    *base.add(4).cast::<*mut u8>() = ptr21.cast_mut();
                                }
                            }
                        }
                    }
                    *ptr0.add(80).cast::<usize>() = len23;
                    *ptr0.add(76).cast::<*mut u8>() = result23;
                    let vec25 = entry;
                    let len25 = vec25.len();
                    let layout25 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec25.len() * 8,
                        4,
                    );
                    let result25 = if layout25.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout25).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout25);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec25.into_iter().enumerate() {
                        let base = result25.add(i * 8);
                        {
                            let vec24 = e;
                            let ptr24 = vec24.as_ptr().cast::<u8>();
                            let len24 = vec24.len();
                            *base.add(4).cast::<usize>() = len24;
                            *base.add(0).cast::<*mut u8>() = ptr24.cast_mut();
                        }
                    }
                    *ptr0.add(88).cast::<usize>() = len25;
                    *ptr0.add(84).cast::<*mut u8>() = result25;
                    let ptr26 = ret_area.0.as_mut_ptr().cast::<u8>();
                    #[cfg(target_arch = "wasm32")]
                    #[link(wasm_import_module = "delano:wallet/actions@0.1.0")]
                    extern "C" {
                        #[link_name = "extend"]
                        fn wit_import(_: *mut u8, _: *mut u8);
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    fn wit_import(_: *mut u8, _: *mut u8) {
                        unreachable!()
                    }
                    wit_import(ptr0, ptr26);
                    let l27 = i32::from(*ptr26.add(0).cast::<u8>());
                    if layout11.size() != 0 {
                        _rt::alloc::dealloc(result11.cast(), layout11);
                    }
                    if layout13.size() != 0 {
                        _rt::alloc::dealloc(result13.cast(), layout13);
                    }
                    if layout17.size() != 0 {
                        _rt::alloc::dealloc(result17.cast(), layout17);
                    }
                    if layout19.size() != 0 {
                        _rt::alloc::dealloc(result19.cast(), layout19);
                    }
                    if layout23.size() != 0 {
                        _rt::alloc::dealloc(result23.cast(), layout23);
                    }
                    if layout25.size() != 0 {
                        _rt::alloc::dealloc(result25.cast(), layout25);
                    }
                    for (ptr, layout) in cleanup_list {
                        if layout.size() != 0 {
                            _rt::alloc::dealloc(ptr.cast(), layout);
                        }
                    }
                    match l27 {
                        0 => {
                            let e = {
                                let l28 = *ptr26.add(4).cast::<*mut u8>();
                                let l29 = *ptr26.add(8).cast::<usize>();
                                let len30 = l29;
                                let l31 = *ptr26.add(12).cast::<*mut u8>();
                                let l32 = *ptr26.add(16).cast::<usize>();
                                let len33 = l32;
                                let l34 = *ptr26.add(20).cast::<*mut u8>();
                                let l35 = *ptr26.add(24).cast::<usize>();
                                let len36 = l35;
                                let l37 = *ptr26.add(28).cast::<*mut u8>();
                                let l38 = *ptr26.add(32).cast::<usize>();
                                let len39 = l38;
                                let l40 = i32::from(*ptr26.add(36).cast::<u8>());
                                let l50 = *ptr26.add(48).cast::<*mut u8>();
                                let l51 = *ptr26.add(52).cast::<usize>();
                                let base55 = l50;
                                let len55 = l51;
                                let mut result55 = _rt::Vec::with_capacity(len55);
                                for i in 0..len55 {
                                    let base = base55.add(i * 8);
                                    let e55 = {
                                        let l52 = *base.add(0).cast::<*mut u8>();
                                        let l53 = *base.add(4).cast::<usize>();
                                        let len54 = l53;
                                        _rt::Vec::from_raw_parts(l52.cast(), len54, len54)
                                    };
                                    result55.push(e55);
                                }
                                _rt::cabi_dealloc(base55, len55 * 8, 4);
                                let l56 = *ptr26.add(56).cast::<*mut u8>();
                                let l57 = *ptr26.add(60).cast::<usize>();
                                let base61 = l56;
                                let len61 = l57;
                                let mut result61 = _rt::Vec::with_capacity(len61);
                                for i in 0..len61 {
                                    let base = base61.add(i * 8);
                                    let e61 = {
                                        let l58 = *base.add(0).cast::<*mut u8>();
                                        let l59 = *base.add(4).cast::<usize>();
                                        let len60 = l59;
                                        _rt::Vec::from_raw_parts(l58.cast(), len60, len60)
                                    };
                                    result61.push(e61);
                                }
                                _rt::cabi_dealloc(base61, len61 * 8, 4);
                                let l62 = *ptr26.add(64).cast::<*mut u8>();
                                let l63 = *ptr26.add(68).cast::<usize>();
                                let base67 = l62;
                                let len67 = l63;
                                let mut result67 = _rt::Vec::with_capacity(len67);
                                for i in 0..len67 {
                                    let base = base67.add(i * 8);
                                    let e67 = {
                                        let l64 = *base.add(0).cast::<*mut u8>();
                                        let l65 = *base.add(4).cast::<usize>();
                                        let len66 = l65;
                                        _rt::Vec::from_raw_parts(l64.cast(), len66, len66)
                                    };
                                    result67.push(e67);
                                }
                                _rt::cabi_dealloc(base67, len67 * 8, 4);
                                let l68 = *ptr26.add(72).cast::<*mut u8>();
                                let l69 = *ptr26.add(76).cast::<usize>();
                                let base73 = l68;
                                let len73 = l69;
                                let mut result73 = _rt::Vec::with_capacity(len73);
                                for i in 0..len73 {
                                    let base = base73.add(i * 8);
                                    let e73 = {
                                        let l70 = *base.add(0).cast::<*mut u8>();
                                        let l71 = *base.add(4).cast::<usize>();
                                        let len72 = l71;
                                        _rt::Vec::from_raw_parts(l70.cast(), len72, len72)
                                    };
                                    result73.push(e73);
                                }
                                _rt::cabi_dealloc(base73, len73 * 8, 4);
                                let l74 = *ptr26.add(80).cast::<*mut u8>();
                                let l75 = *ptr26.add(84).cast::<usize>();
                                let base84 = l74;
                                let len84 = l75;
                                let mut result84 = _rt::Vec::with_capacity(len84);
                                for i in 0..len84 {
                                    let base = base84.add(i * 12);
                                    let e84 = {
                                        let l76 = i32::from(*base.add(0).cast::<u8>());
                                        use super::super::super::delano::wallet::types::VkCompressed as V83;
                                        let v83 = match l76 {
                                            0 => {
                                                let e83 = {
                                                    let l77 = *base.add(4).cast::<*mut u8>();
                                                    let l78 = *base.add(8).cast::<usize>();
                                                    let len79 = l78;
                                                    _rt::Vec::from_raw_parts(l77.cast(), len79, len79)
                                                };
                                                V83::G1(e83)
                                            }
                                            n => {
                                                debug_assert_eq!(n, 1, "invalid enum discriminant");
                                                let e83 = {
                                                    let l80 = *base.add(4).cast::<*mut u8>();
                                                    let l81 = *base.add(8).cast::<usize>();
                                                    let len82 = l81;
                                                    _rt::Vec::from_raw_parts(l80.cast(), len82, len82)
                                                };
                                                V83::G2(e83)
                                            }
                                        };
                                        v83
                                    };
                                    result84.push(e84);
                                }
                                _rt::cabi_dealloc(base84, len84 * 12, 4);
                                super::super::super::delano::wallet::types::CredentialCompressed {
                                    sigma: super::super::super::delano::wallet::types::SignatureCompressed {
                                        z: _rt::Vec::from_raw_parts(l28.cast(), len30, len30),
                                        y_g1: _rt::Vec::from_raw_parts(l31.cast(), len33, len33),
                                        y_hat: _rt::Vec::from_raw_parts(l34.cast(), len36, len36),
                                        t: _rt::Vec::from_raw_parts(l37.cast(), len39, len39),
                                    },
                                    update_key: match l40 {
                                        0 => None,
                                        1 => {
                                            let e = {
                                                let l41 = *ptr26.add(40).cast::<*mut u8>();
                                                let l42 = *ptr26.add(44).cast::<usize>();
                                                let base49 = l41;
                                                let len49 = l42;
                                                let mut result49 = _rt::Vec::with_capacity(len49);
                                                for i in 0..len49 {
                                                    let base = base49.add(i * 8);
                                                    let e49 = {
                                                        let l43 = *base.add(0).cast::<*mut u8>();
                                                        let l44 = *base.add(4).cast::<usize>();
                                                        let base48 = l43;
                                                        let len48 = l44;
                                                        let mut result48 = _rt::Vec::with_capacity(len48);
                                                        for i in 0..len48 {
                                                            let base = base48.add(i * 8);
                                                            let e48 = {
                                                                let l45 = *base.add(0).cast::<*mut u8>();
                                                                let l46 = *base.add(4).cast::<usize>();
                                                                let len47 = l46;
                                                                _rt::Vec::from_raw_parts(l45.cast(), len47, len47)
                                                            };
                                                            result48.push(e48);
                                                        }
                                                        _rt::cabi_dealloc(base48, len48 * 8, 4);
                                                        result48
                                                    };
                                                    result49.push(e49);
                                                }
                                                _rt::cabi_dealloc(base49, len49 * 8, 4);
                                                result49
                                            };
                                            Some(e)
                                        }
                                        _ => _rt::invalid_enum_discriminant(),
                                    },
                                    commitment_vector: result55,
                                    opening_vector: result61,
                                    issuer_public: super::super::super::delano::wallet::types::IssuerPublicCompressed {
                                        parameters: super::super::super::delano::wallet::types::ParamSetCommitmentCompressed {
                                            pp_commit_g1: result67,
                                            pp_commit_g2: result73,
                                        },
                                        vk: result84,
                                    },
                                }
                            };
                            Ok(e)
                        }
                        1 => {
                            let e = {
                                let l85 = *ptr26.add(4).cast::<*mut u8>();
                                let l86 = *ptr26.add(8).cast::<usize>();
                                let len87 = l86;
                                let bytes87 = _rt::Vec::from_raw_parts(
                                    l85.cast(),
                                    len87,
                                    len87,
                                );
                                _rt::string_lift(bytes87)
                            };
                            Err(e)
                        }
                        _ => _rt::invalid_enum_discriminant(),
                    }
                }
            }
            #[allow(unused_unsafe, clippy::all)]
            /// Export a function that proves selected attributes in a given credential
            /// Returns the selected attributes in the proper order in order to verify the proof,
            /// as each Attribute needs to be verified from their respective Entry.
            pub fn prove(values: &Provables) -> Result<Proven, _rt::String> {
                unsafe {
                    let mut cleanup_list = _rt::Vec::new();
                    #[repr(align(4))]
                    struct RetArea([::core::mem::MaybeUninit<u8>; 128]);
                    let mut ret_area = RetArea(
                        [::core::mem::MaybeUninit::uninit(); 128],
                    );
                    let ptr0 = ret_area.0.as_mut_ptr().cast::<u8>();
                    let super::super::super::delano::wallet::types::Provables {
                        credential: credential1,
                        entries: entries1,
                        selected: selected1,
                        nonce: nonce1,
                    } = values;
                    let super::super::super::delano::wallet::types::CredentialCompressed {
                        sigma: sigma2,
                        update_key: update_key2,
                        commitment_vector: commitment_vector2,
                        opening_vector: opening_vector2,
                        issuer_public: issuer_public2,
                    } = credential1;
                    let super::super::super::delano::wallet::types::SignatureCompressed {
                        z: z3,
                        y_g1: y_g13,
                        y_hat: y_hat3,
                        t: t3,
                    } = sigma2;
                    let vec4 = z3;
                    let ptr4 = vec4.as_ptr().cast::<u8>();
                    let len4 = vec4.len();
                    *ptr0.add(4).cast::<usize>() = len4;
                    *ptr0.add(0).cast::<*mut u8>() = ptr4.cast_mut();
                    let vec5 = y_g13;
                    let ptr5 = vec5.as_ptr().cast::<u8>();
                    let len5 = vec5.len();
                    *ptr0.add(12).cast::<usize>() = len5;
                    *ptr0.add(8).cast::<*mut u8>() = ptr5.cast_mut();
                    let vec6 = y_hat3;
                    let ptr6 = vec6.as_ptr().cast::<u8>();
                    let len6 = vec6.len();
                    *ptr0.add(20).cast::<usize>() = len6;
                    *ptr0.add(16).cast::<*mut u8>() = ptr6.cast_mut();
                    let vec7 = t3;
                    let ptr7 = vec7.as_ptr().cast::<u8>();
                    let len7 = vec7.len();
                    *ptr0.add(28).cast::<usize>() = len7;
                    *ptr0.add(24).cast::<*mut u8>() = ptr7.cast_mut();
                    match update_key2 {
                        Some(e) => {
                            *ptr0.add(32).cast::<u8>() = (1i32) as u8;
                            let vec10 = e;
                            let len10 = vec10.len();
                            let layout10 = _rt::alloc::Layout::from_size_align_unchecked(
                                vec10.len() * 8,
                                4,
                            );
                            let result10 = if layout10.size() != 0 {
                                let ptr = _rt::alloc::alloc(layout10).cast::<u8>();
                                if ptr.is_null() {
                                    _rt::alloc::handle_alloc_error(layout10);
                                }
                                ptr
                            } else {
                                ::core::ptr::null_mut()
                            };
                            for (i, e) in vec10.into_iter().enumerate() {
                                let base = result10.add(i * 8);
                                {
                                    let vec9 = e;
                                    let len9 = vec9.len();
                                    let layout9 = _rt::alloc::Layout::from_size_align_unchecked(
                                        vec9.len() * 8,
                                        4,
                                    );
                                    let result9 = if layout9.size() != 0 {
                                        let ptr = _rt::alloc::alloc(layout9).cast::<u8>();
                                        if ptr.is_null() {
                                            _rt::alloc::handle_alloc_error(layout9);
                                        }
                                        ptr
                                    } else {
                                        ::core::ptr::null_mut()
                                    };
                                    for (i, e) in vec9.into_iter().enumerate() {
                                        let base = result9.add(i * 8);
                                        {
                                            let vec8 = e;
                                            let ptr8 = vec8.as_ptr().cast::<u8>();
                                            let len8 = vec8.len();
                                            *base.add(4).cast::<usize>() = len8;
                                            *base.add(0).cast::<*mut u8>() = ptr8.cast_mut();
                                        }
                                    }
                                    *base.add(4).cast::<usize>() = len9;
                                    *base.add(0).cast::<*mut u8>() = result9;
                                    cleanup_list.extend_from_slice(&[(result9, layout9)]);
                                }
                            }
                            *ptr0.add(40).cast::<usize>() = len10;
                            *ptr0.add(36).cast::<*mut u8>() = result10;
                            cleanup_list.extend_from_slice(&[(result10, layout10)]);
                        }
                        None => {
                            *ptr0.add(32).cast::<u8>() = (0i32) as u8;
                        }
                    };
                    let vec12 = commitment_vector2;
                    let len12 = vec12.len();
                    let layout12 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec12.len() * 8,
                        4,
                    );
                    let result12 = if layout12.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout12).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout12);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec12.into_iter().enumerate() {
                        let base = result12.add(i * 8);
                        {
                            let vec11 = e;
                            let ptr11 = vec11.as_ptr().cast::<u8>();
                            let len11 = vec11.len();
                            *base.add(4).cast::<usize>() = len11;
                            *base.add(0).cast::<*mut u8>() = ptr11.cast_mut();
                        }
                    }
                    *ptr0.add(48).cast::<usize>() = len12;
                    *ptr0.add(44).cast::<*mut u8>() = result12;
                    let vec14 = opening_vector2;
                    let len14 = vec14.len();
                    let layout14 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec14.len() * 8,
                        4,
                    );
                    let result14 = if layout14.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout14).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout14);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec14.into_iter().enumerate() {
                        let base = result14.add(i * 8);
                        {
                            let vec13 = e;
                            let ptr13 = vec13.as_ptr().cast::<u8>();
                            let len13 = vec13.len();
                            *base.add(4).cast::<usize>() = len13;
                            *base.add(0).cast::<*mut u8>() = ptr13.cast_mut();
                        }
                    }
                    *ptr0.add(56).cast::<usize>() = len14;
                    *ptr0.add(52).cast::<*mut u8>() = result14;
                    let super::super::super::delano::wallet::types::IssuerPublicCompressed {
                        parameters: parameters15,
                        vk: vk15,
                    } = issuer_public2;
                    let super::super::super::delano::wallet::types::ParamSetCommitmentCompressed {
                        pp_commit_g1: pp_commit_g116,
                        pp_commit_g2: pp_commit_g216,
                    } = parameters15;
                    let vec18 = pp_commit_g116;
                    let len18 = vec18.len();
                    let layout18 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec18.len() * 8,
                        4,
                    );
                    let result18 = if layout18.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout18).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout18);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec18.into_iter().enumerate() {
                        let base = result18.add(i * 8);
                        {
                            let vec17 = e;
                            let ptr17 = vec17.as_ptr().cast::<u8>();
                            let len17 = vec17.len();
                            *base.add(4).cast::<usize>() = len17;
                            *base.add(0).cast::<*mut u8>() = ptr17.cast_mut();
                        }
                    }
                    *ptr0.add(64).cast::<usize>() = len18;
                    *ptr0.add(60).cast::<*mut u8>() = result18;
                    let vec20 = pp_commit_g216;
                    let len20 = vec20.len();
                    let layout20 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec20.len() * 8,
                        4,
                    );
                    let result20 = if layout20.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout20).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout20);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec20.into_iter().enumerate() {
                        let base = result20.add(i * 8);
                        {
                            let vec19 = e;
                            let ptr19 = vec19.as_ptr().cast::<u8>();
                            let len19 = vec19.len();
                            *base.add(4).cast::<usize>() = len19;
                            *base.add(0).cast::<*mut u8>() = ptr19.cast_mut();
                        }
                    }
                    *ptr0.add(72).cast::<usize>() = len20;
                    *ptr0.add(68).cast::<*mut u8>() = result20;
                    let vec24 = vk15;
                    let len24 = vec24.len();
                    let layout24 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec24.len() * 12,
                        4,
                    );
                    let result24 = if layout24.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout24).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout24);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec24.into_iter().enumerate() {
                        let base = result24.add(i * 12);
                        {
                            use super::super::super::delano::wallet::types::VkCompressed as V23;
                            match e {
                                V23::G1(e) => {
                                    *base.add(0).cast::<u8>() = (0i32) as u8;
                                    let vec21 = e;
                                    let ptr21 = vec21.as_ptr().cast::<u8>();
                                    let len21 = vec21.len();
                                    *base.add(8).cast::<usize>() = len21;
                                    *base.add(4).cast::<*mut u8>() = ptr21.cast_mut();
                                }
                                V23::G2(e) => {
                                    *base.add(0).cast::<u8>() = (1i32) as u8;
                                    let vec22 = e;
                                    let ptr22 = vec22.as_ptr().cast::<u8>();
                                    let len22 = vec22.len();
                                    *base.add(8).cast::<usize>() = len22;
                                    *base.add(4).cast::<*mut u8>() = ptr22.cast_mut();
                                }
                            }
                        }
                    }
                    *ptr0.add(80).cast::<usize>() = len24;
                    *ptr0.add(76).cast::<*mut u8>() = result24;
                    let vec27 = entries1;
                    let len27 = vec27.len();
                    let layout27 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec27.len() * 8,
                        4,
                    );
                    let result27 = if layout27.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout27).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout27);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec27.into_iter().enumerate() {
                        let base = result27.add(i * 8);
                        {
                            let vec26 = e;
                            let len26 = vec26.len();
                            let layout26 = _rt::alloc::Layout::from_size_align_unchecked(
                                vec26.len() * 8,
                                4,
                            );
                            let result26 = if layout26.size() != 0 {
                                let ptr = _rt::alloc::alloc(layout26).cast::<u8>();
                                if ptr.is_null() {
                                    _rt::alloc::handle_alloc_error(layout26);
                                }
                                ptr
                            } else {
                                ::core::ptr::null_mut()
                            };
                            for (i, e) in vec26.into_iter().enumerate() {
                                let base = result26.add(i * 8);
                                {
                                    let vec25 = e;
                                    let ptr25 = vec25.as_ptr().cast::<u8>();
                                    let len25 = vec25.len();
                                    *base.add(4).cast::<usize>() = len25;
                                    *base.add(0).cast::<*mut u8>() = ptr25.cast_mut();
                                }
                            }
                            *base.add(4).cast::<usize>() = len26;
                            *base.add(0).cast::<*mut u8>() = result26;
                            cleanup_list.extend_from_slice(&[(result26, layout26)]);
                        }
                    }
                    *ptr0.add(88).cast::<usize>() = len27;
                    *ptr0.add(84).cast::<*mut u8>() = result27;
                    let vec29 = selected1;
                    let len29 = vec29.len();
                    let layout29 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec29.len() * 8,
                        4,
                    );
                    let result29 = if layout29.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout29).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout29);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec29.into_iter().enumerate() {
                        let base = result29.add(i * 8);
                        {
                            let vec28 = e;
                            let ptr28 = vec28.as_ptr().cast::<u8>();
                            let len28 = vec28.len();
                            *base.add(4).cast::<usize>() = len28;
                            *base.add(0).cast::<*mut u8>() = ptr28.cast_mut();
                        }
                    }
                    *ptr0.add(96).cast::<usize>() = len29;
                    *ptr0.add(92).cast::<*mut u8>() = result29;
                    let vec30 = nonce1;
                    let ptr30 = vec30.as_ptr().cast::<u8>();
                    let len30 = vec30.len();
                    *ptr0.add(104).cast::<usize>() = len30;
                    *ptr0.add(100).cast::<*mut u8>() = ptr30.cast_mut();
                    let ptr31 = ret_area.0.as_mut_ptr().cast::<u8>();
                    #[cfg(target_arch = "wasm32")]
                    #[link(wasm_import_module = "delano:wallet/actions@0.1.0")]
                    extern "C" {
                        #[link_name = "prove"]
                        fn wit_import(_: *mut u8, _: *mut u8);
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    fn wit_import(_: *mut u8, _: *mut u8) {
                        unreachable!()
                    }
                    wit_import(ptr0, ptr31);
                    let l32 = i32::from(*ptr31.add(0).cast::<u8>());
                    if layout12.size() != 0 {
                        _rt::alloc::dealloc(result12.cast(), layout12);
                    }
                    if layout14.size() != 0 {
                        _rt::alloc::dealloc(result14.cast(), layout14);
                    }
                    if layout18.size() != 0 {
                        _rt::alloc::dealloc(result18.cast(), layout18);
                    }
                    if layout20.size() != 0 {
                        _rt::alloc::dealloc(result20.cast(), layout20);
                    }
                    if layout24.size() != 0 {
                        _rt::alloc::dealloc(result24.cast(), layout24);
                    }
                    if layout27.size() != 0 {
                        _rt::alloc::dealloc(result27.cast(), layout27);
                    }
                    if layout29.size() != 0 {
                        _rt::alloc::dealloc(result29.cast(), layout29);
                    }
                    for (ptr, layout) in cleanup_list {
                        if layout.size() != 0 {
                            _rt::alloc::dealloc(ptr.cast(), layout);
                        }
                    }
                    match l32 {
                        0 => {
                            let e = {
                                let l33 = *ptr31.add(4).cast::<*mut u8>();
                                let l34 = *ptr31.add(8).cast::<usize>();
                                let len35 = l34;
                                let l36 = *ptr31.add(12).cast::<*mut u8>();
                                let l37 = *ptr31.add(16).cast::<usize>();
                                let len38 = l37;
                                let l39 = *ptr31.add(20).cast::<*mut u8>();
                                let l40 = *ptr31.add(24).cast::<usize>();
                                let len41 = l40;
                                let l42 = *ptr31.add(28).cast::<*mut u8>();
                                let l43 = *ptr31.add(32).cast::<usize>();
                                let len44 = l43;
                                let l45 = *ptr31.add(36).cast::<*mut u8>();
                                let l46 = *ptr31.add(40).cast::<usize>();
                                let base50 = l45;
                                let len50 = l46;
                                let mut result50 = _rt::Vec::with_capacity(len50);
                                for i in 0..len50 {
                                    let base = base50.add(i * 8);
                                    let e50 = {
                                        let l47 = *base.add(0).cast::<*mut u8>();
                                        let l48 = *base.add(4).cast::<usize>();
                                        let len49 = l48;
                                        _rt::Vec::from_raw_parts(l47.cast(), len49, len49)
                                    };
                                    result50.push(e50);
                                }
                                _rt::cabi_dealloc(base50, len50 * 8, 4);
                                let l51 = *ptr31.add(44).cast::<*mut u8>();
                                let l52 = *ptr31.add(48).cast::<usize>();
                                let len53 = l52;
                                let l54 = *ptr31.add(52).cast::<*mut u8>();
                                let l55 = *ptr31.add(56).cast::<usize>();
                                let len56 = l55;
                                let l57 = *ptr31.add(60).cast::<*mut u8>();
                                let l58 = *ptr31.add(64).cast::<usize>();
                                let len59 = l58;
                                let l60 = *ptr31.add(68).cast::<*mut u8>();
                                let l61 = *ptr31.add(72).cast::<usize>();
                                let len62 = l61;
                                let l63 = i32::from(*ptr31.add(76).cast::<u8>());
                                let l67 = *ptr31.add(88).cast::<*mut u8>();
                                let l68 = *ptr31.add(92).cast::<usize>();
                                let len69 = l68;
                                let l70 = *ptr31.add(96).cast::<*mut u8>();
                                let l71 = *ptr31.add(100).cast::<usize>();
                                let len72 = l71;
                                let l73 = *ptr31.add(104).cast::<*mut u8>();
                                let l74 = *ptr31.add(108).cast::<usize>();
                                let len75 = l74;
                                let l76 = *ptr31.add(112).cast::<*mut u8>();
                                let l77 = *ptr31.add(116).cast::<usize>();
                                let len78 = l77;
                                let l79 = *ptr31.add(120).cast::<*mut u8>();
                                let l80 = *ptr31.add(124).cast::<usize>();
                                let base87 = l79;
                                let len87 = l80;
                                let mut result87 = _rt::Vec::with_capacity(len87);
                                for i in 0..len87 {
                                    let base = base87.add(i * 8);
                                    let e87 = {
                                        let l81 = *base.add(0).cast::<*mut u8>();
                                        let l82 = *base.add(4).cast::<usize>();
                                        let base86 = l81;
                                        let len86 = l82;
                                        let mut result86 = _rt::Vec::with_capacity(len86);
                                        for i in 0..len86 {
                                            let base = base86.add(i * 8);
                                            let e86 = {
                                                let l83 = *base.add(0).cast::<*mut u8>();
                                                let l84 = *base.add(4).cast::<usize>();
                                                let len85 = l84;
                                                _rt::Vec::from_raw_parts(l83.cast(), len85, len85)
                                            };
                                            result86.push(e86);
                                        }
                                        _rt::cabi_dealloc(base86, len86 * 8, 4);
                                        result86
                                    };
                                    result87.push(e87);
                                }
                                _rt::cabi_dealloc(base87, len87 * 8, 4);
                                super::super::super::delano::wallet::types::Proven {
                                    proof: super::super::super::delano::wallet::types::CredProofCompressed {
                                        sigma: super::super::super::delano::wallet::types::SignatureCompressed {
                                            z: _rt::Vec::from_raw_parts(l33.cast(), len35, len35),
                                            y_g1: _rt::Vec::from_raw_parts(l36.cast(), len38, len38),
                                            y_hat: _rt::Vec::from_raw_parts(l39.cast(), len41, len41),
                                            t: _rt::Vec::from_raw_parts(l42.cast(), len44, len44),
                                        },
                                        commitment_vector: result50,
                                        witness_pi: _rt::Vec::from_raw_parts(
                                            l51.cast(),
                                            len53,
                                            len53,
                                        ),
                                        nym_proof: super::super::super::delano::wallet::types::NymProofCompressed {
                                            challenge: _rt::Vec::from_raw_parts(
                                                l54.cast(),
                                                len56,
                                                len56,
                                            ),
                                            pedersen_open: super::super::super::delano::wallet::types::PedersenOpenCompressed {
                                                open_randomness: _rt::Vec::from_raw_parts(
                                                    l57.cast(),
                                                    len59,
                                                    len59,
                                                ),
                                                announce_randomness: _rt::Vec::from_raw_parts(
                                                    l60.cast(),
                                                    len62,
                                                    len62,
                                                ),
                                                announce_element: match l63 {
                                                    0 => None,
                                                    1 => {
                                                        let e = {
                                                            let l64 = *ptr31.add(80).cast::<*mut u8>();
                                                            let l65 = *ptr31.add(84).cast::<usize>();
                                                            let len66 = l65;
                                                            _rt::Vec::from_raw_parts(l64.cast(), len66, len66)
                                                        };
                                                        Some(e)
                                                    }
                                                    _ => _rt::invalid_enum_discriminant(),
                                                },
                                            },
                                            pedersen_commit: _rt::Vec::from_raw_parts(
                                                l67.cast(),
                                                len69,
                                                len69,
                                            ),
                                            public_key: _rt::Vec::from_raw_parts(
                                                l70.cast(),
                                                len72,
                                                len72,
                                            ),
                                            response: _rt::Vec::from_raw_parts(
                                                l73.cast(),
                                                len75,
                                                len75,
                                            ),
                                            damgard: super::super::super::delano::wallet::types::DamgardTransformCompressed {
                                                pedersen: super::super::super::delano::wallet::types::PedersenCompressed {
                                                    h: _rt::Vec::from_raw_parts(l76.cast(), len78, len78),
                                                },
                                            },
                                        },
                                    },
                                    selected: result87,
                                }
                            };
                            Ok(e)
                        }
                        1 => {
                            let e = {
                                let l88 = *ptr31.add(4).cast::<*mut u8>();
                                let l89 = *ptr31.add(8).cast::<usize>();
                                let len90 = l89;
                                let bytes90 = _rt::Vec::from_raw_parts(
                                    l88.cast(),
                                    len90,
                                    len90,
                                );
                                _rt::string_lift(bytes90)
                            };
                            Err(e)
                        }
                        _ => _rt::invalid_enum_discriminant(),
                    }
                }
            }
            #[allow(unused_unsafe, clippy::all)]
            /// Export a function that verifies a proof against a public key, nonce and selected attributes
            pub fn verify(values: &Verifiables) -> Result<bool, _rt::String> {
                unsafe {
                    let mut cleanup_list = _rt::Vec::new();
                    #[repr(align(4))]
                    struct RetArea([::core::mem::MaybeUninit<u8>; 160]);
                    let mut ret_area = RetArea(
                        [::core::mem::MaybeUninit::uninit(); 160],
                    );
                    let ptr0 = ret_area.0.as_mut_ptr().cast::<u8>();
                    let super::super::super::delano::wallet::types::Verifiables {
                        proof: proof1,
                        issuer_public: issuer_public1,
                        nonce: nonce1,
                        selected: selected1,
                    } = values;
                    let super::super::super::delano::wallet::types::CredProofCompressed {
                        sigma: sigma2,
                        commitment_vector: commitment_vector2,
                        witness_pi: witness_pi2,
                        nym_proof: nym_proof2,
                    } = proof1;
                    let super::super::super::delano::wallet::types::SignatureCompressed {
                        z: z3,
                        y_g1: y_g13,
                        y_hat: y_hat3,
                        t: t3,
                    } = sigma2;
                    let vec4 = z3;
                    let ptr4 = vec4.as_ptr().cast::<u8>();
                    let len4 = vec4.len();
                    *ptr0.add(4).cast::<usize>() = len4;
                    *ptr0.add(0).cast::<*mut u8>() = ptr4.cast_mut();
                    let vec5 = y_g13;
                    let ptr5 = vec5.as_ptr().cast::<u8>();
                    let len5 = vec5.len();
                    *ptr0.add(12).cast::<usize>() = len5;
                    *ptr0.add(8).cast::<*mut u8>() = ptr5.cast_mut();
                    let vec6 = y_hat3;
                    let ptr6 = vec6.as_ptr().cast::<u8>();
                    let len6 = vec6.len();
                    *ptr0.add(20).cast::<usize>() = len6;
                    *ptr0.add(16).cast::<*mut u8>() = ptr6.cast_mut();
                    let vec7 = t3;
                    let ptr7 = vec7.as_ptr().cast::<u8>();
                    let len7 = vec7.len();
                    *ptr0.add(28).cast::<usize>() = len7;
                    *ptr0.add(24).cast::<*mut u8>() = ptr7.cast_mut();
                    let vec9 = commitment_vector2;
                    let len9 = vec9.len();
                    let layout9 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec9.len() * 8,
                        4,
                    );
                    let result9 = if layout9.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout9).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout9);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec9.into_iter().enumerate() {
                        let base = result9.add(i * 8);
                        {
                            let vec8 = e;
                            let ptr8 = vec8.as_ptr().cast::<u8>();
                            let len8 = vec8.len();
                            *base.add(4).cast::<usize>() = len8;
                            *base.add(0).cast::<*mut u8>() = ptr8.cast_mut();
                        }
                    }
                    *ptr0.add(36).cast::<usize>() = len9;
                    *ptr0.add(32).cast::<*mut u8>() = result9;
                    let vec10 = witness_pi2;
                    let ptr10 = vec10.as_ptr().cast::<u8>();
                    let len10 = vec10.len();
                    *ptr0.add(44).cast::<usize>() = len10;
                    *ptr0.add(40).cast::<*mut u8>() = ptr10.cast_mut();
                    let super::super::super::delano::wallet::types::NymProofCompressed {
                        challenge: challenge11,
                        pedersen_open: pedersen_open11,
                        pedersen_commit: pedersen_commit11,
                        public_key: public_key11,
                        response: response11,
                        damgard: damgard11,
                    } = nym_proof2;
                    let vec12 = challenge11;
                    let ptr12 = vec12.as_ptr().cast::<u8>();
                    let len12 = vec12.len();
                    *ptr0.add(52).cast::<usize>() = len12;
                    *ptr0.add(48).cast::<*mut u8>() = ptr12.cast_mut();
                    let super::super::super::delano::wallet::types::PedersenOpenCompressed {
                        open_randomness: open_randomness13,
                        announce_randomness: announce_randomness13,
                        announce_element: announce_element13,
                    } = pedersen_open11;
                    let vec14 = open_randomness13;
                    let ptr14 = vec14.as_ptr().cast::<u8>();
                    let len14 = vec14.len();
                    *ptr0.add(60).cast::<usize>() = len14;
                    *ptr0.add(56).cast::<*mut u8>() = ptr14.cast_mut();
                    let vec15 = announce_randomness13;
                    let ptr15 = vec15.as_ptr().cast::<u8>();
                    let len15 = vec15.len();
                    *ptr0.add(68).cast::<usize>() = len15;
                    *ptr0.add(64).cast::<*mut u8>() = ptr15.cast_mut();
                    match announce_element13 {
                        Some(e) => {
                            *ptr0.add(72).cast::<u8>() = (1i32) as u8;
                            let vec16 = e;
                            let ptr16 = vec16.as_ptr().cast::<u8>();
                            let len16 = vec16.len();
                            *ptr0.add(80).cast::<usize>() = len16;
                            *ptr0.add(76).cast::<*mut u8>() = ptr16.cast_mut();
                        }
                        None => {
                            *ptr0.add(72).cast::<u8>() = (0i32) as u8;
                        }
                    };
                    let vec17 = pedersen_commit11;
                    let ptr17 = vec17.as_ptr().cast::<u8>();
                    let len17 = vec17.len();
                    *ptr0.add(88).cast::<usize>() = len17;
                    *ptr0.add(84).cast::<*mut u8>() = ptr17.cast_mut();
                    let vec18 = public_key11;
                    let ptr18 = vec18.as_ptr().cast::<u8>();
                    let len18 = vec18.len();
                    *ptr0.add(96).cast::<usize>() = len18;
                    *ptr0.add(92).cast::<*mut u8>() = ptr18.cast_mut();
                    let vec19 = response11;
                    let ptr19 = vec19.as_ptr().cast::<u8>();
                    let len19 = vec19.len();
                    *ptr0.add(104).cast::<usize>() = len19;
                    *ptr0.add(100).cast::<*mut u8>() = ptr19.cast_mut();
                    let super::super::super::delano::wallet::types::DamgardTransformCompressed {
                        pedersen: pedersen20,
                    } = damgard11;
                    let super::super::super::delano::wallet::types::PedersenCompressed {
                        h: h21,
                    } = pedersen20;
                    let vec22 = h21;
                    let ptr22 = vec22.as_ptr().cast::<u8>();
                    let len22 = vec22.len();
                    *ptr0.add(112).cast::<usize>() = len22;
                    *ptr0.add(108).cast::<*mut u8>() = ptr22.cast_mut();
                    let super::super::super::delano::wallet::types::IssuerPublicCompressed {
                        parameters: parameters23,
                        vk: vk23,
                    } = issuer_public1;
                    let super::super::super::delano::wallet::types::ParamSetCommitmentCompressed {
                        pp_commit_g1: pp_commit_g124,
                        pp_commit_g2: pp_commit_g224,
                    } = parameters23;
                    let vec26 = pp_commit_g124;
                    let len26 = vec26.len();
                    let layout26 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec26.len() * 8,
                        4,
                    );
                    let result26 = if layout26.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout26).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout26);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec26.into_iter().enumerate() {
                        let base = result26.add(i * 8);
                        {
                            let vec25 = e;
                            let ptr25 = vec25.as_ptr().cast::<u8>();
                            let len25 = vec25.len();
                            *base.add(4).cast::<usize>() = len25;
                            *base.add(0).cast::<*mut u8>() = ptr25.cast_mut();
                        }
                    }
                    *ptr0.add(120).cast::<usize>() = len26;
                    *ptr0.add(116).cast::<*mut u8>() = result26;
                    let vec28 = pp_commit_g224;
                    let len28 = vec28.len();
                    let layout28 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec28.len() * 8,
                        4,
                    );
                    let result28 = if layout28.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout28).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout28);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec28.into_iter().enumerate() {
                        let base = result28.add(i * 8);
                        {
                            let vec27 = e;
                            let ptr27 = vec27.as_ptr().cast::<u8>();
                            let len27 = vec27.len();
                            *base.add(4).cast::<usize>() = len27;
                            *base.add(0).cast::<*mut u8>() = ptr27.cast_mut();
                        }
                    }
                    *ptr0.add(128).cast::<usize>() = len28;
                    *ptr0.add(124).cast::<*mut u8>() = result28;
                    let vec32 = vk23;
                    let len32 = vec32.len();
                    let layout32 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec32.len() * 12,
                        4,
                    );
                    let result32 = if layout32.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout32).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout32);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec32.into_iter().enumerate() {
                        let base = result32.add(i * 12);
                        {
                            use super::super::super::delano::wallet::types::VkCompressed as V31;
                            match e {
                                V31::G1(e) => {
                                    *base.add(0).cast::<u8>() = (0i32) as u8;
                                    let vec29 = e;
                                    let ptr29 = vec29.as_ptr().cast::<u8>();
                                    let len29 = vec29.len();
                                    *base.add(8).cast::<usize>() = len29;
                                    *base.add(4).cast::<*mut u8>() = ptr29.cast_mut();
                                }
                                V31::G2(e) => {
                                    *base.add(0).cast::<u8>() = (1i32) as u8;
                                    let vec30 = e;
                                    let ptr30 = vec30.as_ptr().cast::<u8>();
                                    let len30 = vec30.len();
                                    *base.add(8).cast::<usize>() = len30;
                                    *base.add(4).cast::<*mut u8>() = ptr30.cast_mut();
                                }
                            }
                        }
                    }
                    *ptr0.add(136).cast::<usize>() = len32;
                    *ptr0.add(132).cast::<*mut u8>() = result32;
                    match nonce1 {
                        Some(e) => {
                            *ptr0.add(140).cast::<u8>() = (1i32) as u8;
                            let vec33 = e;
                            let ptr33 = vec33.as_ptr().cast::<u8>();
                            let len33 = vec33.len();
                            *ptr0.add(148).cast::<usize>() = len33;
                            *ptr0.add(144).cast::<*mut u8>() = ptr33.cast_mut();
                        }
                        None => {
                            *ptr0.add(140).cast::<u8>() = (0i32) as u8;
                        }
                    };
                    let vec36 = selected1;
                    let len36 = vec36.len();
                    let layout36 = _rt::alloc::Layout::from_size_align_unchecked(
                        vec36.len() * 8,
                        4,
                    );
                    let result36 = if layout36.size() != 0 {
                        let ptr = _rt::alloc::alloc(layout36).cast::<u8>();
                        if ptr.is_null() {
                            _rt::alloc::handle_alloc_error(layout36);
                        }
                        ptr
                    } else {
                        ::core::ptr::null_mut()
                    };
                    for (i, e) in vec36.into_iter().enumerate() {
                        let base = result36.add(i * 8);
                        {
                            let vec35 = e;
                            let len35 = vec35.len();
                            let layout35 = _rt::alloc::Layout::from_size_align_unchecked(
                                vec35.len() * 8,
                                4,
                            );
                            let result35 = if layout35.size() != 0 {
                                let ptr = _rt::alloc::alloc(layout35).cast::<u8>();
                                if ptr.is_null() {
                                    _rt::alloc::handle_alloc_error(layout35);
                                }
                                ptr
                            } else {
                                ::core::ptr::null_mut()
                            };
                            for (i, e) in vec35.into_iter().enumerate() {
                                let base = result35.add(i * 8);
                                {
                                    let vec34 = e;
                                    let ptr34 = vec34.as_ptr().cast::<u8>();
                                    let len34 = vec34.len();
                                    *base.add(4).cast::<usize>() = len34;
                                    *base.add(0).cast::<*mut u8>() = ptr34.cast_mut();
                                }
                            }
                            *base.add(4).cast::<usize>() = len35;
                            *base.add(0).cast::<*mut u8>() = result35;
                            cleanup_list.extend_from_slice(&[(result35, layout35)]);
                        }
                    }
                    *ptr0.add(156).cast::<usize>() = len36;
                    *ptr0.add(152).cast::<*mut u8>() = result36;
                    let ptr37 = ret_area.0.as_mut_ptr().cast::<u8>();
                    #[cfg(target_arch = "wasm32")]
                    #[link(wasm_import_module = "delano:wallet/actions@0.1.0")]
                    extern "C" {
                        #[link_name = "verify"]
                        fn wit_import(_: *mut u8, _: *mut u8);
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    fn wit_import(_: *mut u8, _: *mut u8) {
                        unreachable!()
                    }
                    wit_import(ptr0, ptr37);
                    let l38 = i32::from(*ptr37.add(0).cast::<u8>());
                    if layout9.size() != 0 {
                        _rt::alloc::dealloc(result9.cast(), layout9);
                    }
                    if layout26.size() != 0 {
                        _rt::alloc::dealloc(result26.cast(), layout26);
                    }
                    if layout28.size() != 0 {
                        _rt::alloc::dealloc(result28.cast(), layout28);
                    }
                    if layout32.size() != 0 {
                        _rt::alloc::dealloc(result32.cast(), layout32);
                    }
                    if layout36.size() != 0 {
                        _rt::alloc::dealloc(result36.cast(), layout36);
                    }
                    for (ptr, layout) in cleanup_list {
                        if layout.size() != 0 {
                            _rt::alloc::dealloc(ptr.cast(), layout);
                        }
                    }
                    match l38 {
                        0 => {
                            let e = {
                                let l39 = i32::from(*ptr37.add(4).cast::<u8>());
                                _rt::bool_lift(l39 as u8)
                            };
                            Ok(e)
                        }
                        1 => {
                            let e = {
                                let l40 = *ptr37.add(4).cast::<*mut u8>();
                                let l41 = *ptr37.add(8).cast::<usize>();
                                let len42 = l41;
                                let bytes42 = _rt::Vec::from_raw_parts(
                                    l40.cast(),
                                    len42,
                                    len42,
                                );
                                _rt::string_lift(bytes42)
                            };
                            Err(e)
                        }
                        _ => _rt::invalid_enum_discriminant(),
                    }
                }
            }
            #[allow(unused_unsafe, clippy::all)]
            /// Returns the Issuer's public key if it exists, otherwise returns an error.
            pub fn issuer_public() -> Result<IssuerPublicCompressed, _rt::String> {
                unsafe {
                    #[repr(align(4))]
                    struct RetArea([::core::mem::MaybeUninit<u8>; 28]);
                    let mut ret_area = RetArea([::core::mem::MaybeUninit::uninit(); 28]);
                    let ptr0 = ret_area.0.as_mut_ptr().cast::<u8>();
                    #[cfg(target_arch = "wasm32")]
                    #[link(wasm_import_module = "delano:wallet/actions@0.1.0")]
                    extern "C" {
                        #[link_name = "issuer-public"]
                        fn wit_import(_: *mut u8);
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    fn wit_import(_: *mut u8) {
                        unreachable!()
                    }
                    wit_import(ptr0);
                    let l1 = i32::from(*ptr0.add(0).cast::<u8>());
                    match l1 {
                        0 => {
                            let e = {
                                let l2 = *ptr0.add(4).cast::<*mut u8>();
                                let l3 = *ptr0.add(8).cast::<usize>();
                                let base7 = l2;
                                let len7 = l3;
                                let mut result7 = _rt::Vec::with_capacity(len7);
                                for i in 0..len7 {
                                    let base = base7.add(i * 8);
                                    let e7 = {
                                        let l4 = *base.add(0).cast::<*mut u8>();
                                        let l5 = *base.add(4).cast::<usize>();
                                        let len6 = l5;
                                        _rt::Vec::from_raw_parts(l4.cast(), len6, len6)
                                    };
                                    result7.push(e7);
                                }
                                _rt::cabi_dealloc(base7, len7 * 8, 4);
                                let l8 = *ptr0.add(12).cast::<*mut u8>();
                                let l9 = *ptr0.add(16).cast::<usize>();
                                let base13 = l8;
                                let len13 = l9;
                                let mut result13 = _rt::Vec::with_capacity(len13);
                                for i in 0..len13 {
                                    let base = base13.add(i * 8);
                                    let e13 = {
                                        let l10 = *base.add(0).cast::<*mut u8>();
                                        let l11 = *base.add(4).cast::<usize>();
                                        let len12 = l11;
                                        _rt::Vec::from_raw_parts(l10.cast(), len12, len12)
                                    };
                                    result13.push(e13);
                                }
                                _rt::cabi_dealloc(base13, len13 * 8, 4);
                                let l14 = *ptr0.add(20).cast::<*mut u8>();
                                let l15 = *ptr0.add(24).cast::<usize>();
                                let base24 = l14;
                                let len24 = l15;
                                let mut result24 = _rt::Vec::with_capacity(len24);
                                for i in 0..len24 {
                                    let base = base24.add(i * 12);
                                    let e24 = {
                                        let l16 = i32::from(*base.add(0).cast::<u8>());
                                        use super::super::super::delano::wallet::types::VkCompressed as V23;
                                        let v23 = match l16 {
                                            0 => {
                                                let e23 = {
                                                    let l17 = *base.add(4).cast::<*mut u8>();
                                                    let l18 = *base.add(8).cast::<usize>();
                                                    let len19 = l18;
                                                    _rt::Vec::from_raw_parts(l17.cast(), len19, len19)
                                                };
                                                V23::G1(e23)
                                            }
                                            n => {
                                                debug_assert_eq!(n, 1, "invalid enum discriminant");
                                                let e23 = {
                                                    let l20 = *base.add(4).cast::<*mut u8>();
                                                    let l21 = *base.add(8).cast::<usize>();
                                                    let len22 = l21;
                                                    _rt::Vec::from_raw_parts(l20.cast(), len22, len22)
                                                };
                                                V23::G2(e23)
                                            }
                                        };
                                        v23
                                    };
                                    result24.push(e24);
                                }
                                _rt::cabi_dealloc(base24, len24 * 12, 4);
                                super::super::super::delano::wallet::types::IssuerPublicCompressed {
                                    parameters: super::super::super::delano::wallet::types::ParamSetCommitmentCompressed {
                                        pp_commit_g1: result7,
                                        pp_commit_g2: result13,
                                    },
                                    vk: result24,
                                }
                            };
                            Ok(e)
                        }
                        1 => {
                            let e = {
                                let l25 = *ptr0.add(4).cast::<*mut u8>();
                                let l26 = *ptr0.add(8).cast::<usize>();
                                let len27 = l26;
                                let bytes27 = _rt::Vec::from_raw_parts(
                                    l25.cast(),
                                    len27,
                                    len27,
                                );
                                _rt::string_lift(bytes27)
                            };
                            Err(e)
                        }
                        _ => _rt::invalid_enum_discriminant(),
                    }
                }
            }
        }
    }
    #[allow(dead_code)]
    pub mod wit_ui {
        #[allow(dead_code, clippy::all)]
        pub mod wurbo_types {
            #[used]
            #[doc(hidden)]
            static __FORCE_SECTION_REF: fn() = super::super::super::__link_custom_section_describing_imports;
            use super::super::super::_rt;
            /// Details required in order to add an event listener to an element
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct ListenDetails {
                pub selector: _rt::String,
                pub ty: _rt::String,
            }
            impl ::core::fmt::Debug for ListenDetails {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("ListenDetails")
                        .field("selector", &self.selector)
                        .field("ty", &self.ty)
                        .finish()
                }
            }
        }
        #[allow(dead_code, clippy::all)]
        pub mod wurbo_in {
            #[used]
            #[doc(hidden)]
            static __FORCE_SECTION_REF: fn() = super::super::super::__link_custom_section_describing_imports;
            pub type ListenDetails = super::super::super::delano::wit_ui::wurbo_types::ListenDetails;
            #[allow(unused_unsafe, clippy::all)]
            /// Add an event listener to the given element
            pub fn addeventlistener(details: &ListenDetails) {
                unsafe {
                    let super::super::super::delano::wit_ui::wurbo_types::ListenDetails {
                        selector: selector0,
                        ty: ty0,
                    } = details;
                    let vec1 = selector0;
                    let ptr1 = vec1.as_ptr().cast::<u8>();
                    let len1 = vec1.len();
                    let vec2 = ty0;
                    let ptr2 = vec2.as_ptr().cast::<u8>();
                    let len2 = vec2.len();
                    #[cfg(target_arch = "wasm32")]
                    #[link(wasm_import_module = "delano:wit-ui/wurbo-in@0.1.0")]
                    extern "C" {
                        #[link_name = "addeventlistener"]
                        fn wit_import(_: *mut u8, _: usize, _: *mut u8, _: usize);
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    fn wit_import(_: *mut u8, _: usize, _: *mut u8, _: usize) {
                        unreachable!()
                    }
                    wit_import(ptr1.cast_mut(), len1, ptr2.cast_mut(), len2);
                }
            }
            #[allow(unused_unsafe, clippy::all)]
            /// Emit events from this component. Messages should be serialized JSON strings of Event type.
            pub fn emit(message: &str) {
                unsafe {
                    let vec0 = message;
                    let ptr0 = vec0.as_ptr().cast::<u8>();
                    let len0 = vec0.len();
                    #[cfg(target_arch = "wasm32")]
                    #[link(wasm_import_module = "delano:wit-ui/wurbo-in@0.1.0")]
                    extern "C" {
                        #[link_name = "emit"]
                        fn wit_import(_: *mut u8, _: usize);
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    fn wit_import(_: *mut u8, _: usize) {
                        unreachable!()
                    }
                    wit_import(ptr0.cast_mut(), len0);
                }
            }
        }
        #[allow(dead_code, clippy::all)]
        pub mod context_types {
            #[used]
            #[doc(hidden)]
            static __FORCE_SECTION_REF: fn() = super::super::super::__link_custom_section_describing_imports;
            use super::super::super::_rt;
            /// The type of the app
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct Page {
                pub name: _rt::String,
                pub version: _rt::String,
                pub description: _rt::String,
            }
            impl ::core::fmt::Debug for Page {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("Page")
                        .field("name", &self.name)
                        .field("version", &self.version)
                        .field("description", &self.description)
                        .finish()
                }
            }
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct Everything {
                pub page: Option<Page>,
                /// issue: option<issuer>,
                /// The JSON string of the loadable data (offer or proof)
                pub load: Option<_rt::String>,
            }
            impl ::core::fmt::Debug for Everything {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("Everything")
                        .field("page", &self.page)
                        .field("load", &self.load)
                        .finish()
                }
            }
            #[derive(Clone, Copy, serde::Deserialize, serde::Serialize)]
            pub enum Kovindex {
                Key(u32),
                Op(u32),
                Value(u32),
                Selected(u32),
            }
            impl ::core::fmt::Debug for Kovindex {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    match self {
                        Kovindex::Key(e) => {
                            f.debug_tuple("Kovindex::Key").field(e).finish()
                        }
                        Kovindex::Op(e) => {
                            f.debug_tuple("Kovindex::Op").field(e).finish()
                        }
                        Kovindex::Value(e) => {
                            f.debug_tuple("Kovindex::Value").field(e).finish()
                        }
                        Kovindex::Selected(e) => {
                            f.debug_tuple("Kovindex::Selected").field(e).finish()
                        }
                    }
                }
            }
            #[repr(C)]
            #[derive(Clone, Copy, serde::Deserialize, serde::Serialize)]
            pub struct Entry {
                pub idx: u32,
                pub val: Kovindex,
            }
            impl ::core::fmt::Debug for Entry {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("Entry")
                        .field("idx", &self.idx)
                        .field("val", &self.val)
                        .finish()
                }
            }
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct Kvctx {
                pub ctx: Entry,
                pub value: _rt::String,
            }
            impl ::core::fmt::Debug for Kvctx {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("Kvctx")
                        .field("ctx", &self.ctx)
                        .field("value", &self.value)
                        .finish()
                }
            }
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub struct Message {
                pub peer: _rt::String,
                pub topic: _rt::String,
                pub data: _rt::Vec<u8>,
            }
            impl ::core::fmt::Debug for Message {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    f.debug_struct("Message")
                        .field("peer", &self.peer)
                        .field("topic", &self.topic)
                        .field("data", &self.data)
                        .finish()
                }
            }
            /// The type of context provided
            #[derive(Clone, serde::Deserialize, serde::Serialize)]
            pub enum Context {
                AllContent(Everything),
                /// issuing(issuer),
                /// Adds a new attribute to an existing Entry of the Credential
                Addattribute,
                /// Adds a New Entry to the Credential
                Newentry,
                Editattribute(Kvctx),
                Editmaxentries(u8),
                /// Attempt to generate an offer
                Generateoffer,
                /// Attempt to generate a proof
                Generateproof,
                /// emit a publish event with the proof data
                Publishproof,
                /// Message recieved from the Network?
                Networkevent(Message),
            }
            impl ::core::fmt::Debug for Context {
                fn fmt(
                    &self,
                    f: &mut ::core::fmt::Formatter<'_>,
                ) -> ::core::fmt::Result {
                    match self {
                        Context::AllContent(e) => {
                            f.debug_tuple("Context::AllContent").field(e).finish()
                        }
                        Context::Addattribute => {
                            f.debug_tuple("Context::Addattribute").finish()
                        }
                        Context::Newentry => f.debug_tuple("Context::Newentry").finish(),
                        Context::Editattribute(e) => {
                            f.debug_tuple("Context::Editattribute").field(e).finish()
                        }
                        Context::Editmaxentries(e) => {
                            f.debug_tuple("Context::Editmaxentries").field(e).finish()
                        }
                        Context::Generateoffer => {
                            f.debug_tuple("Context::Generateoffer").finish()
                        }
                        Context::Generateproof => {
                            f.debug_tuple("Context::Generateproof").finish()
                        }
                        Context::Publishproof => {
                            f.debug_tuple("Context::Publishproof").finish()
                        }
                        Context::Networkevent(e) => {
                            f.debug_tuple("Context::Networkevent").field(e).finish()
                        }
                    }
                }
            }
        }
    }
}
#[allow(dead_code)]
pub mod exports {
    #[allow(dead_code)]
    pub mod delano {
        #[allow(dead_code)]
        pub mod wit_ui {
            #[allow(dead_code, clippy::all)]
            pub mod wurbo_out {
                #[used]
                #[doc(hidden)]
                static __FORCE_SECTION_REF: fn() = super::super::super::super::__link_custom_section_describing_imports;
                use super::super::super::super::_rt;
                pub type Context = super::super::super::super::delano::wit_ui::context_types::Context;
                #[doc(hidden)]
                #[allow(non_snake_case)]
                pub unsafe fn _export_customize_cabi<T: Guest>(
                    arg0: *mut u8,
                    arg1: usize,
                ) -> *mut u8 {
                    #[cfg(target_arch = "wasm32")] _rt::run_ctors_once();
                    let base6 = arg0;
                    let len6 = arg1;
                    let mut result6 = _rt::Vec::with_capacity(len6);
                    for i in 0..len6 {
                        let base = base6.add(i * 16);
                        let e6 = {
                            let l0 = *base.add(0).cast::<*mut u8>();
                            let l1 = *base.add(4).cast::<usize>();
                            let len2 = l1;
                            let bytes2 = _rt::Vec::from_raw_parts(l0.cast(), len2, len2);
                            let l3 = *base.add(8).cast::<*mut u8>();
                            let l4 = *base.add(12).cast::<usize>();
                            let len5 = l4;
                            let bytes5 = _rt::Vec::from_raw_parts(l3.cast(), len5, len5);
                            (_rt::string_lift(bytes2), _rt::string_lift(bytes5))
                        };
                        result6.push(e6);
                    }
                    _rt::cabi_dealloc(base6, len6 * 16, 4);
                    let result7 = T::customize(result6);
                    let ptr8 = _RET_AREA.0.as_mut_ptr().cast::<u8>();
                    match result7 {
                        Ok(_) => {
                            *ptr8.add(0).cast::<u8>() = (0i32) as u8;
                        }
                        Err(e) => {
                            *ptr8.add(0).cast::<u8>() = (1i32) as u8;
                            let vec9 = (e.into_bytes()).into_boxed_slice();
                            let ptr9 = vec9.as_ptr().cast::<u8>();
                            let len9 = vec9.len();
                            ::core::mem::forget(vec9);
                            *ptr8.add(8).cast::<usize>() = len9;
                            *ptr8.add(4).cast::<*mut u8>() = ptr9.cast_mut();
                        }
                    };
                    ptr8
                }
                #[doc(hidden)]
                #[allow(non_snake_case)]
                pub unsafe fn __post_return_customize<T: Guest>(arg0: *mut u8) {
                    let l0 = i32::from(*arg0.add(0).cast::<u8>());
                    match l0 {
                        0 => {}
                        _ => {
                            let l1 = *arg0.add(4).cast::<*mut u8>();
                            let l2 = *arg0.add(8).cast::<usize>();
                            _rt::cabi_dealloc(l1, l2, 1);
                        }
                    }
                }
                #[doc(hidden)]
                #[allow(non_snake_case)]
                pub unsafe fn _export_render_cabi<T: Guest>(
                    arg0: i32,
                    arg1: *mut u8,
                    arg2: *mut u8,
                    arg3: *mut u8,
                    arg4: *mut u8,
                    arg5: *mut u8,
                    arg6: *mut u8,
                    arg7: usize,
                    arg8: i32,
                    arg9: *mut u8,
                    arg10: usize,
                ) -> *mut u8 {
                    #[cfg(target_arch = "wasm32")] _rt::run_ctors_once();
                    use super::super::super::super::delano::wit_ui::context_types::Context as V9;
                    let v9 = match arg0 {
                        0 => {
                            let e9 = super::super::super::super::delano::wit_ui::context_types::Everything {
                                page: match arg1 as i32 {
                                    0 => None,
                                    1 => {
                                        let e = {
                                            let len0 = arg3 as usize;
                                            let bytes0 = _rt::Vec::from_raw_parts(
                                                arg2.cast(),
                                                len0,
                                                len0,
                                            );
                                            let len1 = arg5 as usize;
                                            let bytes1 = _rt::Vec::from_raw_parts(
                                                arg4.cast(),
                                                len1,
                                                len1,
                                            );
                                            let len2 = arg7;
                                            let bytes2 = _rt::Vec::from_raw_parts(
                                                arg6.cast(),
                                                len2,
                                                len2,
                                            );
                                            super::super::super::super::delano::wit_ui::context_types::Page {
                                                name: _rt::string_lift(bytes0),
                                                version: _rt::string_lift(bytes1),
                                                description: _rt::string_lift(bytes2),
                                            }
                                        };
                                        Some(e)
                                    }
                                    _ => _rt::invalid_enum_discriminant(),
                                },
                                load: match arg8 {
                                    0 => None,
                                    1 => {
                                        let e = {
                                            let len3 = arg10;
                                            let bytes3 = _rt::Vec::from_raw_parts(
                                                arg9.cast(),
                                                len3,
                                                len3,
                                            );
                                            _rt::string_lift(bytes3)
                                        };
                                        Some(e)
                                    }
                                    _ => _rt::invalid_enum_discriminant(),
                                },
                            };
                            V9::AllContent(e9)
                        }
                        1 => V9::Addattribute,
                        2 => V9::Newentry,
                        3 => {
                            let e9 = {
                                use super::super::super::super::delano::wit_ui::context_types::Kovindex as V4;
                                let v4 = match arg2 as i32 {
                                    0 => {
                                        let e4 = arg3 as i32 as u32;
                                        V4::Key(e4)
                                    }
                                    1 => {
                                        let e4 = arg3 as i32 as u32;
                                        V4::Op(e4)
                                    }
                                    2 => {
                                        let e4 = arg3 as i32 as u32;
                                        V4::Value(e4)
                                    }
                                    n => {
                                        debug_assert_eq!(n, 3, "invalid enum discriminant");
                                        let e4 = arg3 as i32 as u32;
                                        V4::Selected(e4)
                                    }
                                };
                                let len5 = arg5 as usize;
                                let bytes5 = _rt::Vec::from_raw_parts(
                                    arg4.cast(),
                                    len5,
                                    len5,
                                );
                                super::super::super::super::delano::wit_ui::context_types::Kvctx {
                                    ctx: super::super::super::super::delano::wit_ui::context_types::Entry {
                                        idx: arg1 as i32 as u32,
                                        val: v4,
                                    },
                                    value: _rt::string_lift(bytes5),
                                }
                            };
                            V9::Editattribute(e9)
                        }
                        4 => {
                            let e9 = arg1 as i32 as u8;
                            V9::Editmaxentries(e9)
                        }
                        5 => V9::Generateoffer,
                        6 => V9::Generateproof,
                        7 => V9::Publishproof,
                        n => {
                            debug_assert_eq!(n, 8, "invalid enum discriminant");
                            let e9 = {
                                let len6 = arg2 as usize;
                                let bytes6 = _rt::Vec::from_raw_parts(
                                    arg1.cast(),
                                    len6,
                                    len6,
                                );
                                let len7 = arg4 as usize;
                                let bytes7 = _rt::Vec::from_raw_parts(
                                    arg3.cast(),
                                    len7,
                                    len7,
                                );
                                let len8 = arg6 as usize;
                                super::super::super::super::delano::wit_ui::context_types::Message {
                                    peer: _rt::string_lift(bytes6),
                                    topic: _rt::string_lift(bytes7),
                                    data: _rt::Vec::from_raw_parts(arg5.cast(), len8, len8),
                                }
                            };
                            V9::Networkevent(e9)
                        }
                    };
                    let result10 = T::render(v9);
                    let ptr11 = _RET_AREA.0.as_mut_ptr().cast::<u8>();
                    match result10 {
                        Ok(e) => {
                            *ptr11.add(0).cast::<u8>() = (0i32) as u8;
                            let vec12 = (e.into_bytes()).into_boxed_slice();
                            let ptr12 = vec12.as_ptr().cast::<u8>();
                            let len12 = vec12.len();
                            ::core::mem::forget(vec12);
                            *ptr11.add(8).cast::<usize>() = len12;
                            *ptr11.add(4).cast::<*mut u8>() = ptr12.cast_mut();
                        }
                        Err(e) => {
                            *ptr11.add(0).cast::<u8>() = (1i32) as u8;
                            let vec13 = (e.into_bytes()).into_boxed_slice();
                            let ptr13 = vec13.as_ptr().cast::<u8>();
                            let len13 = vec13.len();
                            ::core::mem::forget(vec13);
                            *ptr11.add(8).cast::<usize>() = len13;
                            *ptr11.add(4).cast::<*mut u8>() = ptr13.cast_mut();
                        }
                    };
                    ptr11
                }
                #[doc(hidden)]
                #[allow(non_snake_case)]
                pub unsafe fn __post_return_render<T: Guest>(arg0: *mut u8) {
                    let l0 = i32::from(*arg0.add(0).cast::<u8>());
                    match l0 {
                        0 => {
                            let l1 = *arg0.add(4).cast::<*mut u8>();
                            let l2 = *arg0.add(8).cast::<usize>();
                            _rt::cabi_dealloc(l1, l2, 1);
                        }
                        _ => {
                            let l3 = *arg0.add(4).cast::<*mut u8>();
                            let l4 = *arg0.add(8).cast::<usize>();
                            _rt::cabi_dealloc(l3, l4, 1);
                        }
                    }
                }
                #[doc(hidden)]
                #[allow(non_snake_case)]
                pub unsafe fn _export_activate_cabi<T: Guest>(
                    arg0: i32,
                    arg1: *mut u8,
                    arg2: usize,
                ) {
                    #[cfg(target_arch = "wasm32")] _rt::run_ctors_once();
                    T::activate(
                        match arg0 {
                            0 => None,
                            1 => {
                                let e = {
                                    let base3 = arg1;
                                    let len3 = arg2;
                                    let mut result3 = _rt::Vec::with_capacity(len3);
                                    for i in 0..len3 {
                                        let base = base3.add(i * 8);
                                        let e3 = {
                                            let l0 = *base.add(0).cast::<*mut u8>();
                                            let l1 = *base.add(4).cast::<usize>();
                                            let len2 = l1;
                                            let bytes2 = _rt::Vec::from_raw_parts(
                                                l0.cast(),
                                                len2,
                                                len2,
                                            );
                                            _rt::string_lift(bytes2)
                                        };
                                        result3.push(e3);
                                    }
                                    _rt::cabi_dealloc(base3, len3 * 8, 4);
                                    result3
                                };
                                Some(e)
                            }
                            _ => _rt::invalid_enum_discriminant(),
                        },
                    );
                }
                pub trait Guest {
                    /// Optionally customize the configuration of the templates used to render the component
                    fn customize(
                        templates: _rt::Vec<(_rt::String, _rt::String)>,
                    ) -> Result<(), _rt::String>;
                    /// renders the initial Web component with the given data
                    /// and the target template to use as top level entry point
                    fn render(ctx: Context) -> Result<_rt::String, _rt::String>;
                    /// listen on all or given selectors
                    fn activate(selectors: Option<_rt::Vec<_rt::String>>);
                }
                #[doc(hidden)]
                macro_rules! __export_delano_wit_ui_wurbo_out_0_1_0_cabi {
                    ($ty:ident with_types_in $($path_to_types:tt)*) => {
                        const _ : () = { #[export_name =
                        "delano:wit-ui/wurbo-out@0.1.0#customize"] unsafe extern "C" fn
                        export_customize(arg0 : * mut u8, arg1 : usize,) -> * mut u8 {
                        $($path_to_types)*:: _export_customize_cabi::<$ty > (arg0, arg1)
                        } #[export_name =
                        "cabi_post_delano:wit-ui/wurbo-out@0.1.0#customize"] unsafe
                        extern "C" fn _post_return_customize(arg0 : * mut u8,) {
                        $($path_to_types)*:: __post_return_customize::<$ty > (arg0) }
                        #[export_name = "delano:wit-ui/wurbo-out@0.1.0#render"] unsafe
                        extern "C" fn export_render(arg0 : i32, arg1 : * mut u8, arg2 : *
                        mut u8, arg3 : * mut u8, arg4 : * mut u8, arg5 : * mut u8, arg6 :
                        * mut u8, arg7 : usize, arg8 : i32, arg9 : * mut u8, arg10 :
                        usize,) -> * mut u8 { $($path_to_types)*::
                        _export_render_cabi::<$ty > (arg0, arg1, arg2, arg3, arg4, arg5,
                        arg6, arg7, arg8, arg9, arg10) } #[export_name =
                        "cabi_post_delano:wit-ui/wurbo-out@0.1.0#render"] unsafe extern
                        "C" fn _post_return_render(arg0 : * mut u8,) {
                        $($path_to_types)*:: __post_return_render::<$ty > (arg0) }
                        #[export_name = "delano:wit-ui/wurbo-out@0.1.0#activate"] unsafe
                        extern "C" fn export_activate(arg0 : i32, arg1 : * mut u8, arg2 :
                        usize,) { $($path_to_types)*:: _export_activate_cabi::<$ty >
                        (arg0, arg1, arg2) } };
                    };
                }
                #[doc(hidden)]
                pub(crate) use __export_delano_wit_ui_wurbo_out_0_1_0_cabi;
                #[repr(align(4))]
                struct _RetArea([::core::mem::MaybeUninit<u8>; 12]);
                static mut _RET_AREA: _RetArea = _RetArea(
                    [::core::mem::MaybeUninit::uninit(); 12],
                );
            }
        }
    }
}
mod _rt {
    pub use alloc_crate::vec::Vec;
    pub use alloc_crate::string::String;
    pub unsafe fn invalid_enum_discriminant<T>() -> T {
        if cfg!(debug_assertions) {
            panic!("invalid enum discriminant")
        } else {
            core::hint::unreachable_unchecked()
        }
    }
    pub unsafe fn string_lift(bytes: Vec<u8>) -> String {
        if cfg!(debug_assertions) {
            String::from_utf8(bytes).unwrap()
        } else {
            String::from_utf8_unchecked(bytes)
        }
    }
    pub use alloc_crate::alloc;
    pub fn as_i32<T: AsI32>(t: T) -> i32 {
        t.as_i32()
    }
    pub trait AsI32 {
        fn as_i32(self) -> i32;
    }
    impl<'a, T: Copy + AsI32> AsI32 for &'a T {
        fn as_i32(self) -> i32 {
            (*self).as_i32()
        }
    }
    impl AsI32 for i32 {
        #[inline]
        fn as_i32(self) -> i32 {
            self as i32
        }
    }
    impl AsI32 for u32 {
        #[inline]
        fn as_i32(self) -> i32 {
            self as i32
        }
    }
    impl AsI32 for i16 {
        #[inline]
        fn as_i32(self) -> i32 {
            self as i32
        }
    }
    impl AsI32 for u16 {
        #[inline]
        fn as_i32(self) -> i32 {
            self as i32
        }
    }
    impl AsI32 for i8 {
        #[inline]
        fn as_i32(self) -> i32 {
            self as i32
        }
    }
    impl AsI32 for u8 {
        #[inline]
        fn as_i32(self) -> i32 {
            self as i32
        }
    }
    impl AsI32 for char {
        #[inline]
        fn as_i32(self) -> i32 {
            self as i32
        }
    }
    impl AsI32 for usize {
        #[inline]
        fn as_i32(self) -> i32 {
            self as i32
        }
    }
    pub unsafe fn cabi_dealloc(ptr: *mut u8, size: usize, align: usize) {
        if size == 0 {
            return;
        }
        let layout = alloc::Layout::from_size_align_unchecked(size, align);
        alloc::dealloc(ptr, layout);
    }
    pub unsafe fn bool_lift(val: u8) -> bool {
        if cfg!(debug_assertions) {
            match val {
                0 => false,
                1 => true,
                _ => panic!("invalid bool discriminant"),
            }
        } else {
            val != 0
        }
    }
    #[cfg(target_arch = "wasm32")]
    pub fn run_ctors_once() {
        wit_bindgen_rt::run_ctors_once();
    }
    extern crate alloc as alloc_crate;
}
/// Generates `#[no_mangle]` functions to export the specified type as the
/// root implementation of all generated traits.
///
/// For more information see the documentation of `wit_bindgen::generate!`.
///
/// ```rust
/// # macro_rules! export{ ($($t:tt)*) => (); }
/// # trait Guest {}
/// struct MyType;
///
/// impl Guest for MyType {
///     // ...
/// }
///
/// export!(MyType);
/// ```
#[allow(unused_macros)]
#[doc(hidden)]
macro_rules! __export_delanocreds_wit_ui_impl {
    ($ty:ident) => {
        self::export!($ty with_types_in self);
    };
    ($ty:ident with_types_in $($path_to_types_root:tt)*) => {
        $($path_to_types_root)*::
        exports::delano::wit_ui::wurbo_out::__export_delano_wit_ui_wurbo_out_0_1_0_cabi!($ty
        with_types_in $($path_to_types_root)*:: exports::delano::wit_ui::wurbo_out);
    };
}
#[doc(inline)]
pub(crate) use __export_delanocreds_wit_ui_impl as export;
#[cfg(target_arch = "wasm32")]
#[link_section = "component-type:wit-bindgen:0.35.0:delano:wit-ui@0.1.0:delanocreds-wit-ui:encoded world"]
#[doc(hidden)]
pub static __WIT_BINDGEN_COMPONENT_TYPE: [u8; 2837] = *b"\
\0asm\x0d\0\x01\0\0\x19\x16wit-component-encoding\x04\0\x07\x8c\x15\x01A\x02\x01\
A\x19\x01B5\x01p}\x04\0\x09attribute\x03\0\0\x01p\x01\x04\0\x05entry\x03\0\x02\x01\
p}\x04\0\x05nonce\x03\0\x04\x01p}\x04\0\x05proof\x03\0\x06\x01p\x03\x04\0\x08sel\
ected\x03\0\x08\x01p\x03\x01p\x01\x01r\x02\x07entries\x0a\x06remove\x0b\x04\0\x0b\
redactables\x03\0\x0c\x01k\x0d\x01k\x03\x01k}\x01r\x03\x06redact\x0e\x10addition\
al-entry\x0f\x0bmax-entries\x10\x04\0\x0coffer-config\x03\0\x11\x01p}\x01r\x04\x01\
z\x13\x04y-g1\x13\x05y-hat\x13\x01t\x13\x04\0\x14signature-compressed\x03\0\x14\x01\
p\x13\x01r\x02\x0cpp-commit-g1\x16\x0cpp-commit-g2\x16\x04\0\x1fparam-set-commit\
ment-compressed\x03\0\x17\x01q\x02\x02g1\x01\x13\0\x02g2\x01\x13\0\x04\0\x0dvk-c\
ompressed\x03\0\x19\x01p\x1a\x01r\x02\x0aparameters\x18\x02vk\x1b\x04\0\x18issue\
r-public-compressed\x03\0\x1c\x01p\x16\x01k\x1e\x01r\x05\x05sigma\x15\x0aupdate-\
key\x1f\x11commitment-vector\x16\x0eopening-vector\x16\x0dissuer-public\x1d\x04\0\
\x15credential-compressed\x03\0\x20\x01r\x04\x0acredential!\x07entries\x0a\x08se\
lected\x0b\x05nonce\x13\x04\0\x09provables\x03\0\"\x01r\x01\x01h\x13\x04\0\x13pe\
dersen-compressed\x03\0$\x01r\x01\x08pedersen%\x04\0\x1cdamgard-transform-compre\
ssed\x03\0&\x01k\x13\x01r\x03\x0fopen-randomness\x13\x13announce-randomness\x13\x10\
announce-element(\x04\0\x18pedersen-open-compressed\x03\0)\x01r\x06\x09challenge\
\x13\x0dpedersen-open*\x0fpedersen-commit\x13\x0apublic-key\x13\x08response\x13\x07\
damgard'\x04\0\x14nym-proof-compressed\x03\0+\x01r\x02\x08nymproof,\x05nonce(\x04\
\0\x0dissue-options\x03\0-\x01r\x04\x05sigma\x15\x11commitment-vector\x16\x0awit\
ness-pi\x13\x09nym-proof,\x04\0\x15cred-proof-compressed\x03\0/\x01r\x02\x05proo\
f0\x08selected\x09\x04\0\x06proven\x03\01\x01r\x04\x05proof0\x0dissuer-public\x1d\
\x05nonce(\x08selected\x09\x04\0\x0bverifiables\x03\03\x03\0\x19delano:wallet/ty\
pes@0.1.0\x05\0\x02\x03\0\0\x09attribute\x02\x03\0\0\x09provables\x02\x03\0\0\x0b\
verifiables\x02\x03\0\0\x0coffer-config\x02\x03\0\0\x0dissue-options\x02\x03\0\0\
\x05nonce\x02\x03\0\0\x05entry\x02\x03\0\0\x06proven\x02\x03\0\0\x15credential-c\
ompressed\x02\x03\0\0\x14nym-proof-compressed\x02\x03\0\0\x18issuer-public-compr\
essed\x01B.\x02\x03\x02\x01\x01\x04\0\x09attribute\x03\0\0\x02\x03\x02\x01\x02\x04\
\0\x09provables\x03\0\x02\x02\x03\x02\x01\x03\x04\0\x0bverifiables\x03\0\x04\x02\
\x03\x02\x01\x04\x04\0\x0coffer-config\x03\0\x06\x02\x03\x02\x01\x05\x04\0\x0dis\
sue-options\x03\0\x08\x02\x03\x02\x01\x06\x04\0\x05nonce\x03\0\x0a\x02\x03\x02\x01\
\x07\x04\0\x05entry\x03\0\x0c\x02\x03\x02\x01\x08\x04\0\x06proven\x03\0\x0e\x02\x03\
\x02\x01\x09\x04\0\x15credential-compressed\x03\0\x10\x02\x03\x02\x01\x0a\x04\0\x14\
nym-proof-compressed\x03\0\x12\x02\x03\x02\x01\x0b\x04\0\x18issuer-public-compre\
ssed\x03\0\x14\x01p}\x01j\x01\x13\x01s\x01@\x01\x05nonce\x16\0\x17\x04\0\x0dget-\
nym-proof\x01\x18\x01p\x01\x01k\x09\x01j\x01\x11\x01s\x01@\x03\x0aattributes\x19\
\x0amaxentries}\x07options\x1a\0\x1b\x04\0\x05issue\x01\x1c\x01@\x02\x04cred\x11\
\x06config\x07\0\x1b\x04\0\x05offer\x01\x1d\x01@\x01\x05offer\x11\0\x1b\x04\0\x06\
accept\x01\x1e\x01@\x02\x04cred\x11\x05entry\x0d\0\x1b\x04\0\x06extend\x01\x1f\x01\
j\x01\x0f\x01s\x01@\x01\x06values\x03\0\x20\x04\0\x05prove\x01!\x01j\x01\x7f\x01\
s\x01@\x01\x06values\x05\0\"\x04\0\x06verify\x01#\x01j\x01\x15\x01s\x01@\0\0$\x04\
\0\x0dissuer-public\x01%\x03\0\x1bdelano:wallet/actions@0.1.0\x05\x0c\x01B\x02\x01\
r\x02\x08selectors\x02tys\x04\0\x0elisten-details\x03\0\0\x03\0\x1fdelano:wit-ui\
/wurbo-types@0.1.0\x05\x0d\x02\x03\0\x02\x0elisten-details\x01B\x06\x02\x03\x02\x01\
\x0e\x04\0\x0elisten-details\x03\0\0\x01@\x01\x07details\x01\x01\0\x04\0\x10adde\
ventlistener\x01\x02\x01@\x01\x07messages\x01\0\x04\0\x04emit\x01\x03\x03\0\x1cd\
elano:wit-ui/wurbo-in@0.1.0\x05\x0f\x01B\x13\x01r\x03\x04names\x07versions\x0bde\
scriptions\x04\0\x04page\x03\0\0\x01k\x01\x01ks\x01r\x02\x04page\x02\x04load\x03\
\x04\0\x0aeverything\x03\0\x04\x01r\x02\x03keys\x05values\x04\0\x09input-ctx\x03\
\0\x06\x01q\x04\x03key\x01y\0\x02op\x01y\0\x05value\x01y\0\x08selected\x01y\0\x04\
\0\x08kovindex\x03\0\x08\x01r\x02\x03idxy\x03val\x09\x04\0\x05entry\x03\0\x0a\x01\
r\x02\x03ctx\x0b\x05values\x04\0\x05kvctx\x03\0\x0c\x01p}\x01r\x03\x04peers\x05t\
opics\x04data\x0e\x04\0\x07message\x03\0\x0f\x01q\x09\x0ball-content\x01\x05\0\x0c\
addattribute\0\0\x08newentry\0\0\x0deditattribute\x01\x0d\0\x0eeditmaxentries\x01\
}\0\x0dgenerateoffer\0\0\x0dgenerateproof\0\0\x0cpublishproof\0\0\x0cnetworkeven\
t\x01\x10\0\x04\0\x07context\x03\0\x11\x03\0!delano:wit-ui/context-types@0.1.0\x05\
\x10\x02\x03\0\x04\x07context\x01B\x0e\x02\x03\x02\x01\x11\x04\0\x07context\x03\0\
\0\x01o\x02ss\x01p\x02\x01j\0\x01s\x01@\x01\x09templates\x03\0\x04\x04\0\x09cust\
omize\x01\x05\x01j\x01s\x01s\x01@\x01\x03ctx\x01\0\x06\x04\0\x06render\x01\x07\x01\
ps\x01k\x08\x01@\x01\x09selectors\x09\x01\0\x04\0\x08activate\x01\x0a\x04\0\x1dd\
elano:wit-ui/wurbo-out@0.1.0\x05\x12\x04\0&delano:wit-ui/delanocreds-wit-ui@0.1.\
0\x04\0\x0b\x18\x01\0\x12delanocreds-wit-ui\x03\0\0\0G\x09producers\x01\x0cproce\
ssed-by\x02\x0dwit-component\x070.220.0\x10wit-bindgen-rust\x060.35.0";
#[inline(never)]
#[doc(hidden)]
pub fn __link_custom_section_describing_imports() {
    wit_bindgen_rt::maybe_link_cabi_realloc();
}
