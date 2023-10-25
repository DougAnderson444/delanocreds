//! User Interface to accept a credential offer.
//! Takes the base64 encoded CBOR [Credential] as input, and optional hints for the fields and
//! operators (ie. Age > , First Name = , etc.)
//!
//! TODO: We need to save the plain text attributes (or at least the hints) associated with the credential offer, so that
//! the user can generate proofs later. The [Attribute]s are not actually needed to accept, but are
//! needed to prove.

use crate::app::components::{attributes::AttributeEntry, error::Error};
use delanocreds::{verify_proof, Credential, Entry, Initial, Nym, Offer};
use leptos::*;
use leptos_router::use_params_map;

/// Accept an offer. Shows the Attribute input form, as you need to enter Attributes that match the
/// Credential offer in order to accept it.
#[component]
pub fn Accept() -> impl IntoView {
    let nym = use_context::<ReadSignal<Nym<Initial>>>();
    match nym {
        Some(nym) => view! {
            <UserAccept nym />
        }
        .into_view(),
        _ => view! {
        <Error message="No Nym in Context".to_string() />
        }
        .into_view(),
    }
}

#[component]
fn UserAccept(nym: ReadSignal<Nym<Initial>>) -> impl IntoView {
    // we can access the :id param reactively with `use_params_map`
    let params = use_params_map();
    let id = move || params.with(|params| params.get("id").cloned().unwrap_or_default());

    let (attributes, set_attributes) = create_signal(vec![]);

    let (offer, set_offer) = create_signal(None::<Offer>);
    let offer_processed = move || offer.get().is_some();
    let offer_details = move || offer_processed().then(|| offer.get().unwrap().to_string());

    // When the buttom is clicked, run them through accept_offer
    // We need a derived signal that is reactive to the button click
    create_effect(move |_| {
        // deserialize the offer from the URL
        match Credential::from_url_safe(&id()) {
            Ok(offer) => {
                log::debug!("Valid offer");

                set_offer(Some(offer.clone().into()));
                // accept the offer
                match nym.with(|n| n.accept(&offer.into())) {
                    Ok(cred) => {
                        log::info!("Credential accepted: {}", cred.to_string());

                        const NONCE: Option<&[u8]> = None;
                        let entries: &[Entry] = &[attributes.get().into()];
                        log::debug!("entries: {:?}", entries);
                        let (proof, provable_entries) = nym.with(|n| {
                            let mut building = n.proof_builder(&cred, entries);
                            // iterate through all Attributes, select each one
                            attributes
                                .get()
                                .iter()
                                .fold(&mut building, |builder, attribute| {
                                    log::debug!("selecting attribute: {:?}", attribute);
                                    builder.select_attribute(attribute.clone())
                                })
                                .prove(NONCE)
                        });

                        // if the proof can pass verify_proof, then return Ok(proof)
                        match verify_proof(&cred.issuer_public, &proof, &provable_entries) {
                            Ok(true) => log::info!("Proof verified."),
                            Ok(false) => {
                                log::error!("{:?}", delanocreds::error::Error::InvalidProof)
                            }
                            Err(e) => {
                                log::error!("{:?}", delanocreds::error::Error::IssuerError(e))
                            }
                        };
                    }
                    Err(e) => log::error!("Error accepting offer: {:?}", e),
                }
            }
            Err(e) => log::error!("Error deserializing offer: {:?}", e),
        }
    });

    view! {
        "Credential: "
        <AttributeEntry setter=set_attributes>
            "Generate Proof"
        </AttributeEntry>
                <details>
                    <summary>"Offer"</summary>
                    <pre class="whitespace-pre-wrap">
                        <code>
                            {offer_details}
                        </code>
                    </pre>
                </details>
    }
}
