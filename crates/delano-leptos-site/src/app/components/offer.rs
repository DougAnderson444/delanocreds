//! Issue a credential.
use crate::app::components::{attributes::AttributeEntry, qrcode::ReactiveQRCode};
use delanocreds::{
    error, Attribute, Credential, Entry, Issuer, MaxCardinality, MaxEntries, Nym, Randomized,
};
use leptos::*;

/// Takes Vec<Attribute> and returns a Credential Offer
pub fn create_offer(
    issuer: ReadSignal<Issuer>,
    nym: &ReadSignal<Nym<Randomized>>,
    attributes: Vec<Attribute>,
) -> Result<(Credential, Vec<Entry>), error::Error> {
    const NONCE: Option<&str> = None;

    // Issue the (Powerful) Root Credential to Arbitary Nym
    let cred = match issuer.with(|i| {
        i.credential()
            .with_entry(attributes.clone().into())
            .max_entries(&MaxEntries::new(2))
            .issue_to(&nym.with(|nym| nym.nym_proof(NONCE)))
    }) {
        Ok(cred) => cred,
        Err(e) => panic!("Error issuing cred: {:?}", e),
    };

    // 1. Offer the unchanged Credential to Bob's Nym
    let (offer, provable_entries) =
        nym.with(|nym| nym.offer_builder(&cred, &[attributes.into()]).open_offer())?;
    Ok((offer.into(), provable_entries))
}

/// The Offer component. Gets the MaxCardinality from the context and loads the form.
#[component]
pub fn Offer() -> impl IntoView {
    let max_cardinality = use_context::<MaxCardinality>();
    let nym = use_context::<ReadSignal<Nym<Randomized>>>();

    match (max_cardinality, nym) {
        (Some(cardinality), Some(nym)) => view! {
            <div class="">"Let's Create some Credentials!"</div>
            <OfferForm max_cardinality=cardinality nym=nym />
        }
        .into_view(),
        _ => view! {
            <div class="text-2xl">"No Max Cardinality in Context"</div>
        }
        .into_view(),
    }
}

/// Component to issue a credential.
///
/// A form with customizable input fields, and a QR code to send and scan.
#[component]
pub fn OfferForm(
    /// The Max Cardinality of the credential (up to n attributes)
    /// Default value on an optional prop is its Default::default() value
    #[prop(optional)]
    max_cardinality: MaxCardinality,
    /// The Nym to issue the credential to
    nym: ReadSignal<Nym<Randomized>>,
) -> impl IntoView {
    // get issuer from context
    let issuer = expect_context::<ReadSignal<Issuer>>();

    // offer is a signal that displays the offer
    let (offer, set_offer) = create_signal("".to_string());
    // href link string
    let (offer_link, set_offer_link) = create_signal("".to_string());

    let (attributes, set_attributes) = create_signal(Vec::<Attribute>::new());

    // When offer buttom is clicked, run them through create_offer
    // We need a derived signal that is reactive to the button click
    create_effect(move |_| {
        let attributes = attributes.get();
        log::debug!("attributes: {:?}", attributes);

        let offer = create_offer(issuer, &nym, attributes);
        match offer {
            Ok((cred, provable_entries)) => {
                let link = cred.to_url_safe();
                set_offer_link.set(format!("?offer={}", link));
                set_offer.set(format!("{}", cred));
                log::info!("Provable Entries: {:?}", provable_entries);
            }
            Err(e) => panic!("Error creating offer: {:?}", e),
        };
    });

    view! {
        <div>
            "Name a few public attributes, and consider adding a safety attribute that only they would have/know"
            <AttributeEntry setter=set_attributes max_cardinality >
                "Create Offer"
            </AttributeEntry>


        <div class="flex justify-end m-2 font-semibold text-lg">

            </div>  <div class="text-2xl">Offer</div> <div class="text-xs break-all">
                <div class="">
                    <a href=offer_link target="_blank" class="text-blue-500 underline">
                        "Offer Link"
                    </a>
                </div>
                <details>
                    <summary class="text-2xl">Offer Text</summary>
                    <pre class="whitespace-pre-wrap">
                        <code>{offer}</code>
                    </pre>
                </details>
            </div> <details class="mt-4">
                <summary class="text-2xl">Offer QR Code</summary>
                <div class="flex justify-center">
                    <ReactiveQRCode signal=offer/>
                </div>
            </details>
        </div>
    }
}
