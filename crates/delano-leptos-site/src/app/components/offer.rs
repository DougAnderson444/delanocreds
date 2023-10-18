//! Issue a credential.
use crate::app::components::qrcode::ReactiveQRCode;
use delanocreds::{
    error, Attribute, Credential, Entry, Issuer, MaxCardinality, MaxEntries, Nym, UserKey,
};
use leptos::*;

/// Takes Vec<Attribute> and returns a Credential Offer
pub fn create_offer(
    issuer: ReadSignal<Issuer>,
    nym: &Nym,
    attributes: Vec<Attribute>,
) -> Result<(Credential, Vec<Entry>), error::Error> {
    const NONCE: Option<&str> = None;

    // Issue the (Powerful) Root Credential to Arbitary Nym
    let cred = match issuer.with(|i| {
        i.credential()
            .with_entry(attributes.clone().into())
            .max_entries(&MaxEntries::new(2))
            .issue_to(&nym.nym_proof(NONCE))
    }) {
        Ok(cred) => cred,
        Err(e) => panic!("Error issuing cred: {:?}", e),
    };

    // 1. Offer the unchanged Credential to Bob's Nym
    let (offer, provable_entries) = nym
        .offer_builder(&cred, &[attributes.into()])
        .open_offer()?;
    Ok((offer.into(), provable_entries))
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
) -> impl IntoView {
    // get issuer from context
    let issuer = expect_context::<ReadSignal<Issuer>>();
    let user = UserKey::new();
    let nym = user.nym(issuer.with(|i| i.public.parameters.clone()));

    let initial_length: usize = 1;

    // `next_id` will let us generate unique IDs
    // we do this by simply incrementing the ID by one
    // each time we create a counter
    let mut next_id = initial_length;

    // we generate an initial list as in <StaticList/>
    // but this time we include the ID along with the signal
    let initial_attributes = (0..initial_length)
        .map(|id| (id, create_signal("".to_string())))
        .collect::<Vec<_>>();

    // now we store that initial list in a signal
    // this way, we'll be able to modify the list over time,
    // adding and removing attributes, and it will change reactively
    let (attributes, set_attributes) = create_signal(initial_attributes);

    // let offer = create_memo(move |_| really_expensive_computation(value.get()));

    let add_item = move |_| {
        // create a signal for the new counter
        let sig = create_signal("".to_string());
        // add this counter to the list of attributes
        set_attributes.update(move |attributes| {
            // since `.update()` gives us `&mut T`
            // we can just use normal Vec methods like `push`
            attributes.push((next_id, sig))
        });
        // increment the ID so it's always unique
        next_id += 1;
    };

    // calculate a remaining Signal *max_cardinality - attributes.get().len()
    let remaining = move || *max_cardinality - attributes.get().len();
    // cloned because we need to move it into the closure below
    let remaining_c = remaining.clone();
    let show_remaining = move || format!("{:?} remaining", remaining_c());
    // disbale the "Add" button when none remaining
    let disabled = move || remaining() == 0;

    // offer is a signal that displays the offer
    let (offer, set_offer) = create_signal("".to_string());

    // When offer buttom is clicked, run them through create_offer
    // We need a derived signal that is reactive to the button click
    let offer_clicked = move |_| {
        let attributes = attributes.get();
        // get just the second value from each tuple
        let attributes = attributes
            .iter()
            .map(|(_, (attr, _))| Attribute::new(attr.get()))
            .collect();

        let offer = create_offer(issuer, &nym, attributes);
        match offer {
            Ok((cred, provable_entries)) => {
                log::info!("Offer: {}\nProvable Entries: {:?}", cred, provable_entries);
                set_offer.set(format!("{}\n{:?}", cred, provable_entries));
            }
            Err(e) => panic!("Error creating offer: {:?}", e),
        };
    };

    view! {
        <div>
            "Name a few public attributes, and consider adding a safety attribute that only they would know"
            <div class="flex flex-col items-center">
                // The <For/> component is central here
                // This allows for efficient, key list rendering
                <For
                    // `each` takes any function that returns an iterator
                    // this should usually be a signal or derived signal
                    // if it's not reactive, just render a Vec<_> instead of <For/>
                    each=attributes
                    // the key should be unique and stable for each row
                    // using an index is usually a bad idea, unless your list
                    // can only grow, because moving items around inside the list
                    // means their indices will change and they will all rerender
                    key=|attr| attr.0
                    // `children` receives each item from your `each` iterator
                    // and returns a view
                    children=move |(id, (_read_attr, set_attr))| {
                        view! {
                            <div class="flex flex-row items-center">
                                <AttributeInput setter=set_attr/>
                                <div class="flex-grow-0 mx-2">
                                    <button
                                        class="bg-red-500 hover:bg-red-700 text-xl text-white font-bold py-2 px-4 rounded shadow"
                                        on:click=move |_| {
                                            set_attributes
                                                .update(|attribs| {
                                                    attribs.retain(|(this_id, _)| this_id != &id)
                                                });
                                        }
                                    >

                                        "X"
                                    </button>
                                </div>
                            </div>
                        }
                    }
                />

            </div> <div class="flex flex-row items-center">
                <button
                    on:click=add_item
                    disabled=disabled
                    class=" disabled:bg-gray-500
                    bg-blue-500
                    hover:bg-blue-700
                    text-white
                    text-2xl
                    font-bold
                    py-2
                    px-4
                    rounded "
                >
                    "+"
                </button>
                <div class="text-neutral-800 text-sm m-2">{show_remaining}</div>
            </div> <div class="flex justify-end m-2 font-semibold text-lg">
                <button
                    on:click=offer_clicked
                    class="
                    bg-blue-500
                    hover:bg-blue-700
                    text-white
                    font-bold
                    py-2
                    px-4
                    rounded "
                >
                    "Create Offer"
                </button>
            </div>
            <div class="text-2xl">Summary</div>
            <ul class="text-lg">
                <For
                    each=attributes
                    key=|attr| attr.0
                    children=move |(_id, (attr, _set_attr))| view! { <li>{attr}</li> }
                />
            </ul>
            <div class="text-2xl">Offer</div> <div class="text-xs break-all">
                <pre class="whitespace-pre-wrap">
                    <code>{offer}</code>
                </pre>
            </div>
            <details class="mt-4">
                <summary class="text-2xl">Offer QR Code</summary>
                <div class="flex justify-center">
                    <ReactiveQRCode signal=offer />
                </div>
            </details>
        </div>
    }
}

/// An Attribute entry form
/// Lets you pick a key, value, and operator ("=", "<", ">")
#[component]
pub fn AttributeInput(setter: WriteSignal<String>) -> impl IntoView {
    // on keyup, compute the Attribute for this Input
    let (key, set_key) = create_signal("".to_string());
    let (op, set_op) = create_signal("=".to_string());
    let (value, set_value) = create_signal("".to_string());

    // TODO: Standardize a Schema? The format is arbitrary, as it's hashed, but it should be consistent.
    let attr_str = move || with!(|key, op, value| format!("{} {} {}", key, op, value));

    // use setter every time attr_str changes
    create_effect(move |_| setter.set(attr_str()));
    // let attribute = Attribute::new(attr_str());

    view! {
        <form class="flex flex-col sm:flex-row py-1 animate-slideDown">
            <input
                on:keyup=move |ev| set_key(event_target_value(&ev))
                type="text"
                class="flex-1 border-2 border-blue-200 sm:rounded-l-md p-2"
                placeholder="First Name"
            />
            <select
                class="p-1 bg-blue-500 text-white font-semibold"
                on:change=move |ev| set_op(event_target_value(&ev))
            >
                <option value="=">"="</option>
                <option value="<">"<"</option>
                <option value=">">">"</option>
            </select>
            <input
                on:keyup=move |ev| set_value(event_target_value(&ev))
                type="text"
                class="flex-1 border-2 border-blue-200 sm:rounded-r-md p-2"
                placeholder="Doug"
            />
        </form>
    }
}
