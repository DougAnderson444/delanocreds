use std::ops::Deref;

use delanocreds::MaxCardinality;
use leptos::*;
use wasm_bindgen::JsValue;

/// Initial Attributes
#[derive(Default)]
pub struct InitialAttributes(Vec<AttributeKOV>);

impl Deref for InitialAttributes {
    type Target = Vec<AttributeKOV>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Attrubite Entry Form, uses
#[component]
pub fn AttributeEntry(
    #[prop(default = 1)] initial_length: usize,
    #[prop(optional)] max_cardinality: MaxCardinality,
    #[prop(optional)] attribute_hints: InitialAttributes,
    setter: WriteSignal<Vec<delanocreds::Attribute>>,
    children: Children,
) -> impl IntoView {
    // we generate an initial list as in <StaticList/>
    // but this time we include the ID along with the signal
    // If attribute_hints is not default, then use it to initalize
    // let initial_attributes = (0..initial_length)
    //     .map(|id| (id, create_signal("".to_string())))
    //     .collect::<Vec<_>>();
    let initial_attributes = attribute_hints
        .clone()
        .into_iter()
        .enumerate()
        .map(|(id, attr)| (id, create_signal(attr)))
        .collect::<Vec<_>>();

    // now we store that initial list in a signal
    // this way, we'll be able to modify the list over time,
    // adding and removing attributes, and it will change reactively
    let (attributes, set_attributes) = create_signal(initial_attributes);
    // `next_id` will let us generate unique IDs
    // we do this by simply incrementing the ID by one
    // each time we create a counter
    let mut next_id = initial_length;

    let add_item = move |_| {
        // create a signal for the new counter
        let sig = create_signal(AttributeKOV::default());
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

    // When offer buttom is clicked, run them through create_offer
    // We need a derived signal that is reactive to the button click
    let on_submit = move |_| {
        log::debug!("on_submit");
        let attributes = attributes.get();
        // get just the second value from each tuple
        let attributes = attributes
            .iter()
            .map(|(_, (attr, _))| delanocreds::Attribute::new(attr.get().to_string()))
            .collect();

        setter.set(attributes);
    };

    view! {
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
                children=move |(id, (attr_kov, set_attr))| {
                    view! {
                        <div class="flex flex-row items-center">
                            <AttributeInput initial=attr_kov.get() setter=set_attr/>
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

        </div>
        <div class="flex flex-row items-center">
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
        </div>
        <div class="flex justify-end m-2 font-semibold text-lg">
            <button
                on:click=on_submit
                class="
                bg-blue-500
                hover:bg-blue-700
                text-white
                font-bold
                py-2
                px-4
                rounded "
                >
                {children()}
            </button>
        </div>
        <div class="text-2xl">Summary</div>
            <ul class="text-lg">
                <For
                    each=attributes
                    key=|attr| attr.0
                    children=move |(_id, (attr, _set_attr))| view! { <li>{attr().to_string()}</li> }
                />
            </ul>
    }
}

/// Constant representing the Equal operator
pub const EQUAL: &str = "=";
/// Constant representing the Less Than operator
pub const LESS_THAN: &str = "<";
/// Constant representing the Greater Than operator
pub const GREATER_THAN: &str = ">";

/// Enum of Possible Operators
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Operator {
    /// Equals Operator
    #[default]
    Equal,
    /// Less Than Operator
    LessThan,
    /// Greater Than Operator
    GreaterThan,
}

impl Operator {
    pub const EQUAL: &'static str = EQUAL;
    pub const LESS_THAN: &'static str = LESS_THAN;
    pub const GREATER_THAN: &'static str = GREATER_THAN;

    /// Return the value of the enum variant
    pub fn value(&self) -> &'static str {
        match self {
            Operator::Equal => Self::EQUAL,
            Operator::LessThan => Self::LESS_THAN,
            Operator::GreaterThan => Self::GREATER_THAN,
        }
    }
}

impl ToString for Operator {
    fn to_string(&self) -> String {
        self.value().to_string()
    }
}

impl TryFrom<String> for Operator {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            Operator::EQUAL => Ok(Operator::Equal),
            Operator::LESS_THAN => Ok(Operator::LessThan),
            Operator::GREATER_THAN => Ok(Operator::GreaterThan),
            _ => Err(format!("Invalid Operator: {}", value)),
        }
    }
}

/// Atrribute Key Operator Value (KOV)
#[derive(Default, Clone)]
pub struct AttributeKOV {
    /// Key
    pub key: AttributeKey,
    /// Operator
    pub op: Operator,
    /// Value
    pub value: AttributeValue,
}

/// Newtype Key to create an AttributeKOV struct
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttributeKey(String);

impl Deref for AttributeKey {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<AttributeKey> for JsValue {
    fn from(key: AttributeKey) -> Self {
        JsValue::from(key.0)
    }
}

/// Newtype Value to create an AttributeKOV struct
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttributeValue(String);

impl Deref for AttributeValue {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<AttributeValue> for JsValue {
    fn from(value: AttributeValue) -> Self {
        JsValue::from(value.0)
    }
}

impl AttributeKOV {
    /// Create a new AttributeKOV from AttributeKey, Operator, and AttributeValue
    pub fn new(key: AttributeKey, op: Operator, value: AttributeValue) -> Self {
        Self { key, op, value }
    }
}

impl ToString for AttributeKOV {
    fn to_string(&self) -> String {
        format!("{} {} {}", *self.key, self.op.to_string(), *self.value)
    }
}

/// An Attribute entry form
/// Lets you pick a key, value, and operator ("=", "<", ">")
#[component]
pub fn AttributeInput(initial: AttributeKOV, setter: WriteSignal<AttributeKOV>) -> impl IntoView {
    // on keyup, compute the Attribute for this Input
    let (key, set_key) = create_signal(initial.key);
    let (op, set_op) = create_signal(initial.op);
    let (value, set_value) = create_signal(initial.value);

    // TODO: Standardize a Schema? The format is arbitrary, as it's hashed, but it should be consistent.
    let attrs = move || {
        with!(|key, op, value| AttributeKOV::new(
            AttributeKey(key.to_string()),
            Operator::try_from(op.to_string()).expect("form to behave properly"),
            AttributeValue(value.to_string())
        ))
    };

    // use setter every time attr_str changes
    create_effect(move |_| setter.set(attrs()));
    // let attribute = Attribute::new(attr_str());

    view! {
        <form class="flex flex-col sm:flex-row py-1 animate-slideDown">
            <input
                on:keyup=move |ev| set_key(AttributeKey(event_target_value(&ev)))
                type="text"
                class="flex-1 border-2 border-blue-200 sm:rounded-l-md p-2"
                placeholder="First Name"
                prop:value=key
            />
            <select
                class="p-1 bg-blue-500 text-white font-semibold"
                on:change=move |ev| set_op(event_target_value(&ev).try_into().expect("form to behave"))
            >
                <option value="=" selected=move || op().value() == Operator::EQUAL>{Operator::EQUAL.to_string()}</option>
                <option value="<" selected=move || op().value() == Operator::LESS_THAN >{Operator::LESS_THAN.to_string()}</option>
                <option value=">" selected=move || op().value() == Operator::GREATER_THAN >{Operator::GREATER_THAN.to_string()}</option>
            </select>
            <input
                on:keyup=move |ev| set_value(AttributeValue(event_target_value(&ev)))
                type="text"
                class="flex-1 border-2 border-blue-200 sm:rounded-r-md p-2"
                placeholder="Doug"
                prop:value=value
        />
        </form>
    }
}
