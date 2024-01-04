export function buildCodeString(namespace) {
	return `
      const bc = new BroadcastChannel('${namespace}');
      export function addeventlistener({ selector, ty }) {
        document.querySelector(selector).addEventListener(ty, (e) => {
          let ctx = {
            tag: e.target.name,
            val: {
              value: e.target.value,
            }
          };

          let el = e.target.closest('[data-slot]');
          if(el) {
            ctx = { tag: el.dataset.slot, val: ctx };
            el = el.closest('[data-slot]');
          }

          let rendered = window.${namespace}.render(ctx); 

          // console.log({ctx}, {rendered});
          bc.postMessage(rendered);
        });
      }`;
}

export function buildWalletActions() {
	// Stub these with noop:
	//
	// /// Returns the active Nym of the component.
	// get-nym-proof: func(nonce: nonce) -> result<list<u8>, string>;
	//
	// /// Issue a credential Entry to a Nym with maximum entries.
	// issue: func(nymproof: list<u8>, attributes: list<attribute>, maxentries: u8, nonce: option<list<u8>>) -> result<list<u8>, string>;
	//
	// /// Create an offer for a credential with its given entries and a given configuration.
	// offer: func(cred: list<u8>, config: offer-config) -> result<list<u8>, string>;
	//
	// /// Accept a credential offer and return the accepte Credential bytes
	// accept: func(offer: list<u8>) -> result<list<u8>, string>;
	//
	// /// Export a function that proves selected attributes in a given credential
	// prove: func(values: provables) -> result<list<u8>, string>;
	//
	// /// Export a function that verifies a proof against a public key, nonce and selected attributes
	// verify: func(values: verifiables) -> result<bool, string>;
	return `
    export function getNymProof(nonce) {
      // return a Uint8Array
      return new Uint8Array(69).fill(42);
    }

    export function issue(nymproof, attributes, maxentries, nonce) {
      // return a Uint8Array
      return new Uint8Array(69).fill(42);
    }

    export function offer(cred, config) {
      // return a Uint8Array
      return new Uint8Array(69).fill(42); 
    }

    export function accept(offer) {
      // return a Uint8Array
      return new Uint8Array(69).fill(42);
    }

    export function prove(values) {
      // return a Uint8Array
      return new Uint8Array(69).fill(42);
    }

    export function verify(values) {
      true
    }
  `;
}
