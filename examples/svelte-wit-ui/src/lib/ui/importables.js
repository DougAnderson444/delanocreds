export function buildCodeString(namespace) {
	return `
      const bc = new BroadcastChannel('${namespace}');
      export function addeventlistener({ selector, ty }) {
        document.querySelector(selector).addEventListener(ty, (e) => {

          let val = e.target.value;

          // detect if form event
          if(e.target.closest('form')) {
            e.preventDefault();
          }

          let tag  = e.target.dataset.contextName || e.target.name;

          try {
            val = Object.assign({}, 
                    typeof JSON.parse(e.target.dataset.contextValue) === 'object' 
                    ? JSON.parse(e.target.dataset.contextValue) 
                    : {}, 
                    { value: e.target.value });
          } catch(e) {
            console.warn('Could not parse contextValue');
          }

          let ctx = { tag, val };

          let el = e.target.closest('[data-slot]');
          if(el) {
            ctx = { tag: el.dataset.slot, val: ctx };
            el = el.closest('[data-slot]');
          }

          let rendered = window.${namespace}.render(ctx); 

          bc.postMessage(rendered);
        });
      }

      // Enables the guest components to emit a broadcast message to all peers on the same domain origin browsing context
      export function emit(message) {
        bc.postMessage(message);
      }
`;
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
