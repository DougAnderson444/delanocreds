//! A quick binary to test the library and
//! get some --release compile time stats
//! # Quick Bench
//! For eight (8) attributes, the following benchmarks were observed for each step:
//!
//! | Step           | Time (ms) |
//! | -------------- | --------- |
//! | Setup          | 118       |
//! | Issue          | 168       |
//! | Offer          | 5         |
//! | Accept         | 83        |
//! | Prove          | 36        |
//! | Verify         | 124       |
//! | =============  | ========= |
//! | **Total Time** | **535**   |

use anyhow::Result;
use delanocreds::{
    verify_proof, Attribute, Credential, Entry, Issuer, MaxCardinality, MaxEntries, Nonce, Nym,
};

pub fn main() -> Result<()> {
    println!(" \nRunning a short basic test: \n");
    let _ = basic_bench();
    println!(" \nCreating and proving 30 of 100 credentials: \n");
    let _ = bench_30_of_100();

    Ok(())
}

pub fn basic_bench() -> Result<()> {
    let nonce = Nonce::default();
    //start timer
    let start = std::time::Instant::now();

    // Delegate a subset of attributes
    let age = Attribute::new("age = 30");
    let name = Attribute::new("name = Alice");
    let drivers = Attribute::new("driver license = 12");
    let gender = Attribute::new("gender = male");
    let company = Attribute::new("company = ACME");
    let drivers_type_b = Attribute::new("driver license type = B");
    let insurance = Attribute::new("Insurance = 2");
    let car_type = Attribute::new("Car type = BMW");

    let message1_str = vec![age.clone(), name.clone(), drivers];
    let message2_str = vec![gender, company, drivers_type_b];
    let message3_str = vec![insurance.clone(), car_type];

    // Test proving a credential to verifiers
    let all_attributes = vec![
        Entry::new(&message1_str),
        Entry::new(&message2_str),
        Entry::new(&message3_str),
    ];

    let last = start.elapsed();
    eprintln!("Time to setup attributes: {:?}", last);

    let l_message = MaxEntries::new(10);
    let signer = Issuer::new(MaxCardinality::new(8), l_message);

    let alice_nym = Nym::new();

    let bobby_nym = Nym::new();

    let position = 5; // index of the update key to be used for the added element
    let index_l = all_attributes.len() + position;
    let k_prime = Some(std::cmp::min(index_l, l_message.into())); // k_prime must be: MIN(messages_vector.len()) < k_prime < MAX(l_message)

    eprintln!(
        "Time to setup DAC: {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );
    let last = start.elapsed();

    let cred = signer.issue_cred(
        &all_attributes,
        k_prime,
        &alice_nym.nym_proof(&nonce),
        Some(&nonce),
    )?;

    eprintln!(
        "Time to issue cred: {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );
    let last = start.elapsed();

    let opening_vector_restricted = cred.opening_vector;
    // opening_vector_restricted[0] = Scalar::zero(); // means the selected attributes cannot include the first commit in the vector

    let cred_restricted = Credential {
        sigma: cred.sigma,
        commitment_vector: cred.commitment_vector,
        // restrict opening to read only
        opening_vector: opening_vector_restricted,
        update_key: cred.update_key,
        issuer_public: cred.issuer_public,
    };

    // offer to bobby_nym
    let alice_del_to_bobby = alice_nym.offer(&cred_restricted, &None)?;

    eprintln!(
        "Time to offer cred: {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );
    let last = start.elapsed();

    // bobby_nym accepts
    let bobby_cred = bobby_nym.accept(&alice_del_to_bobby)?;

    eprintln!(
        "Time to accept cred: {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );
    let last = start.elapsed();

    // subset of each message set
    let sub_list1_str = vec![age, name];
    let sub_list2_str = vec![];
    let sub_list3_str = vec![insurance];

    let selected_attrs = vec![
        Entry::new(&sub_list1_str),
        Entry::new(&sub_list2_str),
        Entry::new(&sub_list3_str),
    ];

    // prepare a proof
    let proof = bobby_nym.prove(&bobby_cred, &all_attributes, &selected_attrs, &nonce);

    eprintln!(
        "Time to prove: {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );
    let last = start.elapsed();

    assert!(verify_proof(
        &signer.public,
        &proof,
        &selected_attrs,
        Some(&nonce)
    ));

    eprintln!(
        "Time to verify : {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );

    Ok(())
}

fn bench_30_of_100() -> Result<()> {
    // Bench Variables:
    // l - upper bound for the length of the commitment vector
    // t - upper bound for the cardinality of the committed sets
    // n < t - number of attributes in each attribute set A_i in commitment C_i (same for each commitment level)
    // k - length of attribute set vector
    // k_prime - number of attributes sets which can be delegated

    // we set the above parameters as t = 25, l = 15, k = 4, k' = 7 and n = 10 to cover many different use-cases

    let nonce = Nonce::default();

    //start timer
    let start = std::time::Instant::now();

    let n_cardinality = 16; // Allow up to 16 Attributes per Entry or per Proof, 6*16 = 96 max
    let l_max_entries = 6; // Choose 5 from each Entry Level, 6*5 = 30 selected

    // Delegate a subset of attributes
    let entry = |_| {
        Entry::new(
            &(0..n_cardinality)
                .collect::<std::vec::Vec<i32>>()
                .iter()
                .map(|_| Attribute::from(format!("age > 21")))
                .collect::<Vec<_>>(),
        )
    };
    let all_attributes = (0..l_max_entries)
        .collect::<std::vec::Vec<usize>>()
        .iter()
        .map(entry)
        .collect::<Vec<_>>();

    let last = start.elapsed();
    eprintln!("Time to setup attributes: {:?}", last);

    let l_message = MaxEntries::new(l_max_entries);
    let signer = Issuer::new(
        MaxCardinality::new(n_cardinality.try_into().unwrap()),
        l_message,
    );

    let alice_nym = Nym::new();

    let bobby_nym = Nym::new();

    let position = 5; // index of the update key to be used for the added element
    let index_l = all_attributes.len() + position;
    let k_prime = Some(std::cmp::min(index_l, l_message.into())); // k_prime must be: MIN(messages_vector.len()) < k_prime < MAX(l_message)

    eprintln!(
        "Time to setup DAC: {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );
    let last = start.elapsed();

    let cred = match signer.issue_cred(
        &all_attributes,
        k_prime,
        &alice_nym.nym_proof(&nonce),
        Some(&nonce),
    ) {
        Ok(cred) => cred,
        Err(e) => {
            eprintln!("Error issuing cred: {:?}", e);
            return Ok(());
        }
    };

    eprintln!(
        "Time to issue cred: {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );
    let last = start.elapsed();

    let opening_vector_restricted = cred.opening_vector;
    // opening_vector_restricted[0] = Scalar::zero(); // means the selected attributes cannot include the first commit in the vector

    let cred_restricted = Credential {
        sigma: cred.sigma,
        commitment_vector: cred.commitment_vector,
        // restrict opening to read only
        opening_vector: opening_vector_restricted,
        update_key: cred.update_key,
        issuer_public: cred.issuer_public,
    };

    // offer to bobby_nym
    let alice_del_to_bobby = alice_nym.offer(&cred_restricted, &None)?;

    eprintln!(
        "Time to offer cred: {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );
    let last = start.elapsed();

    // bobby_nym accepts
    let bobby_cred = bobby_nym.accept(&alice_del_to_bobby)?;

    eprintln!(
        "Time to accept cred: {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );
    let last = start.elapsed();

    // make an array of the first 5 elements of each entry in all_attributes
    let selected_attrs: Vec<Entry> = all_attributes
        .iter()
        .map(|e| Entry::new(&e.iter().take(5).cloned().collect::<Vec<_>>()))
        .collect();

    // prepare a proof
    let proof = bobby_nym.prove(&bobby_cred, &all_attributes, &selected_attrs, &nonce);

    eprintln!(
        "Time to prove: {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );
    let last = start.elapsed();

    assert!(verify_proof(
        &signer.public,
        &proof,
        &selected_attrs,
        Some(&nonce)
    ));

    eprintln!(
        "Time to verify : {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );

    Ok(())
}
