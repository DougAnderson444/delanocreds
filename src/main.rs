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
    verify_proof, Attribute, Credential, CredentialBuilder, Entry, Issuer, MaxCardinality,
    MaxEntries, UserKey,
};

pub fn main() -> Result<()> {
    println!(" \nRunning a short basic test: \n");
    let _ = basic_bench();
    println!(" \nCreating and proving n of m credentials: \n");
    let _ = bench_96_attributes();

    Ok(())
}

pub fn basic_bench() -> Result<()> {
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

    let alice = UserKey::new();
    let alice_nym = alice.nym(signer.public.parameters.clone());

    let robert = UserKey::new();
    let bobby_nym = robert.nym(signer.public.parameters.clone());

    let position = 5; // index of the update key to be used for the added element
    let index_l = all_attributes.len() + position;
    let k_prime = Some(std::cmp::min(index_l, l_message.into())); // k_prime must be: MIN(messages_vector.len()) < k_prime < MAX(l_message)

    eprintln!(
        "Time to setup DAC: {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );
    let last = start.elapsed();

    let cred = signer.issue_cred(&all_attributes, k_prime, &alice_nym.public)?;

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
        vk: cred.vk,
    };

    // offer to bobby_nym
    let alice_del_to_bobby = alice_nym.offer(&cred_restricted, &None, &bobby_nym.public)?;

    eprintln!(
        "Time to offer cred: {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );
    let last = start.elapsed();

    // bobby_nym accepts
    let bobby_cred = bobby_nym.accept(&alice_del_to_bobby);

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
    let proof = bobby_nym.prove(&bobby_cred, &all_attributes, &selected_attrs);

    eprintln!(
        "Time to prove: {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );
    let last = start.elapsed();

    assert!(verify_proof(&signer.public.vk, &proof, &selected_attrs)?);

    eprintln!(
        "Time to verify : {:?} (+{:?})",
        start.elapsed(),
        start.elapsed() - last
    );

    Ok(())
}

fn bench_96_attributes() -> Result<()> {
    //start timer
    let start = std::time::Instant::now();

    // Create 6 Entry with 16 Cardinality, then prove the first 5 Attribute from each of the 6
    // Entry, then verify the proof
    let length = 6;
    let cardinality = 30;
    let total = length * cardinality;

    // create an Issuer, a User, and issue a cred to a Nym
    let issuer = Issuer::new(MaxCardinality::new(cardinality), MaxEntries::new(length));
    let alice = UserKey::new();
    let nym = alice.nym(issuer.public.parameters.clone());

    let mut entrys = Vec::new();
    for i in 0..length {
        let mut attrs = Vec::new();
        for j in 0..cardinality {
            attrs.push(Attribute::new(format!("entry {}, attr {}", i, j)));
        }
        entrys.push(Entry::new(&attrs));
    }

    let mut cred_buildr = issuer.credential();
    for entry in &entrys {
        cred_buildr.with_entry(entry.clone());
    }
    let cred = cred_buildr.issue_to(&nym.public)?;

    let mut all_entries = Vec::new();
    for entry in &entrys {
        all_entries.push(entry.clone());
    }

    let mut selected_entries = Vec::new();

    // The maxmimum we can select is limited by the Set Cardinality of the Issuer
    let limit = (cardinality as f32 / length as f32).floor() as usize;

    (0..length).for_each(|i| {
        let mut attrs = Vec::new();
        for j in 0..limit {
            attrs.push(all_entries[i][j].clone());
        }
        selected_entries.push(Entry::new(&attrs));
    });

    let proof = nym.prove(&cred, &all_entries, &selected_entries);

    assert!(verify_proof(&issuer.public.vk, &proof, &selected_entries).unwrap());

    eprintln!(
        "Time to verify {} out of {} attibutes: {:?}",
        limit * length,
        total,
        start.elapsed()
    );

    Ok(())
}
