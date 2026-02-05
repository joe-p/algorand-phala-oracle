#![no_main]

use dcap_qvl::quote::Quote;
use sha2::{Digest, Sha384};
sp1_zkvm::entrypoint!(main);

type EventDigest = [u8; 48];

// NOTE: Collateral verification is skipped in this guest code since we're not using a real TDX
// server yet

pub fn main() {
    let quote_bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let rtmr3_event_digests_vec = sp1_zkvm::io::read::<Vec<Vec<u8>>>();
    // let collateral_bytes = sp1_zkvm::io::read::<Vec<u8>>();
    // let time = sp1_zkvm::io::read::<u64>();
    //
    // let collateral: QuoteCollateralV3 =
    //     borsh::from_slice(collateral_bytes.as_slice()).expect("failed to deserialize collateral");

    let event_digests: Vec<EventDigest> = rtmr3_event_digests_vec
        .into_iter()
        .map(|d| {
            let mut arr = [0u8; 48];
            arr.copy_from_slice(&d);
            arr
        })
        .collect();

    let mut replayed_rtmr = [0u8; 48];
    for digest in &event_digests {
        let hasher = Sha384::default();
        replayed_rtmr = hasher
            .chain_update(replayed_rtmr)
            .chain_update(digest)
            .finalize()
            .into();
    }

    let quote: Quote = Quote::parse(&quote_bytes).expect("failed to parse quote");

    let quoted_rt_mr3 = quote
        .report
        .as_td10()
        .expect("failed to get td15 report")
        .rt_mr3;

    assert_eq!(
        quoted_rt_mr3, replayed_rtmr,
        "RTMR3 mismatch: quoted RTMR3 does not match replayed RTMR3"
    );

    // let report = verify(&quote_bytes, &collateral, time).expect("failed to verify quote");
    // let report_bytes = borsh::to_vec(&report).expect("failed to serialize report");
}
