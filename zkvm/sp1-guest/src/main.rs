#![no_main]

use dcap_qvl::quote::Quote;
use sha2::{Digest, Sha384};
sp1_zkvm::entrypoint!(main);

type EventDigest = [u8; 48];

// IMR0 Events: 17
// IMR1 Events: 5
// IMR2 Events: 2
// IMR3 Events: 9

enum RTMR {
    RTMR0 = 0,
    RTMR1 = 1,
    RTMR2 = 2,
    RTMR3 = 3,
}

impl RTMR {
    fn range(&self) -> std::ops::Range<usize> {
        match self {
            RTMR::RTMR0 => 0..17,
            RTMR::RTMR1 => 17..22,
            RTMR::RTMR2 => 22..24,
            RTMR::RTMR3 => 24..33,
        }
    }
}

fn replay_rtmr(event_digests: &[EventDigest], rmtr: RTMR) -> [u8; 48] {
    let mut mr = [0u8; 48];
    for digest in &event_digests[rmtr.range()] {
        let hasher = Sha384::default();
        mr = hasher
            .chain_update(mr)
            .chain_update(digest)
            .finalize()
            .into();
    }
    mr
}

#[derive(Debug, PartialEq, Eq)]
struct RMTRValues {
    rtmr0: [u8; 48],
    rtmr1: [u8; 48],
    rtmr2: [u8; 48],
    rtmr3: [u8; 48],
}

impl RMTRValues {
    fn from_event_digests(event_digests: &[EventDigest]) -> Self {
        Self {
            rtmr0: replay_rtmr(event_digests, RTMR::RTMR0),
            rtmr1: replay_rtmr(event_digests, RTMR::RTMR1),
            rtmr2: replay_rtmr(event_digests, RTMR::RTMR2),
            rtmr3: replay_rtmr(event_digests, RTMR::RTMR3),
        }
    }
}

pub fn main() {
    let quote_bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let rtmr_event_digests = sp1_zkvm::io::read::<Vec<Vec<u8>>>();

    // TODO: verify compose hash and app id against event digest based on index
    let compose_hash = sp1_zkvm::io::read::<Vec<u8>>();
    let app_id = sp1_zkvm::io::read::<Vec<u8>>();

    // NOTE: Collateral verification is skipped in this guest code since we're not using a real TDX
    // server yet
    //
    // let collateral_bytes = sp1_zkvm::io::read::<Vec<u8>>();
    // let time = sp1_zkvm::io::read::<u64>();
    //
    // let collateral: QuoteCollateralV3 =
    //     borsh::from_slice(collateral_bytes.as_slice()).expect("failed to deserialize collateral");
    //
    // verify(&quote_bytes, &collateral, time).expect("failed to verify quote");

    let event_digests: Vec<EventDigest> = rtmr_event_digests
        .into_iter()
        .map(|d| {
            let mut arr = [0u8; 48];
            arr.copy_from_slice(&d);
            arr
        })
        .collect();

    let quote: Quote = Quote::parse(&quote_bytes).expect("failed to parse quote");

    let report = quote.report.as_td10().expect("failed to get td10 report");
    let replayed_rtmr_values = RMTRValues::from_event_digests(&event_digests);
    let quoted_rtmr_values = RMTRValues {
        rtmr0: report.rt_mr0,
        rtmr1: report.rt_mr1,
        rtmr2: report.rt_mr2,
        rtmr3: report.rt_mr3,
    };

    assert_eq!(
        replayed_rtmr_values, quoted_rtmr_values,
        "RTMR3 mismatch: quoted RTMR3 does not match replayed RTMR3"
    );

    assert_eq!(
        report.report_data[32..],
        [0u8; 32],
        "Report data is longer than 32 bytes"
    );

    sp1_zkvm::io::commit_slice(&report.rt_mr0);
    sp1_zkvm::io::commit_slice(&report.rt_mr1);
    sp1_zkvm::io::commit_slice(&report.rt_mr2);
    sp1_zkvm::io::commit_slice(&report.rt_mr3);
    sp1_zkvm::io::commit_slice(&report.report_data[..32]);
    sp1_zkvm::io::commit_slice(&compose_hash);
    sp1_zkvm::io::commit_slice(&app_id);
}
