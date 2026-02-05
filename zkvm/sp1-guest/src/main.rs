#![no_main]

use dcap_qvl::{QuoteCollateralV3, verify::rustcrypto::verify};
use tiny_keccak::{Hasher, Keccak};
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let quote = sp1_zkvm::io::read::<Vec<u8>>();
    let collateral_bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let time = sp1_zkvm::io::read::<u64>();

    let collateral: QuoteCollateralV3 =
        borsh::from_slice(collateral_bytes.as_slice()).expect("failed to deserialize collateral");

    let report = verify(&quote, &collateral, time).expect("failed to verify quote");

    let report_bytes = borsh::to_vec(&report).expect("failed to serialize report");

    println!("Report bytes len; {}", report_bytes.len());
    let mut hasher = Keccak::v256();
    hasher.update(&report_bytes);

    sp1_zkvm::io::commit_slice(&report_bytes);
}
