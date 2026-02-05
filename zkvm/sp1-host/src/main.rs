use std::time::Instant;

use dcap_qvl::PHALA_PCCS_URL;
use dcap_qvl::collateral::get_collateral;
use sp1_sdk::{Prover, ProverClient, SP1Stdin, include_elf};
pub const PROVER_ELF: &[u8] = include_elf!("sp1-guest");

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let quote_hex = reqwest::get("http://localhost:3000/quote")
        .await
        .expect("should be able to get quote")
        .text()
        .await
        .expect("should be able to get quote hex");

    let quote = hex::decode(quote_hex).expect("should be able to decode quote hex");

    let collateral = get_collateral(PHALA_PCCS_URL, &quote)
        .await
        .expect("failed to get collateral");

    println!("Collateral fetched successfully.");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut stdin = SP1Stdin::new();
    stdin.write(&quote);
    stdin.write(&borsh::to_vec(&collateral).expect("should be able to serialize collateral"));
    stdin.write(&now);

    let client = ProverClient::builder().mock().build();

    println!("Executing prover...");
    let (mut output, report) = client.execute(PROVER_ELF, &stdin).run().unwrap();
    println!("Program executed successfully.");
}
