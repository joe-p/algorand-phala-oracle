use dstack_sdk_types::dstack::GetQuoteResponse;
use sp1_sdk::{ProverClient, SP1Stdin, include_elf};
pub const PROVER_ELF: &[u8] = include_elf!("sp1-guest");

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let quote_json = reqwest::get("http://localhost:3000/quote")
        .await
        .expect("should be able to get quote")
        .text()
        .await
        .expect("should be able to get quote hex");

    let quote_resp: GetQuoteResponse =
        serde_json::from_str(&quote_json).expect("should be able to parse quote response");

    let quote = quote_resp
        .decode_quote()
        .expect("should be able to decode quote");

    let rtmr3_event_digests_vec = quote_resp
        .decode_event_log()
        .expect("should be able to decode event log")
        .into_iter()
        .filter(|event| event.imr == 3)
        .map(|event| hex::decode(&event.digest).expect("should be able to decode digest"))
        .collect::<Vec<Vec<u8>>>();

    // let collateral = get_collateral(PHALA_PCCS_URL, &quote)
    //     .await
    //     .expect("failed to get collateral");
    //
    // println!("Collateral fetched successfully.");
    // let now = std::time::SystemTime::now()
    //     .duration_since(std::time::UNIX_EPOCH)
    //     .unwrap()
    //     .as_secs();

    let mut stdin = SP1Stdin::new();
    stdin.write(&quote);
    stdin.write(&rtmr3_event_digests_vec);
    // stdin.write(&borsh::to_vec(&collateral).expect("should be able to serialize collateral"));
    // stdin.write(&now);

    let client = ProverClient::builder().mock().build();

    println!("Executing prover...");
    let (_output, report) = client.execute(PROVER_ELF, &stdin).run().unwrap();

    println!("Program executed successfully.");
    println!("Report: {:#?}", report);
}
