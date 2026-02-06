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

    // NOTE: Collateral verification is skipped in this host code since we're not using a real TDX
    //
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

    // TODO: Compose hash and app id should be provided by the host environment
    stdin.write(&vec![] as &Vec<u8>); // compose_hash
    stdin.write(&vec![] as &Vec<u8>); // app_id

    // stdin.write(&borsh::to_vec(&collateral).expect("should be able to serialize collateral"));
    // stdin.write(&now);

    let client = ProverClient::builder().mock().build();

    println!("Executing prover...");
    let (mut output, report) = client.execute(PROVER_ELF, &stdin).run().unwrap();

    println!("Program executed successfully.");
    println!("Report: {:#?}", report);

    let mut rmtr3_bytes = [0u8; 48];
    output.read_slice(&mut rmtr3_bytes);
    println!("RTMR3: {}", hex::encode(rmtr3_bytes));

    let mut committed_key = [0u8; 32];
    output.read_slice(&mut committed_key);
    println!("ed25519 key: {}", hex::encode(committed_key));

    let app_key = reqwest::get("http://localhost:3000/key")
        .await
        .expect("should be able to get quote")
        .bytes()
        .await
        .expect("should be able to get quote hex");

    assert_eq!(&committed_key[..], &app_key[..], "App key mismatch");
}
