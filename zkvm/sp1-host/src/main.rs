use dstack_sdk_types::dstack::GetQuoteResponse;
use sp1_sdk::{ProverClient, SP1Stdin, include_elf};
pub const PROVER_ELF: &[u8] = include_elf!("sp1-guest");

fn get_rtmr_event_digests(quote_resp: &GetQuoteResponse, imr: u32) -> Vec<Vec<u8>> {
    quote_resp
        .decode_event_log()
        .expect("should be able to decode event log")
        .into_iter()
        .filter(|event| event.imr == imr)
        .map(|event| hex::decode(&event.digest).expect("should be able to decode digest"))
        .collect::<Vec<Vec<u8>>>()
}

fn get_event_payload(quote_resp: &GetQuoteResponse, event: &str) -> Vec<u8> {
    quote_resp
        .decode_event_log()
        .expect("should be able to decode event log")
        .into_iter()
        .find(|event_log| event_log.event == event)
        .map(|event_log| {
            hex::decode(&event_log.event_payload).expect("should be able to decode payload")
        })
        .expect("should have event")
}

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

    let rtmr0_vec = get_rtmr_event_digests(&quote_resp, 0);
    let rtmr1_vec = get_rtmr_event_digests(&quote_resp, 1);
    let rtmr2_vec = get_rtmr_event_digests(&quote_resp, 2);
    let rtmr3_vec = get_rtmr_event_digests(&quote_resp, 3);

    let all_digests_vec = [rtmr0_vec, rtmr1_vec, rtmr2_vec, rtmr3_vec].concat();

    let mut stdin = SP1Stdin::new();
    stdin.write(&quote);
    stdin.write(&all_digests_vec);

    stdin.write(&get_event_payload(&quote_resp, "compose-hash"));
    stdin.write(&get_event_payload(&quote_resp, "app-id"));

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

    // stdin.write(&borsh::to_vec(&collateral).expect("should be able to serialize collateral"));
    // stdin.write(&now);

    let client = ProverClient::builder().mock().build();

    println!("Executing prover...");
    let (mut output, report) = client.execute(PROVER_ELF, &stdin).run().unwrap();

    println!("Program executed successfully.");
    println!("Gas: {:#?}", report.gas.unwrap());

    let mut rmtr0_bytes = [0u8; 48];
    let mut rmtr1_bytes = [0u8; 48];
    let mut rmtr2_bytes = [0u8; 48];
    let mut rmtr3_bytes = [0u8; 48];

    output.read_slice(&mut rmtr0_bytes);
    output.read_slice(&mut rmtr1_bytes);
    output.read_slice(&mut rmtr2_bytes);
    output.read_slice(&mut rmtr3_bytes);
    println!("RTMR0: {}", hex::encode(rmtr0_bytes));
    println!("RTMR1: {}", hex::encode(rmtr1_bytes));
    println!("RTMR2: {}", hex::encode(rmtr2_bytes));
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
