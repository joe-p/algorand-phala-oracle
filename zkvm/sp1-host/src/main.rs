use axum::response::IntoResponse;
use dstack_sdk_types::dstack::GetQuoteResponse;
use sp1_sdk::{Prover, ProverClient, SP1Stdin, include_elf};
pub const PROVER_ELF: &[u8] = include_elf!("sp1-guest");
use axum::{Json, Router, routing::get, routing::post};
use dotenv::dotenv;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};
use std::fs;
use std::io::{Cursor, Read};

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ProofResponse {
    #[serde_as(as = "Base64")]
    pub rtmr0: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub rtmr1: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub rtmr2: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub rtmr3: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub committed_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub compose_hash: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub app_id: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub proof: Vec<u8>,
    pub signals: Vec<String>,
}

const ELF_CACHE_PATH: &str = "sp1_elf.bin";
const PROOF_CACHE_PATH: &str = "sp1_proof_response.json";

fn load_cached_proof() -> Option<ProofResponse> {
    let cached_elf = fs::read(ELF_CACHE_PATH).ok()?;
    if cached_elf != PROVER_ELF {
        return None;
    }

    let cached_json = fs::read_to_string(PROOF_CACHE_PATH).ok()?;
    serde_json::from_str(&cached_json).ok()
}

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

async fn get_vk() -> impl IntoResponse {
    sp1_verifier::GROTH16_VK_BYTES.to_vec()
}

async fn get_proof(Json(quote_resp): Json<GetQuoteResponse>) -> Json<ProofResponse> {
    sp1_sdk::utils::setup_logger();

    if let Some(cached) = load_cached_proof() {
        return Json(cached);
    }

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

    let client = ProverClient::builder()
        .network_for(sp1_sdk::network::NetworkMode::Mainnet)
        .build();

    println!("Executing prover...");
    let setup_start = std::time::Instant::now();
    // Setup the program for proving.
    let (pk, _) = client.setup(PROVER_ELF);
    let setup_duration = setup_start.elapsed();
    println!("Setup completed in {:?}", setup_duration);

    let prove_start = std::time::Instant::now();

    // Generate the proof
    let proof = client
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .expect("failed to generate proof");

    let prove_duration = prove_start.elapsed();
    println!("Proving completed in {:?}", prove_duration);

    println!("Successfully generated proof!");

    let groth_proof = proof.proof.try_as_groth_16().expect("not a groth16 proof");

    println!("Program executed successfully.");

    let mut cursor = Cursor::new(proof.public_values.as_slice());

    let mut rmtr0_bytes = [0u8; 48];
    let mut rmtr1_bytes = [0u8; 48];
    let mut rmtr2_bytes = [0u8; 48];
    let mut rmtr3_bytes = [0u8; 48];
    cursor
        .read_exact(&mut rmtr0_bytes)
        .expect("should read RTMR0");
    cursor
        .read_exact(&mut rmtr1_bytes)
        .expect("should read RTMR1");
    cursor
        .read_exact(&mut rmtr2_bytes)
        .expect("should read RTMR2");
    cursor
        .read_exact(&mut rmtr3_bytes)
        .expect("should read RTMR3");
    println!("RTMR0: {}", hex::encode(rmtr0_bytes));
    println!("RTMR1: {}", hex::encode(rmtr1_bytes));
    println!("RTMR2: {}", hex::encode(rmtr2_bytes));
    println!("RTMR3: {}", hex::encode(rmtr3_bytes));

    let mut committed_key = [0u8; 32];
    let mut compose_hash_bytes = [0u8; 32];
    cursor
        .read_exact(&mut committed_key)
        .expect("should read committed key");
    cursor
        .read_exact(&mut compose_hash_bytes)
        .expect("should read compose hash");
    println!("ed25519 key: {}", hex::encode(committed_key));
    println!("Compose hash: {}", hex::encode(compose_hash_bytes));

    let mut app_id_bytes = [0u8; 20];
    cursor
        .read_exact(&mut app_id_bytes)
        .expect("should read app id");
    println!("App ID: {}", hex::encode(app_id_bytes));

    if cursor.position() != proof.public_values.as_slice().len() as u64 {
        panic!("Did not consume all public values bytes");
    }

    fs::write(ELF_CACHE_PATH, PROVER_ELF).expect("failed to write elf to file");

    let proof_bytes = if groth_proof.encoded_proof.is_empty() {
        [0u8; 1].to_vec() // Return a default proof if the encoded proof is empty
    } else {
        hex::decode(&groth_proof.encoded_proof).expect("failed to decode proof")
    };

    let proof_response = ProofResponse {
        rtmr0: rmtr0_bytes.to_vec(),
        rtmr1: rmtr1_bytes.to_vec(),
        rtmr2: rmtr2_bytes.to_vec(),
        rtmr3: rmtr3_bytes.to_vec(),
        committed_key: committed_key.to_vec(),
        compose_hash: compose_hash_bytes.to_vec(),
        app_id: app_id_bytes.to_vec(),
        proof: proof_bytes,
        signals: groth_proof.public_inputs.to_vec(),
    };

    if let Ok(serialized) = serde_json::to_string(&proof_response) {
        let _ = fs::write(PROOF_CACHE_PATH, serialized);
    }

    Json(proof_response)
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Build our application with a route
    let app = Router::new()
        .route("/proof", post(get_proof))
        .route("/vk", get(get_vk));

    // Run the server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    println!("Server running on http://127.0.0.1:3000");

    axum::serve(listener, app).await.unwrap();
}
