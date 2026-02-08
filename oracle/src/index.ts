import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2";
import { DstackClient } from "@phala/dstack-sdk";
import {
  CatFactsOracleClient,
  CatFactsOracleFactory,
} from "../contracts/clients/CatFactsOracleClient";
import { AlgorandClient, microAlgo } from "@algorandfoundation/algokit-utils";
import {
  SignedTransaction,
  type Transaction,
  type TransactionSigner,
} from "algosdk";
import * as algosdk from "algosdk";
import { concatBytes } from "@noble/curves/utils.js";
import { blake3 } from "@noble/hashes/blake3";

type RawProofResponse = {
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  committed_key: string;
  compose_hash: string;
  app_id: string;
  proof: string;
  signals: [string, string];
};

type ProofResponse = {
  rtmr0: Uint8Array;
  rtmr1: Uint8Array;
  rtmr2: Uint8Array;
  rtmr3: Uint8Array;
  committedKey: Uint8Array;
  composeHash: Uint8Array;
  appId: Uint8Array;
  signals: [bigint, bigint];
  proof: Uint8Array;
};

function decodeProofResponse(raw: RawProofResponse): ProofResponse {
  console.debug("Decoding proof response: ", raw);
  return {
    rtmr0: new Uint8Array(Buffer.from(raw.rtmr0, "base64")),
    rtmr1: new Uint8Array(Buffer.from(raw.rtmr1, "base64")),
    rtmr2: new Uint8Array(Buffer.from(raw.rtmr2, "base64")),
    rtmr3: new Uint8Array(Buffer.from(raw.rtmr3, "base64")),
    committedKey: new Uint8Array(Buffer.from(raw.committed_key, "base64")),
    composeHash: new Uint8Array(Buffer.from(raw.compose_hash, "base64")),
    appId: new Uint8Array(Buffer.from(raw.app_id, "base64")),
    proof: new Uint8Array(Buffer.from(raw.proof, "base64")),
    signals: [BigInt(raw.signals[0]), BigInt(raw.signals[1])],
  };
}

const client = new DstackClient("../dstack/sdk/simulator/dstack.sock");

// NOTE: In production, we'd not use a fixed seed, but we are using it here so
// we can easily cache the proof
const seed = new Uint8Array(32).fill(0);
const key = ed25519.keygen(seed);

const defaultSender = new algosdk.Address(key.publicKey);
const defaultSigner: TransactionSigner = async (
  txns: Transaction[],
  _,
): Promise<Uint8Array[]> => {
  return txns.map((txn) => {
    const txBytes = txn.bytesToSign();
    const sig = ed25519.sign(txBytes, key.secretKey);
    const signedTxn: SignedTransaction = new SignedTransaction({ txn, sig });
    return algosdk.encodeMsgpack(signedTxn);
  });
};

let appClient: CatFactsOracleClient;

const algorand = AlgorandClient.defaultLocalNet();
algorand.account.setSigner(defaultSender, defaultSigner);

// /// Hash the public values using the provided `hasher` function, mask the top 3 bits and
// /// return a BigUint.
// pub fn hash_bn254_with_fn<F>(&self, hasher: F) -> BigUint
// where
//     F: Fn(&[u8]) -> Vec<u8>,
// {
//     // Hash the public values.
//     let mut hash = hasher(self.buffer.data.as_slice());
//
//     // Mask the top 3 bits.
//     hash[0] &= 0b00011111;
//
//     // Return the masked hash as a BigUint.
//     BigUint::from_bytes_be(hash.as_slice())
// }
const signalHasher = (bytes: Uint8Array) => {
  const hash: Uint8Array = sha256(bytes);
  hash[0] &= 0b00011111;
  return algosdk.bytesToBigInt(hash);
};

const bootstrap = async () => {
  console.log("Address:", defaultSender.toString());
  const factory = algorand.client.getTypedAppFactory(CatFactsOracleFactory, {
    defaultSender: new algosdk.Address(key.publicKey),
    defaultSigner,
  });

  console.log("Getting quote... this may take a minute");
  const quote = await client.getQuote(key.publicKey);
  const proofRes = await fetch("http://localhost:3000/proof", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(quote),
  });

  const rawProofRes: RawProofResponse = await proofRes.json();

  const { rtmr0, rtmr1, rtmr2, rtmr3, composeHash, appId, signals } =
    decodeProofResponse(rawProofRes);

  const computedSignal = signalHasher(
    concatBytes(rtmr0, rtmr1, rtmr2, rtmr3, key.publicKey, composeHash, appId),
  );

  if (computedSignal !== signals[1]) {
    throw new Error(
      "Signal verification failed. Got " +
        computedSignal +
        ", expected " +
        signals[0],
    );
  }

  // In prod another account would create the app
  const res = await factory.send.create.bare({
    sender: await algorand.account.localNetDispenser(),
  });

  appClient = res.appClient;

  await algorand.account.ensureFundedFromEnvironment(
    appClient.appAddress,
    (1).algo(),
  );

  await appClient.send.bootstrap({
    staticFee: microAlgo(3_000),
    args: {
      signals,
      proof: new Uint8Array(0),
      committedInputs: {
        rtmr0,
        rtmr1,
        rtmr2,
        rtmr3,
        pubkey: key.publicKey,
        composeHash,
        appId: appId,
      },
      coverFeeTxn: await appClient.params.coverFee({
        args: [],
        staticFee: microAlgo(0),
      }),
    },
  });
};

await bootstrap();

const factEveryBlock = async () => {
  let round = (await algorand.client.algod.status().do()).lastRound;

  while (true) {
    const { fact } = (await (
      await fetch("https://catfact.ninja/fact")
    ).json()) as Record<string, string>;

    console.debug(`Round ${round}: Adding fact "${fact}"`);

    await appClient
      .newGroup()
      .addFact({
        args: {
          fact: fact!,
          coverFeeTxn: await appClient.params.coverFee({
            args: [],
            staticFee: microAlgo(0),
          }),
        },
        staticFee: microAlgo(3_000),
      })
      .addTransaction(
        await algorand.createTransaction.payment({
          sender: defaultSender,
          signer: defaultSigner,
          receiver: appClient.appAddress,
          amount: (0).algo(),
          closeRemainderTo: appClient.appAddress,
        }),
      )
      .send();

    console.debug(`Round ${round}: Fact added. Waiting for next round...`);

    // In prod we'll wait for a block, but for now use timeout
    // await algorand.client.algod.statusAfterBlock(round).do();
    await new Promise((resolve) => setTimeout(resolve, 3000));

    round += 1n;
  }
};

factEveryBlock();
