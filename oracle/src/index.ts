import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256, sha384 } from "@noble/hashes/sha2";
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
import { utf8ToBytes } from "@noble/hashes/utils";

type RawProofResponse = {
  rtmr0: string;
  rtmr1: string;
  rtmr2: string;
  rtmr3: string;
  committed_key: string;
  compose_hash: string;
  app_id: string;
};

type ProofResponse = {
  rtmr0: Uint8Array;
  rtmr1: Uint8Array;
  rtmr2: Uint8Array;
  rtmr3: Uint8Array;
  committedKey: Uint8Array;
  composeHash: Uint8Array;
  appId: Uint8Array;
};

function decodeProofResponse(raw: RawProofResponse): ProofResponse {
  return {
    rtmr0: new Uint8Array(Buffer.from(raw.rtmr0, "base64")),
    rtmr1: new Uint8Array(Buffer.from(raw.rtmr1, "base64")),
    rtmr2: new Uint8Array(Buffer.from(raw.rtmr2, "base64")),
    rtmr3: new Uint8Array(Buffer.from(raw.rtmr3, "base64")),
    committedKey: new Uint8Array(Buffer.from(raw.committed_key, "base64")),
    composeHash: new Uint8Array(Buffer.from(raw.compose_hash, "base64")),
    appId: new Uint8Array(Buffer.from(raw.app_id, "base64")),
  };
}

const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;

/**
 * Calculate the digest for a dstack runtime event.
 *
 * Formula: SHA384(event_type_bytes || ":" || event_name || ":" || payload)
 */
function calculateEventDigest(
  eventName: string,
  payload: Uint8Array,
): Uint8Array {
  // Convert event type to little-endian bytes (u32)
  const eventTypeBytes = new Uint8Array(4);
  new DataView(eventTypeBytes.buffer).setUint32(
    0,
    DSTACK_RUNTIME_EVENT_TYPE,
    true,
  );

  const colon = utf8ToBytes(":");
  const eventNameBytes = utf8ToBytes(eventName);

  // Concatenate: event_type || ":" || event_name || ":" || payload
  const message = concatBytes(
    eventTypeBytes,
    colon,
    eventNameBytes,
    colon,
    payload,
  );

  return sha384(message);
}

const client = new DstackClient("../dstack/sdk/simulator/dstack.sock");
const key = ed25519.keygen();
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

const bootstrap = async () => {
  const factory = algorand.client.getTypedAppFactory(CatFactsOracleFactory, {
    defaultSender: new algosdk.Address(key.publicKey),
    defaultSigner,
  });

  const quote = await client.getQuote(key.publicKey);
  const proofRes = await fetch("http://localhost:3000/proof", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(quote),
  });

  const rawProofRes: RawProofResponse = await proofRes.json();

  const { rtmr0, rtmr1, rtmr2, rtmr3, composeHash, appId } =
    decodeProofResponse(rawProofRes);

  const signal = sha256(
    concatBytes(rtmr0, rtmr1, rtmr2, rtmr3, key.publicKey, composeHash, appId),
  );

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
      signals: [
        algosdk.bytesToBigInt(signal),
        algosdk.bytesToBigInt(new Uint8Array(32)), // vk hash
      ],
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

console.debug("Public Key:", Buffer.from(key.publicKey).toString("hex"));
console.debug("Address:", defaultSender.toString());

await bootstrap();

const quote = await client.getQuote(key.publicKey);
const eventLogs: any[] = JSON.parse(quote.event_log);
const imr0 = eventLogs.filter((l) => l.imr === 0).map((l) => l.event);
const imr1 = eventLogs.filter((l) => l.imr === 1).map((l) => l.event);
const imr2 = eventLogs.filter((l) => l.imr === 2).map((l) => l.event);
const imr3 = eventLogs.filter((l) => l.imr === 3).map((l) => l.event);

eventLogs.forEach((event) => {
  console.debug(event);
  const calculatedDigest = calculateEventDigest(
    event.event,
    new Uint8Array(Buffer.from(event.event_payload, "hex")),
  );
  console.debug(
    `Calculated Digest: ${Buffer.from(calculatedDigest).toString("hex")}`,
  );
  console.debug(`Event Digest:      ${event.digest}`);
  console.debug(
    `Digest Match:      ${
      Buffer.from(calculatedDigest).toString("hex") === event.digest
    }`,
  );
});
console.debug("IMR0 Events:", imr0.length);
console.debug("IMR1 Events:", imr1.length);
console.debug("IMR2 Events:", imr2.length);
console.debug("IMR3 Events:", imr3.length);
console.debug("IMR3:", imr3);

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
