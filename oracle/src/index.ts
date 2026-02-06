import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2";
import { DstackClient } from "@phala/dstack-sdk";
import express from "express";
import { CatFactsOracleFactory } from "../contracts/clients/CatFactsOracleClient";
import {
  algo,
  AlgorandClient,
  microAlgo,
} from "@algorandfoundation/algokit-utils";
import {
  SignedTransaction,
  type Transaction,
  type TransactionSigner,
} from "algosdk";
import * as algosdk from "algosdk";
import { concatBytes } from "@noble/curves/utils.js";

// const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;

/**
 * Calculate the digest for a dstack runtime event.
 *
 * Formula: SHA384(event_type_bytes || ":" || event_name || ":" || payload)
 */
// function calculateEventDigest(
//   eventName: string,
//   payload: Uint8Array,
// ): Uint8Array {
//   // Convert event type to little-endian bytes (u32)
//   const eventTypeBytes = new Uint8Array(4);
//   new DataView(eventTypeBytes.buffer).setUint32(
//     0,
//     DSTACK_RUNTIME_EVENT_TYPE,
//     true,
//   );
//
//   const colon = utf8ToBytes(":");
//   const eventNameBytes = utf8ToBytes(eventName);
//
//   // Concatenate: event_type || ":" || event_name || ":" || payload
//   const message = concatBytes(
//     eventTypeBytes,
//     colon,
//     eventNameBytes,
//     colon,
//     payload,
//   );
//
//   return sha384(message);
// }

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

const bootstrap = async () => {
  const algorand = AlgorandClient.defaultLocalNet();

  const factory = algorand.client.getTypedAppFactory(CatFactsOracleFactory, {
    defaultSender: new algosdk.Address(key.publicKey),
    defaultSigner,
  });

  const info = await client.info();
  const appId = new Uint8Array(Buffer.from(info.app_id, "hex"));
  const composeHash = new Uint8Array(Buffer.from(info.compose_hash, "hex"));
  const rtmr3 = new Uint8Array(48);

  const signal = sha256(concatBytes(rtmr3, key.publicKey, composeHash, appId));

  // In prod another account would create the app
  const { appClient } = await factory.send.create.bare({
    sender: await algorand.account.localNetDispenser(),
  });
  await algorand.account.ensureFundedFromEnvironment(
    appClient.appAddress,
    (1).algo(),
  );

  await appClient.send.bootstrap({
    staticFee: microAlgo(3_000),
    args: {
      signals: [algosdk.bytesToBigInt(signal)],
      _proof: new Uint8Array(0),
      committedInputs: {
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

  await appClient.send.addFact({
    args: {
      fact: "Cats are cool",
      coverFeeTxn: await appClient.params.coverFee({
        args: [],
        staticFee: microAlgo(0),
      }),
    },
    staticFee: microAlgo(3_000),
  });
};

console.debug("Public Key:", Buffer.from(key.publicKey).toString("hex"));
console.debug("Address:", defaultSender.toString());

await bootstrap();

const app = express();
const PORT = 3000;

app.get("/quote", async (_, res) => {
  const quote = await client.getQuote(key.publicKey);
  res.send(quote);
});

app.get("/key", (_, res) => {
  res.send(key.publicKey);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
