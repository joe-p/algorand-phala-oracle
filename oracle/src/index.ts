import { ed25519 } from "@noble/curves/ed25519.js";
import { sha384 } from "@noble/hashes/sha2";
import { DstackClient } from "@phala/dstack-sdk";
import express from "express";

import { concatBytes, utf8ToBytes } from "@noble/hashes/utils";

const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;

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
console.debug("Public Key:", Buffer.from(key.publicKey).toString("hex"));

const eventLog: Record<string, string>[] = JSON.parse(
  (await client.getQuote("")).event_log,
);

const composeHashDigestHex = eventLog.find(
  (e) => e.event === "compose-hash",
)?.digest;

if (!composeHashDigestHex) {
  throw new Error("Compose hash digest not found in event log");
}

const appIdDigestHex = eventLog.find((e) => e.event === "app-id")?.digest;

if (!appIdDigestHex) {
  throw new Error("App ID digest not found in event log");
}

const info = await client.info();

const appId = new Uint8Array(Buffer.from(info.app_id, "hex"));
console.debug("App ID len", appId.byteLength);

const app = express();
const PORT = 3000;

app.get("/quote", async (_, res) => {
  const quote = await client.getQuote(key.publicKey);
  res.send(quote);
});

app.get("/key", (_, res) => {
  res.send(key.publicKey);
});

app.get("/bootstrap", async (_, res) => {
  res.send();
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
