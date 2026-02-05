import { ed25519 } from "@noble/curves/ed25519.js";
import { DstackClient } from "@phala/dstack-sdk";
import express from "express";
import "dotenv/config";

const client = new DstackClient("../dstack/sdk/simulator/dstack.sock");
const key = ed25519.keygen();
console.debug("Public Key:", Buffer.from(key.publicKey).toString("hex"));

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
