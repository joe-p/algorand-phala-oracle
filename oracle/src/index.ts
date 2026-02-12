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
import {
  Groth16Bn254LsigVerifier,
  decodeGnarkGroth16Bn254Proof,
  decodeGnarkGroth16Bn254Vk,
} from "snarkjs-algorand";
import { env } from "node:process";

const DEV_MODE = true;
const ALGORAND_APP: bigint = BigInt(env.ALGORAND_APP ?? 0n);
const ALGORAND_NETWORK =
  (env.ALGORAND_NETWORK as "mainnet" | "testnet" | "localnet") ?? "localnet";

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

function signalHasher(bytes: Uint8Array) {
  const hash: Uint8Array = sha256(bytes);
  hash[0]! &= 0b00011111; // So the value fits in the bn254 scalar field
  return algosdk.bytesToBigInt(hash);
}

const dstackClient = new DstackClient("../dstack/sdk/simulator/dstack.sock");

async function bootstrap(): Promise<{
  algorand: AlgorandClient;
  appClient: CatFactsOracleClient;
  oracleServiceAddress: algosdk.Address;
}> {
  let algorand: AlgorandClient;
  switch (ALGORAND_NETWORK) {
    case "mainnet":
      algorand = AlgorandClient.mainNet();
      break;
    case "testnet":
      algorand = AlgorandClient.testNet();
      break;
    case "localnet":
      algorand = AlgorandClient.defaultLocalNet();
      break;
    default:
      throw new Error("Invalid ALGORAND_NETWORK: " + ALGORAND_NETWORK);
  }

  let seed: Uint8Array | undefined = undefined;
  if (DEV_MODE) {
    seed = new Uint8Array(32).fill(0);
  }
  const key = ed25519.keygen(seed);

  const oracleServiceAddress = new algosdk.Address(key.publicKey);
  const defaultSigner: TransactionSigner = async (
    txns: Transaction[],
    indexesToSign: number[],
  ): Promise<Uint8Array[]> => {
    let stxns: Uint8Array[] = [];

    for (const i of indexesToSign) {
      const txn = txns[i]!;
      const txBytes = txn.bytesToSign();
      const sig = ed25519.sign(txBytes, key.secretKey);
      const signedTxn: SignedTransaction = new SignedTransaction({ txn, sig });
      stxns.push(algosdk.encodeMsgpack(signedTxn));
    }

    return stxns;
  };

  algorand.account.setSigner(oracleServiceAddress, defaultSigner);

  console.log("Address:", oracleServiceAddress.toString());
  const factory = algorand.client.getTypedAppFactory(CatFactsOracleFactory, {
    defaultSender: new algosdk.Address(key.publicKey),
    defaultSigner,
  });

  console.log("Getting proof... this may take a minute");
  const quote = await dstackClient.getQuote(key.publicKey);
  const proofRes = await fetch("http://localhost:3000/proof", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(quote),
  });

  const rawProofRes = (await proofRes.json()) as RawProofResponse;

  const { rtmr0, rtmr1, rtmr2, rtmr3, composeHash, appId, signals, proof } =
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

  const gnarkVk = await (
    await (await fetch("http://localhost:3000/vk")).blob()
  ).bytes();

  const lsigVerifier = new Groth16Bn254LsigVerifier({
    totalLsigs: 2,
    appOffset: 2,
    algorand,
    vk: decodeGnarkGroth16Bn254Vk(gnarkVk),
  });

  let appClient: CatFactsOracleClient;

  if (DEV_MODE) {
    const res = await factory.send.create.createApplication({
      args: {
        verifierAddress: (await lsigVerifier.lsigAccount()).addr.toString(),
      },
      sender: await algorand.account.localNetDispenser(),
    });

    appClient = res.appClient;

    await algorand.account.ensureFundedFromEnvironment(
      appClient.appAddress,
      (1).algo(),
    );
  } else {
    if (ALGORAND_APP === 0n) {
      throw new Error(
        "ALGORAND_APP env var must be set to a deployed app in production",
      );
    }
    appClient = factory.getAppClientById({ appId: ALGORAND_APP });
  }

  const composer = appClient.newGroup();

  await lsigVerifier.verificationParams({
    proof: decodeGnarkGroth16Bn254Proof(proof),
    signals,
    composer,
    paramsCallback: async (params) => {
      const { lsigParams, lsigsFee, args } = params;

      // Call app with signals and proof via lsig
      composer.bootstrap({
        staticFee: microAlgo(3_000n + lsigsFee.microAlgo),
        args: {
          ...args,
          committedInputs: {
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            pubkey: key.publicKey,
            composeHash,
            appId,
          },
          verifier: await algorand.createTransaction.payment({
            ...lsigParams,
            amount: microAlgo(0),
            receiver: appClient.appAddress,
          }),
          coverFeeTxn: await appClient.params.coverFee({
            args: [],
            staticFee: microAlgo(0),
          }),
        },
      });
    },
  });

  // NOTE: There seems to be a bug with the signer for the lsig, for some reason the lsig txn is getting a ed25519 sig
  const innerComposer = await composer.composer();
  const { atc } = await innerComposer.build();
  const txnsWithSigners = atc.buildGroup();
  txnsWithSigners[0]!.signer = (await lsigVerifier.lsigAccount()).signer;

  const atcRes = await atc.execute(algorand.client.algod, 3);
  console.log("Bootstrap transaction sent", atcRes.txIDs);

  return { algorand, appClient, oracleServiceAddress };
}

async function factEveryBlock(
  algorand: AlgorandClient,
  appClient: CatFactsOracleClient,
  oracleServiceAddress: algosdk.Address,
) {
  let round = (await algorand.client.algod.status().do()).lastRound;

  while (true) {
    const { fact } = (await (
      await fetch("https://catfact.ninja/fact")
    ).json()) as Record<string, string>;

    console.debug(`Round ${round}: Adding fact "${fact}"`);

    // Send group from defaultSender, which always has a balance of 0 ALGO
    // 1. fee: 0 appl to call `coverFee`. This triggers an inner payment to the sender to cover the cost of the group's fees plus account MBR
    // 2. fee: 3000 appl to call `addFact` with the data and the fee to cover the group
    // 3. fee: 0 pay to close the account and return the remaining balance to the app (fee: 0)
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
          sender: oracleServiceAddress,
          receiver: appClient.appAddress,
          amount: (0).algo(),
          closeRemainderTo: appClient.appAddress,
        }),
      )
      .send();

    console.debug(`Round ${round}: Fact added. Waiting for next round...`);

    if (DEV_MODE) {
      await new Promise((resolve) => setTimeout(resolve, 3000));
    } else {
      await algorand.client.algod.statusAfterBlock(round).do();
    }

    round += 1n;
  }
}

const { algorand, appClient, oracleServiceAddress } = await bootstrap();
factEveryBlock(algorand, appClient, oracleServiceAddress);
