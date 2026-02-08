import {
  assert,
  BoxMap,
  Bytes,
  Contract,
  GlobalState,
  itxn,
  op,
  Account,
} from "@algorandfoundation/algorand-typescript";

import type {
  bytes,
  gtxn,
  uint64,
} from "@algorandfoundation/algorand-typescript";
import {
  methodSelector,
  Uint256,
} from "@algorandfoundation/algorand-typescript/arc4";
import {
  Global,
  GTxn,
  sha256,
  Txn,
} from "@algorandfoundation/algorand-typescript/op";

export type bytes32 = bytes<32>;
export type PhalaAppID = bytes<20>;
export type Signals = Uint256[];
export type Sha384Digest = bytes<48>;

// Placeholder for proof type
type Groth16Bn254Proof = {
  /** Prover's first commitment (G1 point) */
  pi_a: bytes<64>;
  /** Prover's second commitment (G2 point) */
  pi_b: bytes<128>;
  /** Prover's third commitment (G1 point) */
  pi_c: bytes<64>;
};

export type CommittedInputs = {
  rtmr0: Sha384Digest;
  rtmr1: Sha384Digest;
  rtmr2: Sha384Digest;
  rtmr3: Sha384Digest;
  pubkey: bytes32;
  composeHash: bytes32;
  appID: PhalaAppID;
};

export class PhalaTdxOracle extends Contract {
  /** The hash of the Docker compose file.
   * See https://github.com/Dstack-TEE/dstack/blob/63f30ce7eb78ba940e8bb36aeaf57b1aa79b6e5c/sdk/js/src/get-compose-hash.ts#L102
   */
  composeHash = GlobalState<bytes32>({ key: "c" });

  /** The Phala application ID. We need to anchor against the app to prevent multiple apps contending to interact with the contract */
  phalaAppId = GlobalState<PhalaAppID>({ key: "a" });

  /** The ed25519 public key the app will use to submit data. This will rotate each time the app is restarted */
  oracleServiceAddress = GlobalState<Account>({ key: "o" });

  /** The Runtime Measurement Register for virtual hardware */
  rtmr0 = GlobalState<Sha384Digest>({ key: "0" });

  /** The Runtime Measurement Register for the kernel */
  rtmr1 = GlobalState<Sha384Digest>({ key: "1" });

  /** The Runtime Measurement Register for the kernel cmdline and initrd */
  rtmr2 = GlobalState<Sha384Digest>({ key: "2" });

  /** The Runtime Measurement Register for the following application events:
   * - system-preparing
   * - app-id
   * - compose-hash
   * - instance-id
   * - boot-mr-done
   * - os-image-hash
   * - key-provider
   * - storage-fs
   * - system-read
   */
  rtmr3 = GlobalState<Sha384Digest>({ key: "3" });

  vkHash = GlobalState<bytes32>({ key: "v" });

  protected updatePubkey(signals: Signals, committedInputs: CommittedInputs) {
    const toBeHashed = committedInputs.rtmr0
      .concat(committedInputs.rtmr1)
      .concat(committedInputs.rtmr2)
      .concat(committedInputs.rtmr3)
      .concat(committedInputs.pubkey)
      .concat(committedInputs.composeHash)
      .concat(committedInputs.appID);
    const computedSignal = sha256(toBeHashed).bitwiseAnd(
      Bytes.fromHex(
        "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      ),
    );

    assert(signals.length === 2, "Invalid signals length");
    assert(signals.at(1)!.bytes === computedSignal, "Signal mismatch");

    assert(
      committedInputs.composeHash === this.composeHash.value,
      "Compose hash mismatch",
    );

    assert(
      committedInputs.appID === this.phalaAppId.value,
      "Phala App ID mismatch",
    );
    assert(committedInputs.rtmr0 === this.rtmr0.value, "RTMR0 mismatch");
    assert(committedInputs.rtmr1 === this.rtmr1.value, "RTMR1 mismatch");
    assert(committedInputs.rtmr2 === this.rtmr2.value, "RTMR2 mismatch");
    assert(committedInputs.rtmr3 === this.rtmr3.value, "RTMR3 mismatch");
    assert(signals.at(0)!.bytes === this.vkHash.value, "VK hash mismatch");
    this.oracleServiceAddress.value = Account(committedInputs.pubkey);
  }

  protected assertSenderIsPhalaApp() {
    assert(
      Txn.sender === this.oracleServiceAddress.value,
      "Sender is not the registered app",
    );
  }

  protected assertFeeCovered(coverFeeTxn: gtxn.ApplicationCallTxn) {
    assert(
      coverFeeTxn.appArgs(0) === methodSelector(this.coverFee),
      "Invalid cover fee txn",
    );
  }

  bootstrap(
    // TODO: save this addr in global state in ctor
    verifier: gtxn.PaymentTxn,
    signals: Signals,
    proof: Groth16Bn254Proof,
    committedInputs: CommittedInputs,
    coverFeeTxn: gtxn.ApplicationCallTxn,
  ) {
    assert(!this.phalaAppId.hasValue, "Contract already bootstrapped");
    this.assertFeeCovered(coverFeeTxn);

    this.phalaAppId.value = committedInputs.appID;
    this.composeHash.value = committedInputs.composeHash;
    this.rtmr0.value = committedInputs.rtmr0;
    this.rtmr1.value = committedInputs.rtmr1;
    this.rtmr2.value = committedInputs.rtmr2;
    this.rtmr3.value = committedInputs.rtmr3;
    this.vkHash.value = signals.at(0)!.bytes.toFixed({ length: 32 });

    this.updatePubkey(signals, committedInputs);
  }

  coverFee() {
    const gindex: uint64 = Txn.groupIndex + 1;
    const method = GTxn.applicationArgs(gindex, 0);

    assert(GTxn.applicationId(gindex) === Global.currentApplicationId);
    assert(method !== methodSelector(this.coverFee));

    if (method !== methodSelector(this.bootstrap)) {
      this.assertSenderIsPhalaApp();
    }

    itxn
      .payment({
        receiver: Txn.sender,
        amount: GTxn.fee(gindex) + Global.minBalance - op.balance(Txn.sender),
      })
      .submit();
  }
}

export class CatFactsOracle extends PhalaTdxOracle {
  facts = BoxMap<uint64, string>({ keyPrefix: "" });

  addFact(coverFeeTxn: gtxn.ApplicationCallTxn, fact: string) {
    this.assertSenderIsPhalaApp();
    this.assertFeeCovered(coverFeeTxn);

    assert(coverFeeTxn.appArgs(0) === methodSelector(this.coverFee));

    this.facts(Global.round).value = fact;
  }
}
