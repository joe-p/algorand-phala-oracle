import {
  assert,
  BoxMap,
  Contract,
  GlobalState,
  itxn,
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
  GITxn,
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
export type Proof = bytes<0>;

export type CommittedInputs = {
  rtmr0: Sha384Digest;
  rtmr1: Sha384Digest;
  rtmr2: Sha384Digest;
  rtmr3: Sha384Digest;
  pubkey: bytes32;
  composeHash: bytes32;
  appID: PhalaAppID;
};

export class Oracle extends Contract {
  /** The hash of the Docker compose file.
   * See https://github.com/Dstack-TEE/dstack/blob/63f30ce7eb78ba940e8bb36aeaf57b1aa79b6e5c/sdk/js/src/get-compose-hash.ts#L102
   */
  composeHash = GlobalState<bytes32>();

  /** The Phala application ID. We need to anchor against the app to prevent multiple apps contending to interact with the contract */
  appID = GlobalState<PhalaAppID>();

  /** The ed25519 public key the app will use to submit data. This will rotate each time the app is restarted */
  pubkey = GlobalState<bytes32>();

  /** The Runtime Measurement Register for virtual hardware */
  rtmr0 = GlobalState<Sha384Digest>();

  /** The Runtime Measurement Register for the kernel */
  rtmr1 = GlobalState<Sha384Digest>();

  /** The Runtime Measurement Register for the kernel cmdline and initrd */
  rtmr2 = GlobalState<Sha384Digest>();

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
  rtmr3 = GlobalState<Sha384Digest>();

  protected updatePubkey(signals: Signals, committedInputs: CommittedInputs) {
    const toBeHashed = committedInputs.rtmr0
      .concat(committedInputs.rtmr1)
      .concat(committedInputs.rtmr2)
      .concat(committedInputs.rtmr3)
      .concat(committedInputs.pubkey)
      .concat(committedInputs.composeHash)
      .concat(committedInputs.appID);
    const computedSignal = sha256(toBeHashed);

    assert(signals.length !== 2, "Invalid signals length");
    assert(signals.at(0)!.bytes === computedSignal, "Signal mismatch");

    assert(
      committedInputs.composeHash === this.composeHash.value,
      "Compose hash mismatch",
    );

    assert(committedInputs.appID === this.appID.value, "Phala App ID mismatch");
    assert(committedInputs.rtmr0 === this.rtmr0.value, "RTMR0 mismatch");
    assert(committedInputs.rtmr1 === this.rtmr1.value, "RTMR1 mismatch");
    assert(committedInputs.rtmr2 === this.rtmr2.value, "RTMR2 mismatch");
    assert(committedInputs.rtmr3 === this.rtmr3.value, "RTMR3 mismatch");

    this.pubkey.value = committedInputs.pubkey;
  }

  protected assertSenderIsPhalaApp() {
    assert(
      Txn.sender.bytes === this.pubkey.value,
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
    signals: Signals,
    _proof: Proof,
    committedInputs: CommittedInputs,
    coverFeeTxn: gtxn.ApplicationCallTxn,
  ) {
    assert(!this.appID.hasValue, "Contract already bootstrapped");
    this.assertFeeCovered(coverFeeTxn);

    this.appID.value = committedInputs.appID;
    this.composeHash.value = committedInputs.composeHash;
    this.rtmr0.value = committedInputs.rtmr0;
    this.rtmr1.value = committedInputs.rtmr1;
    this.rtmr2.value = committedInputs.rtmr2;
    this.rtmr3.value = committedInputs.rtmr3;

    this.updatePubkey(signals, committedInputs);
  }

  coverFee() {
    const gindex: uint64 = Txn.groupIndex + 1;

    const method = GTxn.applicationArgs(gindex, 0);
    let amount = GTxn.fee(gindex);

    assert(GTxn.applicationId(gindex) === Global.currentApplicationId);
    assert(method !== methodSelector(this.coverFee));

    if (method === methodSelector(this.bootstrap)) {
      amount += Global.minBalance;
    } else {
      this.assertSenderIsPhalaApp();
    }

    itxn
      .payment({
        receiver: Txn.sender,
        amount,
      })
      .submit();
  }
}

export class CatFactsOracle extends Oracle {
  facts = BoxMap<uint64, string>({ keyPrefix: "" });

  addFact(coverFeeTxn: gtxn.ApplicationCallTxn, fact: string) {
    this.assertSenderIsPhalaApp();
    this.assertFeeCovered(coverFeeTxn);

    assert(coverFeeTxn.appArgs(0) === methodSelector(this.coverFee));

    this.facts(Global.round).value = fact;
  }
}
