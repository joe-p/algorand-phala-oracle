import {
  assert,
  Bytes,
  Contract,
  GlobalState,
} from "@algorandfoundation/algorand-typescript";

import type { bytes } from "@algorandfoundation/algorand-typescript";
import { Uint256 } from "@algorandfoundation/algorand-typescript/arc4";
import { sha256 } from "@algorandfoundation/algorand-typescript/op";

export type bytes32 = bytes<32>;
export type PhalaAppID = bytes<20>;
export type Signals = Uint256[];
export type Sha384Digest = bytes<48>;

// Placeholder for proof type
export type Proof = bytes<0>;

export type CommittedInputs = {
  rtmr3: Sha384Digest;
  pubkey: bytes32;
  composeHash: bytes32;
  appID: PhalaAppID;
};

export class OracleContract extends Contract {
  /** The hash of the Docker compose file.
   * See https://github.com/Dstack-TEE/dstack/blob/63f30ce7eb78ba940e8bb36aeaf57b1aa79b6e5c/sdk/js/src/get-compose-hash.ts#L102
   */
  composeHash = GlobalState<bytes32>();

  /** The Phala application ID. Note that this is NOT the digest from the event log, this is the app ID itself */
  appID = GlobalState<PhalaAppID>();

  /** The ed25519 public key the app will use to submit data */
  pubkey = GlobalState<bytes32>();

  /** The Runtime Measurement Register 3 value.
   * See https://docs.phala.com/phala-cloud/attestation/verify-your-application#advanced-verification
   */
  rmtr3 = GlobalState<Sha384Digest>();

  private updatePubkeyAndRtmr3(
    signals: Signals,
    committedInputs: CommittedInputs,
  ) {
    const toBeHashed = committedInputs.rtmr3
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

    this.pubkey.value = committedInputs.pubkey;
    this.rmtr3.value = committedInputs.rtmr3;
  }

  createApplication(
    signals: Signals,
    _proof: Proof,
    committedInputs: CommittedInputs,
  ) {
    this.pubkey.value = committedInputs.pubkey;
    this.appID.value = committedInputs.appID;
    this.composeHash.value = committedInputs.composeHash;

    this.updatePubkeyAndRtmr3(signals, committedInputs);
  }
}
