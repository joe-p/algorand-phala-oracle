# Algorand Phala Oracle

This repo contains four components for the Algorand Phala Oracle:

- `oracle/src/index.ts`: The main oracle service that fetches data from external sources and submits it to the Algorand blockchain.
- `oracle/contracts/oracle.algo.ts`: The smart contracts that run on the Algorand blockchain to receive and process the data submitted by the oracle.
- `zkvm/sp1-guest`: The SP1 zkVM program that verifies the integrity of the Phala app
- `zkvm/sp1-host`: The SP1 host that gets the attestation from Intel and uses the succinct prover network to generate a groth16 proof that is verified on-chain

Put together, these components enable a trust-minimized (see Trust section below for details) oracle solution for Algorand. The current implementation in this repo is a useless "cat facts" oracle that publishes responses from the public API at https://catfact.ninja/fact to boxes in a smart contract. The contents of the `CatFactOracle` contract and `src/index.ts`, however, can easily be modified to support any data source and any logic for processing the data before submitting it to the blockchain.

## Status

This repo is for research purposes only. The code has not been audited and is not production ready.

## Trust

The design in this repo is intended to minimize the trust needed for an oracle, but there still is some trust required. Whether or not this design is suitable for a given use case depends on the specific requirements of that use case and the level of trust that is acceptable. The trust assumptions for this design are as follows:

### Intel Attestation

Phala utilizes Intel TDX to create a secure enclave for the oracle service. This means that users must trust Intel's attestation process to ensure that the oracle service is running in a secure environment. If the attestation process is compromised, it could potentially allow an attacker to run malicious code in the enclave and manipulate the data being submitted to the blockchain. The entity we must trust here is Intel. We trust that Intel's attestation keypairs are not compromised and that they only sign attestations for genuine TDX enclaves.

It should also be noted that like any other software, we are implicitly trusting it works as intended. There has been a history of software vulnerabilities in Intel's SGX, such as Plundervolt, Foreshadow, and SGAxe.

#### Mitigations

The main way to mitigate the risk of Intel attestation being compromised is to use at least one other server running the oracle service using another TEE (i.e. AMD SEV-SNP). If a 2/2 threshold is required, a failure in the Intel attestation process would result in a liveness failure but not a safety failure.

### Phala Hardware

Intel TDX's security model assumes that malicious actors do not have direct access to the hardware. If an attacker has physical access to the machine running the oracle service, they could potentially tamper with the hardware or extract sensitive information from the enclave and/or forge a fake attestation quote. The entity we must trust here is the operator of the machine running the oracle service. We trust that they have taken appropriate measures to secure the hardware and prevent unauthorized access. According to [this LinkedIn post](https://www.linkedin.com/posts/phala-network_the-new-ddr5-vulnerability-cant-touch-phala-activity-7389007270052884480-YByK/), Phala uses OVH and other [tier 3](https://uptimeinstitute.com/tiers) data centers.

#### Mitigations

The main way to mitigate the risk of hardware being compromised is to use at least one other server running the oracle service using another TEE (i.e. AMD SEV-SNP). Multiple services can then use some sort of consensus mechanism to determine the correct data to submit to the blockchain. At this point, this is essentially a decentralized oracle network similar to Chainlink or Wormhole guardians, but with a smaller number of nodes.

## Chain of Trust in Contract State

### SP1 STARK Verification Key Hash

**Contract Property Name:** `vkHash`

**Global State Key:** `k`

This hash is a commitment to the verification key for the SP1 STARK proof that proves integrity of the oracle service via verifying the Intel TDX attestation and all the related commitments.

### SP1 SNARK Verification Address

**Contract Property Name:** `verifierAddress`

**Global State Key:** `v`

This is the address of the Algorand smart contract (typically a [stateless logic signature](https://github.com/joe-p/snarkjs-algorand/blob/main/contracts/out/Groth16Bn254VerifierLsig.teal)) that is used to verify the Groth16 proof that wraps the SP1 STARK proof. If the contract is a stateless lsig, the address itself is a commitment to the Groth16 verification key. If the contract is a stateful app, then the app's logic must be trusted.

### Runtime Measurement Register: RTMR0

**Contract Property Name:** `rtmr0`

**Global State Key:** `0`

RTMR0 is a register in the Intel TDX architecture that contains a commitment to the virtual hardware that the oracle service is running on. Trust is established via Intel's attestation process which we verify off-chain and prove on-chain via SP1 proof.

### Runtime Measurement Register: RTMR1

**Contract Property Name:** `rtmr1`

**Global State Key:** `1`

RTMR1 is a register in the Intel TDX architecture that contains a commitment to the linux kernel that the oracle service is running on.

### Runtime Measurement Register: RTMR2

**Contract Property Name:** `rtmr2`

**Global State Key:** `2`

RTMR2 is a register in the Intel TDX architecture that contains a commitment to the kernel cmdline and initrd that the oracle service is running with.

### Runtime Measurement Register: RTMR3

**Contract Property Name:** `rtmr3`

**Global State Key:** `3`

RTMR3 is a register in the Intel TDX architecture that contains a commitment to the events following that occur during the start sequence of the Phala service. A change in `RTMR3` means there was a change to the oracle service implementation.

- system-preparing
- app-id
- compose-hash
- instance-id
- boot-mr-done
- os-image-hash
- key-provider
- storage-fs
- system-read

### Compose Hash

**Contract Property Name:** `composeHash`

**Global State Key:** `c`

The compose hash is the sha256 hash of the Docker Compose file used to deploy the oracle service. A change in the compose hash indicates a change in the deployment configuration of the oracle service. It should be noted that this value is encapsulated in the `RTMR3` register, so it's not strictly necessary to store it in global state, but it is included for ease of access and verification.

The dstack SDK can be used to verify the compose hash off-chain: https://github.com/Dstack-TEE/dstack/blob/63f30ce7eb78ba940e8bb36aeaf57b1aa79b6e5c/sdk/js/src/get-compose-hash.ts#L102

### Oracle Service Address

**Contract Property Name:** `oracleServiceAddress`

**Global State Key:** `o`

The oracle service address is the Algorand address that the oracle service uses to submit transactions to the blockchain. This key is ephemeral and may change when the oracle service is restarted. In order to change the key a proof must be generated by the SP1 host that includes the new oracle service address and all the above commitments. This ensures that the only thing changing is the keypair itself and not the underlying software or hardware that the oracle service is running on.
