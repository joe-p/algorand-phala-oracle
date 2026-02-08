# Algorand Phala Oracle

This repo contains four components for the Algorand Phala Oracle:

- `oracle/src/index.ts`: The main oracle service that fetches data from external sources and submits it to the Algorand blockchain.
- `oracle/contracts/oracle.algo.ts`: The smart contracts that run on the Algorand blockchain to receive and process the data submitted by the oracle.
- `zkvm/sp1-guest`: The SP1 zkVM program that verifies the integrity of the Phala app
- `zkvm/sp1-host`: The SP1 host that gets the attestation from Intel and uses the succinct prover network to generate a groth16 proof that is verified on-chain

Put together, these components enable a trust-minimized (see Trust section below for details) oracle solution for Algorand. The current implementation in this repo is a useless "cat facts" oracle that publishes responses from the public API at https://catfact.ninja/fact to boxes in a smart contract. The contents of the `CatFactOracle` contract and `src/index.ts`, however, can easily be modified to support any data source and any logic for processing the data before submitting it to the blockchain.

## Trust

The design in this repo is intended to minimize the trust needed for an oracle, but there still is some trust required. Whether or not this design is suitable for a given use case depends on the specific requirements of that use case and the level of trust that is acceptable. The trust assumptions for this design are as follows:

### Intel Attestation

Phala utilizes Intel TDX to create a secure enclave for the oracle service. This means that users must trust Intel's attestation process to ensure that the oracle service is running in a secure environment. If the attestation process is compromised, it could potentially allow an attacker to run malicious code in the enclave and manipulate the data being submitted to the blockchain. The entity we must trust here is Intel. We trust that Intel's attestation keypairs are not compromised and that they only sign attestations for genuine TDX enclaves.

### Phala Hardware

Intel TDX's security model assumes that malicious actors do not have direct access to the hardware. If an attacker has physical access to the machine running the oracle service, they could potentially tamper with the hardware or extract sensitive information from the enclave and/or forge a fake attestation quote. The entity we must trust here is the operator of the machine running the oracle service. We trust that they have taken appropriate measures to secure the hardware and prevent unauthorized access. According to [this LinkedIn post](https://www.linkedin.com/posts/phala-network_the-new-ddr5-vulnerability-cant-touch-phala-activity-7389007270052884480-YByK/), Phala uses OVH and other [tier 3](https://uptimeinstitute.com/tiers) data centers.
