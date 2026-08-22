# BlockForensic-D (BFD)

**BlockForensic-D (BFD)** is a research prototype for verifiable selective disclosure of digital evidence with lifecycle-bound capabilities and threshold-attested destruction.

The evaluated implementation uses **Hyperledger Fabric 3.1.1 with SmartBFT ordering** and is tested with IIoT and industrial-control evidence. The protocol itself is not tied to a specific evidence format and can be instantiated in other digital-evidence settings through deployment-specific scope and governance mappings.

## Main features

- One persistent chunk-Merkle commitment per evidence artifact.
- Three disclosure modes: `HASH_ONLY`, `CHUNK_SET`, and `FULL_CHUNKS`.
- Signed disclosure capabilities bound to scope, commitment, lifecycle state/epoch, and expiry.
- Governed destruction through request, approval, and threshold-attested reporting.
- Post-destruction blocking of new BFD-authorized disclosure while preserving the commitment, audit/destruction records, and historical verification.

> `DESTROYED` is a governed protocol state. BFD does not claim that blockchain can independently prove physical deletion of all off-chain evidence copies or key material.

## Repository structure

```text
BFD/
├── README.md
├── chaincode/        Hyperledger Fabric smart contract
├── codeclient/       Client-side protocol and experiment code
├── caliper/          Hyperledger Caliper benchmark artifacts
├── results/          Curated evaluation results
└── docs/
    └── reproducibility.md
```

## Main implementation components

```text
chaincode/lib/ForensicContract.js

codeclient/
├── forensic-crypto.js
├── evidence-chunker.js
├── evidence-merkle.js
├── capability-manager.js
├── disclosure-protocol.js
├── paper3-client.js
└── experiments/
    ├── experiment-runner.js
    ├── run-disclosure-bench.js
    ├── metrics-schema.js
    └── fabric-e2e-lifecycle-destruction-ms-bench.sh
```

The experiment runner also depends on the corresponding `core/`, `adapters/`, and `profiles/` modules under `codeclient/experiments/`.

## Evaluation artifacts

The repository contains artifacts for:

- **E2** — selective disclosure over one persistent commitment.
- **E3** — evidence-size scaling with a bounded disclosure scope.
- **E4** — chunk-size sensitivity.
- **E7** — lifecycle, adversarial controls, governed destruction, and historical verification.
- **Caliper** — per-operation ledger throughput and latency.

Reported Caliper values are **selected zero-failure, latency-constrained operating points**, not maximum or saturation throughput.

## Datasets

The evaluation uses **Edge-IIoTset** and **SWaT.A6**. Raw third-party datasets are not redistributed in this repository and must be obtained from their original providers under the applicable access conditions.

## Reproducibility

See [`docs/reproducibility.md`](docs/reproducibility.md) for the evaluated environment, dataset preparation, experiment mapping, execution guidance, and artifact-preservation rules.

The repository should preserve the implementation and result files corresponding to the evaluated manuscript baseline. Later code changes should not silently replace that baseline while retaining the original reported results.

## Citation

Repository:

```text
https://github.com/BlockForensic-D/BFD
```

Please cite the corresponding BlockForensic-D manuscript and the repository snapshot used for reproduction.
