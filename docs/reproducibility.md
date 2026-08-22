# BlockForensic-D Reproducibility Guide

This document describes the minimum information needed to reproduce or inspect the evaluated BlockForensic-D (BFD) research artifact.

## 1. Evaluated environment

The manuscript evaluation uses the following main environment:

```text
Hyperledger Fabric      3.1.1
Ordering                SmartBFT
Application orgs        3
Peers                    1 peer per application org
Ordering service        4 orderers in a separate ordering organization
State database          LevelDB
Caliper workers         4
Submission model        fixed-rate
Operating system        Ubuntu 20.04
CPU                     Intel Core i7-8559U @ 2.70 GHz
Memory                  32 GB
Storage                 2 TB SSD
```

The reported setup is a single-host experimental deployment. It should therefore be interpreted as a controlled research testbed rather than a production-capacity estimate.

## 2. Repository layout

```text
BFD/
├── chaincode/
├── codeclient/
├── caliper/
├── results/
└── docs/
    └── reproducibility.md
```

The main evaluated chaincode is:

```text
chaincode/lib/ForensicContract.js
```

Main client-side protocol files include:

```text
codeclient/forensic-crypto.js
codeclient/evidence-chunker.js
codeclient/evidence-merkle.js
codeclient/capability-manager.js
codeclient/disclosure-protocol.js
codeclient/paper3-client.js
```

Main experiment files include:

```text
codeclient/experiments/experiment-runner.js
codeclient/experiments/run-disclosure-bench.js
codeclient/experiments/metrics-schema.js
codeclient/experiments/fabric-e2e-lifecycle-destruction-ms-bench.sh
```

The public experiment runner must also include the `core/`, `adapters/`, and `profiles/` modules that it imports.

## 3. Dataset preparation

BFD uses two established IIoT and industrial-control cybersecurity datasets:

- **Edge-IIoTset**, including the vulnerability-scanner attack PCAP used in the selective-disclosure and related experiments.
- **SWaT.A6**, used in the evidence-size scaling evaluation.

Raw dataset files are not redistributed in this repository.

Obtain the datasets from their original providers and place the required local files according to the paths expected by the published experiment configuration, manifest, or adapter.

Do not commit:

```text
raw Edge-IIoTset files
raw SWaT files
credentials or access tokens
Fabric identity secrets
private cryptographic keys
```

## 4. E2 — selective disclosure

E2 evaluates different disclosure scopes over one committed artifact.

Evaluated setup:

```text
Artifact size       16 MiB
Default chunk size  4096 B (4 KiB)
Total chunks        4096
Warm-up             10 repetitions
Measured            30 repetitions
```

The evaluated modes are:

```text
HASH_ONLY
CHUNK_SET
FULL_CHUNKS
```

The `CHUNK_SET` scopes used in the controlled experiment are positional and are selected to vary disclosed content size. BFD does not itself determine packet-level semantic relevance. In deployment, an external parser or investigator may map semantic criteria to chunk indices before capability issuance.

Primary implementation:

```text
codeclient/experiments/experiment-runner.js
codeclient/experiments/run-disclosure-bench.js
codeclient/experiments/core/
codeclient/experiments/adapters/
codeclient/experiments/profiles/
```

Curated results belong under:

```text
results/e2-selective-disclosure/
```

## 5. E3 — evidence-size scaling

E3 evaluates bounded disclosure while the underlying evidence size increases.

Primary evaluated evidence sizes:

```text
1 MiB
16 MiB
64 MiB
128 MiB
256 MiB
512 MiB
```

The evaluated disclosure window remains 32 KiB (8 chunks at the 4 KiB default).

An additional 1 GiB feasibility evaluation may be retained as a separate artifact.

Primary implementation:

```text
codeclient/experiments/experiment-runner.js
codeclient/experiments/adapters/swat-a6-adapter.js
codeclient/experiments/core/
```

Curated results belong under:

```text
results/e3-scaling/
```

## 6. E4 — chunk-size sensitivity

E4 evaluates the trade-off between disclosure granularity, proof size, serialized bundle size, and generation cost.

Evaluated chunk sizes:

```text
512 B
1 KiB
4 KiB
16 KiB
64 KiB
```

The 4 KiB default should be interpreted as a workload-specific compromise rather than a universal optimum.

Primary implementation:

```text
codeclient/experiments/experiment-runner.js
codeclient/experiments/adapters/edge-iiotset-adapter.js
codeclient/experiments/core/
```

Curated results belong under:

```text
results/e4-chunk-size/
```

## 7. E7 — lifecycle and governed destruction

The lifecycle/governance experiment is driven by:

```text
codeclient/experiments/fabric-e2e-lifecycle-destruction-ms-bench.sh
```

and uses:

```text
codeclient/paper3-client.js
chaincode/lib/ForensicContract.js
```

The final evaluated campaign contains:

```text
Evidence records                         30
Positive recorded operations           1201
Adversarial/post-destruction controls    180
Successful destruction reports            30
Post-destruction record checks             90
Historical disclosure verifications       90
```

The adversarial controls exercise a defined subset of chaincode enforcement paths. They should not be interpreted as exhaustive testing of every rejection branch.

The chaincode validates destruction governance and attestations, but it cannot independently observe physical deletion of off-chain key material. `DESTROYED` is therefore a governed protocol state rather than blockchain proof of physical erasure.

Curated results belong under:

```text
results/e7-lifecycle/
```

## 8. Hyperledger Caliper evaluation

Caliper benchmark definitions, workload modules, network files, and scripts are stored under:

```text
caliper/
```

Curated summaries and reports belong under:

```text
results/caliper/
```

The manuscript reports operation-specific **selected zero-failure, latency-constrained operating points**.

These values are not saturation-capacity measurements. For example, a reported value such as `115.8 TPS` for preservation should be treated as a demonstrated operating point under the tested offered rate, not as the maximum capacity of BFD.

When reproducing Caliper results, retain at least:

```text
configured send rate
achieved throughput
latency
failed transaction count
benchmark configuration
```

## 9. Reproduction workflow

A practical reproduction sequence is:

```text
1. Clone the repository.
2. Install the exact Node.js dependencies from the provided package/lock files.
3. Deploy the evaluated Fabric 3.1.1 SmartBFT network.
4. Deploy the evaluated chaincode.
5. Obtain and place the required third-party datasets locally.
6. Run E2/E3/E4 with the published experiment configuration or manifest.
7. Run E7 using the lifecycle shell harness and Fabric Gateway client.
8. Run the Caliper operation benchmarks with the published workload and network files.
9. Write reproduced outputs to a separate directory.
10. Compare reproduced outputs with the curated files under results/.
```

Do **not** overwrite the curated manuscript results during reproduction.

## 10. Artifact provenance

The repository should preserve a clear relationship between:

```text
evaluated code
experiment configuration
reported results
manuscript claims
```

If later hardening or implementation changes are introduced, keep them distinguishable from the evaluated baseline.

For manuscript submission or revision, a tagged GitHub release is recommended so that the exact evaluated artifact snapshot can be cited.

## 11. Interpretation boundaries

When using this repository, keep the following boundaries in mind:

- BFD verifies authorization, scope binding, commitment consistency, and lifecycle state.
- Semantic relevance of evidence content remains case-specific and external to the BFD protocol.
- Previously disclosed lawful bundles cannot be cryptographically retracted.
- `DESTROYED` blocks future BFD-authorized disclosure but does not prove universal deletion of all external copies.
- Caliper results are selected operating points, not universal Fabric capacity bounds.
- Cross-study performance comparisons are contextual because workloads, topologies, transaction semantics, and platform configurations differ.
