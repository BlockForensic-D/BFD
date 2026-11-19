# Revised BFD research artifact

The manuscript evaluates Hyperledger Fabric 3.1.4 with SmartBFT, three peers and four orderers on one physical host. Node.js 20.19.3 was used on the experiment host. The original submission code and results remain in the top-level baseline directories.

## Protocol implementation

| Manuscript component | Source |
|---|---|
| Fabric entry point, lifecycle, authorization, sessions and destruction | [index.js](index.js), [contract](src/chaincode/contract.cjs), [service](src/chaincode/service.cjs) |
| Commitment construction, acquisition audit and opening verification | [files](src/client/files.cjs), [cryptography](src/shared/crypto.cjs), [bundle](src/client/bundle.cjs) |
| Semantic record selection | [semantic mapping](src/client/semantic.cjs) |
| Release checks, clock and off-chain key erasure | [release](src/client/release.cjs), [clock](src/client/clock.cjs), [erasure](src/client/erasure.cjs) |

[SOURCE_PINS.json](SOURCE_PINS.json) records SHA-256 digests of the 18 deployed-package files and two fixture helpers. Its release ID identifies the experiment source manifest. The separate host package digest identifies the original Fabric package. The local tests use fixtures. Deploying the contract requires an independently configured Fabric network, identities and policies.

## Results by manuscript table

| Table | Files and interpretation |
|---|---|
| 2. Disclosure exposure and cost | [Disclosure results](results/disclosure.json), 12 mode/scope conditions on three real-derived artifacts. Bundle sizes are serialized bytes. Precision flags and 95% half-widths accompany timing estimates. |
| 3. Structural scaling | [Scaling results](results/scaling.json). Select the eight-chunk scope for the reported scaling series. |
| 4–5. Chunk size, acquisition audit and semantic mapping | [Selected chunk-size conditions](results/chunk-size.json) include commitment and audit estimates. Use the 4096-byte contiguous rows for Table 5 and the [mapping estimates](results/mapping.json) for its index and query times, record counts, and mapping checks. |
| 6. Security controls | [Recorded outcomes](results/security.json) cover selected Fabric and local/model cases. The race and destruction-history cases ran on Fabric. Rollback used an application-state model. A prompt stale reply allowed completion. Historical HASH_ONLY verification checks bindings. The JSON is a selected outcome summary. |
| 7. Ledger operations | [Run-level measurements](results/ledger-runs.csv) and [configuration and selection](results/ledger-protocol.json). The report uses 42 of 44 measured attempts, three completed runs per operation. Two incomplete attempts are identified with their request counts. |
| 8. Commitment-opening alternatives | [Confirmation measurements](results/openings.csv.gz) and [configuration](results/opening-protocol.json). The compact CSV preserves the four table metrics and original block and condition identifiers for all 8,400 observations across 180 cells. The pilot is counted separately. |

Table 8 uses the CORE cohort, EDGE_REAL_PCAP, and profiles M1 (individual Merkle paths), M2 (Merkle multiproof), P (KZG/SHPLONK) and V (Pointproofs). The four scopes are single-middle, prefix-8, prefix-64 and scattered-64. For single-middle the paper displays one Merkle row (M1). Time is in milliseconds and sizes are bytes. The table uses arithmetic means and sample standard deviations across 60 confirmation blocks per Edge-IIoTset cell. Dataset acquisition is subject to the original providers’ access terms.

## Check the artifact locally

Run these commands from the repository root using Node.js and Python 3. The offline regression suite exercises production modules with local fixtures and requires no running Fabric network. The Python commands write CSV to standard output and recompute summaries using the recorded measurements.

```sh
node --test revision/tests/audit-hardening.test.cjs
python3 revision/summarize.py ledger
python3 revision/summarize.py openings
```

The original package metadata and lockfile are retained for source verification. The historical npm check and demo entries refer to scripts in the full experiment workspace. Use the commands above with this compact snapshot. The two Python commands reproduce aggregate statistics. Repeating host timings requires the original corpus, benchmark workers and network configuration. [Source export hashes](results/provenance.json) identify the measurement inputs used to assemble the public extracts.
