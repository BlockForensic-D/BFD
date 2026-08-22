'use strict';

const { buildItem } = require('../lib/seed-flow');
const { getDefaults } = require('../lib/caliper-utils');

const item = buildItem({
  prefix: 'dataset-check',
  workerIndex: 0,
  index: 0,
  scopeProfile: 'HASH_ONLY'
});

const token = item.capabilityToken;

const out = {
  defaults: getDefaults(),
  evidence: {
    evidenceId: item.evidence.evidenceId,
    evidenceType: item.evidence.evidenceType,
    datasetRef: item.evidence.datasetRef,
    sourceDataset: item.evidence.sourceDataset,
    sourceAttackType: item.evidence.sourceAttackType,
    datasetWindowName: item.evidence.datasetWindowName,
    evidenceSizeBytes: item.evidence.evidenceSizeBytes,
    fileHash: item.evidence.fileHash,
    datasetProfileId: item.evidence.datasetProfileId
  },
  commitPayload: item.commitPayload,
  capabilityBinding: {
    evidenceId: token.evidenceId,
    granteeId: token.granteeId,
    issuerId: token.issuerId,
    scope: token.scope,
    chunkMerkleRoot: token.chunkMerkleRoot,
    commitmentVersion: token.commitmentVersion,
    lifecycleStateAtIssuance: token.lifecycleStateAtIssuance,
    evidenceLifecycleEpoch: token.evidenceLifecycleEpoch
  },
  consistencyCheck: {
    sameEvidenceId: item.evidence.evidenceId === token.evidenceId,
    sameMerkleRoot: item.commitPayload.chunkMerkleRoot === token.chunkMerkleRoot,
    sameCommitmentVersion: item.commitPayload.commitmentVersion === token.commitmentVersion,
    expectedDatasetProfile: item.evidence.datasetProfileId === 'edge_vulnscan_1mib_v3',
    expectedWindowBytes: item.evidence.evidenceSizeBytes === 1048576,
    expectedChunkCount: item.commitPayload.chunkCount === 256,
    expectedChunkSize: item.commitPayload.chunkSize === 4096,
    expectedFileHash: item.evidence.fileHash === '3305193e4b259d2ef62db3631b7fc851c8f6ee29a67986d31dcbc83e2337a09a',
    expectedMerkleRoot: item.commitPayload.chunkMerkleRoot === 'e8d0456496dd9e4df85a732408c281d19871127dec280dcc08c56a3d9f3898b3'
  }
};

console.log(JSON.stringify(out, null, 2));

const failed = Object.entries(out.consistencyCheck).filter(([, v]) => v !== true);

if (failed.length > 0) {
  console.error('\nFAILED CHECKS:');
  for (const [k, v] of failed) {
    console.error(`- ${k}: ${v}`);
  }
  process.exit(1);
}

console.log('\nDataset-derived Caliper payload check: PASS');
