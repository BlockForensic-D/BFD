'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { sha256Hex } = require('./canonical-json');
const { evidenceId: makeEvidenceId, receiptRef: makeReceiptRef } = require('./ids');
const { createCapabilityToken, requestedIndicesForScope } = require('./crypto-capability');
const { buildDestructionReceipt } = require('./crypto-destruction-attestation');
const { repoRoot } = require('./caliper-utils');

function randomDigest(label = '') {
  return crypto.createHash('sha256').update(`${label}:${crypto.randomBytes(32).toString('hex')}`).digest('hex');
}

function loadDatasetProfile(profileId) {
  const id = String(profileId || '').trim();
  if (!id) return null;

  const p = path.join(repoRoot(), 'config/dataset-profiles.json');
  if (!fs.existsSync(p)) {
    throw new Error(`datasetProfileId=${id} configured, but ${p} does not exist`);
  }

  const profiles = JSON.parse(fs.readFileSync(p, 'utf8'));
  const profile = profiles[id];

  if (!profile) {
    throw new Error(`Missing dataset profile: ${id}`);
  }

  return profile;
}

function buildEvidencePayload({ prefix, workerIndex, index, custodianId, datasetRef, datasetProfile }) {
  const evidenceId = makeEvidenceId(prefix || 'ev-caliper', workerIndex || 0, index || 0);
  const fallbackDigest = randomDigest(evidenceId);
  const profile = datasetProfile || null;

  const fileHash = profile?.fileHash || fallbackDigest;
  const ref = profile?.profileId || datasetRef || 'caliper-synthetic-ledger-payload';

  const payload = {
    evidenceId,
    incidentId: 'CALIPER_LEDGER_BENCH',
    evidenceType: profile ? 'PCAP_WINDOW_METADATA_ONLY' : 'SYNTHETIC_METADATA_ONLY',
    datasetRef: ref,
    integrityHash: fileHash,
    fileHash,
    collectionTimestamp: new Date().toISOString(),
    custodyOwnerId: custodianId,
    disclosureAuthorityId: custodianId,
    sourceDeviceId: `device-${workerIndex || 0}`,
    notes: profile
      ? 'Dataset-derived metadata payload for ledger-side Caliper benchmark. Raw PCAP bytes are not submitted.'
      : 'Synthetic metadata payload for ledger-side Caliper benchmark. No evidence bytes are submitted.'
  };

  if (profile) {
    payload.sourceDataset = profile.dataset;
    payload.sourceAttackType = profile.attack;
    payload.datasetWindowName = profile.windowName;
    payload.evidenceSizeBytes = profile.windowBytes;
    payload.datasetProfileId = profile.profileId;
    payload.profileEvidenceId = profile.profileEvidenceId;
  }

  return payload;
}

function buildCommitPayload({ evidenceId, custodianId, commitmentVersion, chunkCount, chunkSize, datasetProfile }) {
  const profile = datasetProfile || null;

  const payload = {
    chunkMerkleRoot: profile?.chunkMerkleRoot || randomDigest(`root:${evidenceId}`),
    chunkCount: Number.isInteger(profile?.chunkCount)
      ? profile.chunkCount
      : (Number.isInteger(chunkCount) ? chunkCount : 256),
    chunkSize: Number.isInteger(profile?.chunkSize)
      ? profile.chunkSize
      : (Number.isInteger(chunkSize) ? chunkSize : 4096),
    commitmentVersion: profile?.commitmentVersion || commitmentVersion || 'chunk-merkle-v3-hmac-opening',
    custodyOwnerId: custodianId,
    disclosureAuthorityId: custodianId
  };

  if (profile) {
    payload.datasetProfileId = profile.profileId;
    payload.profileEvidenceId = profile.profileEvidenceId;
    payload.datasetWindowBytes = profile.windowBytes;
    payload.datasetFileHash = profile.fileHash;
  }

  return payload;
}

function scopeFromProfile(profile, chunkCount) {
  const p = String(profile || 'HASH_ONLY').toUpperCase();
  if (p === 'HASH_ONLY') return { type: 'HASH_ONLY' };
  if (p === 'FULL_CHUNKS') return { type: 'FULL_CHUNKS' };
  if (p === 'CHUNK_SET_MEDIUM') return { type: 'CHUNK_SET', indices: Array.from({ length: Math.min(100, chunkCount || 256) }, (_, i) => i) };
  if (p === 'CHUNK_SET_LARGE') return { type: 'CHUNK_SET', indices: Array.from({ length: Math.min(1000, chunkCount || 1024) }, (_, i) => i) };
  if (p === 'CHUNK_SET' || p === 'CHUNK_SET_SMALL') return { type: 'CHUNK_SET', indices: Array.from({ length: Math.min(10, chunkCount || 256) }, (_, i) => i) };
  throw new Error(`Unsupported scope profile: ${profile}`);
}

function buildCapabilityForEvidence({ evidenceId, issuerId, granteeId, chunkMerkleRoot, commitmentVersion, scopeProfile, chunkCount, privateKeyPem }) {
  const scope = scopeFromProfile(scopeProfile || 'HASH_ONLY', chunkCount || 256);
  const token = createCapabilityToken({
    evidenceId,
    issuerId,
    granteeId,
    scope,
    purpose: 'CALIPER_DISCLOSURE_AUTHORIZATION',
    commitmentVersion: commitmentVersion || 'chunk-merkle-v3-hmac-opening',
    chunkMerkleRoot,
    lifecycleStateAtIssuance: 'COMMITTED',
    evidenceLifecycleEpoch: 1,
    allowedLifecycleStates: ['AUTHORIZED', 'DISCLOSED', 'COMMITTED']
  }, privateKeyPem);
  return { token, requestedChunkIndices: requestedIndicesForScope(scope) };
}

function buildDestructionRequest(index) {
  return {
    reasonCode: 'RETENTION_POLICY',
    requestRef: `caliper-destruction-request-${index}`,
    justification: `Caliper benchmark destruction request ${index}`
  };
}

function buildDestructionApproval(index) {
  return {
    approvalRef: `caliper-destruction-approval-${index}`,
    approvalNote: `Approved for Caliper benchmark ${index}`
  };
}

function buildReceiptForEvidence({ evidenceId, index, destroyedKeyClasses, thresholdPolicy, attesters }) {
  const completedAt = new Date().toISOString();
  return buildDestructionReceipt({
    evidenceId,
    completedAt,
    receiptRef: makeReceiptRef(evidenceId, index || 0),
    destroyedKeyClasses: destroyedKeyClasses || ['EMK', 'K_SALT'],
    thresholdPolicy,
    attesters
  });
}

module.exports = {
  randomDigest,
  loadDatasetProfile,
  buildEvidencePayload,
  buildCommitPayload,
  scopeFromProfile,
  buildCapabilityForEvidence,
  buildDestructionRequest,
  buildDestructionApproval,
  buildReceiptForEvidence
};
