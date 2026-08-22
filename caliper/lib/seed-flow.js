'use strict';

const path = require('node:path');
const { loadOrCreateKeyStore, getKeyPair } = require('./key-store');
const { getIdentityConfig, getDefaults, send, jsonArg, repoRoot } = require('./caliper-utils');
const {
  buildEvidencePayload,
  buildCommitPayload,
  buildCapabilityForEvidence,
  loadDatasetProfile,
  buildDestructionRequest,
  buildDestructionApproval,
  buildReceiptForEvidence
} = require('./payload-builders');

function keyStorePath() {
  return path.join(repoRoot(), 'artifacts/keys/caliper-ed25519-keys.json');
}

function getKeyStore() {
  const identities = require(path.join(repoRoot(), 'config/identities.json'));
  return loadOrCreateKeyStore(keyStorePath(), identities);
}

async function registerCorePublicKeys(sutAdapter, contractId, opts = {}) {
  const defaults = getDefaults();
  const store = getKeyStore();
  const adminIdentity = opts.adminIdentity || getIdentityConfig('EvidenceCustodian').caliperIdentity;
  const entries = [
    { logical: 'EvidenceCustodian', purpose: 'DISCLOSURE_CAPABILITY' },
    { logical: 'EvidenceCustodian', purpose: 'DESTRUCTION_ATTESTATION' },
    { logical: 'DataProtectionOfficer', purpose: 'DESTRUCTION_ATTESTATION' },
    { logical: 'JudicialReviewer', purpose: 'DESTRUCTION_ATTESTATION' }
  ];

  for (const entry of entries) {
    const cfg = getIdentityConfig(entry.logical);
    const key = getKeyPair(store, entry.logical);
    try {
      await send(sutAdapter, {
        contractId: contractId || defaults.contractId,
        identity: adminIdentity,
        fcn: 'registerPublicKey',
        args: [cfg.actorId, 'Ed25519', key.publicKeyPem, entry.purpose],
        readOnly: false
      });
    } catch (err) {
      const msg = String(err && err.message ? err.message : err);
      // Registering the same key is idempotent enough for benchmark setup; keep going.
      if (!msg.includes('Public key') && !msg.includes('already') && !msg.includes('MVCC')) {
        console.warn(`[registerCorePublicKeys] ${entry.logical}/${entry.purpose}: ${msg}`);
      }
    }
  }
}

async function preserveEvidence(sutAdapter, contractId, item, collectorIdentity) {
  await send(sutAdapter, {
    contractId,
    identity: collectorIdentity || getIdentityConfig('GatewayCollector').caliperIdentity,
    fcn: 'preserveEvidence',
    args: [jsonArg(item.evidence)],
    readOnly: false
  });
}

async function commitEvidence(sutAdapter, contractId, item, custodianIdentity) {
  await send(sutAdapter, {
    contractId,
    identity: custodianIdentity || getIdentityConfig('EvidenceCustodian').caliperIdentity,
    fcn: 'commitPreservedEvidence',
    args: [item.evidence.evidenceId, jsonArg(item.commitPayload)],
    readOnly: false
  });
}

async function issueCapability(sutAdapter, contractId, item, custodianIdentity) {
  await send(sutAdapter, {
    contractId,
    identity: custodianIdentity || getIdentityConfig('EvidenceCustodian').caliperIdentity,
    fcn: 'issueDisclosureCapability',
    args: [jsonArg(item.capabilityToken)],
    readOnly: false
  });
}

async function requestDestruction(sutAdapter, contractId, item, dpoIdentity, index) {
  await send(sutAdapter, {
    contractId,
    identity: dpoIdentity || getIdentityConfig('DataProtectionOfficer').caliperIdentity,
    fcn: 'requestEvidenceDestruction',
    args: [item.evidence.evidenceId, jsonArg(buildDestructionRequest(index || 0))],
    readOnly: false
  });
}

async function approveDestruction(sutAdapter, contractId, item, judicialIdentity, index) {
  await send(sutAdapter, {
    contractId,
    identity: judicialIdentity || getIdentityConfig('JudicialReviewer').caliperIdentity,
    fcn: 'approveEvidenceDestruction',
    args: [item.evidence.evidenceId, jsonArg(buildDestructionApproval(index || 0))],
    readOnly: false
  });
}

function buildItem({ prefix, workerIndex, index, scopeProfile, activeCapabilityCount = 1 }) {
  const defaults = getDefaults();
  const store = getKeyStore();
  const custodian = getIdentityConfig('EvidenceCustodian');
  const grantee = getIdentityConfig('ExternalVendor');
  const datasetProfile = loadDatasetProfile(defaults.datasetProfileId);

  const evidence = buildEvidencePayload({
    prefix: prefix || 'ev-caliper',
    workerIndex,
    index,
    custodianId: custodian.actorId,
    datasetRef: defaults.datasetRef,
    datasetProfile
  });
  const commitPayload = buildCommitPayload({
    evidenceId: evidence.evidenceId,
    custodianId: custodian.actorId,
    commitmentVersion: defaults.commitmentVersion,
    chunkCount: defaults.chunkCount,
    chunkSize: defaults.chunkSize,
    datasetProfile
  });
  const custodianKey = getKeyPair(store, 'EvidenceCustodian');
  const cap = buildCapabilityForEvidence({
    evidenceId: evidence.evidenceId,
    issuerId: custodian.actorId,
    granteeId: grantee.actorId,
    chunkMerkleRoot: commitPayload.chunkMerkleRoot,
    commitmentVersion: commitPayload.commitmentVersion,
    scopeProfile: scopeProfile || 'HASH_ONLY',
    chunkCount: commitPayload.chunkCount,
    privateKeyPem: custodianKey.privateKeyPem
  });

  const attesterLogicals = ['DataProtectionOfficer', 'JudicialReviewer', 'EvidenceCustodian'];
  const attesters = attesterLogicals.map((logical) => {
    const cfg = getIdentityConfig(logical);
    const key = getKeyPair(store, logical);
    return {
      role: cfg.role,
      actorId: cfg.actorId,
      publicKeyRef: cfg.actorId,
      privateKeyPem: key.privateKeyPem
    };
  });
  const receipt = buildReceiptForEvidence({
    evidenceId: evidence.evidenceId,
    index,
    destroyedKeyClasses: defaults.destroyedKeyClasses,
    thresholdPolicy: defaults.destructionThreshold,
    attesters
  });

  return {
    evidence,
    commitPayload,
    capabilityToken: cap.token,
    requestedChunkIndices: cap.requestedChunkIndices,
    destructionReceipt: receipt,
    activeCapabilityCount
  };
}

async function seedToState(sutAdapter, contractId, item, targetState, index) {
  const defaults = getDefaults();
  const cid = contractId || defaults.contractId;
  const state = String(targetState || 'PRESERVED').toUpperCase();

  await registerCorePublicKeys(sutAdapter, cid);

  if (['PRESERVED','COMMITTED','AUTHORIZED','DESTRUCTION_REQUESTED','DESTRUCTION_APPROVED','DESTROYED'].includes(state)) {
    await preserveEvidence(sutAdapter, cid, item);
  }
  if (['COMMITTED','AUTHORIZED','DESTRUCTION_REQUESTED','DESTRUCTION_APPROVED','DESTROYED'].includes(state)) {
    await commitEvidence(sutAdapter, cid, item);
  }
  if (['AUTHORIZED'].includes(state)) {
    await issueCapability(sutAdapter, cid, item);
  }
  if (['DESTRUCTION_REQUESTED','DESTRUCTION_APPROVED','DESTROYED'].includes(state)) {
    await requestDestruction(sutAdapter, cid, item, null, index);
  }
  if (['DESTRUCTION_APPROVED','DESTROYED'].includes(state)) {
    await approveDestruction(sutAdapter, cid, item, null, index);
  }
  if (['DESTROYED'].includes(state)) {
    await send(sutAdapter, {
      contractId: cid,
      identity: getIdentityConfig('EvidenceCustodian').caliperIdentity,
      fcn: 'reportEvidenceDestroyed',
      args: [item.evidence.evidenceId, jsonArg(item.destructionReceipt)],
      readOnly: false
    });
  }
}

module.exports = {
  getKeyStore,
  registerCorePublicKeys,
  buildItem,
  seedToState,
  preserveEvidence,
  commitEvidence,
  issueCapability,
  requestDestruction,
  approveDestruction
};
