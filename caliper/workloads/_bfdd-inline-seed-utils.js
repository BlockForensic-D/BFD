'use strict';

const { jsonArg, getIdentityConfig, send } = require('../lib/caliper-utils');
const {
  registerCorePublicKeys,
  buildItem,
  preserveEvidence,
  commitEvidence,
  issueCapability,
  requestDestruction,
  approveDestruction
} = require('../lib/seed-flow');
const { computeScopeDigest } = require('../lib/crypto-capability');
const { sha256CanonicalWithoutFieldsHex } = require('../lib/canonical-json');

function buildItemFor(workerIndex, index, prefix, scopeProfile = 'HASH_ONLY') {
  return buildItem({
    prefix,
    workerIndex,
    index: Number(workerIndex) * 1000000 + Number(index),
    scopeProfile
  });
}

function capabilityHash(token) {
  return sha256CanonicalWithoutFieldsHex(token, ['signature']);
}

function bundleHash(bundle) {
  return sha256CanonicalWithoutFieldsHex(bundle, ['bundleHash']);
}

function buildHashOnlyBundle(item) {
  const token = item.capabilityToken;

  const bundle = {
    version: 'disclosure-bundle-v1',
    manifest: {
      version: 'manifest-v1',
      evidenceId: item.evidence.evidenceId,
      capId: token.capId,
      capHash: capabilityHash(token),
      scopeDigest: computeScopeDigest(token.scope),
      disclosureType: 'HASH_ONLY',
      chunkMerkleRoot: item.commitPayload.chunkMerkleRoot,
      commitmentVersion: item.commitPayload.commitmentVersion,
      disclosedChunkIndices: [],
      requestedChunkIndices: [],
      generatedAt: new Date().toISOString()
    },
    capabilityToken: token,
    disclosedChunks: [],
    proofs: []
  };

  bundle.bundleHash = bundleHash(bundle);
  return bundle;
}

async function getCommitment(sutAdapter, contractId, evidenceId, readOnly = true) {
  return send(sutAdapter, {
    contractId,
    identity: getIdentityConfig('EvidenceCustodian').caliperIdentity,
    fcn: 'getEvidenceCommitment',
    args: [evidenceId],
    readOnly
  });
}

async function requestDisclosure(sutAdapter, contractId, item) {
  return send(sutAdapter, {
    contractId,
    identity: getIdentityConfig('ExternalVendor').caliperIdentity,
    fcn: 'requestDisclosure',
    args: [
      item.evidence.evidenceId,
      jsonArg(item.capabilityToken),
      jsonArg(item.requestedChunkIndices || [])
    ],
    readOnly: false
  });
}

async function verifyDisclosure(sutAdapter, contractId, item, bundle) {
  return send(sutAdapter, {
    contractId,
    identity: getIdentityConfig('ExternalVendor').caliperIdentity,
    fcn: 'verifyDisclosure',
    args: [item.evidence.evidenceId, jsonArg(bundle)],
    readOnly: false
  });
}

async function reportDestroyed(sutAdapter, contractId, item) {
  return send(sutAdapter, {
    contractId,
    identity: getIdentityConfig('EvidenceCustodian').caliperIdentity,
    fcn: 'reportEvidenceDestroyed',
    args: [item.evidence.evidenceId, jsonArg(item.destructionReceipt)],
    readOnly: false
  });
}

async function getDestructionRecord(sutAdapter, contractId, evidenceId) {
  return send(sutAdapter, {
    contractId,
    identity: getIdentityConfig('DataProtectionOfficer').caliperIdentity,
    fcn: 'getEvidenceDestructionRecord',
    args: [evidenceId],
    readOnly: true
  });
}

async function seedCommittedItem(sutAdapter, contractId, item) {
  await preserveEvidence(sutAdapter, contractId, item);
  await commitEvidence(sutAdapter, contractId, item);
  await getCommitment(sutAdapter, contractId, item.evidence.evidenceId, true);
}

async function seedDisclosureRequestedItem(sutAdapter, contractId, item) {
  await seedCommittedItem(sutAdapter, contractId, item);
  await issueCapability(sutAdapter, contractId, item);
  await requestDisclosure(sutAdapter, contractId, item);
  return buildHashOnlyBundle(item);
}

async function seedHistoricalDisclosureItem(sutAdapter, contractId, item, index) {
  const bundle = await seedDisclosureRequestedItem(sutAdapter, contractId, item);

  await verifyDisclosure(sutAdapter, contractId, item, bundle);
  await requestDestruction(sutAdapter, contractId, item, null, index);
  await approveDestruction(sutAdapter, contractId, item, null, index);
  await reportDestroyed(sutAdapter, contractId, item);
  await getDestructionRecord(sutAdapter, contractId, item.evidence.evidenceId);

  return bundle;
}

async function seedDestroyedItem(sutAdapter, contractId, item, index) {
  await seedCommittedItem(sutAdapter, contractId, item);
  await requestDestruction(sutAdapter, contractId, item, null, index);
  await approveDestruction(sutAdapter, contractId, item, null, index);
  await reportDestroyed(sutAdapter, contractId, item);
  await getDestructionRecord(sutAdapter, contractId, item.evidence.evidenceId);
}

async function prepareKeys(sutAdapter, contractId) {
  await registerCorePublicKeys(sutAdapter, contractId);
}

function nextItem(state) {
  if (!state.items || state.items.length === 0) {
    throw new Error(`${state.operation} seeded pool is empty: worker=${state.workerIndex}`);
  }

  const index = state.circular === true
    ? state.next % state.items.length
    : state.next;

  const item = state.items[index];

  if (!item) {
    throw new Error(`${state.operation} seeded pool exhausted: worker=${state.workerIndex}, next=${state.next}, seeded=${state.items.length}, circular=${state.circular === true}`);
  }

  state.next += 1;
  return item;
}

module.exports = {
  buildItemFor,
  prepareKeys,
  seedCommittedItem,
  seedDisclosureRequestedItem,
  seedHistoricalDisclosureItem,
  seedDestroyedItem,
  nextItem
};
