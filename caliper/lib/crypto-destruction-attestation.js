'use strict';

const crypto = require('node:crypto');
const { canonicalizeJson, sha256Hex } = require('./canonical-json');

function normalizeDestroyedKeyClasses(value) {
  const allowed = new Set(['EMK', 'DEK', 'K_SALT', 'K_META']);
  const raw = Array.isArray(value) ? value : [];
  return [...new Set(raw.map((x) => String(x || '').trim().toUpperCase()).filter((x) => allowed.has(x)))].sort();
}

function buildDestructionStatement({ evidenceId, destructionMethod, receiptRef, completedAt, destroyedKeyClasses, role, actorId, attestedAt }) {
  return {
    purpose: 'EVIDENCE_DESTRUCTION_ATTESTATION',
    evidenceId: String(evidenceId),
    destructionMethod: String(destructionMethod),
    receiptRef: String(receiptRef || ''),
    completedAt: String(completedAt || ''),
    destroyedKeyClasses: normalizeDestroyedKeyClasses(destroyedKeyClasses),
    role: String(role || ''),
    actorId: String(actorId || ''),
    attestedAt: String(attestedAt || '')
  };
}

function signDestructionAttestation(statementInput, privateKeyPem, publicKeyRef) {
  const statement = buildDestructionStatement(statementInput);
  const canonical = canonicalizeJson(statement);
  const statementHash = sha256Hex(canonical);
  const signature = crypto.sign(null, Buffer.from(canonical, 'utf8'), crypto.createPrivateKey(privateKeyPem)).toString('hex');
  return {
    role: statement.role,
    actorId: statement.actorId,
    publicKeyRef: publicKeyRef || statement.actorId,
    attestedAt: statement.attestedAt,
    statement,
    statementHash,
    signature
  };
}

function buildDestructionReceipt({ evidenceId, completedAt, receiptRef, destroyedKeyClasses, thresholdPolicy, attesters }) {
  const destructionMethod = 'ATTESTED_KEY_DESTRUCTION';
  const keyClasses = normalizeDestroyedKeyClasses(destroyedKeyClasses || ['EMK', 'K_SALT']);
  const attestations = attesters.map((att) => signDestructionAttestation({
    evidenceId,
    destructionMethod,
    receiptRef,
    completedAt,
    destroyedKeyClasses: keyClasses,
    role: att.role,
    actorId: att.actorId,
    attestedAt: att.attestedAt || completedAt
  }, att.privateKeyPem, att.publicKeyRef || att.actorId));

  return {
    destroyed: true,
    completed: true,
    destructionMethod,
    receiptRef,
    completedAt,
    destroyedKeyClasses: keyClasses,
    emkDestroyed: keyClasses.includes('EMK'),
    dekDestroyed: keyClasses.includes('DEK'),
    saltKeyDestroyed: keyClasses.includes('K_SALT'),
    metadataKeyDestroyed: keyClasses.includes('K_META'),
    keyMaterialDestroyed: keyClasses.length > 0,
    requireThresholdAttestation: true,
    thresholdPolicy: thresholdPolicy || {
      required: 2,
      eligibleRoles: ['DataProtectionOfficer', 'JudicialReviewer', 'EvidenceCustodian']
    },
    destructionAttestations: attestations
  };
}

module.exports = { normalizeDestroyedKeyClasses, buildDestructionStatement, signDestructionAttestation, buildDestructionReceipt };
