'use strict';

import crypto from 'node:crypto';
import {
  isPlainObject,
  canonicalizeWithoutFields,
  canonicalSha256HexWithoutFields,
  canonicalSha256Hex,
  signCanonicalObjectWithoutFields,
  verifyCanonicalObjectWithoutFields
} from './forensic-crypto.js';
import {
  CAPABILITY_ACCESS_STATES,
  normalizeCapabilityAccessState,
  isCapabilityUsableState,
  buildCapabilityStateFields,
  applyCapabilityUse
} from './governance-state-manager.js';

const CAPABILITY_VERSION = 'cap-v1';
const CAPABILITY_VERSION_V3 = 'cap-v3';

const DEFAULT_DISCLOSURE_LIFECYCLE_STATES = Object.freeze([
  'COMMITTED',
  'AUTHORIZED',
  'DISCLOSED'
]);

const SCOPE_TYPES = Object.freeze({
  HASH_ONLY: 'HASH_ONLY',
  CHUNK_SET: 'CHUNK_SET',
  FULL_CHUNKS: 'FULL_CHUNKS'
});

const ALLOWED_TOKEN_FIELDS = Object.freeze([
  'capId',
  'evidenceId',
  'issuerId',
  'granteeId',
  'scope',
  'purpose',
  'issuedAt',
  'expiresAt',
  'nonce',
  'version',
  'bindingDigest',
  'commitmentVersion',
  'chunkMerkleRoot',
  'lifecycleStateAtIssuance',
  'evidenceLifecycleEpoch',
  'allowedLifecycleStates',
  'signature'
]);

function assertNonEmptyString(value, fieldName) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new TypeError(`${fieldName} must be a non-empty string`);
  }
}

function normalizeId(value, fieldName = 'identifier') {
  assertNonEmptyString(value, fieldName);
  return value.trim();
}

function sanitizeIdFragment(value, maxLen = 16) {
  const normalized = normalizeId(value, 'identifier')
    .replace(/[^a-zA-Z0-9_-]/g, '')
    .slice(0, maxLen);

  if (!normalized) {
    throw new Error(`Unable to sanitize identifier fragment from: ${value}`);
  }

  return normalized;
}

function generateNonceHex(bytes = 16) {
  if (!Number.isInteger(bytes) || bytes <= 0 || bytes > 128) {
    throw new RangeError('bytes must be an integer between 1 and 128');
  }
  return crypto.randomBytes(bytes).toString('hex');
}

function createCapId({ evidenceId, granteeId, nonce, prefix = 'DCAP' }) {
  assertNonEmptyString(prefix, 'prefix');
  const e = sanitizeIdFragment(evidenceId, 18);
  const g = sanitizeIdFragment(granteeId, 18);
  const n = sanitizeIdFragment(nonce, 12);
  return `${prefix}-${e}-${g}-${n}`;
}

function normalizeIsoTimestamp(value, fieldName) {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) {
      throw new TypeError(`${fieldName} is an invalid Date`);
    }
    return value.toISOString();
  }

  if (typeof value === 'string' && value.trim().length > 0) {
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) {
      throw new TypeError(`${fieldName} must be a valid ISO timestamp`);
    }
    return d.toISOString();
  }

  throw new TypeError(`${fieldName} must be a Date or ISO timestamp string`);
}

function normalizeChunkIndices(indices) {
  if (!Array.isArray(indices)) {
    throw new TypeError('scope.indices must be an array');
  }

  const normalized = [];
  const seen = new Set();

  for (const idx of indices) {
    if (!Number.isInteger(idx) || idx < 0) {
      throw new TypeError('scope.indices must contain only non-negative integers');
    }
    if (!seen.has(idx)) {
      seen.add(idx);
      normalized.push(idx);
    }
  }

  normalized.sort((a, b) => a - b);
  return normalized;
}

function normalizeScope(scope) {
  if (!isPlainObject(scope)) {
    throw new TypeError('scope must be a plain object');
  }

  assertNonEmptyString(scope.type, 'scope.type');
  const type = scope.type.trim().toUpperCase();

  if (!Object.values(SCOPE_TYPES).includes(type)) {
    throw new Error(`Unsupported scope.type: ${scope.type}`);
  }

  switch (type) {
    case SCOPE_TYPES.HASH_ONLY:
      return { type: SCOPE_TYPES.HASH_ONLY };

    case SCOPE_TYPES.FULL_CHUNKS:
      return { type: SCOPE_TYPES.FULL_CHUNKS };

    case SCOPE_TYPES.CHUNK_SET: {
      const indices = normalizeChunkIndices(scope.indices);
      if (indices.length === 0) {
        throw new Error('CHUNK_SET scope must contain at least one chunk index');
      }
      return {
        type: SCOPE_TYPES.CHUNK_SET,
        indices
      };
    }

    default:
      throw new Error(`Unhandled scope.type: ${type}`);
  }
}

function validateScope(scope) {
  try {
    const normalized = normalizeScope(scope);
    return { valid: true, normalized };
  } catch (err) {
    return {
      valid: false,
      reason: err instanceof Error ? err.message : 'invalid_scope'
    };
  }
}

function normalizeOptionalDigestHex(value, fieldName) {
  if (value == null || value === '') {
    return null;
  }

  if (typeof value !== 'string' || !/^[a-fA-F0-9]{64}$/.test(value.trim())) {
    throw new TypeError(`${fieldName} must be a valid 64-char SHA-256 hex string`);
  }

  return value.trim().toLowerCase();
}

function normalizeOptionalNonEmptyString(value, fieldName) {
  if (value == null || value === '') return null;
  return normalizeId(String(value), fieldName);
}

function normalizeOptionalNonNegativeSafeInt(value, fieldName) {
  if (value == null || value === '') return null;
  const parsed = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new TypeError(`${fieldName} must be a non-negative safe integer`);
  }
  return parsed;
}

function normalizeLifecycleStateName(value, fieldName = 'lifecycleState') {
  const normalized = normalizeId(String(value), fieldName).trim().toUpperCase();
  return normalized;
}

function normalizeAllowedLifecycleStates(value) {
  if (value == null) return null;
  if (!Array.isArray(value)) {
    throw new TypeError('allowedLifecycleStates must be an array');
  }
  const normalized = [...new Set(value.map((item) => normalizeLifecycleStateName(item, 'allowedLifecycleStates[]')))]
    .sort();
  if (normalized.length === 0) {
    throw new Error('allowedLifecycleStates must not be empty when provided');
  }
  return normalized;
}

function computeScopeDigest(scope) {
  const normalized = normalizeScope(scope);
  return canonicalSha256Hex(normalized);
}

function assertNoUnexpectedFields(obj, allowedFields) {
  const unknown = Object.keys(obj).filter((k) => !allowedFields.includes(k));
  if (unknown.length > 0) {
    throw new Error(`Unexpected field(s): ${unknown.join(', ')}`);
  }
}

function buildCapabilityPayload(params) {
  if (!isPlainObject(params)) {
    throw new TypeError('buildCapabilityPayload expects a plain object');
  }

  const capId = params.capId
    ? normalizeId(params.capId, 'capId')
    : null;

  const evidenceId = normalizeId(params.evidenceId, 'evidenceId');
  const issuerId = normalizeId(params.issuerId, 'issuerId');
  const granteeId = normalizeId(params.granteeId, 'granteeId');
  const purpose = typeof params.purpose === 'string' ? params.purpose.trim() : '';

  const issuedAt = normalizeIsoTimestamp(params.issuedAt, 'issuedAt');
  const expiresAt = normalizeIsoTimestamp(params.expiresAt, 'expiresAt');

  const issuedAtDate = new Date(issuedAt);
  const expiresAtDate = new Date(expiresAt);
  if (expiresAtDate.getTime() <= issuedAtDate.getTime()) {
    throw new Error('expiresAt must be later than issuedAt');
  }

  const nonce = params.nonce
    ? normalizeId(params.nonce, 'nonce')
    : generateNonceHex(8);

  const scope = normalizeScope(params.scope);
  const version = params.version
    ? normalizeId(params.version, 'version')
    : CAPABILITY_VERSION;

  const bindingDigest = normalizeOptionalDigestHex(params.bindingDigest, 'bindingDigest');
  const commitmentVersion = normalizeOptionalNonEmptyString(params.commitmentVersion, 'commitmentVersion');
  const chunkMerkleRoot = normalizeOptionalDigestHex(params.chunkMerkleRoot, 'chunkMerkleRoot');
  const lifecycleStateAtIssuance = params.lifecycleStateAtIssuance == null
    ? null
    : normalizeLifecycleStateName(params.lifecycleStateAtIssuance, 'lifecycleStateAtIssuance');
  const evidenceLifecycleEpoch = normalizeOptionalNonNegativeSafeInt(
    params.evidenceLifecycleEpoch,
    'evidenceLifecycleEpoch'
  );
  const allowedLifecycleStates = normalizeAllowedLifecycleStates(params.allowedLifecycleStates);

  return {
    capId: capId || createCapId({ evidenceId, granteeId, nonce }),
    evidenceId,
    issuerId,
    granteeId,
    scope,
    purpose,
    issuedAt,
    expiresAt,
    nonce,
    version,
    ...(bindingDigest ? { bindingDigest } : {}),
    ...(commitmentVersion ? { commitmentVersion } : {}),
    ...(chunkMerkleRoot ? { chunkMerkleRoot } : {}),
    ...(lifecycleStateAtIssuance ? { lifecycleStateAtIssuance } : {}),
    ...(evidenceLifecycleEpoch != null ? { evidenceLifecycleEpoch } : {}),
    ...(allowedLifecycleStates ? { allowedLifecycleStates } : {})
  };
}

function canonicalizeCapabilityPayload(payloadWithoutSignature) {
  return canonicalizeWithoutFields(payloadWithoutSignature, ['signature']);
}

function computeCapHash(payloadOrToken) {
  if (!isPlainObject(payloadOrToken)) {
    throw new TypeError('computeCapHash expects a plain object');
  }
  return canonicalSha256HexWithoutFields(payloadOrToken, ['signature']);
}

function signCapability(payloadWithoutSignature, issuerPrivateKey) {
  if (!issuerPrivateKey) {
    throw new TypeError('issuerPrivateKey is required');
  }

  const payload = buildCapabilityPayload(payloadWithoutSignature);
  const signature = signCanonicalObjectWithoutFields(
    payload,
    issuerPrivateKey,
    ['signature']
  );

  return {
    ...payload,
    signature
  };
}

function verifyCapabilityToken(token, issuerPublicKey, now = new Date()) {
  try {
    if (!isPlainObject(token)) {
      return { valid: false, reason: 'token_not_plain_object' };
    }

    if (!issuerPublicKey) {
      return { valid: false, reason: 'missing_issuer_public_key' };
    }

    assertNoUnexpectedFields(token, ALLOWED_TOKEN_FIELDS);
    assertNonEmptyString(token.signature, 'signature');

    const payload = buildCapabilityPayload({
  capId: token.capId,
  evidenceId: token.evidenceId,
  issuerId: token.issuerId,
  granteeId: token.granteeId,
  scope: token.scope,
  purpose: token.purpose,
  issuedAt: token.issuedAt,
  expiresAt: token.expiresAt,
  nonce: token.nonce,
  version: token.version,
  bindingDigest: token.bindingDigest,
  commitmentVersion: token.commitmentVersion,
  chunkMerkleRoot: token.chunkMerkleRoot,
  lifecycleStateAtIssuance: token.lifecycleStateAtIssuance,
  evidenceLifecycleEpoch: token.evidenceLifecycleEpoch,
  allowedLifecycleStates: token.allowedLifecycleStates
});

    const signatureValid = verifyCanonicalObjectWithoutFields(
      {
        ...payload,
        signature: token.signature
      },
      token.signature,
      issuerPublicKey,
      ['signature']
    );

    if (!signatureValid) {
      return { valid: false, reason: 'invalid_signature' };
    }

    const nowDate = now instanceof Date ? now : new Date(now);
    if (Number.isNaN(nowDate.getTime())) {
      return { valid: false, reason: 'invalid_now' };
    }

    const expiresAtDate = new Date(payload.expiresAt);
    if (expiresAtDate.getTime() <= nowDate.getTime()) {
      return { valid: false, reason: 'expired' };
    }

    const capHash = computeCapHash(payload);
    const scopeDigest = computeScopeDigest(payload.scope);

    const normalizedToken = {
      ...payload,
      signature: token.signature
    };

    return {
      valid: true,
      payload,
      token: normalizedToken,
      capHash,
      scopeDigest
    };
  } catch (err) {
    return {
      valid: false,
      reason: err instanceof Error ? err.message : 'verification_failed'
    };
  }
}

function normalizeRequestedChunkIndices(requestedChunkIndices) {
  if (typeof requestedChunkIndices === 'undefined' || requestedChunkIndices === null) {
    return [];
  }
  return normalizeChunkIndices(requestedChunkIndices);
}

function checkScope(capabilityScope, requestedChunkIndices) {
  try {
    const normalizedScope = normalizeScope(capabilityScope);
    const normalizedRequestedChunks = normalizeRequestedChunkIndices(requestedChunkIndices);

    if (normalizedScope.type === SCOPE_TYPES.HASH_ONLY) {
      if (normalizedRequestedChunks.length === 0) {
        return {
          allowed: true,
          normalizedScope,
          normalizedRequestedChunks
        };
      }
      return {
        allowed: false,
        normalizedScope,
        normalizedRequestedChunks,
        reason: 'hash_only_scope_requires_empty_chunk_request'
      };
    }

    if (normalizedScope.type === SCOPE_TYPES.FULL_CHUNKS) {
      return {
        allowed: true,
        normalizedScope,
        normalizedRequestedChunks
      };
    }

    if (normalizedScope.type === SCOPE_TYPES.CHUNK_SET) {
      const allowedSet = new Set(normalizedScope.indices);
      const isSubset = normalizedRequestedChunks.every((idx) => allowedSet.has(idx));

      if (!isSubset) {
        return {
          allowed: false,
          normalizedScope,
          normalizedRequestedChunks,
          reason: 'requested_chunks_out_of_scope'
        };
      }

      return {
        allowed: true,
        normalizedScope,
        normalizedRequestedChunks
      };
    }

    return {
      allowed: false,
      normalizedScope,
      normalizedRequestedChunks,
      reason: 'unknown_scope_type'
    };
  } catch (err) {
    return {
      allowed: false,
      normalizedScope: null,
      normalizedRequestedChunks: [],
      reason: err instanceof Error ? err.message : 'scope_check_failed'
    };
  }
}

function evaluateCapabilityValidity(tokenOrPayload, context = {}) {
  try {
    if (!isPlainObject(tokenOrPayload)) {
      return { valid: false, reason: 'token_not_plain_object' };
    }

    const now = context.now ?? new Date();
    const usable = isCapabilityUsableAtTime(tokenOrPayload, now);
    if (!usable.usable) {
      return { valid: false, reason: usable.reason, capabilityState: usable.state };
    }

    if (context.actorId != null && String(context.actorId).trim() !== String(tokenOrPayload.granteeId).trim()) {
      return { valid: false, reason: 'holder_identity_mismatch' };
    }

    if (context.evidenceId != null && String(context.evidenceId).trim() !== String(tokenOrPayload.evidenceId).trim()) {
      return { valid: false, reason: 'evidence_id_mismatch' };
    }

    if (context.commitmentVersion != null && tokenOrPayload.commitmentVersion != null) {
      if (String(context.commitmentVersion).trim() !== String(tokenOrPayload.commitmentVersion).trim()) {
        return { valid: false, reason: 'commitment_version_mismatch' };
      }
    }

    if (context.chunkMerkleRoot != null && tokenOrPayload.chunkMerkleRoot != null) {
      const expectedRoot = normalizeOptionalDigestHex(context.chunkMerkleRoot, 'context.chunkMerkleRoot');
      const tokenRoot = normalizeOptionalDigestHex(tokenOrPayload.chunkMerkleRoot, 'token.chunkMerkleRoot');
      if (expectedRoot !== tokenRoot) {
        return { valid: false, reason: 'chunk_merkle_root_mismatch' };
      }
    }

    if (context.evidenceLifecycleEpoch != null && tokenOrPayload.evidenceLifecycleEpoch != null) {
      const expectedEpoch = normalizeOptionalNonNegativeSafeInt(context.evidenceLifecycleEpoch, 'context.evidenceLifecycleEpoch');
      const tokenEpoch = normalizeOptionalNonNegativeSafeInt(tokenOrPayload.evidenceLifecycleEpoch, 'token.evidenceLifecycleEpoch');
      if (expectedEpoch !== tokenEpoch) {
        return { valid: false, reason: 'lifecycle_epoch_mismatch' };
      }
    }

    if (context.currentLifecycleState != null) {
      const currentState = normalizeLifecycleStateName(context.currentLifecycleState, 'currentLifecycleState');
      const allowedStates = tokenOrPayload.allowedLifecycleStates
        ? normalizeAllowedLifecycleStates(tokenOrPayload.allowedLifecycleStates)
        : DEFAULT_DISCLOSURE_LIFECYCLE_STATES;
      if (!allowedStates.includes(currentState)) {
        return { valid: false, reason: `lifecycle_state_not_allowed:${currentState}` };
      }
    }

    const scopeCheck = checkScope(tokenOrPayload.scope, context.requestedChunkIndices ?? []);
    if (!scopeCheck.allowed) {
      return { valid: false, reason: `scope_check_failed:${scopeCheck.reason}` };
    }

    return { valid: true, reason: null };
  } catch (err) {
    return { valid: false, reason: err instanceof Error ? err.message : 'capability_validity_failed' };
  }
}

function isCapabilityExpired(tokenOrPayload, now = new Date()) {
  const nowDate = now instanceof Date ? now : new Date(now);
  if (!tokenOrPayload || typeof tokenOrPayload.expiresAt !== 'string') {
    throw new TypeError('tokenOrPayload must contain expiresAt');
  }

  const expiresAtDate = new Date(tokenOrPayload.expiresAt);
  if (Number.isNaN(expiresAtDate.getTime()) || Number.isNaN(nowDate.getTime())) {
    throw new TypeError('Invalid expiresAt or now timestamp');
  }

  return expiresAtDate.getTime() <= nowDate.getTime();
}


function capabilityRecordToState(record) {
  return normalizeCapabilityAccessState(record);
}

function isCapabilityUsableAtTime(recordOrToken, now = new Date()) {
  const state = normalizeCapabilityAccessState(recordOrToken);
  if (!isCapabilityUsableState(state)) {
    return { usable: false, state, reason: `capability_not_usable:${state}` };
  }
  if (recordOrToken?.expiresAt && isCapabilityExpired(recordOrToken, now)) {
    return { usable: false, state: CAPABILITY_ACCESS_STATES.EXPIRED, reason: 'capability_expired' };
  }
  return { usable: true, state, reason: null };
}

function applyCapabilityStateTransition(record, action, at = new Date().toISOString()) {
  const normalizedAction = String(action || '').trim().toUpperCase();
  if (normalizedAction === 'USE' || normalizedAction === 'VERIFY' || normalizedAction === 'DISCLOSURE_VERIFIED') {
    return applyCapabilityUse(record, at);
  }
  if (normalizedAction === 'REVOKE') {
    return {
      ...record,
      ...buildCapabilityStateFields(CAPABILITY_ACCESS_STATES.REVOKED),
      revokedAt: at,
    };
  }
  if (normalizedAction === 'EXPIRE') {
    return {
      ...record,
      ...buildCapabilityStateFields(CAPABILITY_ACCESS_STATES.EXPIRED),
      expiredAt: at,
    };
  }
  throw new Error(`Unsupported capability state transition action: ${action}`);
}

function buildInitialStateFields() {
  return buildCapabilityStateFields(CAPABILITY_ACCESS_STATES.ACTIVE);
}

export {
  CAPABILITY_VERSION,
  CAPABILITY_VERSION_V3,
  DEFAULT_DISCLOSURE_LIFECYCLE_STATES,
  SCOPE_TYPES,
  ALLOWED_TOKEN_FIELDS,
  generateNonceHex,
  createCapId,
  normalizeIsoTimestamp,
  normalizeChunkIndices,
  normalizeScope,
  validateScope,
  computeScopeDigest,
  buildCapabilityPayload,
  canonicalizeCapabilityPayload,
  computeCapHash,
  signCapability,
  verifyCapabilityToken,
  normalizeRequestedChunkIndices,
  checkScope,
  evaluateCapabilityValidity,
  isCapabilityExpired,
  CAPABILITY_ACCESS_STATES,
  capabilityRecordToState,
  isCapabilityUsableAtTime,
  applyCapabilityStateTransition,
  buildInitialStateFields
};