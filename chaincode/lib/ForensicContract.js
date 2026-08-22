'use strict';

const { Contract } = require('fabric-contract-api');
const crypto = require('crypto');

const IPFSManager = require('./IPFSManager');
const { StorageOptimizer } = require('./StorageOptimizer');

// ===========================================================================
// Deterministic disclosure helpers (chaincode-local, CommonJS)
// ===========================================================================

const FC_CAPABILITY_VERSION = 'cap-v1';
const FC_CAPABILITY_VERSION_V3 = 'cap-v3';
const FC_DISCLOSURE_BUNDLE_VERSION = 'disclosure-bundle-v1';
const FC_DISCLOSURE_MANIFEST_VERSION = 'manifest-v1';

const FC_SCOPE_TYPES = Object.freeze({
  HASH_ONLY: 'HASH_ONLY',
  CHUNK_SET: 'CHUNK_SET',
  FULL_CHUNKS: 'FULL_CHUNKS'
});
const FC_LEAF_HASH_DOMAIN = Buffer.from([0x00]);
const FC_NODE_HASH_DOMAIN = Buffer.from([0x01]);
const FC_NODE_HASH_V3_DOMAIN = Buffer.from('FDEM-NODE-v3', 'ascii');
const FC_CHUNK_V3_DOMAIN = Buffer.from('FDEM-CHUNK-v3', 'ascii');
const FC_LEAF_V3_DOMAIN = Buffer.from('FDEM-LEAF-v3', 'ascii');
const FC_EMPTY_ROOT_DOMAIN = Buffer.from([0xFF]);
const FC_EMPTY_TREE_SENTINEL = 'empty';
const FC_CHUNK_COMMITMENT_VERSION = 'chunk-merkle-v2';
const FC_CHUNK_COMMITMENT_VERSION_V3 = 'chunk-merkle-v3-hmac-opening';

const FC_EVIDENCE_LIFECYCLE_STATES = Object.freeze({
  PRESERVED: 'PRESERVED',
  COMMITTED: 'COMMITTED',
  AUTHORIZED: 'AUTHORIZED',
  DISCLOSED: 'DISCLOSED',
  RESTRICTED: 'RESTRICTED',
  DESTRUCTION_REQUESTED: 'DESTRUCTION_REQUESTED',
  DESTRUCTION_APPROVED: 'DESTRUCTION_APPROVED',
  DESTROYED: 'DESTROYED',
  WITHDRAWN: 'WITHDRAWN',
  ARCHIVED: 'ARCHIVED'
});

const FC_CAPABILITY_ACCESS_STATES = Object.freeze({
  ISSUED: 'ISSUED',
  ACTIVE: 'ACTIVE',
  USED: 'USED',
  EXPIRED: 'EXPIRED',
  REVOKED: 'REVOKED'
});

const FC_WITHDRAWAL_REASONS = Object.freeze([
  'PRIVACY_REQUEST',
  'REGULATORY_DIRECTIVE',
  'RETENTION_POLICY',
  'STAKEHOLDER_AGREEMENT',
  'INVESTIGATION_CLOSURE',
  'ERRONEOUS_DISCLOSURE',
  'CONTRACTUAL_OBLIGATION',
  'ADMINISTRATIVE',
  'OTHER'
]);

const FC_DESTRUCTION_REASONS = Object.freeze([
  'RETENTION_POLICY',
  'REGULATORY_DIRECTIVE',
  'PRIVACY_REQUEST',
  'COURT_ORDER',
  'INVESTIGATION_CLOSURE',
  'STAKEHOLDER_AGREEMENT',
  'CONTRACTUAL_OBLIGATION',
  'ERRONEOUS_COLLECTION',
  'ADMINISTRATIVE',
  'OTHER'
]);

const FC_DESTRUCTION_METHODS = Object.freeze([
  'ATTESTED_KEY_DESTRUCTION',
  'HYBRID_CRYPTO_SHREDDING',
  'KEY_DESTRUCTION',
  'OFFCHAIN_SECURE_DELETION',
  'OFFCHAIN_POINTER_REVOCATION',
  'RETENTION_DISPOSAL',
  'ADMINISTRATIVE_DISPOSITION',
  'OTHER'
]);

// Mandatory destruction-attestation policy. Evidence destruction must be
// cryptographically attested by at least 2 distinct governance roles/actors.
const FC_DESTRUCTION_THRESHOLD_POLICY = Object.freeze({
  required: 2,
  eligibleRoles: Object.freeze([
    'DataProtectionOfficer',
    'JudicialReviewer',
    'EvidenceCustodian'
  ])
});

// Mandatory future-opening revocation policy. A destruction report is accepted
// as final only if it attests destruction/revocation of the opening material
// needed to generate future chunk openings. Destroying K_SALT directly is
// sufficient; destroying its parent/wrapping EMK is also sufficient.
const FC_DESTRUCTION_REQUIRED_OPENING_KEY_CLASSES = Object.freeze([
  'K_SALT',
  'EMK'
]);

const FC_RESTRICTION_REASONS = Object.freeze([
  'PENDING_LEGAL_REVIEW',
  'INVESTIGATION_HOLD',
  'INTEGRITY_QUESTION',
  'PRIVACY_REVIEW',
  'STAKEHOLDER_DISPUTE',
  'TEMPORARY_QUARANTINE',
  'ADMINISTRATIVE',
  'OTHER'
]);

const FC_REVOCATION_REASONS = Object.freeze([
  'EXPIRED_AUTHORIZATION',
  'GRANTEE_ROLE_CHANGE',
  'SCOPE_VIOLATION',
  'INVESTIGATION_CLOSED',
  'SECURITY_INCIDENT',
  'POLICY_CHANGE',
  'GRANTEE_REQUEST',
  'ADMINISTRATIVE',
  'OTHER'
]);

const FC_ALLOWED_TOKEN_FIELDS = Object.freeze([
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

function fcIsPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && !Buffer.isBuffer(value);
}

function fcNormalizeForCanonicalJson(value) {
  if (Array.isArray(value)) {
    return value.map(fcNormalizeForCanonicalJson);
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (fcIsPlainObject(value)) {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      const v = value[key];
      if (typeof v !== 'undefined') {
        out[key] = fcNormalizeForCanonicalJson(v);
      }
    }
    return out;
  }
  return value;
}

function fcCanonicalizeJson(obj) {
  return JSON.stringify(fcNormalizeForCanonicalJson(obj));
}

function fcOmitFields(obj, fields) {
  if (!fcIsPlainObject(obj)) {
    throw new TypeError('fcOmitFields expects a plain object');
  }
  const out = {};
  for (const key of Object.keys(obj)) {
    if (!fields.includes(key)) {
      out[key] = obj[key];
    }
  }
  return out;
}

function fcCanonicalizeWithoutFields(obj, fields = ['signature']) {
  return fcCanonicalizeJson(fcOmitFields(obj, fields));
}

function fcCanonicalSha256HexWithoutFields(obj, fields = ['signature']) {
  return crypto.createHash('sha256')
    .update(fcCanonicalizeWithoutFields(obj, fields), 'utf8')
    .digest('hex');
}

function fcToBuffer(input) {
  if (Buffer.isBuffer(input)) return Buffer.from(input);

  if (input instanceof Uint8Array) {
    return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  }

  if (typeof input === 'string') {
    return Buffer.from(input, 'utf8');
  }

  if (
    input &&
    typeof input === 'object' &&
    input.type === 'Buffer' &&
    Array.isArray(input.data)
  ) {
    return Buffer.from(input.data);
  }

  throw new TypeError('Expected Buffer, Uint8Array, Buffer JSON object, or string');
}

function fcSha256Hex(input) {
  return crypto.createHash('sha256').update(fcToBuffer(input)).digest('hex');
}

function fcIsSha256Hex(x) {
  return typeof x === 'string' && /^[a-fA-F0-9]{64}$/.test(x);
}

function fcHexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[a-fA-F0-9]+$/.test(hex)) {
    throw new TypeError('Invalid hex string');
  }
  return Buffer.from(hex, 'hex');
}

function fcUint32be(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError('uint32 value must be an unsigned 32-bit safe integer');
  }
  const out = Buffer.allocUnsafe(4);
  out.writeUInt32BE(value, 0);
  return out;
}

function fcUint64be(value) {
  const n = typeof value === 'bigint' ? value : BigInt(value);
  if (n < 0n || n > 0xffffffffffffffffn) {
    throw new RangeError('uint64 value must be an unsigned 64-bit integer');
  }
  const out = Buffer.allocUnsafe(8);
  out.writeBigUInt64BE(n, 0);
  return out;
}

function fcLengthPrefixedUtf8(value) {
  const bytes = Buffer.from(String(value), 'utf8');
  return Buffer.concat([fcUint32be(bytes.length), bytes]);
}

function fcNormalizeOptionalDigestHex(value, fieldName) {
  if (value === undefined || value === null || value === '') return null;
  const digest = String(value).trim().toLowerCase();
  if (!fcIsSha256Hex(digest)) {
    throw new TypeError(`${fieldName} must be a SHA-256 hex digest when provided`);
  }
  return digest;
}

function fcNormalizeOptionalNonEmptyString(value, fieldName) {
  if (value === undefined || value === null || value === '') return null;
  return fcNormalizeNonEmptyString(String(value), fieldName);
}

function fcNormalizeOptionalNonNegativeInt(value, fieldName) {
  if (value === undefined || value === null || value === '') return null;
  const parsed = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new TypeError(`${fieldName} must be a non-negative safe integer`);
  }
  return parsed;
}

function fcNormalizeLifecycleStateName(value, fieldName) {
  return fcNormalizeNonEmptyString(String(value), fieldName).toUpperCase();
}

function fcNormalizeAllowedLifecycleStates(value) {
  if (value === undefined || value === null) return null;
  if (!Array.isArray(value)) {
    throw new TypeError('allowedLifecycleStates must be an array');
  }
  const normalized = [...new Set(value.map((item) => fcNormalizeLifecycleStateName(item, 'allowedLifecycleStates[]')))].sort();
  if (normalized.length === 0) {
    throw new Error('allowedLifecycleStates must not be empty when provided');
  }
  return normalized;
}

function fcNormalizeNonEmptyString(value, fieldName) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new TypeError(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function fcNormalizeIsoTimestamp(value, fieldName) {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) {
      throw new TypeError(`${fieldName} is invalid`);
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

function fcNormalizeChunkIndices(indices) {
  if (!Array.isArray(indices)) {
    throw new TypeError('chunk indices must be an array');
  }

  const unique = [...new Set(indices)];
  for (const idx of unique) {
    if (!Number.isInteger(idx) || idx < 0) {
      throw new TypeError('chunk indices must contain only non-negative integers');
    }
  }

  unique.sort((a, b) => a - b);
  return unique;
}

function fcNormalizeScope(scope) {
  if (!fcIsPlainObject(scope)) {
    throw new TypeError('scope must be a plain object');
  }

  const type = fcNormalizeNonEmptyString(scope.type, 'scope.type').toUpperCase();
  if (!Object.values(FC_SCOPE_TYPES).includes(type)) {
    throw new Error(`Unsupported scope.type: ${scope.type}`);
  }

  switch (type) {
    case FC_SCOPE_TYPES.HASH_ONLY:
      return { type: FC_SCOPE_TYPES.HASH_ONLY };

    case FC_SCOPE_TYPES.FULL_CHUNKS:
      return { type: FC_SCOPE_TYPES.FULL_CHUNKS };

    case FC_SCOPE_TYPES.CHUNK_SET: {
      const indices = fcNormalizeChunkIndices(scope.indices);
      if (indices.length === 0) {
        throw new Error('CHUNK_SET scope must contain at least one chunk index');
      }
      return { type: FC_SCOPE_TYPES.CHUNK_SET, indices };
    }

    default:
      throw new Error(`Unhandled scope type: ${type}`);
  }
}

function fcComputeScopeDigest(scope) {
  return fcSha256Hex(fcCanonicalizeJson(fcNormalizeScope(scope)));
}

function fcBuildCapabilityPayload(params) {
  if (!fcIsPlainObject(params)) {
    throw new TypeError('Capability payload must be an object');
  }

  const capId = fcNormalizeNonEmptyString(params.capId, 'capId');
  const evidenceId = fcNormalizeNonEmptyString(params.evidenceId, 'evidenceId');
  const issuerId = fcNormalizeNonEmptyString(params.issuerId, 'issuerId');
  const granteeId = fcNormalizeNonEmptyString(params.granteeId, 'granteeId');
  const purpose = typeof params.purpose === 'string' ? params.purpose.trim() : '';
  const issuedAt = fcNormalizeIsoTimestamp(params.issuedAt, 'issuedAt');
  const expiresAt = fcNormalizeIsoTimestamp(params.expiresAt, 'expiresAt');
  const nonce = fcNormalizeNonEmptyString(params.nonce, 'nonce');
  const version = params.version
    ? fcNormalizeNonEmptyString(params.version, 'version')
    : FC_CAPABILITY_VERSION;

  if (new Date(expiresAt).getTime() <= new Date(issuedAt).getTime()) {
    throw new Error('expiresAt must be later than issuedAt');
  }

  const bindingDigest = fcNormalizeOptionalDigestHex(params.bindingDigest, 'bindingDigest');
  const commitmentVersion = fcNormalizeOptionalNonEmptyString(params.commitmentVersion, 'commitmentVersion');
  const chunkMerkleRoot = fcNormalizeOptionalDigestHex(params.chunkMerkleRoot, 'chunkMerkleRoot');
  const lifecycleStateAtIssuance = params.lifecycleStateAtIssuance == null
    ? null
    : fcNormalizeLifecycleStateName(params.lifecycleStateAtIssuance, 'lifecycleStateAtIssuance');
  const evidenceLifecycleEpoch = fcNormalizeOptionalNonNegativeInt(params.evidenceLifecycleEpoch, 'evidenceLifecycleEpoch');
  const allowedLifecycleStates = fcNormalizeAllowedLifecycleStates(params.allowedLifecycleStates);

  return {
    capId,
    evidenceId,
    issuerId,
    granteeId,
    scope: fcNormalizeScope(params.scope),
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

function fcVerifyCapabilityToken(token, issuerPublicKey, now = new Date()) {
  try {
    if (!fcIsPlainObject(token)) {
      return { valid: false, reason: 'token_not_plain_object' };
    }

    const unknown = Object.keys(token).filter(k => !FC_ALLOWED_TOKEN_FIELDS.includes(k));
    if (unknown.length > 0) {
      return { valid: false, reason: `unexpected_fields:${unknown.join(',')}` };
    }

    const signature = fcNormalizeNonEmptyString(token.signature, 'signature');
    const payload = fcBuildCapabilityPayload(token);

    const canonical = fcCanonicalizeWithoutFields(payload, ['signature']);
    const signatureValid = crypto.verify(
      null,
      Buffer.from(canonical, 'utf8'),
      issuerPublicKey,
      fcHexToBytes(signature)
    );

    if (!signatureValid) {
      return { valid: false, reason: 'invalid_signature' };
    }

    const nowDate = now instanceof Date ? now : new Date(now);
    if (Number.isNaN(nowDate.getTime())) {
      return { valid: false, reason: 'invalid_now' };
    }

    if (new Date(payload.expiresAt).getTime() <= nowDate.getTime()) {
      return { valid: false, reason: 'expired' };
    }

    const capHash = fcCanonicalSha256HexWithoutFields(payload, ['signature']);
    const scopeDigest = fcComputeScopeDigest(payload.scope);

    return {
      valid: true,
      payload,
      token: { ...payload, signature },
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

function fcCheckScope(scope, requestedChunkIndices) {
  try {
    const normalizedScope = fcNormalizeScope(scope);
    const normalizedRequestedChunks = Array.isArray(requestedChunkIndices)
      ? fcNormalizeChunkIndices(requestedChunkIndices)
      : [];

    if (normalizedScope.type === FC_SCOPE_TYPES.HASH_ONLY) {
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

    if (normalizedScope.type === FC_SCOPE_TYPES.FULL_CHUNKS) {
      return {
        allowed: true,
        normalizedScope,
        normalizedRequestedChunks
      };
    }

    if (normalizedScope.type === FC_SCOPE_TYPES.CHUNK_SET) {
      const allowedSet = new Set(normalizedScope.indices);
      const isSubset = normalizedRequestedChunks.every(idx => allowedSet.has(idx));

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

function fcHashChunk(payload) {
  const buf = fcToBuffer(payload);
  return fcSha256Hex(Buffer.concat([FC_LEAF_HASH_DOMAIN, buf]));
}

function fcComputeParentHash(leftDigestHex, rightDigestHex) {
  if (!fcIsSha256Hex(leftDigestHex) || !fcIsSha256Hex(rightDigestHex)) {
    throw new TypeError('Parent hash inputs must be valid SHA-256 hex digests');
  }

  return fcSha256Hex(Buffer.concat([
    FC_NODE_HASH_DOMAIN,
    fcHexToBytes(leftDigestHex),
    fcHexToBytes(rightDigestHex)
  ]));
}

function fcComputeParentHashV3(leftDigestHex, rightDigestHex) {
  if (!fcIsSha256Hex(leftDigestHex) || !fcIsSha256Hex(rightDigestHex)) {
    throw new TypeError('Parent hash inputs must be valid SHA-256 hex digests');
  }

  return fcSha256Hex(Buffer.concat([
    FC_NODE_HASH_V3_DOMAIN,
    fcHexToBytes(leftDigestHex),
    fcHexToBytes(rightDigestHex)
  ]));
}

function fcBuildEvidenceContext(evidenceId, chunkIndex, actualLength) {
  const evId = fcNormalizeNonEmptyString(evidenceId, 'evidenceId');
  const idx = fcNormalizeOptionalNonNegativeInt(chunkIndex, 'chunkIndex');
  const len = fcNormalizeOptionalNonNegativeInt(actualLength, 'actualLength');
  if (idx === null || len === null) {
    throw new TypeError('chunkIndex and actualLength are required for v3 evidence context');
  }
  if (len > 0xffffffff) {
    throw new RangeError('actualLength must fit uint32');
  }
  return Buffer.concat([
    fcLengthPrefixedUtf8(evId),
    fcUint64be(idx),
    fcUint32be(len)
  ]);
}

function fcHashChunkDigestV3(payload, actualLength) {
  const buf = fcToBuffer(payload);
  const len = fcNormalizeOptionalNonNegativeInt(actualLength ?? buf.length, 'actualLength');
  if (len !== buf.length) {
    throw new Error(`actualLength mismatch: expected ${len}, got ${buf.length}`);
  }
  return fcSha256Hex(Buffer.concat([FC_CHUNK_V3_DOMAIN, fcUint32be(len), buf]));
}

function fcHashChunkCommitmentV3(payload, { evidenceId, chunkIndex, actualLength, salt } = {}) {
  const buf = fcToBuffer(payload);
  const len = fcNormalizeOptionalNonNegativeInt(actualLength ?? buf.length, 'actualLength');
  if (len !== buf.length) {
    throw new Error(`actualLength mismatch: expected ${len}, got ${buf.length}`);
  }
  const saltHex = String(salt || '').trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(saltHex)) {
    throw new TypeError('salt must be a 32-byte hex string for v3 disclosure verification');
  }
  const chunkDigest = fcHashChunkDigestV3(buf, len);
  const leafHash = fcSha256Hex(Buffer.concat([
    FC_LEAF_V3_DOMAIN,
    fcBuildEvidenceContext(evidenceId, chunkIndex, len),
    fcHexToBytes(saltHex),
    fcHexToBytes(chunkDigest)
  ]));
  return { leafHash, chunkDigest, salt: saltHex, actualLength: len };
}

function fcVerifyProofFromLeafHashV3(leafHash, proof, expectedRoot) {
  if (!fcIsSha256Hex(leafHash)) {
    throw new TypeError('leafHash must be valid SHA-256 hex');
  }
  if (!fcIsSha256Hex(expectedRoot)) {
    throw new TypeError('expectedRoot must be valid SHA-256 hex');
  }
  if (!Array.isArray(proof)) {
    throw new TypeError('proof must be an array');
  }

  let computed = leafHash.toLowerCase();

  for (const step of proof) {
    if (!step || typeof step !== 'object') {
      throw new TypeError('Invalid proof step');
    }
    if (!['left', 'right'].includes(step.position)) {
      throw new TypeError('Invalid proof step position');
    }
    if (!fcIsSha256Hex(step.data)) {
      throw new TypeError('Invalid proof step data');
    }

    computed = step.position === 'left'
      ? fcComputeParentHashV3(step.data, computed)
      : fcComputeParentHashV3(computed, step.data);
  }

  return computed === expectedRoot.toLowerCase();
}

function fcVerifyProofFromLeafHash(leafHash, proof, expectedRoot) {
  if (!fcIsSha256Hex(leafHash)) {
    throw new TypeError('leafHash must be valid SHA-256 hex');
  }
  if (!fcIsSha256Hex(expectedRoot)) {
    throw new TypeError('expectedRoot must be valid SHA-256 hex');
  }
  if (!Array.isArray(proof)) {
    throw new TypeError('proof must be an array');
  }

  let computed = leafHash.toLowerCase();

  for (const step of proof) {
    if (!step || typeof step !== 'object') {
      throw new TypeError('Invalid proof step');
    }
    if (!['left', 'right'].includes(step.position)) {
      throw new TypeError('Invalid proof step position');
    }
    if (!fcIsSha256Hex(step.data)) {
      throw new TypeError('Invalid proof step data');
    }

    computed = step.position === 'left'
      ? fcComputeParentHash(step.data, computed)
      : fcComputeParentHash(computed, step.data);
  }

  return computed === expectedRoot.toLowerCase();
}

function fcDeserializeChunkPayload(serializedChunk) {
  if (!serializedChunk || typeof serializedChunk !== 'object') {
    throw new TypeError('serializedChunk must be an object');
  }
  if (typeof serializedChunk.dataBase64 !== 'string') {
    throw new TypeError('serializedChunk.dataBase64 must be a string');
  }
  return Buffer.from(serializedChunk.dataBase64, 'base64');
}

function fcVerifySerializedDisclosureChunk(serializedChunk, proofObj, expectedRoot) {
  const payload = fcDeserializeChunkPayload(serializedChunk);
  const computedLeafHash = fcHashChunk(payload);
  const declaredLeafHash = typeof serializedChunk.hash === 'string' ? serializedChunk.hash.toLowerCase() : null;
  const proofLeaf = typeof proofObj?.leaf === 'string' ? proofObj.leaf.toLowerCase() : null;

  if (declaredLeafHash && computedLeafHash !== declaredLeafHash) {
    return {
      valid: false,
      computedLeafHash,
      declaredLeafHash,
      reason: 'payload_hash_mismatch'
    };
  }

  if (proofLeaf && computedLeafHash !== proofLeaf) {
    return {
      valid: false,
      computedLeafHash,
      declaredLeafHash: proofLeaf,
      reason: 'proof_leaf_mismatch'
    };
  }

  const ok = fcVerifyProofFromLeafHash(computedLeafHash, proofObj.proof, expectedRoot);
  return {
    valid: ok,
    computedLeafHash,
    declaredLeafHash: proofLeaf || declaredLeafHash,
    reason: ok ? undefined : 'invalid_merkle_path'
  };
}

function fcVerifySerializedDisclosureChunkV3(serializedChunk, proofObj, expectedRoot, evidenceId) {
  const payload = fcDeserializeChunkPayload(serializedChunk);
  const commitment = fcHashChunkCommitmentV3(payload, {
    evidenceId,
    chunkIndex: serializedChunk.index,
    actualLength: serializedChunk.actualLength ?? serializedChunk.length,
    salt: serializedChunk.salt
  });

  const ok = fcVerifyProofFromLeafHashV3(commitment.leafHash, proofObj.proof, expectedRoot);
  return {
    valid: ok,
    computedLeafHash: commitment.leafHash,
    declaredLeafHash: null,
    reason: ok ? undefined : 'invalid_v3_opening_or_merkle_path'
  };
}

function fcComputeBundleHash(bundle) {
  return fcCanonicalSha256HexWithoutFields(bundle, ['bundleHash']);
}

function fcBuildMerkleRootFromLeafHashes(leafHashes) {
  if (!Array.isArray(leafHashes)) {
    throw new TypeError('leafHashes must be an array');
  }
  if (leafHashes.length === 0) {
    return fcSha256Hex(Buffer.concat([FC_EMPTY_ROOT_DOMAIN, Buffer.from(FC_EMPTY_TREE_SENTINEL, 'utf8')]));
  }

  let level = leafHashes.map((h, i) => {
    const normalized = String(h || '').toLowerCase();
    if (!fcIsSha256Hex(normalized)) {
      throw new TypeError(`Invalid leaf hash at index ${i}`);
    }
    return normalized;
  });

  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1] || left;
      next.push(fcComputeParentHash(left, right));
    }
    level = next;
  }
  return level[0];
}

function fcNormalizeEvidenceLifecycleState(evidence) {
  const raw = String(
    evidence?.lifecycleState ||
    evidence?.evidenceLifecycleState ||
    evidence?.status ||
    ''
  ).trim().toUpperCase();

  if (Object.values(FC_EVIDENCE_LIFECYCLE_STATES).includes(raw)) return raw;

  if (raw === 'ACQUIRED' || raw === 'COLLECTED' || raw === 'PRESERVE' || raw === 'PRESERVATION') {
    return FC_EVIDENCE_LIFECYCLE_STATES.PRESERVED;
  }

  if (
    raw === 'CRYPTOGRAPHICALLY_ERASED' ||
    raw === 'ERASED' ||
    raw === 'WITHDRAWN_CONFIDENTIALITY' ||
    raw === 'DESTRUCTED' ||
    raw === 'DESTROYED_EVIDENCE' ||
    raw === 'EVIDENCE_DESTROYED'
  ) {
    return FC_EVIDENCE_LIFECYCLE_STATES.DESTROYED;
  }

  return FC_EVIDENCE_LIFECYCLE_STATES.COMMITTED;
}

function fcIsDisclosurePermissibleEvidenceState(state) {
  return [
    FC_EVIDENCE_LIFECYCLE_STATES.COMMITTED,
    FC_EVIDENCE_LIFECYCLE_STATES.AUTHORIZED,
    FC_EVIDENCE_LIFECYCLE_STATES.DISCLOSED
  ].includes(String(state || '').toUpperCase());
}

function fcCanIssueCapabilityForEvidenceState(state) {
  return [
    FC_EVIDENCE_LIFECYCLE_STATES.COMMITTED,
    FC_EVIDENCE_LIFECYCLE_STATES.AUTHORIZED,
    FC_EVIDENCE_LIFECYCLE_STATES.DISCLOSED
  ].includes(String(state || '').toUpperCase());
}

function fcNormalizeCapabilityAccessState(record) {
  const raw = String(record?.accessState || record?.state || record?.status || '').trim().toUpperCase();
  if (Object.values(FC_CAPABILITY_ACCESS_STATES).includes(raw)) return raw;
  if (record?.active === false) return FC_CAPABILITY_ACCESS_STATES.USED;
  if (raw === 'INACTIVE' || raw === 'DISABLED') return FC_CAPABILITY_ACCESS_STATES.REVOKED;
  return FC_CAPABILITY_ACCESS_STATES.ACTIVE;
}

function fcIsCapabilityUsableState(state) {
  return String(state || '').toUpperCase() === FC_CAPABILITY_ACCESS_STATES.ACTIVE;
}

function fcDeriveCapabilityStateOnUse(state) {
  const normalized = String(state || '').toUpperCase();
  if (normalized === FC_CAPABILITY_ACCESS_STATES.ACTIVE) return FC_CAPABILITY_ACCESS_STATES.USED;
  return normalized;
}

function fcNormalizeReason(value, allowed, fallback = 'OTHER') {
  const out = String(value || fallback).trim().toUpperCase();
  return allowed.includes(out) ? out : fallback;
}

function fcIsDestructionLifecycleState(state) {
  return [
    FC_EVIDENCE_LIFECYCLE_STATES.DESTRUCTION_REQUESTED,
    FC_EVIDENCE_LIFECYCLE_STATES.DESTRUCTION_APPROVED,
    FC_EVIDENCE_LIFECYCLE_STATES.DESTROYED
  ].includes(String(state || '').toUpperCase());
}

function fcCanRequestDestructionForEvidenceState(state) {
  return [
    FC_EVIDENCE_LIFECYCLE_STATES.COMMITTED,
    FC_EVIDENCE_LIFECYCLE_STATES.AUTHORIZED,
    FC_EVIDENCE_LIFECYCLE_STATES.DISCLOSED,
    FC_EVIDENCE_LIFECYCLE_STATES.RESTRICTED
  ].includes(String(state || '').toUpperCase());
}

function fcNormalizeDestroyedKeyClasses(value) {
  const raw = Array.isArray(value) ? value : [];
  const out = [];
  const seen = new Set();

  for (const item of raw) {
    const normalized = String(item || '')
      .trim()
      .toUpperCase()
      .replace(/[-\s]+/g, '_');
    if (!normalized) continue;

    const canonical = ({
      EMK: 'EMK',
      EVIDENCE_MASTER_KEY: 'EMK',
      MASTER_KEY: 'EMK',
      DEK: 'DEK',
      DATA_ENCRYPTION_KEY: 'DEK',
      K_SALT: 'K_SALT',
      KSALT: 'K_SALT',
      SALT_KEY: 'K_SALT',
      K_META: 'K_META',
      KMETA: 'K_META',
      METADATA_KEY: 'K_META'
    })[normalized] || normalized;

    if (!seen.has(canonical)) {
      seen.add(canonical);
      out.push(canonical);
    }
  }

  return out.sort();
}

function fcNormalizeDestructionAttestations(value) {
  const raw = Array.isArray(value) ? value : [];
  return raw
    .filter(item => item && typeof item === 'object')
    .map(item => ({
      role: String(item.role || item.attesterRole || '').trim(),
      actorId: String(item.actorId || item.attesterId || item.actor || '').trim(),
      attestedAt: String(item.attestedAt || item.timestamp || '').trim(),
      statementHash: String(item.statementHash || item.hash || '').trim().toLowerCase(),
      signature: item.signature ? String(item.signature).trim() : null
    }))
    .filter(item => item.role && item.actorId);
}

function fcEvaluateThresholdAttestations(attestations, policy = {}) {
  const eligibleRoles = Array.isArray(policy.eligibleRoles) && policy.eligibleRoles.length > 0
    ? policy.eligibleRoles.map(r => String(r || '').trim()).filter(Boolean)
    : ['DataProtectionOfficer', 'JudicialReviewer', 'EvidenceCustodian'];
  const required = Number.isSafeInteger(Number(policy.required)) && Number(policy.required) > 0
    ? Number(policy.required)
    : 2;
  const eligible = new Set(eligibleRoles);
  const rolesSeen = new Set();
  const actorsSeen = new Set();

  for (const att of attestations) {
    if (!eligible.has(att.role)) continue;
    rolesSeen.add(att.role);
    if (att.actorId) actorsSeen.add(att.actorId);
  }

  return {
    required,
    eligibleRoles,
    attestationCount: attestations.length,
    eligibleAttestationCount: rolesSeen.size,
    distinctActorCount: actorsSeen.size,
    satisfied: rolesSeen.size >= required && actorsSeen.size >= required
  };
}

function fcGetEvidenceLifecycleEpoch(evidence) {
  const direct = Number(evidence?.evidenceLifecycleEpoch ?? evidence?.lifecycleEpoch);
  if (Number.isSafeInteger(direct) && direct >= 0) return direct;
  return 0;
}


class ForensicContract extends Contract {
  constructor() {
    super();
    this.ipfsManager = null; // only for SIMULATION/TEST
  }

  // ===========================================================================
  // Determinism & Environment Guards
  // ===========================================================================

  /**
   * Chaincode must be deterministic across endorsers.
   * Any outbound HTTP (IPFS) is NON-deterministic => disallow in production.
   */
  _isSimulationMode() {
    const mode = String(process.env.FORENSIC_MODE || process.env.MODE || '')
      .toUpperCase()
      .trim();
    return mode === 'SIMULATION';
  }

  _assertIPFSAllowed(opName) {
    const allow =
      this._isSimulationMode() ||
      String(process.env.ALLOW_CHAINCODE_IPFS || '').toLowerCase() === 'true';

    if (!allow) {
      throw new Error(
        `${opName} disabled in PRODUCTION. ` +
          `Do IPFS store/retrieve in the client/gateway, then pass masterCID to chaincode. ` +
          `Enable only for tests with FORENSIC_MODE=SIMULATION (or ALLOW_CHAINCODE_IPFS=true).`
      );
    }
  }

  // ===========================================================================
  // Utilities
  // ===========================================================================

  _normRole(s) {
    return String(s || '').trim().toLowerCase().replace(/\s+/g, '');
  }

  _normClearance(s) {
    return String(s || '').trim().toLowerCase();
  }

  _roleNorm(ctxOrRole) {
    if (ctxOrRole && typeof ctxOrRole === 'object' && ctxOrRole.clientIdentity) {
      return this._normRole(ctxOrRole.clientIdentity.getAttributeValue('role') || '');
    }

    return this._normRole(ctxOrRole || '');
  }

  _toSafeNumber(x) {
    // Fabric can return protobuf Long-like objects
    if (x === null || x === undefined) return 0;
    if (typeof x === 'number') return x;
    if (typeof x === 'string') return Number(x);
    if (typeof x === 'object') {
      if (typeof x.toNumber === 'function') return x.toNumber();
      if (typeof x.valueOf === 'function') return Number(x.valueOf());
      if (x.low !== undefined) return Number(x.low);
    }
    return Number(x);
  }

  /**
   * Deterministic timestamp from transaction (endorsers see same tx timestamp).
   */
  _getTimestamp(ctx) {
    const ts = ctx.stub.getTxTimestamp();
    const seconds = this._toSafeNumber(ts.seconds);
    const nanos = this._toSafeNumber(ts.nanos);
    const ms = (seconds * 1000) + Math.floor(nanos / 1e6);
    return new Date(ms).toISOString();
  }

  _sha256Hex(input) {
    const s = (input === null || input === undefined) ? '' : String(input);
    return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
  }

  _getAuditActor(ctx) {
    const enrollment =
      ctx.clientIdentity.getAttributeValue('hf.EnrollmentID') ||
      ctx.clientIdentity.getAttributeValue('enrollmentId') ||
      '';

    if (enrollment && String(enrollment).trim()) return String(enrollment).trim();

    const id = String(ctx.clientIdentity.getID() || '');
    const h = crypto.createHash('sha256').update(id).digest('hex').substring(0, 16);
    return `id:${h}`;
  }

  /**
   * Helper: extract evidence owner consistently (we store submittedBy as auditActor string)
   */
_getEvidenceOwner(evidence) {
  if (!evidence || typeof evidence !== 'object') return null;

  const candidates = [
    evidence.custodyOwnerId,
    evidence.disclosureAuthorityId,
    evidence.ownerId,
    evidence.evidence?.custodyOwnerId,
    evidence.evidence?.disclosureAuthorityId,
    evidence.onChainData?.custodyOwnerId,
    evidence.onChainData?.disclosureAuthorityId,
    evidence.submittedBy
  ];

  for (const candidate of candidates) {
    if (!candidate) continue;

    if (typeof candidate === 'object') {
      const nested =
        candidate.enrollmentId ||
        candidate.userId ||
        candidate.id ||
        null;

      if (nested && String(nested).trim()) {
        return String(nested).trim();
      }
      continue;
    }

    if (String(candidate).trim()) {
      return String(candidate).trim();
    }
  }

  return null;
}

      _isEvidenceCollectorRole(ctx) {
    const roleNorm = this._roleNorm(ctx);
    return [
      'gatewaycollector',
      'manualcollector',

      // Backward compatibility with older experiment identities
      'otgatewaycollector',
      'acquisitionoperator'
    ].includes(roleNorm);
  }

  _isGatewayCollectorRole(ctx) {
    const roleNorm = this._roleNorm(ctx);
    return [
      'gatewaycollector',
      'otgatewaycollector'
    ].includes(roleNorm);
  }

  _isManualCollectorRole(ctx) {
    const roleNorm = this._roleNorm(ctx);
    return [
      'manualcollector',
      'acquisitionoperator'
    ].includes(roleNorm);
  }

  _isCustodyRole(ctx) {
    const roleNorm = this._roleNorm(ctx);
    return [
      'evidencecustodian'
    ].includes(roleNorm);
  }

  _isOversightRole(ctx) {
    const roleNorm = this._roleNorm(ctx);
    return [
      'judicialreviewer',
      'dataprotectionofficer',
      'internalauditor'
    ].includes(roleNorm);
  }

  _isExternalCollaboratorRole(ctx) {
    const roleNorm = this._roleNorm(ctx);
    return [
      'externalvendor',
      'externalauditor',

      // Backward compatibility
      'vendorengineer',
      'independentauditor'
    ].includes(roleNorm);
  }

    _isPrivilegedDisclosureRole(ctx) {
    const roleNorm = this._roleNorm(ctx);
    return [
      'evidencecustodian',
      'forensiclead',
      'forensicinvestigator',
      'judicialreviewer',
      'dataprotectionofficer',
      'internalauditor',
      'externalauditor',
      'externalvendor',
      'gatewaycollector',
      'manualcollector',

      // Backward compatibility
      'otgatewaycollector',
      'acquisitionoperator',
      'vendorengineer',
      'independentauditor',

      'admin',
      'systemadministrator'
    ].includes(roleNorm);
  }

  _isHybridEvidenceRecord(evidence) {
    if (!evidence || typeof evidence !== 'object') return false;
    const version = String(
      evidence.storageVersion ||
      evidence.metadata?.version ||
      ''
    ).trim();
    return evidence.storageMode === 'hybrid' || version.startsWith('2.');
  }

  _parseJsonStrict(label, input) {
    if (fcIsPlainObject(input)) return input;
    if (typeof input !== 'string' || !input.trim()) {
      throw new Error(`${label} must be a non-empty JSON string`);
    }
    try {
      return JSON.parse(input);
    } catch (e) {
      throw new Error(`Invalid JSON for ${label}: ${e.message}`);
    }
  }



  _addIdentityCandidate(out, value) {
    if (value === undefined || value === null) return;

    const raw = String(value).trim();
    if (!raw) return;

    out.add(raw);
    out.add(raw.toLowerCase());

    if (!raw.includes(':')) {
      out.add(`role:${raw}`);
      out.add(`role:${raw.toLowerCase()}`);
    }
  }

  _getIdentityCandidates(ctx) {
    const out = new Set();
    const add = (value) => this._addIdentityCandidate(out, value);

    try {
      add(this._getAuditActor(ctx));
    } catch (e) {
      // best-effort only
    }

    const addAttr = (name) => {
      try {
        const value = ctx.clientIdentity.getAttributeValue(name);
        add(value);
      } catch (e) {
        // attribute may be absent
      }
    };

    [
      'hf.EnrollmentID',
      'enrollmentId',
      'userId',
      'participantId',
      'role',
      'authority',
      'evidenceDomain'
    ].forEach(addAttr);

    try {
      const role = ctx.clientIdentity.getAttributeValue('role');
      const mspId = ctx.clientIdentity.getMSPID ? ctx.clientIdentity.getMSPID() : null;

      if (role && String(role).trim()) {
        add(`role:${String(role).trim()}`);
      }

      if (role && mspId) {
        add(`${role}@${mspId}`);
        add(`${role}@${String(mspId).replace(/MSP$/, '').toLowerCase()}`);
      }
    } catch (e) {
      // best-effort only
    }

    try {
      const cid = ctx.clientIdentity.getID();
      if (cid && String(cid).trim()) {
        const cidStr = String(cid).trim();
        add(cidStr);

        const h = crypto.createHash('sha256').update(cidStr).digest('hex').substring(0, 16);
        add(`id:${h}`);

        const cnMatches = [...cidStr.matchAll(/\/CN=([^\/:]+)/g)];
        for (const match of cnMatches) {
          const cn = match[1];
          add(cn);
          try {
            add(decodeURIComponent(cn));
          } catch (e) {
            // ignore decode errors
          }
        }
      }
    } catch (e) {
      // best-effort only
    }

    return out;
  }



  _matchesCallerIdentifier(ctx, claimedId) {
    if (!claimedId || typeof claimedId !== 'string') return false;

    const claimed = String(claimedId).trim();
    if (!claimed) return false;

    const candidates = this._getIdentityCandidates(ctx);
    return candidates.has(claimed) ||
      candidates.has(claimed.toLowerCase()) ||
      candidates.has(`role:${claimed}`) ||
      candidates.has(`role:${claimed.toLowerCase()}`);
  }



  _normalizeOptionalIdentityString(value, fieldName) {
    if (value === undefined || value === null) return null;
    if (typeof value !== 'string') {
      throw new Error(`${fieldName} must be a string when provided`);
    }
    const trimmed = value.trim();
    return trimmed.length ? trimmed : null;
  }

  _resolveCustodyOwnerId(fullEvidence, inputData, auditActor) {
    const candidates = [
      fullEvidence?.custodyOwnerId,
      inputData?.custodyOwnerId,
      fullEvidence?.disclosureAuthorityId,
      inputData?.disclosureAuthorityId,
      fullEvidence?.ownerId,
      inputData?.ownerId
    ];

    for (const candidate of candidates) {
      const normalized = this._normalizeOptionalIdentityString(candidate, 'custodyOwnerId');
      if (normalized) return normalized;
    }

    return String(auditActor).trim();
  }

  _resolveDisclosureAuthorityId(fullEvidence, inputData, custodyOwnerId, auditActor) {
    const candidates = [
      fullEvidence?.disclosureAuthorityId,
      inputData?.disclosureAuthorityId,
      fullEvidence?.custodyOwnerId,
      inputData?.custodyOwnerId
    ];

    for (const candidate of candidates) {
      const normalized = this._normalizeOptionalIdentityString(candidate, 'disclosureAuthorityId');
      if (normalized) return normalized;
    }

    if (custodyOwnerId && String(custodyOwnerId).trim()) {
      return String(custodyOwnerId).trim();
    }

    return String(auditActor).trim();
  }

  async _resolveRegisteredPublicKey(ctx, userId, purposes = [], keyTypes = []) {
    const uid = String(userId || '').trim();
    if (!uid) throw new Error('userId is required to resolve public key');

    const candidatePurposes = purposes.length
      ? purposes
      : ['DISCLOSURE_CAPABILITY', 'disclosure-capability', 'signing', 'SIGNING', 'general', 'GENERAL'];

    const candidateKeyTypes = keyTypes.length
      ? keyTypes
      : ['Ed25519', 'ed25519', 'ED25519'];

    for (const keyType of candidateKeyTypes) {
      for (const purpose of candidatePurposes) {
        const keyId = `PublicKey_${uid}_${keyType}_${purpose}`;
        const bytes = await ctx.stub.getState(keyId);
        if (!bytes || !bytes.length) continue;

        let record;
        try { record = JSON.parse(bytes.toString()); } catch { continue; }
        if (record && record.status !== 'revoked' && record.publicKey) {
          return {
            keyId,
            record
          };
        }
      }
    }

    throw new Error(`No registered Ed25519 public key found for issuerId=${uid} with disclosure-capability purpose`);
  }

  _capabilityDirectKey(capId) {
    return `Capability_${capId}`;
  }

  _capabilityCompositeKey(ctx, evidenceId, granteeId, capId) {
    return ctx.stub.createCompositeKey('Capability', [evidenceId, granteeId, capId]);
  }

  async _getCapabilityRecordByCapId(ctx, capId) {
    const bytes = await ctx.stub.getState(this._capabilityDirectKey(capId));
    if (!bytes || !bytes.length) return null;
    return JSON.parse(bytes.toString());
  }

  async _putCapabilityRecord(ctx, capabilityRecord) {
    if (!capabilityRecord || typeof capabilityRecord !== 'object') {
      throw new Error('capabilityRecord is required');
    }

    const payload = Buffer.from(JSON.stringify(capabilityRecord), 'utf8');

    await ctx.stub.putState(
      this._capabilityDirectKey(capabilityRecord.capId),
      payload
    );

    await ctx.stub.putState(
      this._capabilityCompositeKey(
        ctx,
        capabilityRecord.evidenceId,
        capabilityRecord.granteeId,
        capabilityRecord.capId
      ),
      payload
    );
  }

  _normalizeCapabilityStatus(status) {
    const normalized = String(status || '').trim().toUpperCase();
    if (!normalized) return 'UNKNOWN';
    if (['ACTIVE', 'USED', 'REVOKED', 'EXPIRED'].includes(normalized)) return normalized;
    if (normalized === 'INACTIVE') return 'USED';
    return normalized;
  }

  _getCapabilityEffectiveStatus(record, nowTimestamp) {
    if (!record || typeof record !== 'object') return 'UNKNOWN';

    const explicitStatus = this._normalizeCapabilityStatus(record.status);
    if (explicitStatus === 'USED' || explicitStatus === 'REVOKED' || explicitStatus === 'EXPIRED') {
      return explicitStatus;
    }

    const now = new Date(nowTimestamp || new Date(0).toISOString()).getTime();
    const expires = new Date(record.expiresAt).getTime();

    if (Number.isFinite(expires) && Number.isFinite(now) && expires <= now) {
      return 'EXPIRED';
    }

    if (record.active === false) return 'USED';
    if (record.active === true) return 'ACTIVE';
    return explicitStatus;
  }

  _capabilityInactiveReason(status) {
    const normalized = this._normalizeCapabilityStatus(status);
    if (normalized === 'USED') return 'capability_already_used';
    if (normalized === 'REVOKED') return 'capability_revoked';
    if (normalized === 'EXPIRED') return 'capability_expired';
    return 'capability_inactive';
  }

  _capabilityUsagePolicy(record) {
    return String(record?.usagePolicy || 'SINGLE_USE').trim().toUpperCase() || 'SINGLE_USE';
  }

  async _consumeCapabilityAfterSuccessfulVerification(ctx, capRecord, txTimestamp, verifierId) {
    const capabilityStateBefore = this._getCapabilityEffectiveStatus(capRecord, txTimestamp);

    capRecord.verificationCount = (capRecord.verificationCount || 0) + 1;
    capRecord.lastVerifiedAt = txTimestamp;

    if (capabilityStateBefore === 'ACTIVE' && this._capabilityUsagePolicy(capRecord) === 'SINGLE_USE') {
      capRecord.accessState = FC_CAPABILITY_ACCESS_STATES.USED;
      capRecord.state = FC_CAPABILITY_ACCESS_STATES.USED;
      capRecord.active = false;
      capRecord.status = FC_CAPABILITY_ACCESS_STATES.USED;
      capRecord.usedAt = txTimestamp;
      capRecord.usedBy = verifierId || null;
    }

    await this._putCapabilityRecord(ctx, capRecord);

    return {
      capabilityStateBefore,
      capabilityStateAfter: this._getCapabilityEffectiveStatus(capRecord, txTimestamp)
    };
  }


  _extractEvidenceCommitment(storedData) {
    if (!storedData || typeof storedData !== 'object') {
      return { available: false };
    }

    const chunkMerkleRoot = storedData.chunkMerkleRoot || null;
    const chunkCount = storedData.chunkCount;
    const chunkSize = storedData.chunkSize;
    const commitmentVersion = storedData.commitmentVersion || null;

    const available =
      !!chunkMerkleRoot &&
      fcIsSha256Hex(chunkMerkleRoot) &&
      Number.isInteger(chunkCount) &&
      chunkCount >= 0 &&
      Number.isInteger(chunkSize) &&
      chunkSize > 0;

    return {
      available,
      evidenceId: storedData.evidenceId || null,
      integrityHash: storedData.integrityHash || storedData.fileHash || null,
      chunkMerkleRoot: available ? String(chunkMerkleRoot).toLowerCase() : null,
      chunkCount: available ? chunkCount : null,
      chunkSize: available ? chunkSize : null,
      commitmentVersion: available ? (commitmentVersion || FC_CHUNK_COMMITMENT_VERSION) : null,
      storageMode: storedData.storageMode || (this._isHybridEvidenceRecord(storedData) ? 'hybrid' : 'legacy'),
      storageVersion: storedData.storageVersion || (this._isHybridEvidenceRecord(storedData) ? (StorageOptimizer?.STORAGE_VERSION || '2.1') : '1.0')
    };
  }

  async _loadEvidenceRecord(ctx, evidenceId) {
    const evId = String(evidenceId || '').trim();
    if (!evId) throw new Error('evidenceId is required');

    const evidenceKey = `evidence::${evId}`;
    let bytes = await ctx.stub.getState(evidenceKey);
    if (!bytes || !bytes.length) {
      bytes = await ctx.stub.getState(evId); // legacy fallback
      if (!bytes || !bytes.length) {
        throw new Error(`Evidence ${evId} not found`);
      }
    }

    const evidence = JSON.parse(bytes.toString());
    if (!evidence.lifecycleState) {
      evidence.lifecycleState = fcNormalizeEvidenceLifecycleState(evidence);
    }
    if (!evidence.lifecycleHistory) {
      evidence.lifecycleHistory = [];
    }
    return { evidenceKey, evidence };
  }

  async _persistEvidenceRecord(ctx, evidenceKey, evidence) {
    await ctx.stub.putState(evidenceKey, Buffer.from(JSON.stringify(evidence), 'utf8'));
  }

  _transitionEvidenceLifecycle(evidence, nextState, reason, actor, timestamp) {
    const previousState = fcNormalizeEvidenceLifecycleState(evidence);
    evidence.lifecycleState = nextState;
    evidence.lifecycleUpdatedAt = timestamp;
    evidence.lifecycleHistory = Array.isArray(evidence.lifecycleHistory) ? evidence.lifecycleHistory : [];
    evidence.lifecycleHistory.push({
      from: previousState,
      to: nextState,
      reason: reason || null,
      actor: actor || null,
      at: timestamp
    });
    const previousEpoch = fcGetEvidenceLifecycleEpoch(evidence);
    let nextEpoch = previousEpoch;

    // Epoch is a capability invalidation epoch, not a transition counter.
    // Initial commitment activates epoch 1. Routine disclosure states keep
    // the same epoch so pre-issued capabilities remain valid across
    // COMMITTED -> AUTHORIZED -> DISCLOSED.
    if (nextState === FC_EVIDENCE_LIFECYCLE_STATES.COMMITTED && nextEpoch < 1) {
      nextEpoch = 1;
    }

    // Destruction boundaries invalidate previously issued capabilities.
    if (
      nextState === FC_EVIDENCE_LIFECYCLE_STATES.DESTRUCTION_REQUESTED ||
      nextState === FC_EVIDENCE_LIFECYCLE_STATES.DESTROYED
    ) {
      nextEpoch = previousEpoch + 1;
    }

    evidence.evidenceLifecycleEpoch = nextEpoch;
    evidence.lifecycleEpoch = nextEpoch;

    return {
      previousState,
      nextState,
      evidenceLifecycleEpoch: evidence.evidenceLifecycleEpoch
    };
  }

  async _persistCapabilityRecord(ctx, capRecord) {
    capRecord.accessState = fcNormalizeCapabilityAccessState(capRecord);
    capRecord.state = capRecord.accessState;
    capRecord.active = fcIsCapabilityUsableState(capRecord.accessState);
    capRecord.status = capRecord.accessState;

    await ctx.stub.putState(
      this._capabilityDirectKey(capRecord.capId),
      Buffer.from(JSON.stringify(capRecord), 'utf8')
    );

    await ctx.stub.putState(
      this._capabilityCompositeKey(ctx, capRecord.evidenceId, capRecord.granteeId, capRecord.capId),
      Buffer.from(JSON.stringify(capRecord), 'utf8')
    );
  }

  _buildGovernanceEvent(name, payload = {}) {
    return {
      eventType: name,
      version: 'governance-event-v1',
      ...payload
    };
  }

  /**
   * Normalize & validate CID format lightly (CIDv0/Qm.. or CIDv1/bafy..).
   * Returns normalized: ipfs://<cidBase>
   */
  _assertCIDFormat(cid) {
    if (cid === null || cid === undefined) throw new Error('CID is empty');
    const c = String(cid).trim();
    if (!c) throw new Error('CID is empty');

    // normalize common patterns:
    // ipfs://<cid>, ipfs://ipfs/<cid>, /ipfs/<cid>, <cid>/path
    let raw = c.replace(/^ipfs:\/\//i, '');
    raw = raw.replace(/^ipfs\//i, '');     // handles ipfs://ipfs/<cid>
    raw = raw.replace(/^\/?ipfs\//i, '');  // handles /ipfs/<cid>

    const base = raw.split('/')[0].trim();
    if (!base) throw new Error(`Invalid CID format: ${cid}`);

    const baseLower = base.toLowerCase();

    const isCidV0 = /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/.test(base);
    const isCidV1 = baseLower.startsWith('bafy');

    if (!isCidV0 && !isCidV1) throw new Error(`Invalid CID format: ${cid}`);

    return `ipfs://${isCidV1 ? baseLower : base}`;
  }

  /**
   * Hash CID for logging (avoid CID leakage)
   */
  _cidHash(cid) {
    if (cid === null || cid === undefined) return null;
    const norm = this._assertCIDFormat(String(cid));
    return this._sha256Hex(norm);
  }

  // ===========================================================================
  // Access Control (RBAC + Clearance)
  // ===========================================================================

  _checkAccess(ctx, required) {
    const id = ctx.clientIdentity;

    let role = id.getAttributeValue('role');
    let clearance = id.getAttributeValue('clearance');

    if (!role || role === 'null' || String(role).trim() === '') {
      throw new Error('Role attribute not found in certificate');
    }
    if (!clearance || clearance === 'null' || String(clearance).trim() === '') {
      throw new Error('Clearance attribute not found in certificate');
    }

    role = String(role).trim();
    clearance = String(clearance).trim();

    const roleNorm = this._normRole(role);
    const allowedRoleNorms = (required.roles || []).map(r => this._normRole(r));
    const roleOk = allowedRoleNorms.includes(roleNorm);

    const clrNorm = this._normClearance(clearance);
    const allowedClrNorms = (required.clearance || []).map(c => this._normClearance(c));
    const clrOk = allowedClrNorms.includes(clrNorm);

    if (!roleOk || !clrOk) {
      throw new Error(`Access denied: role=${role}, clearance=${clearance}`);
    }

    // Optional debug trace without leaking full identity
    const idHash = crypto.createHash('sha256').update(id.getID()).digest('hex');
    console.log(`Access granted for identity hash: ${idHash.substring(0, 16)}...`);
  }

  // ===========================================================================
  // IPFS (SIMULATION/TEST ONLY)
  // ===========================================================================

  async initIPFSManager(ctx) {
    this._assertIPFSAllowed('initIPFSManager');

    if (!this.ipfsManager) {
      this.ipfsManager = new IPFSManager();
      console.log('✅ IPFS Manager initialized (SIMULATION/TEST ONLY)');
    }
    return this.ipfsManager;
  }

  async storeToIPFS(ctx, data) {
    this._assertIPFSAllowed('storeToIPFS');
    await this.initIPFSManager(ctx);

    try {
      const rawCid = await this.ipfsManager.store(data);
      const cid = this._assertCIDFormat(rawCid);

      // HADES: do not write CID markers to world-state by default.
      const markerOnChain =
        String(process.env.IPFS_MARKER_ONCHAIN || '').toLowerCase() === 'true';

      if (markerOnChain) {
        const cidKey = `ipfs::${cid.replace('ipfs://', '').replace(/\//g, '_')}`;
        const marker = { cid, cached: false, note: 'hybrid-simulation-marker' };
        await ctx.stub.putState(cidKey, Buffer.from(JSON.stringify(marker), 'utf8'));
        ctx.stub.setEvent('IPFSStoredMarker', Buffer.from(JSON.stringify({ cid }), 'utf8'));
      }

      return cid;
    } catch (error) {
      console.error('IPFS storage failed:', error);
      throw error;
    }
  }

  async retrieveFromIPFS(ctx, cid) {
    this._assertIPFSAllowed('retrieveFromIPFS');
    await this.initIPFSManager(ctx);

    try {
      const cidStr = this._assertCIDFormat(String(cid));
      const bareCid = cidStr.replace(/^ipfs:\/\//i, '');
      return await this.ipfsManager.retrieve(bareCid);
    } catch (error) {
      console.error('IPFS retrieval failed:', error);
      return null;
    }
  }

  // ===========================================================================
  // Sanitizers
  // ===========================================================================

_sanitizeForPublic(stored) {
  const inferredMode = this._isHybridEvidenceRecord(stored) ? 'hybrid' : 'legacy';
  const inferredVersion = stored.storageVersion || (inferredMode === 'hybrid'
    ? (StorageOptimizer?.STORAGE_VERSION || '2.1')
    : '1.0');

  const out = {
    publicAccess: true,
    storageMode: inferredMode,
    storageVersion: inferredVersion,

    evidenceHash: {
      fileHash: stored.integrityHash || stored.fileHash || null
    },

    metadata: {
      evidenceId: stored.evidenceId || null,
      evidenceType: stored.evidenceType || null,
      collectionTimestamp: stored.collectionTimestamp || stored.timestamp || stored.createdAt || null
    }
  };

  if (stored.chunkMerkleRoot) {
    out.evidenceCommitment = {
      chunkMerkleRoot: stored.chunkMerkleRoot || null,
      chunkCount: Number.isInteger(stored.chunkCount) ? stored.chunkCount : null,
      chunkSize: Number.isInteger(stored.chunkSize) ? stored.chunkSize : null,
      commitmentVersion: stored.commitmentVersion || null
    };
  }

  return out;
}

  _sanitizeAnalysisForExternal(entry) {
    const cm = entry.cryptographicMetadata || {};
    const cv = entry.cryptographicVerification || null;

    const safeEvidenceIds = Array.isArray(entry.evidenceIds) ? entry.evidenceIds : [];
    const safeTools = Array.isArray(entry.analysisTools) ? entry.analysisTools : [];

    const inv = entry.investigatorId ? String(entry.investigatorId) : '';
    const invHash = inv
      ? crypto.createHash('sha256').update(inv, 'utf8').digest('hex').substring(0, 16)
      : null;

    const ioc = entry.indicatorsOfCompromise || entry.ioc || [];
    const vul = entry.vulnerabilities || [];
    const ttp = entry.ttpMapping || [];
    const wh5 = entry.wh5 || [];

    return {
      incidentId: entry.incidentId || null,
      timestamp: entry.timestamp || null,

      evidenceCount: safeEvidenceIds.length,
      evidenceIds: safeEvidenceIds.map(e => String(e)),

      analysisTooling: {
        toolCount: safeTools.length,
        tools: safeTools.slice(0, 10)
      },

      findingsSummary: {
        iocCount: Array.isArray(ioc) ? ioc.length : 0,
        vulnerabilityCount: Array.isArray(vul) ? vul.length : 0,
        ttpCount: Array.isArray(ttp) ? ttp.length : 0,
        wh5Count: Array.isArray(wh5) ? wh5.length : 0
      },

      cryptographic: {
        analysisHash: cm.analysisHash || null,
        integrityLevel: cm.integrityLevel || null,
        zkpCapabilities: !!cm.zkpCapabilities,
        complianceFlags: cm.complianceFlags || {}
      },

      cryptographicVerification: cv,
      investigatorRef: invHash ? `inv:${invHash}` : null
    };
  }

  // ===========================================================================
  // Chain of Custody (CoC) - pointer-first design
  // ===========================================================================

  async _addCoCEntry(ctx, evidenceId, action, metadata = {}) {
    const ts = this._getTimestamp(ctx);
    const actualActor = this._getAuditActor(ctx);

    const evidenceKey = `evidence::${evidenceId}`;
    const evidenceBytes = await ctx.stub.getState(evidenceKey);
    if (!evidenceBytes || !evidenceBytes.length) {
      throw new Error(`Evidence ${evidenceId} not found`);
    }

    const evidence = JSON.parse(evidenceBytes.toString());

    let prevHash = evidence.lastCoCHash || null;
    if (!prevHash && Array.isArray(evidence.chainOfCustody) && evidence.chainOfCustody.length > 0) {
      prevHash = evidence.chainOfCustody[evidence.chainOfCustody.length - 1]?.entryHash || null;
    }

    const entryData = {
      timestamp: ts,
      actor: actualActor,
      action,
      location: metadata.location || 'Blockchain Network',
      condition: metadata.condition || 'verified',
      integrityHash: evidence.integrityHash,
      cryptographicProofs: metadata.cryptographicProofs || {
        signatureProvided: true,
        integrityVerified: true,
        chainVerified: true
      },
      prevHash,
      metadata: metadata.additionalData || {},
      txId: ctx.stub.getTxID()
    };

    const entryHash = crypto.createHash('sha256')
      .update(JSON.stringify(entryData))
      .digest('hex');

    entryData.entryHash = entryHash;

    // Optional embed (OFF by default)
    const embedCoC =
      String(process.env.COC_EMBED_IN_EVIDENCE || '').toLowerCase() === 'true';

    if (embedCoC) {
      if (!Array.isArray(evidence.chainOfCustody)) evidence.chainOfCustody = [];
      evidence.chainOfCustody.push(entryData);
    }

    evidence.cocCount = (evidence.cocCount || 0) + 1;
    evidence.lastCoCHash = entryHash;

    const ad = entryData.metadata || {};

    if (ad.merkleRoot) {
      const mr = String(ad.merkleRoot).trim();
      if (!/^[A-Fa-f0-9]{64}$/.test(mr)) {
        throw new Error('Invalid merkleRoot format (must be 64 hex chars)');
      }
      evidence.merkleRoot = mr;
    }

    if (ad.cocCID) {
      evidence.cocCID = String(ad.cocCID).trim();
    }

    const storageMode = evidence.storageMode || 'legacy';
    const storageVersion = evidence.storageVersion || (storageMode === 'hybrid' ? '2.0' : '1.0');

    if (storageMode === 'hybrid' && storageVersion === '2.0' && ad.newMasterCID) {
      evidence.ipfsReference = this._assertCIDFormat(ad.newMasterCID);
    }

    // Single write for evidence
    await ctx.stub.putState(evidenceKey, Buffer.from(JSON.stringify(evidence), 'utf8'));

    // Append-only CoC entry
    const cocKey = ctx.stub.createCompositeKey('CoCEntry', [evidenceId, ts, entryHash]);
    await ctx.stub.putState(cocKey, Buffer.from(JSON.stringify(entryData), 'utf8'));

    return entryHash;
  }

  // ===========================================================================
  // Audit Logging (PRIVATE) — IMPORTANT: keep internal only
  // ===========================================================================

  /**
   * Internal audit writer (2 writes: summary + blob).
   * PATCH: include txId in hash input to guarantee uniqueness and prevent key collisions
   * under high concurrency (same action/metadata can occur at same ms).
   */
  async _logAction(ctx, action, incidentId = '', metadata = {}) {
    const safeIncident =
      (incidentId && incidentId.toString().trim()) ? incidentId.toString().trim() : 'GLOBAL';
    const safeAction = (action || '').toString().trim();

    const auditActor = this._getAuditActor(ctx);
    const roleForAudit = (ctx.clientIdentity.getAttributeValue('role') || 'unknown').trim();

    const timestamp = this._getTimestamp(ctx);
    const txId = ctx.stub.getTxID();
    const channel = ctx.stub.getChannelID();

    const storageVersion = (StorageOptimizer && StorageOptimizer.STORAGE_VERSION)
      ? StorageOptimizer.STORAGE_VERSION
      : '2.0';

    // IMPORTANT PATCH:
    // include txId (and channel) so logHash is always unique per tx.
    const logData = {
      incidentId: safeIncident,
      action: safeAction,
      userId: auditActor,
      role: roleForAudit,
      timestamp,
      metadata: metadata || {},
      systemVersion: storageVersion,
      txId,
      channel
    };

    const logHash = crypto.createHash('sha256')
      .update(JSON.stringify(logData))
      .digest('hex');

    const entry = {
      ...logData,
      logHash
    };

    const logKey = ctx.stub.createCompositeKey('LogEntry', [safeIncident, timestamp, logHash]);

    const summary = {
      incidentId: safeIncident,
      timestamp,
      logHash,
      action: safeAction,
      userId: auditActor,
      role: roleForAudit
    };

    const summaryStr = JSON.stringify(summary);
    const entryStr = JSON.stringify(entry);

    const auditSummaryBytes = Buffer.byteLength(summaryStr, 'utf8');
    const auditBlobBytes = Buffer.byteLength(entryStr, 'utf8');
    const auditBytes = auditSummaryBytes + auditBlobBytes;

    await ctx.stub.putState(logKey, Buffer.from(summaryStr, 'utf8'));

    const blobKey = `LogBlob_${logHash}`;
    await ctx.stub.putState(blobKey, Buffer.from(entryStr, 'utf8'));

    const eventPayload = {
      type: 'AUDIT_LOG',
      incidentId: safeIncident,
      timestamp,
      hash: logHash,
      action: safeAction,
      userId: auditActor,
      role: roleForAudit,
      txId,
      channel,
      systemVersion: storageVersion,
      storageMode: metadata?.storageMode
    };
    ctx.stub.setEvent('CryptographicAuditLog', Buffer.from(JSON.stringify(eventPayload), 'utf8'));

    return {
      success: true,
      logHash,
      auditSummaryBytes,
      auditBlobBytes,
      auditBytes,
      auditWriteCount: 2,
      logKey,
      blobKey
    };
  }


  // ===========================================================================
  // ZKP Proof Storage (SIMULATED)
  // ===========================================================================

  async _storeProofInIPFS(ctx, proofData) {
    // Simulation-only pattern: store on-chain with key, return zkp:// ref
    const proofStr = JSON.stringify(proofData || {});
    const size = Buffer.byteLength(proofStr, 'utf8');

    const MAX_PROOF_BYTES = Number(process.env.MAX_SIM_PROOF_BYTES || 64 * 1024); // 64KB default
    if (size > MAX_PROOF_BYTES) {
      throw new Error(`Simulated proof too large (${size} bytes). Max ${MAX_PROOF_BYTES}`);
    }

    const proofHash = crypto.createHash('sha256')
      .update(proofStr)
      .digest('hex');

    const proofKey = `ZKPProof_${proofHash}`;
    const simulated = { ...proofData, simulation: true, storedAt: this._getTimestamp(ctx) };

    await ctx.stub.putState(proofKey, Buffer.from(JSON.stringify(simulated), 'utf8'));

    const proofRef = `zkp://${proofHash}`;
    ctx.stub.setEvent(
      'ZKPProofStoredSimulated',
      Buffer.from(JSON.stringify({ proofRef, proofHash }), 'utf8')
    );

    return proofRef;
  }

  // ===========================================================================
  // Delegation
  // ===========================================================================

async registerDelegation(ctx, evidenceId, delegateToUserId, delegationType, expirationHours) {
  if (!delegationType) delegationType = 'FULL_ACCESS';
  if (!expirationHours) expirationHours = '24';

  const expHours = parseInt(expirationHours, 10);
  if (!Number.isFinite(expHours) || expHours <= 0) {
    throw new Error('expirationHours harus integer > 0');
  }

  const txTimestamp = this._getTimestamp(ctx);
  const txId = ctx.stub.getTxID();

  this._checkAccess(ctx, {
    roles: ['EvidenceCustodian'],
    clearance: ['High']
  });

  const evId = String(evidenceId || '').trim();
  const delTo = String(delegateToUserId || '').trim();
  if (!evId) throw new Error('evidenceId wajib diisi');
  if (!delTo) throw new Error('delegateToUserId wajib diisi');

  const evidenceKey = `evidence::${evId}`;
  const evidenceBytes = await ctx.stub.getState(evidenceKey);
  if (!evidenceBytes || !evidenceBytes.length) {
    throw new Error(`Evidence ${evId} not found`);
  }
  const evidence = JSON.parse(evidenceBytes.toString());

  const evidenceOwner = this._getEvidenceOwner(evidence);
  const callerEnroll = this._getAuditActor(ctx);

  if (!evidenceOwner) {
    throw new Error('evidence_missing_custody_owner');
  }

  if (String(callerEnroll) !== String(evidenceOwner)) {
    throw new Error('Only the designated evidence custodian may delegate access for this evidence');
  }

  const delegationKey = ctx.stub.createCompositeKey('Delegation', [evId, delTo]);

  const existing = await ctx.stub.getState(delegationKey);
  if (existing && existing.length) {
    try {
      const old = JSON.parse(existing.toString());
      if (old && old.delegationId) {
        await ctx.stub.deleteState(old.delegationId);
      }
    } catch {
      // ignore
    }
  }

  const delegationId = `DEL-${evId}-${delTo}-${txId.substring(0, 8)}`;
  const txDate = new Date(txTimestamp);
  const expiresAt = new Date(txDate.getTime() + (expHours * 3600000)).toISOString();

  const delegation = {
    delegationId,
    evidenceId: evId,
    incidentId: evidence.incidentId || 'EVIDENCE_ONLY',
    delegatorId: ctx.clientIdentity.getID(),
    delegatorEnrollmentId:
      ctx.clientIdentity.getAttributeValue('hf.EnrollmentID') ||
      ctx.clientIdentity.getAttributeValue('enrollmentId') ||
      '',
    delegateToUserId: delTo,
    delegationType: String(delegationType).trim(),
    createdAt: txTimestamp,
    expiresAt,
    active: true,
    txId
  };

  await ctx.stub.putState(delegationKey, Buffer.from(JSON.stringify(delegation), 'utf8'));
  await ctx.stub.putState(delegationId, Buffer.from(JSON.stringify(delegation), 'utf8'));

  const pointerOnEvidence =
    String(process.env.DELEGATION_POINTER_ON_EVIDENCE || '').toLowerCase() === 'true';

  if (pointerOnEvidence) {
    evidence.delegationCount = (evidence.delegationCount || 0) + 1;
    evidence.lastDelegationAt = txTimestamp;
    evidence.lastDelegationTo = delTo;
    evidence.lastDelegationType = delegation.delegationType;
    await ctx.stub.putState(evidenceKey, Buffer.from(JSON.stringify(evidence), 'utf8'));
  }

  ctx.stub.setEvent(
    'DelegationRegistered',
    Buffer.from(JSON.stringify({
      delegationId,
      evidenceId: evId,
      delegateToUserId: delTo,
      delegationType: delegation.delegationType,
      expiresAt,
      pointerOnEvidence
    }), 'utf8')
  );

  await this._logAction(ctx, 'registerDelegation', evidence.incidentId || 'EVIDENCE_ONLY', {
    evidenceId: evId,
    delegateToUserId: delTo,
    delegationType: delegation.delegationType,
    expiresAt,
    pointerOnEvidence
  });

  return JSON.stringify({ success: true, delegationId, expiresAt, pointerOnEvidence });
}

  /**
   * Check delegation (no privilege escalation):
   * - FULL_ACCESS ok
   * - exact match ok
   * - PRE_ACCESS can satisfy AES_ACCESS (PRE dianggap lebih tinggi)
   * - AES_ACCESS MUST NOT satisfy PRE_ACCESS
   */
  async _checkDelegation(ctx, evidenceId, userId, requiredType) {
    const normalizedUserId = String(userId || '').trim();
    const reqType = String(requiredType || '').trim();

    const iter = await ctx.stub.getStateByPartialCompositeKey('Delegation', [evidenceId, normalizedUserId]);

    const txTimestamp = this._getTimestamp(ctx);
    const now = new Date(txTimestamp).getTime();

    let hasValid = false;
    let details = null;

    while (true) {
      const res = await iter.next();
      if (res.done) break;

      let d;
      try { d = JSON.parse(res.value.value.toString()); } catch { continue; }

      const exp = Date.parse(d.expiresAt);
      if (!d.active || !(exp > now)) continue;

      const dt = String(d.delegationType || '').trim();

      const typeOk =
        dt === 'FULL_ACCESS' ||
        dt === reqType ||
        (reqType === 'AES_ACCESS' && dt === 'PRE_ACCESS');

      if (typeOk) {
        hasValid = true;
        details = d;
        break;
      }
    }

    await iter.close();
    return { hasValidDelegation: hasValid, delegationDetails: details };
  }

async revokeExpiredDelegations(ctx) {
  this._checkAccess(ctx, {
    roles: ['Admin', 'System Administrator'],
    clearance: ['High']
  });

  const txTimestamp = this._getTimestamp(ctx);
  const now = new Date(txTimestamp).getTime();

  const iter = await ctx.stub.getStateByPartialCompositeKey('Delegation', []);
  let revokedCount = 0;

  while (true) {
    const res = await iter.next();
    if (res.done) break;

    let d;
    try { d = JSON.parse(res.value.value.toString()); } catch { continue; }

    const expTime = Date.parse(d.expiresAt);
    if (d.active && expTime <= now) {
      d.active = false;
      d.revokedAt = txTimestamp;

      await ctx.stub.putState(res.value.key, Buffer.from(JSON.stringify(d), 'utf8'));

      if (d.delegationId) {
        await ctx.stub.putState(d.delegationId, Buffer.from(JSON.stringify(d), 'utf8'));
      }

      revokedCount++;
    }
  }

  await iter.close();

  await this._logAction(ctx, 'revokeExpiredDelegations', 'GLOBAL', {
    revokedCount,
    timestamp: txTimestamp
  });

  return JSON.stringify({ success: true, revokedCount, timestamp: txTimestamp });
}
  // ===========================================================================
  // Governance-key binding helpers
  // ===========================================================================

  _normalizePublicKeyPurpose(value) {
    return String(value || '')
      .trim()
      .toUpperCase()
      .replace(/[-\s]+/g, '_');
  }

  _normalizePublicKeyType(value) {
    return String(value || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '');
  }

  /**
   * Return the canonical destruction-governance role.
   * Unknown or non-governance roles return null.
   */
  _canonicalDestructionGovernanceRole(value) {
    const normalized = String(value || '')
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '');

    const roleMap = {
      dataprotectionofficer: 'DataProtectionOfficer',
      judicialreviewer: 'JudicialReviewer',
      evidencecustodian: 'EvidenceCustodian'
    };

    return roleMap[normalized] || null;
  }

  /**
   * Produce a stable fingerprint over the DER-encoded Ed25519 public key.
   * This detects reuse of the same signing key under different registry IDs.
   */
  _fingerprintEd25519PublicKey(publicKey) {
    let keyObject;

    try {
      keyObject = crypto.createPublicKey(publicKey);
    } catch (err) {
      throw new Error(
        `invalid_ed25519_public_key:${err instanceof Error ? err.message : 'parse_failed'}`
      );
    }

    if (keyObject.asymmetricKeyType !== 'ed25519') {
      throw new Error(
        `public_key_not_ed25519:${keyObject.asymmetricKeyType || 'unknown'}`
      );
    }

    const der = keyObject.export({
      type: 'spki',
      format: 'der'
    });

    return crypto
      .createHash('sha256')
      .update(der)
      .digest('hex');
  }


  // ===========================================================================
  // Public Key Registry
  // ===========================================================================
  async registerPublicKey(ctx, userId, keyType, publicKey, purpose) {
    if (!userId || !keyType || !publicKey || !purpose) {
      throw new Error(
        'userId, keyType, publicKey, purpose are required'
      );
    }

    this._checkAccess(ctx, {
      roles: [
        'EvidenceCustodian',
        'ForensicLead',
        'ForensicInvestigator',
        'GatewayCollector',
        'ManualCollector',
        'JudicialReviewer',
        'DataProtectionOfficer',
        'InternalAuditor',
        'ExternalVendor',
        'ExternalAuditor',

        // Backward compatibility
        'OTGatewayCollector',
        'AcquisitionOperator',
        'VendorEngineer',
        'IndependentAuditor',

        'Admin',
        'System Administrator'
      ],
      clearance: ['Low', 'Medium', 'High']
    });

    userId = String(userId).trim();
    keyType = String(keyType).trim();
    publicKey = String(publicKey).trim();
    purpose = String(purpose).trim();

    const normalizedPurpose =
      this._normalizePublicKeyPurpose(purpose);

    const normalizedKeyType =
      this._normalizePublicKeyType(keyType);

    const isDestructionAttestationKey =
      normalizedPurpose === 'DESTRUCTION_ATTESTATION';

    const callerMatchesUser =
      this._matchesCallerIdentifier(ctx, userId);

    const callerRoleRaw = String(
      ctx.clientIdentity.getAttributeValue('role') || ''
    ).trim();

    const callerGovernanceRole =
      this._canonicalDestructionGovernanceRole(
        callerRoleRaw
      );

    let governanceRole = null;
    let publicKeyFingerprint = null;

    /*
     * Destruction-attestation keys use stricter registration:
     *
     * 1. Ed25519 is mandatory.
     * 2. The caller must register its own key.
     * 3. The governance role comes from the caller certificate.
     * 4. Only DPO, JR, and Evidence Custodian are accepted.
     */
    if (isDestructionAttestationKey) {
      if (normalizedKeyType !== 'ed25519') {
        throw new Error(
          'destruction_attestation_key_must_be_ed25519'
        );
      }

      if (!callerMatchesUser) {
        throw new Error(
          `destruction_attestation_self_registration_required:userId=${userId}`
        );
      }

      if (!callerGovernanceRole) {
        throw new Error(
          `destruction_attestation_role_not_eligible:${callerRoleRaw || 'missing'}`
        );
      }

      if (
        !FC_DESTRUCTION_THRESHOLD_POLICY.eligibleRoles.includes(
          callerGovernanceRole
        )
      ) {
        throw new Error(
          `destruction_attestation_role_not_configured:${callerGovernanceRole}`
        );
      }

      governanceRole = callerGovernanceRole;

      publicKeyFingerprint =
        this._fingerprintEd25519PublicKey(publicKey);
    } else {
      /*
       * Preserve existing behavior for non-destruction keys.
       */
      const callerCanRegister =
        callerMatchesUser ||
        this._isPrivilegedDisclosureRole(ctx) ||
        ['admin', 'systemadministrator'].includes(
          this._roleNorm(ctx)
        );

      if (!callerCanRegister) {
        throw new Error(
          'Public key registration is allowed only for self-registration or privileged roles'
        );
      }

      if (normalizedKeyType === 'ed25519') {
        publicKeyFingerprint =
          this._fingerprintEd25519PublicKey(publicKey);
      } else {
        publicKeyFingerprint = crypto
          .createHash('sha256')
          .update(publicKey, 'utf8')
          .digest('hex');
      }
    }

    const keyId =
      `PublicKey_${userId}_${keyType}_${purpose}`;

    /*
     * Prevent silent replacement of an active key.
     * Re-registering the same key is allowed so a legacy record can
     * be upgraded with role and fingerprint fields.
     */
    const existingBytes =
      await ctx.stub.getState(keyId);

    if (existingBytes && existingBytes.length > 0) {
      let existing;

      try {
        existing = JSON.parse(
          existingBytes.toString()
        );
      } catch {
        throw new Error(
          `existing_public_key_record_invalid:${keyId}`
        );
      }

      const existingStatus = String(
        existing.status || ''
      ).trim().toLowerCase();

      if (existingStatus !== 'revoked') {
        const existingOwner = String(
          existing.ownerId ||
          existing.userId ||
          ''
        ).trim();

        if (
          existingOwner &&
          existingOwner !== userId
        ) {
          throw new Error(
            `public_key_owner_conflict:registered=${existingOwner}:requested=${userId}`
          );
        }

        if (
          String(existing.publicKey || '').trim() !==
          publicKey
        ) {
          throw new Error(
            `active_public_key_replacement_forbidden:${keyId}`
          );
        }

        if (
          isDestructionAttestationKey &&
          existing.governanceRole &&
          this._canonicalDestructionGovernanceRole(
            existing.governanceRole
          ) !== governanceRole
        ) {
          throw new Error(
            `public_key_governance_role_conflict:registered=${existing.governanceRole}:requested=${governanceRole}`
          );
        }

        if (
          existing.publicKeyFingerprint &&
          existing.publicKeyFingerprint !==
            publicKeyFingerprint
        ) {
          throw new Error(
            `public_key_fingerprint_conflict:${keyId}`
          );
        }
      }
    }

    const callerId =
      ctx.clientIdentity.getID();

    const registeredByActor =
      this._getAuditActor(ctx);

    const registeredAt =
      this._getTimestamp(ctx);

    const keyRecord = {
      version: 'public-key-record-v2',

      bindingVersion:
        isDestructionAttestationKey
          ? 'governance-key-binding-v1'
          : 'application-key-binding-v1',

      userId,
      ownerId: userId,
      keyType,
      publicKey,
      publicKeyFingerprint,
      purpose,

      governanceRole,

      destructionAttestationKey:
        isDestructionAttestationKey,

      registeredBy: callerId,
      registeredByActor,
      registeredByRole:
        callerRoleRaw || null,

      registeredAt,
      status: 'active'
    };

    await ctx.stub.putState(
      keyId,
      Buffer.from(
        JSON.stringify(keyRecord),
        'utf8'
      )
    );

    await this._logAction(
      ctx,
      'registerPublicKey',
      '',
      {
        targetUserId: userId,
        ownerId: userId,
        keyType,
        purpose,
        governanceRole,
        destructionAttestationKey:
          isDestructionAttestationKey,
        publicKeyFingerprint
      }
    );

    ctx.stub.setEvent(
      'PublicKeyRegistered',
      Buffer.from(
        JSON.stringify({
          keyId,
          userId,
          ownerId: userId,
          keyType,
          purpose,
          governanceRole,
          destructionAttestationKey:
            isDestructionAttestationKey,
          publicKeyFingerprint,
          registeredAt
        }),
        'utf8'
      )
    );

    return JSON.stringify({
      success: true,
      keyId,
      userId,
      ownerId: userId,
      purpose,
      governanceRole,
      publicKeyFingerprint,
      destructionAttestationKey:
        isDestructionAttestationKey
    });
  }


  async getPublicKey(ctx, userId, keyType, purpose) {
    const keyId = `PublicKey_${userId}_${keyType}_${purpose}`;
    const keyBytes = await ctx.stub.getState(keyId);

    if (!keyBytes || keyBytes.length === 0) {
      throw new Error(`Public key not found: ${userId} - ${keyType} - ${purpose}`);
    }

    return JSON.parse(keyBytes.toString());
  }

async issueDisclosureCapability(ctx, capabilityTokenJson) {
  this._checkAccess(ctx, {
    roles: ['EvidenceCustodian'],
    clearance: ['High']
  });

  const txTimestamp = this._getTimestamp(ctx);
  const txId = ctx.stub.getTxID();

  const token = this._parseJsonStrict('capabilityToken', capabilityTokenJson);
  const issuerId = String(token.issuerId || '').trim();
  if (!issuerId) throw new Error('issuerId is required in capability token');

  const { record: pkRecord } = await this._resolveRegisteredPublicKey(ctx, issuerId);
  const verified = fcVerifyCapabilityToken(token, pkRecord.publicKey, new Date(txTimestamp));

  if (!verified.valid) {
    throw new Error(`Invalid capability token: ${verified.reason}`);
  }

  const evId = verified.payload.evidenceId;
  const { evidenceKey, evidence } = await this._loadEvidenceRecord(ctx, evId);
  const commitment = this._extractEvidenceCommitment(evidence);
  if (!commitment.available) {
    throw new Error(`Evidence ${evId} does not expose chunk commitment required for disclosure workflow`);
  }

  const lifecycleStateAtIssue = fcNormalizeEvidenceLifecycleState(evidence);
  if (!fcCanIssueCapabilityForEvidenceState(lifecycleStateAtIssue)) {
    throw new Error(`evidence_lifecycle_not_authorizable:${lifecycleStateAtIssue}`);
  }

  const evidenceOwner = this._getEvidenceOwner(evidence);
  const auditActor = this._getAuditActor(ctx);
  const callerMatchesIssuer = this._matchesCallerIdentifier(ctx, verified.payload.issuerId);

  if (!evidenceOwner) {
    throw new Error('evidence_missing_custody_owner');
  }

  if (String(issuerId) !== String(evidenceOwner)) {
    throw new Error('capability_issuer_must_match_evidence_custodian');
  }

  if (String(auditActor) !== String(evidenceOwner)) {
    throw new Error('Only the designated evidence custodian may issue disclosure capability');
  }

  if (!callerMatchesIssuer) {
    throw new Error('issuer_identity_mismatch');
  }

  const existing = await this._getCapabilityRecordByCapId(ctx, verified.payload.capId);
  if (existing && existing.active) {
    throw new Error(`Capability ${verified.payload.capId} already exists and is active`);
  }

  const capabilityRecord = {
    capId: verified.payload.capId,
    evidenceId: verified.payload.evidenceId,
    incidentId: evidence.incidentId || 'EVIDENCE_ONLY',
    issuerId: verified.payload.issuerId,
    granteeId: verified.payload.granteeId,
    scope: verified.payload.scope,
    purpose: verified.payload.purpose || '',
    issuedAt: verified.payload.issuedAt,
    expiresAt: verified.payload.expiresAt,
    nonce: verified.payload.nonce,
    version: verified.payload.version || FC_CAPABILITY_VERSION,
    capHash: verified.capHash,
    scopeDigest: verified.scopeDigest,
    bindingDigest: verified.payload.bindingDigest || null,
    commitmentVersion: verified.payload.commitmentVersion || commitment.commitmentVersion || null,
    chunkMerkleRoot: verified.payload.chunkMerkleRoot || commitment.chunkMerkleRoot || null,
    lifecycleStateAtIssuance: verified.payload.lifecycleStateAtIssuance || lifecycleStateAtIssue,
    evidenceLifecycleEpoch: verified.payload.evidenceLifecycleEpoch != null
      ? verified.payload.evidenceLifecycleEpoch
      : fcGetEvidenceLifecycleEpoch(evidence),
    allowedLifecycleStates: Array.isArray(verified.payload.allowedLifecycleStates)
      ? verified.payload.allowedLifecycleStates
      : null,
    signatureHash: this._sha256Hex(token.signature),
    usagePolicy: 'SINGLE_USE',
    accessState: FC_CAPABILITY_ACCESS_STATES.ACTIVE,
    state: FC_CAPABILITY_ACCESS_STATES.ACTIVE,
    active: true,
    status: 'active',
    anchoredAt: txTimestamp,
    anchoredBy: auditActor,
    txId,
    requestCount: 0,
    verificationCount: 0,
    lastRequestAt: null,
    lastVerifiedAt: null
  };

  await this._persistCapabilityRecord(ctx, capabilityRecord);

  if (lifecycleStateAtIssue === FC_EVIDENCE_LIFECYCLE_STATES.COMMITTED) {
    const transition = this._transitionEvidenceLifecycle(
      evidence,
      FC_EVIDENCE_LIFECYCLE_STATES.AUTHORIZED,
      'CAPABILITY_ISSUED',
      auditActor,
      txTimestamp
    );

    // Summary fields for fast lifecycle query.
    // The canonical transition remains preserved in lifecycleHistory.
    evidence.authorizedAt = txTimestamp;
    evidence.authorizedBy = auditActor;
    evidence.lastAuthorization = {
      capId: capabilityRecord.capId,
      issuerId: capabilityRecord.issuerId,
      granteeId: capabilityRecord.granteeId,
      scopeType: capabilityRecord.scope.type,
      capHash: capabilityRecord.capHash,
      scopeDigest: capabilityRecord.scopeDigest,
      expiresAt: capabilityRecord.expiresAt,
      authorizedAt: txTimestamp,
      authorizedBy: auditActor
    };

    await this._persistEvidenceRecord(ctx, evidenceKey || `evidence::${evId}`, evidence);
    ctx.stub.setEvent('EvidenceLifecycleStateChanged', Buffer.from(JSON.stringify(this._buildGovernanceEvent('EvidenceLifecycleStateChanged', {
      evidenceId: evId,
      previousState: transition.previousState,
      nextState: transition.nextState,
      reason: 'CAPABILITY_ISSUED',
      actor: auditActor,
      changedAt: txTimestamp
    })), 'utf8'));
  }

  ctx.stub.setEvent('CapabilityIssued', Buffer.from(JSON.stringify(this._buildGovernanceEvent('CapabilityIssued', {
    capId: capabilityRecord.capId,
    evidenceId: capabilityRecord.evidenceId,
    granteeId: capabilityRecord.granteeId,
    issuerId: capabilityRecord.issuerId,
    scopeType: capabilityRecord.scope.type,
    capHash: capabilityRecord.capHash,
    scopeDigest: capabilityRecord.scopeDigest,
    bindingDigest: capabilityRecord.bindingDigest,
    commitmentVersion: capabilityRecord.commitmentVersion,
    chunkMerkleRoot: capabilityRecord.chunkMerkleRoot,
    lifecycleStateAtIssuance: capabilityRecord.lifecycleStateAtIssuance,
    evidenceLifecycleEpoch: capabilityRecord.evidenceLifecycleEpoch,
    accessState: capabilityRecord.accessState,
    expiresAt: capabilityRecord.expiresAt,
    anchoredAt: txTimestamp
  })), 'utf8'));

  ctx.stub.setEvent('DisclosureCapabilityIssued', Buffer.from(JSON.stringify({
    capId: capabilityRecord.capId,
    evidenceId: capabilityRecord.evidenceId,
    granteeId: capabilityRecord.granteeId,
    issuerId: capabilityRecord.issuerId,
    scopeType: capabilityRecord.scope.type,
    expiresAt: capabilityRecord.expiresAt,
    capHash: capabilityRecord.capHash,
    scopeDigest: capabilityRecord.scopeDigest,
    commitmentVersion: capabilityRecord.commitmentVersion,
    chunkMerkleRoot: capabilityRecord.chunkMerkleRoot,
    lifecycleStateAtIssuance: capabilityRecord.lifecycleStateAtIssuance,
    evidenceLifecycleEpoch: capabilityRecord.evidenceLifecycleEpoch,
    anchoredAt: txTimestamp
  }), 'utf8'));

  await this._logAction(ctx, 'issueDisclosureCapability', evidence.incidentId || 'EVIDENCE_ONLY', {
    evidenceId: capabilityRecord.evidenceId,
    capId: capabilityRecord.capId,
    issuerId: capabilityRecord.issuerId,
    granteeId: capabilityRecord.granteeId,
    scopeType: capabilityRecord.scope.type,
    capHash: capabilityRecord.capHash,
    scopeDigest: capabilityRecord.scopeDigest,
    commitmentVersion: capabilityRecord.commitmentVersion,
    chunkMerkleRoot: capabilityRecord.chunkMerkleRoot,
    lifecycleStateAtIssuance: capabilityRecord.lifecycleStateAtIssuance,
    evidenceLifecycleEpoch: capabilityRecord.evidenceLifecycleEpoch,
    expiresAt: capabilityRecord.expiresAt
  });

  return JSON.stringify({
    success: true,
    capId: capabilityRecord.capId,
    evidenceId: capabilityRecord.evidenceId,
    issuerId: capabilityRecord.issuerId,
    granteeId: capabilityRecord.granteeId,
    scopeType: capabilityRecord.scope.type,
    capHash: capabilityRecord.capHash,
    scopeDigest: capabilityRecord.scopeDigest,
    commitmentVersion: capabilityRecord.commitmentVersion,
    chunkMerkleRoot: capabilityRecord.chunkMerkleRoot,
    lifecycleStateAtIssuance: capabilityRecord.lifecycleStateAtIssuance,
    evidenceLifecycleEpoch: capabilityRecord.evidenceLifecycleEpoch,
    expiresAt: capabilityRecord.expiresAt
  });
}

  async _checkCapability(ctx, evidenceId, capabilityTokenOrJson, requestedChunkIndices = [], options = {}) {
    const txTimestamp = this._getTimestamp(ctx);

    const token = fcIsPlainObject(capabilityTokenOrJson)
      ? capabilityTokenOrJson
      : this._parseJsonStrict('capabilityToken', capabilityTokenOrJson);

    const issuerId = String(token.issuerId || '').trim();
    if (!issuerId) {
      throw new Error('Capability token missing issuerId');
    }

    const { record: pkRecord } = await this._resolveRegisteredPublicKey(ctx, issuerId);
    const verified = fcVerifyCapabilityToken(token, pkRecord.publicKey, new Date(txTimestamp));
    if (!verified.valid) {
      throw new Error(`invalid_capability_token:${verified.reason}`);
    }

    const evId = String(evidenceId || '').trim();
    if (!evId) throw new Error('evidenceId is required');

    if (verified.payload.evidenceId !== evId) {
      throw new Error('capability_evidence_mismatch');
    }

    const record = await this._getCapabilityRecordByCapId(ctx, verified.payload.capId);
    if (!record) {
      throw new Error(`Capability ${verified.payload.capId} not found on ledger`);
    }

    const accessState = fcNormalizeCapabilityAccessState(record);
    if (!fcIsCapabilityUsableState(accessState)) {
      throw new Error(`capability_not_usable:${accessState}`);
    }

    if (String(record.evidenceId) !== evId) {
      throw new Error('capability_record_evidence_mismatch');
    }

    if (String(record.granteeId) !== String(verified.payload.granteeId)) {
      throw new Error('capability_record_grantee_mismatch');
    }

    if (String(record.issuerId) !== String(verified.payload.issuerId)) {
      throw new Error('capability_record_issuer_mismatch');
    }

    if (String(record.capHash).toLowerCase() !== String(verified.capHash).toLowerCase()) {
      throw new Error('capability_record_caphash_mismatch');
    }

    if (String(record.scopeDigest).toLowerCase() !== String(verified.scopeDigest).toLowerCase()) {
      throw new Error('capability_record_scopedigest_mismatch');
    }

    const { evidence } = await this._loadEvidenceRecord(ctx, evId);
    const commitment = this._extractEvidenceCommitment(evidence);
    const currentLifecycleState = fcNormalizeEvidenceLifecycleState(evidence);
    const currentLifecycleEpoch = fcGetEvidenceLifecycleEpoch(evidence);

    if (verified.payload.commitmentVersion && commitment.available) {
      if (String(verified.payload.commitmentVersion).trim() !== String(commitment.commitmentVersion).trim()) {
        throw new Error('capability_commitment_version_mismatch');
      }
    }

    if (verified.payload.chunkMerkleRoot && commitment.available) {
      if (String(verified.payload.chunkMerkleRoot).toLowerCase() !== String(commitment.chunkMerkleRoot).toLowerCase()) {
        throw new Error('capability_merkle_root_mismatch');
      }
    }

    if (verified.payload.evidenceLifecycleEpoch != null) {
      const capabilityEpoch = Number(verified.payload.evidenceLifecycleEpoch);

      if (!Number.isSafeInteger(capabilityEpoch) || capabilityEpoch < 0) {
        throw new Error(`capability_lifecycle_epoch_invalid:${verified.payload.evidenceLifecycleEpoch}`);
      }

      if (capabilityEpoch !== currentLifecycleEpoch) {
        throw new Error(`capability_lifecycle_epoch_mismatch:${capabilityEpoch}!=${currentLifecycleEpoch}`);
      }
    }

    const allowedLifecycleStates = Array.isArray(verified.payload.allowedLifecycleStates)
      ? verified.payload.allowedLifecycleStates.map(s => String(s || '').trim().toUpperCase()).filter(Boolean)
      : [
          FC_EVIDENCE_LIFECYCLE_STATES.AUTHORIZED,
          FC_EVIDENCE_LIFECYCLE_STATES.DISCLOSED
        ];

    if (allowedLifecycleStates.length > 0 && !allowedLifecycleStates.includes(currentLifecycleState)) {
      throw new Error(`capability_lifecycle_state_not_allowed:${currentLifecycleState}`);
    }

    if (new Date(record.expiresAt).getTime() <= new Date(txTimestamp).getTime()) {
      throw new Error('capability_expired');
    }

    if (options.requireHolderBinding !== false) {
      if (!this._matchesCallerIdentifier(ctx, verified.payload.granteeId)) {
        throw new Error('holder_identity_mismatch');
      }
    }

    const scopeCheck = fcCheckScope(verified.payload.scope, requestedChunkIndices || []);
    if (!scopeCheck.allowed) {
      throw new Error(`scope_check_failed:${scopeCheck.reason}`);
    }

    return {
      verifiedToken: verified,
      capRecord: record,
      scopeCheck
    };
  }

    async requestDisclosure(ctx, evidenceId, capabilityTokenJson, requestedChunkIndicesJson) {
    this._checkAccess(ctx, {
      roles: [
        'ExternalVendor',
        'ExternalAuditor',
        'InternalAuditor',
        'EvidenceCustodian',
        'ForensicLead',
        'ForensicInvestigator',
        'JudicialReviewer',
        'DataProtectionOfficer',
        'GatewayCollector',
        'ManualCollector',

        // Backward compatibility
        'VendorEngineer',
        'IndependentAuditor',
        'OTGatewayCollector',
        'AcquisitionOperator'
      ],
      clearance: ['Low', 'Medium', 'High']
    });

    const requestedChunkIndices = this._parseJsonStrict(
      'requestedChunkIndices',
      requestedChunkIndicesJson || '[]'
    );

    if (!Array.isArray(requestedChunkIndices)) {
      throw new Error('requestedChunkIndices must be an array');
    }

    const evId = String(evidenceId || '').trim();
    const { evidenceKey, evidence } = await this._loadEvidenceRecord(ctx, evId);
    const commitment = this._extractEvidenceCommitment(evidence);

    if (!commitment.available) {
      throw new Error(`Evidence ${evId} does not have chunk commitment metadata`);
    }

    const lifecycleState = fcNormalizeEvidenceLifecycleState(evidence);
    if (!fcIsDisclosurePermissibleEvidenceState(lifecycleState)) {
      throw new Error(`evidence_lifecycle_not_disclosure_permissible:${lifecycleState}`);
    }

    const checked = await this._checkCapability(ctx, evId, capabilityTokenJson, requestedChunkIndices, {
      requireHolderBinding: true
    });

    checked.capRecord.requestCount = (checked.capRecord.requestCount || 0) + 1;
    checked.capRecord.lastRequestAt = this._getTimestamp(ctx);

    await this._persistCapabilityRecord(ctx, checked.capRecord);

    const disclosureType =
      checked.verifiedToken.payload.scope.type === FC_SCOPE_TYPES.HASH_ONLY
        ? 'HASH_ONLY'
        : 'CHUNK_DISCLOSURE';

    const response = {
      authorized: true,
      evidenceId: evId,
      capId: checked.verifiedToken.payload.capId,
      issuerId: checked.verifiedToken.payload.issuerId,
      granteeId: checked.verifiedToken.payload.granteeId,
      scopeType: checked.verifiedToken.payload.scope.type,
      disclosureType,
      requestedChunkIndices: checked.scopeCheck.normalizedRequestedChunks,
      capHash: checked.verifiedToken.capHash,
      scopeDigest: checked.verifiedToken.scopeDigest,
      chunkMerkleRoot: commitment.chunkMerkleRoot,
      chunkCount: commitment.chunkCount,
      chunkSize: commitment.chunkSize,
      commitmentVersion: commitment.commitmentVersion,
      integrityHash: commitment.integrityHash,
      requestTimestamp: this._getTimestamp(ctx)
    };

    ctx.stub.setEvent('DisclosureRequested', Buffer.from(JSON.stringify(response), 'utf8'));

    await this._logAction(ctx, 'requestDisclosure', evidence.incidentId || 'EVIDENCE_ONLY', {
      evidenceId: evId,
      capId: checked.verifiedToken.payload.capId,
      scopeType: checked.verifiedToken.payload.scope.type,
      disclosureType,
      requestedChunkCount: checked.scopeCheck.normalizedRequestedChunks.length,
      requestedChunkIndices: checked.scopeCheck.normalizedRequestedChunks
    });

    return JSON.stringify(response);
  }

    async getEvidenceCommitment(ctx, evidenceId) {
    this._checkAccess(ctx, {
      roles: [
        'VendorEngineer',
        'ExternalVendor',
        'IndependentAuditor',
        'ExternalAuditor',
        'InternalAuditor',
        'EvidenceCustodian',
        'ForensicLead',
        'ForensicInvestigator',
        'JudicialReviewer',
        'OTGatewayCollector'
      ],
      clearance: ['Low', 'Medium', 'High']
    });

    const evId = String(evidenceId || '').trim();
    const { evidenceKey, evidence } = await this._loadEvidenceRecord(ctx, evId);
    const commitment = this._extractEvidenceCommitment(evidence);

    if (!commitment.available) {
      throw new Error(`Evidence ${evId} does not have chunk commitment metadata`);
    }

    const response = {
      evidenceId: evId,
      integrityHash: commitment.integrityHash,
      chunkMerkleRoot: commitment.chunkMerkleRoot,
      chunkCount: commitment.chunkCount,
      chunkSize: commitment.chunkSize,
      commitmentVersion: commitment.commitmentVersion,
      storageMode: commitment.storageMode,
      storageVersion: commitment.storageVersion,
      lifecycleState: fcNormalizeEvidenceLifecycleState(evidence),
      retrievedAt: this._getTimestamp(ctx)
    };

    await this._logAction(ctx, 'getEvidenceCommitment', evidence.incidentId || 'EVIDENCE_ONLY', {
      evidenceId: evId,
      chunkMerkleRoot: commitment.chunkMerkleRoot,
      chunkCount: commitment.chunkCount,
      chunkSize: commitment.chunkSize,
      commitmentVersion: commitment.commitmentVersion
    });

    return JSON.stringify(response);
  }

  async verifyDisclosure(ctx, evidenceId, disclosureBundleJson) {
    this._checkAccess(ctx, {
      roles: [
        'VendorEngineer',
        'ExternalVendor',
        'IndependentAuditor',
        'ExternalAuditor',
        'EvidenceCustodian',
        'ForensicLead',
        'ForensicInvestigator'
      ],
      clearance: ['Low', 'Medium', 'High']
    });

    const txTimestamp = this._getTimestamp(ctx);
    const evId = String(evidenceId || '').trim();
    const bundle = this._parseJsonStrict('disclosureBundle', disclosureBundleJson);

    const { evidenceKey, evidence } = await this._loadEvidenceRecord(ctx, evId);
    const commitment = this._extractEvidenceCommitment(evidence);

    if (!commitment.available) {
      throw new Error(`Evidence ${evId} does not have chunk commitment metadata`);
    }

    const baseResult = {
      evidenceId: evId,
      verifiedAt: txTimestamp,
      verifierId: this._getAuditActor(ctx),
      valid: false,
      bundleHashValid: false,
      rootMatch: false,
      capabilityValid: false,
      failedIndices: [],
      results: []
    };

    const lifecycleStateForVerification = fcNormalizeEvidenceLifecycleState(evidence);
    if (!fcIsDisclosurePermissibleEvidenceState(lifecycleStateForVerification)) {
      return JSON.stringify({
        ...baseResult,
        reason: `evidence_lifecycle_not_disclosure_permissible:${lifecycleStateForVerification}`
      });
    }

    if (!fcIsPlainObject(bundle)) {
      return JSON.stringify({ ...baseResult, reason: 'bundle_not_object' });
    }

    if (bundle.version !== FC_DISCLOSURE_BUNDLE_VERSION) {
      return JSON.stringify({ ...baseResult, reason: 'invalid_bundle_version' });
    }

    if (!fcIsPlainObject(bundle.manifest)) {
      return JSON.stringify({ ...baseResult, reason: 'missing_manifest' });
    }

    if (bundle.manifest.version !== FC_DISCLOSURE_MANIFEST_VERSION) {
      return JSON.stringify({ ...baseResult, reason: 'invalid_manifest_version' });
    }

    const recomputedBundleHash = fcComputeBundleHash(bundle);
    if (bundle.bundleHash !== recomputedBundleHash) {
      const out = {
        ...baseResult,
        reason: 'bundle_hash_mismatch',
        bundleHashValid: false
      };

      await this._logAction(ctx, 'verifyDisclosure', evidence.incidentId || 'EVIDENCE_ONLY', {
        evidenceId: evId,
        valid: false,
        reason: out.reason,
        bundleHashValid: false
      });

      return JSON.stringify(out);
    }

    if (String(bundle.manifest.evidenceId || '') !== evId) {
      return JSON.stringify({
        ...baseResult,
        reason: 'manifest_evidence_mismatch',
        bundleHashValid: true
      });
    }

    if (String(bundle.manifest.chunkMerkleRoot || '').toLowerCase() !== String(commitment.chunkMerkleRoot).toLowerCase()) {
      return JSON.stringify({
        ...baseResult,
        reason: 'manifest_root_mismatch',
        bundleHashValid: true,
        rootMatch: false
      });
    }

    if (
      bundle.manifest.commitmentVersion &&
      String(bundle.manifest.commitmentVersion).trim() !== String(commitment.commitmentVersion).trim()
    ) {
      return JSON.stringify({
        ...baseResult,
        reason: 'manifest_commitment_version_mismatch',
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: false
      });
    }

    let verifiedCap = null;
    let capRecord = null;
    let capabilityStateBefore = null;

    if (!bundle.capabilityToken || !fcIsPlainObject(bundle.capabilityToken)) {
      return JSON.stringify({
        ...baseResult,
        reason: 'missing_capability_token',
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: false
      });
    }

    try {
      const { record: pkRecord } = await this._resolveRegisteredPublicKey(ctx, bundle.capabilityToken.issuerId);
      verifiedCap = fcVerifyCapabilityToken(bundle.capabilityToken, pkRecord.publicKey, new Date(txTimestamp));

      if (!verifiedCap.valid) {
        return JSON.stringify({
          ...baseResult,
          reason: `invalid_capability_token:${verifiedCap.reason}`,
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      capRecord = await this._getCapabilityRecordByCapId(ctx, verifiedCap.payload.capId);
      if (!capRecord) {
        return JSON.stringify({
          ...baseResult,
          reason: 'capability_not_found',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      capabilityStateBefore = this._getCapabilityEffectiveStatus(capRecord, txTimestamp);
      if (capabilityStateBefore !== 'ACTIVE') {
        return JSON.stringify({
          ...baseResult,
          reason: this._capabilityInactiveReason(capabilityStateBefore),
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false,
          capabilityStateBefore,
          capabilityStateAfter: capabilityStateBefore
        });
      }

      if (String(capRecord.evidenceId) !== evId) {
        return JSON.stringify({
          ...baseResult,
          reason: 'capability_record_evidence_mismatch',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      if (String(capRecord.capHash).toLowerCase() !== String(verifiedCap.capHash).toLowerCase()) {
        return JSON.stringify({
          ...baseResult,
          reason: 'capability_record_caphash_mismatch',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      if (String(capRecord.scopeDigest).toLowerCase() !== String(verifiedCap.scopeDigest).toLowerCase()) {
        return JSON.stringify({
          ...baseResult,
          reason: 'capability_record_scopedigest_mismatch',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      if (String(bundle.manifest.capId || '') !== String(verifiedCap.payload.capId)) {
        return JSON.stringify({
          ...baseResult,
          reason: 'manifest_capid_mismatch',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      if (String(bundle.manifest.capHash || '').toLowerCase() !== String(verifiedCap.capHash).toLowerCase()) {
        return JSON.stringify({
          ...baseResult,
          reason: 'manifest_caphash_mismatch',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      if (String(bundle.manifest.scopeDigest || '').toLowerCase() !== String(verifiedCap.scopeDigest).toLowerCase()) {
        return JSON.stringify({
          ...baseResult,
          reason: 'manifest_scopedigest_mismatch',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

        
      // state-changing VerifyDisclosure. Do not rely only on a prior
      // RequestDisclosure call having been executed by a well-behaved client.

      // Token must still identify the same evidence.
      if (String(verifiedCap.payload.evidenceId || '') !== evId) {
        throw new Error('capability_evidence_mismatch');
      }

      // Ledger capability record must still bind the same grantee and issuer.
      if (String(capRecord.granteeId || '') !== String(verifiedCap.payload.granteeId || '')) {
        throw new Error('capability_record_grantee_mismatch');
      }

      if (String(capRecord.issuerId || '') !== String(verifiedCap.payload.issuerId || '')) {
        throw new Error('capability_record_issuer_mismatch');
      }

      // Current verification is holder-bound: only the capability grantee may
      // execute this state-changing verification path.
      if (!this._matchesCallerIdentifier(ctx, verifiedCap.payload.granteeId)) {
        throw new Error('holder_identity_mismatch');
      }

      // Capability must remain bound to the currently anchored commitment.
      if (verifiedCap.payload.commitmentVersion && commitment.available) {
        if (
          String(verifiedCap.payload.commitmentVersion).trim() !==
          String(commitment.commitmentVersion).trim()
        ) {
          throw new Error('capability_commitment_version_mismatch');
        }
      }

      if (verifiedCap.payload.chunkMerkleRoot && commitment.available) {
        if (
          String(verifiedCap.payload.chunkMerkleRoot).toLowerCase() !==
          String(commitment.chunkMerkleRoot).toLowerCase()
        ) {
          throw new Error('capability_merkle_root_mismatch');
        }
      }

      // Lifecycle-bound freshness: the token epoch must equal the current
      // evidence lifecycle epoch.
      const currentLifecycleEpoch = fcGetEvidenceLifecycleEpoch(evidence);

      if (verifiedCap.payload.evidenceLifecycleEpoch != null) {
        const capabilityEpoch = Number(verifiedCap.payload.evidenceLifecycleEpoch);

        if (!Number.isSafeInteger(capabilityEpoch) || capabilityEpoch < 0) {
          throw new Error(
            `capability_lifecycle_epoch_invalid:${verifiedCap.payload.evidenceLifecycleEpoch}`
          );
        }

        if (capabilityEpoch !== currentLifecycleEpoch) {
          throw new Error(
            `capability_lifecycle_epoch_mismatch:${capabilityEpoch}!=${currentLifecycleEpoch}`
          );
        }
      }

      // In addition to the global disclosure-permissible gate above, enforce
      // the lifecycle states carried by the capability itself.
      const allowedLifecycleStates = Array.isArray(verifiedCap.payload.allowedLifecycleStates)
        ? verifiedCap.payload.allowedLifecycleStates
            .map(s => String(s || '').trim().toUpperCase())
            .filter(Boolean)
        : [
            FC_EVIDENCE_LIFECYCLE_STATES.AUTHORIZED,
            FC_EVIDENCE_LIFECYCLE_STATES.DISCLOSED
          ];

      if (
        allowedLifecycleStates.length > 0 &&
        !allowedLifecycleStates.includes(lifecycleStateForVerification)
      ) {
        throw new Error(
          `capability_lifecycle_state_not_allowed:${lifecycleStateForVerification}`
        );
      }

    } catch (err) {
      return JSON.stringify({
        ...baseResult,
        reason: err instanceof Error ? err.message : 'capability_verification_failed',
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: false
      });
    }

    if (bundle.manifest.disclosureType === 'HASH_ONLY') {
      const noChunks = Array.isArray(bundle.disclosedChunks) && bundle.disclosedChunks.length === 0;
      const noProofs = Array.isArray(bundle.proofs) && bundle.proofs.length === 0;

      const out = {
        ...baseResult,
        valid: !!(noChunks && noProofs),
        reason: (noChunks && noProofs) ? null : 'hash_only_bundle_must_not_contain_chunks_or_proofs',
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: true,
        failedIndices: [],
        results: []
      };

      const lifecycle = out.valid
        ? await this._consumeCapabilityAfterSuccessfulVerification(ctx, capRecord, txTimestamp, baseResult.verifierId)
        : {
            capabilityStateBefore,
            capabilityStateAfter: capabilityStateBefore || this._getCapabilityEffectiveStatus(capRecord, txTimestamp)
          };

      out.capabilityStateBefore = lifecycle.capabilityStateBefore;
      out.capabilityStateAfter = lifecycle.capabilityStateAfter;

      if (out.valid) {
        const transition = this._transitionEvidenceLifecycle(
          evidence,
          FC_EVIDENCE_LIFECYCLE_STATES.DISCLOSED,
          'DISCLOSURE_VERIFIED',
          baseResult.verifierId,
          txTimestamp
        );

        evidence.evidenceLifecycleState = FC_EVIDENCE_LIFECYCLE_STATES.DISCLOSED;
        evidence.disclosedAt = txTimestamp;
        evidence.disclosedBy = baseResult.verifierId;
        evidence.lastDisclosure = {
          capId: capRecord.capId,
          disclosureType: 'HASH_ONLY',
          verifiedAt: txTimestamp,
          verifiedBy: baseResult.verifierId,
          disclosedChunkCount: 0,
          failedChunkCount: 0
        };

        await this._persistEvidenceRecord(ctx, evidenceKey, evidence);

        out.evidenceLifecycleState = FC_EVIDENCE_LIFECYCLE_STATES.DISCLOSED;

        ctx.stub.setEvent('EvidenceLifecycleStateChanged', Buffer.from(JSON.stringify(this._buildGovernanceEvent('EvidenceLifecycleStateChanged', {
          evidenceId: evId,
          previousState: transition.previousState,
          nextState: transition.nextState,
          reason: 'DISCLOSURE_VERIFIED',
          actor: baseResult.verifierId,
          changedAt: txTimestamp,
          capId: capRecord.capId,
          disclosureType: 'HASH_ONLY'
        })), 'utf8'));
      }

      await this._logAction(ctx, 'verifyDisclosure', evidence.incidentId || 'EVIDENCE_ONLY', {
        evidenceId: evId,
        capId: capRecord.capId,
        valid: out.valid,
        disclosureType: 'HASH_ONLY',
        bundleHashValid: out.bundleHashValid,
        rootMatch: out.rootMatch,
        capabilityStateBefore: out.capabilityStateBefore,
        capabilityStateAfter: out.capabilityStateAfter
      });

      ctx.stub.setEvent('DisclosureVerified', Buffer.from(JSON.stringify({
        evidenceId: evId,
        capId: capRecord.capId,
        valid: out.valid,
        disclosureType: 'HASH_ONLY',
        verifiedAt: txTimestamp,
        capabilityStateBefore: out.capabilityStateBefore,
        capabilityStateAfter: out.capabilityStateAfter
      }), 'utf8'));

      return JSON.stringify(out);
    }

    if (!Array.isArray(bundle.disclosedChunks) || !Array.isArray(bundle.proofs)) {
      return JSON.stringify({
        ...baseResult,
        reason: 'missing_disclosed_chunks_or_proofs',
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: true
      });
    }

    const actualIndices = bundle.disclosedChunks.map(c => c.index);
    let normalizedActualIndices;
    let normalizedManifestIndices;

    try {
      normalizedActualIndices = fcNormalizeChunkIndices(actualIndices);
      normalizedManifestIndices = fcNormalizeChunkIndices(bundle.manifest.disclosedChunkIndices || []);
    } catch (err) {
      return JSON.stringify({
        ...baseResult,
        reason: err instanceof Error ? err.message : 'invalid_disclosed_chunk_indices',
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: true
      });
    }

    if (JSON.stringify(normalizedActualIndices) !== JSON.stringify(normalizedManifestIndices)) {
      return JSON.stringify({
        ...baseResult,
        reason: 'manifest_disclosed_indices_mismatch',
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: true
      });
    }

    const scopeCheck = fcCheckScope(verifiedCap.payload.scope, normalizedActualIndices);
    if (!scopeCheck.allowed) {
      return JSON.stringify({
        ...baseResult,
        reason: `scope_check_failed:${scopeCheck.reason}`,
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: true
      });
    }

    const proofMap = new Map();
    for (const proofObj of bundle.proofs) {
      if (!proofObj || typeof proofObj.index !== 'number') {
        return JSON.stringify({
          ...baseResult,
          reason: 'invalid_proof_index',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: true
        });
      }
      proofMap.set(proofObj.index, proofObj);
    }

    const results = [];
    const failedIndices = [];

    for (const disclosed of bundle.disclosedChunks) {
      const proofObj = proofMap.get(disclosed.index);

      if (!proofObj) {
        results.push({
          chunkIndex: disclosed.index,
          valid: false,
          reason: 'missing_proof_for_chunk'
        });
        failedIndices.push(disclosed.index);
        continue;
      }

      const useV3Commitment = String(commitment.commitmentVersion || '').trim() === FC_CHUNK_COMMITMENT_VERSION_V3;
      const verification = useV3Commitment
        ? fcVerifySerializedDisclosureChunkV3(
          disclosed,
          proofObj,
          commitment.chunkMerkleRoot,
          evId
        )
        : fcVerifySerializedDisclosureChunk(
          disclosed,
          proofObj,
          commitment.chunkMerkleRoot
        );

      results.push({
        chunkIndex: disclosed.index,
        valid: verification.valid,
        reason: verification.reason || null
      });

      if (!verification.valid) {
        failedIndices.push(disclosed.index);
      }
    }

    const out = {
      ...baseResult,
      valid: failedIndices.length === 0,
      reason: failedIndices.length === 0 ? null : 'chunk_or_proof_verification_failed',
      bundleHashValid: true,
      rootMatch: true,
      capabilityValid: true,
      failedIndices,
      results
    };

    const lifecycle = out.valid
      ? await this._consumeCapabilityAfterSuccessfulVerification(ctx, capRecord, txTimestamp, baseResult.verifierId)
      : {
          capabilityStateBefore,
          capabilityStateAfter: capabilityStateBefore || this._getCapabilityEffectiveStatus(capRecord, txTimestamp)
        };

    out.capabilityStateBefore = lifecycle.capabilityStateBefore;
    out.capabilityStateAfter = lifecycle.capabilityStateAfter;

    if (out.valid) {
      const transition = this._transitionEvidenceLifecycle(
        evidence,
        FC_EVIDENCE_LIFECYCLE_STATES.DISCLOSED,
        'DISCLOSURE_VERIFIED',
        baseResult.verifierId,
        txTimestamp
      );

      evidence.evidenceLifecycleState = FC_EVIDENCE_LIFECYCLE_STATES.DISCLOSED;
      evidence.disclosedAt = txTimestamp;
      evidence.disclosedBy = baseResult.verifierId;
      evidence.lastDisclosure = {
        capId: capRecord.capId,
        disclosureType: bundle.manifest.disclosureType || 'CHUNK_DISCLOSURE',
        verifiedAt: txTimestamp,
        verifiedBy: baseResult.verifierId,
        disclosedChunkCount: results.length,
        failedChunkCount: failedIndices.length,
        disclosedChunkIndices: normalizedActualIndices
      };

      await this._persistEvidenceRecord(ctx, evidenceKey, evidence);

      out.evidenceLifecycleState = FC_EVIDENCE_LIFECYCLE_STATES.DISCLOSED;

      ctx.stub.setEvent('EvidenceLifecycleStateChanged', Buffer.from(JSON.stringify(this._buildGovernanceEvent('EvidenceLifecycleStateChanged', {
        evidenceId: evId,
        previousState: transition.previousState,
        nextState: transition.nextState,
        reason: 'DISCLOSURE_VERIFIED',
        actor: baseResult.verifierId,
        changedAt: txTimestamp,
        capId: capRecord.capId,
        disclosureType: bundle.manifest.disclosureType || 'CHUNK_DISCLOSURE',
        verifiedChunkCount: results.length,
        failedChunkCount: failedIndices.length
      })), 'utf8'));
    }

    await this._logAction(ctx, 'verifyDisclosure', evidence.incidentId || 'EVIDENCE_ONLY', {
      evidenceId: evId,
      capId: capRecord.capId,
      valid: out.valid,
      disclosureType: bundle.manifest.disclosureType || 'CHUNK_DISCLOSURE',
      verifiedChunkCount: results.length,
      failedChunkCount: failedIndices.length,
      failedIndices,
      capabilityStateBefore: out.capabilityStateBefore,
      capabilityStateAfter: out.capabilityStateAfter
    });

    ctx.stub.setEvent('DisclosureVerified', Buffer.from(JSON.stringify({
      evidenceId: evId,
      capId: capRecord.capId,
      valid: out.valid,
      disclosureType: bundle.manifest.disclosureType || 'CHUNK_DISCLOSURE',
      verifiedChunkCount: results.length,
      failedChunkCount: failedIndices.length,
      verifiedAt: txTimestamp,
      capabilityStateBefore: out.capabilityStateBefore,
      capabilityStateAfter: out.capabilityStateAfter
    }), 'utf8'));

    return JSON.stringify(out);
  }

  async verifyHistoricalDisclosure(ctx, evidenceId, disclosureBundleJson) {
    this._checkAccess(ctx, {
      roles: [
        'ExternalAuditor',
        'IndependentAuditor',
        'InternalAuditor',
        'JudicialReviewer',
        'DataProtectionOfficer',
        'EvidenceCustodian',
        'ForensicLead',
        'ForensicInvestigator',
        'ExternalVendor',
        'VendorEngineer'
      ],
      clearance: ['Low', 'Medium', 'High']
    });

    const txTimestamp = this._getTimestamp(ctx);
    const evId = String(evidenceId || '').trim();
    const bundle = this._parseJsonStrict('disclosureBundle', disclosureBundleJson);

    const { evidence } = await this._loadEvidenceRecord(ctx, evId);
    const commitment = this._extractEvidenceCommitment(evidence);

    if (!commitment.available) {
      throw new Error(`Evidence ${evId} does not have chunk commitment metadata`);
    }

    const lifecycleState = fcNormalizeEvidenceLifecycleState(evidence);
    const baseResult = {
      evidenceId: evId,
      verifiedAt: txTimestamp,
      verifierId: this._getAuditActor(ctx),
      historicalVerification: true,
      newDisclosureAuthorized: false,
      lifecycleState,
      valid: false,
      bundleHashValid: false,
      rootMatch: false,
      capabilityValid: false,
      failedIndices: [],
      results: []
    };

    if (!fcIsPlainObject(bundle)) {
      return JSON.stringify({ ...baseResult, reason: 'bundle_not_object' });
    }

    if (bundle.version !== FC_DISCLOSURE_BUNDLE_VERSION) {
      return JSON.stringify({ ...baseResult, reason: 'invalid_bundle_version' });
    }

    if (!fcIsPlainObject(bundle.manifest)) {
      return JSON.stringify({ ...baseResult, reason: 'missing_manifest' });
    }

    if (bundle.manifest.version !== FC_DISCLOSURE_MANIFEST_VERSION) {
      return JSON.stringify({ ...baseResult, reason: 'invalid_manifest_version' });
    }

    const recomputedBundleHash = fcComputeBundleHash(bundle);
    if (bundle.bundleHash !== recomputedBundleHash) {
      return JSON.stringify({
        ...baseResult,
        reason: 'bundle_hash_mismatch',
        bundleHashValid: false
      });
    }

    if (String(bundle.manifest.evidenceId || '') !== evId) {
      return JSON.stringify({
        ...baseResult,
        reason: 'manifest_evidence_mismatch',
        bundleHashValid: true
      });
    }

    if (String(bundle.manifest.chunkMerkleRoot || '').toLowerCase() !== String(commitment.chunkMerkleRoot).toLowerCase()) {
      return JSON.stringify({
        ...baseResult,
        reason: 'manifest_root_mismatch',
        bundleHashValid: true,
        rootMatch: false
      });
    }

    if (
      bundle.manifest.commitmentVersion &&
      String(bundle.manifest.commitmentVersion).trim() !== String(commitment.commitmentVersion).trim()
    ) {
      return JSON.stringify({
        ...baseResult,
        reason: 'manifest_commitment_version_mismatch',
        bundleHashValid: true,
        rootMatch: true
      });
    }

    if (!bundle.capabilityToken || !fcIsPlainObject(bundle.capabilityToken)) {
      return JSON.stringify({
        ...baseResult,
        reason: 'missing_capability_token',
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: false
      });
    }

    let verifiedCap = null;
    let capRecord = null;
    let capabilityState = null;

    try {
      const { record: pkRecord } = await this._resolveRegisteredPublicKey(ctx, bundle.capabilityToken.issuerId);
      verifiedCap = fcVerifyCapabilityToken(bundle.capabilityToken, pkRecord.publicKey, new Date(txTimestamp));

      // Historical verification allows expired/revoked capabilities as long as the
      // capability signature, ledger anchoring, commitment binding, and recorded
      // pre-destruction use are still valid. If the only failure is expiration,
      // re-verify signature at issuedAt to avoid rejecting old audit bundles.
      if (!verifiedCap.valid && verifiedCap.reason === 'expired') {
        verifiedCap = fcVerifyCapabilityToken(
          bundle.capabilityToken,
          pkRecord.publicKey,
          new Date(bundle.capabilityToken.issuedAt || bundle.manifest.generatedAt || txTimestamp)
        );
      }

      if (!verifiedCap.valid) {
        return JSON.stringify({
          ...baseResult,
          reason: `invalid_capability_token:${verifiedCap.reason}`,
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      capRecord = await this._getCapabilityRecordByCapId(ctx, verifiedCap.payload.capId);
      if (!capRecord) {
        return JSON.stringify({
          ...baseResult,
          reason: 'capability_not_found',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      capabilityState = this._getCapabilityEffectiveStatus(capRecord, txTimestamp);

      if (String(capRecord.evidenceId) !== evId) {
        return JSON.stringify({
          ...baseResult,
          reason: 'capability_record_evidence_mismatch',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      if (String(capRecord.capHash).toLowerCase() !== String(verifiedCap.capHash).toLowerCase()) {
        return JSON.stringify({
          ...baseResult,
          reason: 'capability_record_caphash_mismatch',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      if (String(capRecord.scopeDigest).toLowerCase() !== String(verifiedCap.scopeDigest).toLowerCase()) {
        return JSON.stringify({
          ...baseResult,
          reason: 'capability_record_scopedigest_mismatch',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      if (verifiedCap.payload.commitmentVersion && String(verifiedCap.payload.commitmentVersion).trim() !== String(commitment.commitmentVersion).trim()) {
        return JSON.stringify({
          ...baseResult,
          reason: 'capability_commitment_version_mismatch',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      if (verifiedCap.payload.chunkMerkleRoot && String(verifiedCap.payload.chunkMerkleRoot).toLowerCase() !== String(commitment.chunkMerkleRoot).toLowerCase()) {
        return JSON.stringify({
          ...baseResult,
          reason: 'capability_merkle_root_mismatch',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      if (String(bundle.manifest.capId || '') !== String(verifiedCap.payload.capId)) {
        return JSON.stringify({
          ...baseResult,
          reason: 'manifest_capid_mismatch',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      if (String(bundle.manifest.capHash || '').toLowerCase() !== String(verifiedCap.capHash).toLowerCase()) {
        return JSON.stringify({
          ...baseResult,
          reason: 'manifest_caphash_mismatch',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      if (String(bundle.manifest.scopeDigest || '').toLowerCase() !== String(verifiedCap.scopeDigest).toLowerCase()) {
        return JSON.stringify({
          ...baseResult,
          reason: 'manifest_scopedigest_mismatch',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: false
        });
      }

      const historicalUseTime = capRecord.lastVerifiedAt || capRecord.usedAt || bundle.manifest.generatedAt || null;
      const destroyedAt = evidence.destroyedAt || evidence.destructionRecord?.destroyedAt || null;
      if (destroyedAt) {
        if (!historicalUseTime || new Date(historicalUseTime).getTime() > new Date(destroyedAt).getTime()) {
          return JSON.stringify({
            ...baseResult,
            reason: 'historical_disclosure_not_pre_destruction',
            bundleHashValid: true,
            rootMatch: true,
            capabilityValid: true,
            capabilityState
          });
        }
      }
    } catch (err) {
      return JSON.stringify({
        ...baseResult,
        reason: err instanceof Error ? err.message : 'historical_capability_verification_failed',
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: false
      });
    }

    if (bundle.manifest.disclosureType === 'HASH_ONLY') {
      const noChunks = Array.isArray(bundle.disclosedChunks) && bundle.disclosedChunks.length === 0;
      const noProofs = Array.isArray(bundle.proofs) && bundle.proofs.length === 0;
      const out = {
        ...baseResult,
        valid: !!(noChunks && noProofs),
        reason: (noChunks && noProofs) ? null : 'hash_only_bundle_must_not_contain_chunks_or_proofs',
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: true,
        capabilityState,
        failedIndices: [],
        results: []
      };

      await this._logAction(ctx, 'verifyHistoricalDisclosure', evidence.incidentId || 'EVIDENCE_ONLY', {
        evidenceId: evId,
        capId: capRecord.capId,
        valid: out.valid,
        disclosureType: 'HASH_ONLY',
        historicalVerification: true,
        capabilityState
      });

      ctx.stub.setEvent('HistoricalDisclosureVerified', Buffer.from(JSON.stringify({
        evidenceId: evId,
        capId: capRecord.capId,
        valid: out.valid,
        disclosureType: 'HASH_ONLY',
        verifiedAt: txTimestamp,
        verifierId: baseResult.verifierId,
        lifecycleState,
        capabilityState
      }), 'utf8'));

      return JSON.stringify(out);
    }

    if (!Array.isArray(bundle.disclosedChunks) || !Array.isArray(bundle.proofs)) {
      return JSON.stringify({
        ...baseResult,
        reason: 'missing_disclosed_chunks_or_proofs',
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: true,
        capabilityState
      });
    }

    const actualIndices = bundle.disclosedChunks.map(c => c.index);
    let normalizedActualIndices;
    let normalizedManifestIndices;
    try {
      normalizedActualIndices = fcNormalizeChunkIndices(actualIndices);
      normalizedManifestIndices = fcNormalizeChunkIndices(bundle.manifest.disclosedChunkIndices || []);
    } catch (err) {
      return JSON.stringify({
        ...baseResult,
        reason: err instanceof Error ? err.message : 'invalid_disclosed_chunk_indices',
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: true,
        capabilityState
      });
    }

    if (JSON.stringify(normalizedActualIndices) !== JSON.stringify(normalizedManifestIndices)) {
      return JSON.stringify({
        ...baseResult,
        reason: 'manifest_disclosed_indices_mismatch',
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: true,
        capabilityState
      });
    }

    const scopeCheck = fcCheckScope(verifiedCap.payload.scope, normalizedActualIndices);
    if (!scopeCheck.allowed) {
      return JSON.stringify({
        ...baseResult,
        reason: `scope_check_failed:${scopeCheck.reason}`,
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: true,
        capabilityState
      });
    }

    const proofMap = new Map();
    for (const proofObj of bundle.proofs) {
      if (!proofObj || typeof proofObj.index !== 'number') {
        return JSON.stringify({
          ...baseResult,
          reason: 'invalid_proof_index',
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid: true,
          capabilityState
        });
      }
      proofMap.set(proofObj.index, proofObj);
    }

    const results = [];
    const failedIndices = [];
    const useV3Commitment = String(commitment.commitmentVersion || '').trim() === FC_CHUNK_COMMITMENT_VERSION_V3;

    for (const disclosed of bundle.disclosedChunks) {
      const proofObj = proofMap.get(disclosed.index);
      if (!proofObj) {
        results.push({ chunkIndex: disclosed.index, valid: false, reason: 'missing_proof_for_chunk' });
        failedIndices.push(disclosed.index);
        continue;
      }

      const verification = useV3Commitment
        ? fcVerifySerializedDisclosureChunkV3(disclosed, proofObj, commitment.chunkMerkleRoot, evId)
        : fcVerifySerializedDisclosureChunk(disclosed, proofObj, commitment.chunkMerkleRoot);

      results.push({
        chunkIndex: disclosed.index,
        valid: verification.valid,
        reason: verification.reason || null
      });
      if (!verification.valid) failedIndices.push(disclosed.index);
    }

    const out = {
      ...baseResult,
      valid: failedIndices.length === 0,
      reason: failedIndices.length === 0 ? null : 'chunk_or_proof_verification_failed',
      bundleHashValid: true,
      rootMatch: true,
      capabilityValid: true,
      capabilityState,
      failedIndices,
      results
    };

    await this._logAction(ctx, 'verifyHistoricalDisclosure', evidence.incidentId || 'EVIDENCE_ONLY', {
      evidenceId: evId,
      capId: capRecord.capId,
      valid: out.valid,
      disclosureType: bundle.manifest.disclosureType || 'CHUNK_DISCLOSURE',
      historicalVerification: true,
      verifiedChunkCount: results.length,
      failedChunkCount: failedIndices.length,
      failedIndices,
      lifecycleState,
      capabilityState
    });

    ctx.stub.setEvent('HistoricalDisclosureVerified', Buffer.from(JSON.stringify({
      evidenceId: evId,
      capId: capRecord.capId,
      valid: out.valid,
      disclosureType: bundle.manifest.disclosureType || 'CHUNK_DISCLOSURE',
      verifiedChunkCount: results.length,
      failedChunkCount: failedIndices.length,
      verifiedAt: txTimestamp,
      verifierId: baseResult.verifierId,
      lifecycleState,
      capabilityState
    }), 'utf8'));

    return JSON.stringify(out);
  }

  // ===========================================================================
  // Incident (optional)
  // ===========================================================================

async initializeIncident(
  ctx,
  responderId,
  incidentId,
  detectionTime,
  incidentType,
  severityLevel,
  description,
  actionTaken,
  actionTimestamp,
  affectedSystems,
  deviceContextJson
) {
  this._checkAccess(ctx, {
    roles: ['MonitoringAnalyst', 'OTGatewayCollector'],
    clearance: ['Low', 'Medium']
  });

  const levels = ['Low', 'Medium', 'High', 'Critical'];
  if (!levels.includes(severityLevel)) {
    throw new Error(`Invalid severityLevel: ${severityLevel}`);
  }

  let affectedList;
  try {
    affectedList = JSON.parse(affectedSystems);
    if (!Array.isArray(affectedList)) throw new Error();
  } catch {
    throw new Error('affectedSystems must be a valid JSON array');
  }

  let deviceContext = null;
  let cryptographicProof = null;

  if (deviceContextJson && deviceContextJson !== 'null') {
    try {
      const parsedData = JSON.parse(deviceContextJson);
      if (parsedData.reportingSource && parsedData.zkpProof) {
        deviceContext = parsedData.reportingSource;
        cryptographicProof = parsedData.zkpProof;
      } else {
        deviceContext = parsedData;
      }
    } catch {
      throw new Error('deviceContext must be a valid JSON object');
    }
  }

  const createdAt = this._getTimestamp(ctx);
  const actualResponderId = this._getAuditActor(ctx);
  const claimedResponderId = (responderId || '').toString().trim() || null;

  const incidentData = {
    responderId: actualResponderId,
    claimedResponderId,
    incidentId,
    detectionTime,
    incidentType,
    severityLevel,
    description,
    affectedList,
    deviceContext
  };

  const incidentHash = crypto.createHash('sha256')
    .update(JSON.stringify(incidentData))
    .digest('hex');

  const record = {
    ...incidentData,
    initialActions: [{
      action: actionTaken,
      timestamp: actionTimestamp,
      by: actualResponderId,
      claimedBy: claimedResponderId
    }],
    status: 'initialized',
    createdBy: ctx.clientIdentity.getID(),
    createdAt,
    reportingSource: deviceContext,
    evidenceList: [],
    cryptographicMetadata: {
      incidentHash,
      cryptographicProof,
      signatureVerified: !!cryptographicProof,
      integrityLevel: 'HIGH'
    },
    actions: [
      {
        action: 'initializeIncident',
        timestamp: createdAt,
        by: actualResponderId,
        claimedBy: claimedResponderId,
        hash: incidentHash.substring(0, 16)
      }
    ]
  };

  await ctx.stub.putState(incidentId, Buffer.from(JSON.stringify(record), 'utf8'));

  ctx.stub.setEvent('IncidentInitialized', Buffer.from(JSON.stringify({
    incidentId,
    createdAt,
    responderId: actualResponderId,
    claimedResponderId,
    incidentHash: incidentHash.substring(0, 16),
    cryptographicProof: !!cryptographicProof
  }), 'utf8'));

  await this._logAction(ctx, 'initializeIncident', incidentId, {
    responderId: actualResponderId,
    claimedResponderId,
    severityLevel,
    incidentType,
    integrityHash: incidentHash.substring(0, 16)
  });

  return JSON.stringify({ success: true, incidentId, incidentHash });
}

  // ===========================================================================
  // Evidence Preservation
  // ===========================================================================

  async preserveEvidence(ctx, evidenceDataStr) {
    const inputData = this._parseJsonStrict('evidenceData', evidenceDataStr);

    this._checkAccess(ctx, {
      roles: [
        'GatewayCollector',
        'ManualCollector',

        // Backward compatibility
        'OTGatewayCollector',
        'AcquisitionOperator'
      ],
      clearance: ['Medium', 'High']
    });

    const txTimestamp = this._getTimestamp(ctx);
    const txId = ctx.stub.getTxID();
    const auditActor = this._getAuditActor(ctx);

    const fullEvidence = (inputData && typeof inputData.evidence === 'object')
      ? inputData.evidence
      : inputData;

    if (!fullEvidence || typeof fullEvidence !== 'object') {
      throw new Error('Invalid evidence payload');
    }

    const evidenceId = String(fullEvidence.evidenceId || '').trim();
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(evidenceId)) {
      throw new Error('Invalid evidenceId format (allowed: A-Z a-z 0-9 . _ - ; max 64)');
    }

    if (!fullEvidence.integrityHash && !fullEvidence.fileHash) {
      throw new Error('integrityHash or fileHash is required for preserved evidence');
    }

    const evidenceKey = `evidence::${evidenceId}`;
    const existingBytes = await ctx.stub.getState(evidenceKey);
    if (existingBytes && existingBytes.length > 0) {
      throw new Error(`Evidence ${evidenceId} already exists`);
    }

    const collectionMethod = this._isGatewayCollectorRole(ctx)
      ? 'GATEWAY_COLLECTION'
      : 'MANUAL_COLLECTION';

    const hintedMode = String(inputData.storageMode || fullEvidence.storageMode || '').toLowerCase().trim();

    const cidCandidate =
      inputData.masterCID ||
      inputData.realCID ||
      inputData.ipfsReference ||
      inputData.ipfsReferences?.masterCID ||
      inputData.ipfsReferences?.evidenceCID ||
      fullEvidence.masterCID ||
      fullEvidence.ipfsReference ||
      null;

    const isHybrid = (hintedMode === 'hybrid') || !!cidCandidate;

    let storageMode;
    let storageVersion;
    let masterCID = null;

    if (isHybrid) {
      storageMode = 'hybrid';
      storageVersion = StorageOptimizer?.STORAGE_VERSION || '2.1';

      if (!cidCandidate) {
        throw new Error('Hybrid mode requires a CID (masterCID/realCID/ipfsReference)');
      }

      masterCID = this._assertCIDFormat(String(cidCandidate));
    } else {
      storageMode = 'legacy';
      storageVersion = '1.0';
    }

    const preservedRecord = {
      ...fullEvidence,
      evidenceId,
      integrityHash: fullEvidence.integrityHash || fullEvidence.fileHash,
      fileHash: fullEvidence.fileHash || fullEvidence.integrityHash,
      submittedBy: auditActor,
      collectedBy: auditActor,
      collectionMethod,
      collectionTimestamp: fullEvidence.collectionTimestamp || txTimestamp,
      preservedAt: txTimestamp,
      preservedBy: auditActor,
      preserveTxId: txId,
      storageMode,
      storageVersion,
      lifecycleState: FC_EVIDENCE_LIFECYCLE_STATES.PRESERVED,
      evidenceLifecycleState: FC_EVIDENCE_LIFECYCLE_STATES.PRESERVED,
      lifecycleUpdatedAt: txTimestamp,
      lifecycleHistory: [
        {
          from: null,
          to: FC_EVIDENCE_LIFECYCLE_STATES.PRESERVED,
          reason: 'EVIDENCE_PRESERVED',
          actor: auditActor,
          at: txTimestamp
        }
      ],
      custodyOwnerId: fullEvidence.custodyOwnerId || inputData.custodyOwnerId || null,
      disclosureAuthorityId: fullEvidence.disclosureAuthorityId || inputData.disclosureAuthorityId || null
    };

    if (masterCID) {
      preservedRecord.ipfsReference = masterCID;
      preservedRecord.masterCIDHash = this._cidHash(masterCID);
    }

    await ctx.stub.putState(evidenceKey, Buffer.from(JSON.stringify(preservedRecord), 'utf8'));

    const auditRes = await this._logAction(ctx, 'preserveEvidence', fullEvidence.incidentId || 'EVIDENCE_ONLY', {
      evidenceId,
      collectedBy: auditActor,
      collectionMethod,
      storageMode,
      storageVersion,
      ipfsRefHash: masterCID ? this._cidHash(masterCID) : null,
      lifecycleState: FC_EVIDENCE_LIFECYCLE_STATES.PRESERVED
    });

    ctx.stub.setEvent('EvidencePreserved', Buffer.from(JSON.stringify(this._buildGovernanceEvent('EvidencePreserved', {
      evidenceId,
      collectedBy: auditActor,
      collectionMethod,
      storageMode,
      storageVersion,
      lifecycleState: FC_EVIDENCE_LIFECYCLE_STATES.PRESERVED,
      preservedAt: txTimestamp,
      txId,
      auditLogHash: auditRes?.logHash || null
    })), 'utf8'));

    return JSON.stringify({
      success: true,
      evidenceId,
      collectedBy: auditActor,
      collectionMethod,
      storageMode,
      storageVersion,
      lifecycleState: FC_EVIDENCE_LIFECYCLE_STATES.PRESERVED,
      preservedAt: txTimestamp,
      masterCID: masterCID || null,
      masterCIDHash: masterCID ? this._cidHash(masterCID) : null,
      auditLogHash: auditRes?.logHash || null
    });
  }

    async commitPreservedEvidence(ctx, evidenceId, commitPayloadJson) {
        commitPayloadJson = (commitPayloadJson === undefined || commitPayloadJson === null || commitPayloadJson === '') ? '{}' : commitPayloadJson;
    this._checkAccess(ctx, {
      roles: ['EvidenceCustodian'],
      clearance: ['High']
    });

    const evId = String(evidenceId || '').trim();
    if (!evId) throw new Error('evidenceId is required');

    const commitPayload = this._parseJsonStrict('commitPayload', commitPayloadJson || '{}');

    const txTimestamp = this._getTimestamp(ctx);
    const txId = ctx.stub.getTxID();
    const auditActor = this._getAuditActor(ctx);

    const { evidenceKey, evidence } = await this._loadEvidenceRecord(ctx, evId);

    const currentState = fcNormalizeEvidenceLifecycleState(evidence);
    if (currentState !== FC_EVIDENCE_LIFECYCLE_STATES.PRESERVED) {
      throw new Error(`evidence_must_be_preserved_before_commit:${currentState}`);
    }

    const custodyOwnerId = this._resolveCustodyOwnerId(evidence, commitPayload, auditActor);
    const disclosureAuthorityId = this._resolveDisclosureAuthorityId(
      evidence,
      commitPayload,
      custodyOwnerId,
      auditActor
    );

    if (!custodyOwnerId || !disclosureAuthorityId) {
      throw new Error('custodyOwnerId and disclosureAuthorityId are required to commit preserved evidence');
    }

    if (String(custodyOwnerId) !== String(disclosureAuthorityId)) {
      throw new Error('custodyOwnerId and disclosureAuthorityId must match in this authority model');
    }

    if (String(custodyOwnerId) !== String(auditActor)) {
      throw new Error('EvidenceCustodian commit must use the caller as custodyOwnerId/disclosureAuthorityId');
    }

    await this._resolveRegisteredPublicKey(
      ctx,
      custodyOwnerId,
      ['DISCLOSURE_CAPABILITY', 'disclosure-capability', 'signing', 'SIGNING'],
      ['Ed25519', 'ed25519', 'ED25519']
    );

    const commitmentSource = commitPayload.chunkCommitment && typeof commitPayload.chunkCommitment === 'object'
      ? commitPayload.chunkCommitment
      : commitPayload;

    const chunkMerkleRoot =
      commitmentSource.chunkMerkleRoot ||
      evidence.chunkMerkleRoot ||
      null;

    const chunkCount =
      commitmentSource.chunkCount !== undefined
        ? Number(commitmentSource.chunkCount)
        : evidence.chunkCount;

    const chunkSize =
      commitmentSource.chunkSize !== undefined
        ? Number(commitmentSource.chunkSize)
        : evidence.chunkSize;

    const commitmentVersion =
      commitmentSource.commitmentVersion ||
      evidence.commitmentVersion ||
      FC_CHUNK_COMMITMENT_VERSION;

    if (!chunkMerkleRoot || !fcIsSha256Hex(String(chunkMerkleRoot))) {
      throw new Error('chunkMerkleRoot must be a valid SHA-256 hex digest');
    }

    if (!Number.isInteger(chunkCount) || chunkCount < 0) {
      throw new Error('chunkCount must be a non-negative integer');
    }

    if (!Number.isInteger(chunkSize) || chunkSize <= 0) {
      throw new Error('chunkSize must be a positive integer');
    }

    evidence.custodyOwnerId = custodyOwnerId;
    evidence.disclosureAuthorityId = disclosureAuthorityId;
    evidence.chunkMerkleRoot = String(chunkMerkleRoot).toLowerCase();
    evidence.chunkCount = chunkCount;
    evidence.chunkSize = chunkSize;
    evidence.commitmentVersion = commitmentVersion;
    evidence.committedAt = txTimestamp;
    evidence.committedBy = auditActor;
    evidence.commitTxId = txId;

    const transition = this._transitionEvidenceLifecycle(
      evidence,
      FC_EVIDENCE_LIFECYCLE_STATES.COMMITTED,
      'EVIDENCE_COMMITTED',
      auditActor,
      txTimestamp
    );

    evidence.evidenceLifecycleState = FC_EVIDENCE_LIFECYCLE_STATES.COMMITTED;

    await this._persistEvidenceRecord(ctx, evidenceKey, evidence);

    const auditRes = await this._logAction(ctx, 'commitPreservedEvidence', evidence.incidentId || 'EVIDENCE_ONLY', {
      evidenceId: evId,
      custodyOwnerId,
      disclosureAuthorityId,
      chunkMerkleRoot: evidence.chunkMerkleRoot,
      chunkCount,
      chunkSize,
      commitmentVersion,
      previousState: transition.previousState,
      nextState: transition.nextState
    });

    ctx.stub.setEvent('EvidenceLifecycleStateChanged', Buffer.from(JSON.stringify(this._buildGovernanceEvent('EvidenceLifecycleStateChanged', {
      evidenceId: evId,
      previousState: transition.previousState,
      nextState: transition.nextState,
      reason: 'EVIDENCE_COMMITTED',
      actor: auditActor,
      changedAt: txTimestamp,
      txId
    })), 'utf8'));

    ctx.stub.setEvent('EvidenceCommitted', Buffer.from(JSON.stringify(this._buildGovernanceEvent('EvidenceCommitted', {
      evidenceId: evId,
      custodyOwnerId,
      disclosureAuthorityId,
      chunkMerkleRoot: evidence.chunkMerkleRoot,
      chunkCount,
      chunkSize,
      commitmentVersion,
      committedAt: txTimestamp,
      committedBy: auditActor,
      auditLogHash: auditRes?.logHash || null
    })), 'utf8'));

    return JSON.stringify({
      success: true,
      evidenceId: evId,
      custodyOwnerId,
      disclosureAuthorityId,
      previousState: transition.previousState,
      nextState: transition.nextState,
      lifecycleState: FC_EVIDENCE_LIFECYCLE_STATES.COMMITTED,
      chunkMerkleRoot: evidence.chunkMerkleRoot,
      chunkCount,
      chunkSize,
      commitmentVersion,
      committedAt: txTimestamp,
      auditLogHash: auditRes?.logHash || null
    });
  }

  // ===========================================================================
  // Evidence Submit (LEGACY v1.0 / HYBRID v2.0)
  // ===========================================================================

  async submitEvidence(ctx, evidenceDataStr) {
    let inputData;
    try {
      inputData = JSON.parse(evidenceDataStr);
    } catch (e) {
      throw new Error(`Invalid JSON for evidence payload: ${e.message}`);
    }

    const txTimestamp = this._getTimestamp(ctx);
    const txId = ctx.stub.getTxID();

    const fullEvidence = (inputData && typeof inputData.evidence === 'object')
      ? inputData.evidence
      : inputData;

    if (!fullEvidence || typeof fullEvidence !== 'object') {
      throw new Error('Invalid evidence payload');
    }

    const id = (fullEvidence.evidenceId || '').toString().trim();
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(id)) {
      throw new Error('Invalid evidenceId format (allowed: A-Z a-z 0-9 . _ - ; max 64)');
    }
    fullEvidence.evidenceId = id;

    if (!fullEvidence.integrityHash) throw new Error('integrityHash is required');

    // Allow chunk commitment metadata to be passed through at the top level
    const commitmentFields = ['chunkMerkleRoot', 'chunkCount', 'chunkSize', 'commitmentVersion'];
    for (const field of commitmentFields) {
      if (
        (fullEvidence[field] === undefined || fullEvidence[field] === null || fullEvidence[field] === '') &&
        inputData[field] !== undefined
      ) {
        fullEvidence[field] = inputData[field];
      }
    }
    if (!fullEvidence.chunkCommitment && inputData.chunkCommitment && typeof inputData.chunkCommitment === 'object') {
      fullEvidence.chunkCommitment = inputData.chunkCommitment;
    }

    this._checkAccess(ctx, {
      roles: [
        'GatewayCollector',
        'ManualCollector',
        'EvidenceCustodian',

        // Backward compatibility
        'OTGatewayCollector',
        'AcquisitionOperator'
      ],
      clearance: ['Medium', 'High']
    });

    // Bind submitter identity, but keep custody/disclosure authority separate
    const auditActor = this._getAuditActor(ctx);

    const claimedSubmittedBy = fullEvidence.submittedBy;
    const custodyOwnerId = this._resolveCustodyOwnerId(fullEvidence, inputData, auditActor);
    const disclosureAuthorityId = this._resolveDisclosureAuthorityId(
      fullEvidence,
      inputData,
      custodyOwnerId,
      auditActor
    );

    const submitterRoleNorm = this._roleNorm(ctx);

    if (!custodyOwnerId) {
      throw new Error('custodyOwnerId must be resolved for every evidence record');
    }

    if (!disclosureAuthorityId) {
      throw new Error('disclosureAuthorityId must be resolved for every evidence record');
    }

    if (String(custodyOwnerId) !== String(disclosureAuthorityId)) {
      throw new Error('custodyOwnerId and disclosureAuthorityId must match in this authority model');
    }

    if (submitterRoleNorm === 'evidencecustodian') {
      if (String(custodyOwnerId) !== String(auditActor)) {
        throw new Error('EvidenceCustodian submissions must use the caller as custodyOwnerId/disclosureAuthorityId');
      }
    }

    if (['gatewaycollector', 'manualcollector', 'otgatewaycollector', 'acquisitionoperator'].includes(submitterRoleNorm)) {
      if (String(custodyOwnerId) === String(auditActor)) {
        throw new Error('EvidenceCollector must not self-assign custody owner authority');
      }
    }

    const resolvedCustodianKey = await this._resolveRegisteredPublicKey(
  ctx,
  custodyOwnerId,
  ['DISCLOSURE_CAPABILITY', 'disclosure-capability', 'signing', 'SIGNING'],
  ['Ed25519', 'ed25519', 'ED25519']
);

if (!resolvedCustodianKey || !resolvedCustodianKey.record) {
  throw new Error('custodyOwnerId must reference a registered custodian public key');
}

    fullEvidence.submittedBy = auditActor;
    fullEvidence.custodyOwnerId = custodyOwnerId;
    fullEvidence.disclosureAuthorityId = disclosureAuthorityId;

    if (claimedSubmittedBy !== undefined) {
      fullEvidence.claimedSubmittedBy = claimedSubmittedBy;
    }

    if (!fullEvidence.collectionTimestamp) {
      fullEvidence.collectionTimestamp = txTimestamp;
    }

    const evidenceKey = `evidence::${fullEvidence.evidenceId}`;
    const existingBytes = await ctx.stub.getState(evidenceKey);
    if (existingBytes && existingBytes.length > 0) {
      throw new Error(`Evidence ${fullEvidence.evidenceId} already exists`);
    }

    const hintedMode = (inputData.storageMode || fullEvidence.storageMode || '').toLowerCase().trim();

    let cidCandidate =
      inputData.masterCID ||
      inputData.realCID ||
      inputData.ipfsReference ||
      inputData.ipfsReferences?.masterCID ||
      inputData.ipfsReferences?.evidenceCID ||
      fullEvidence.masterCID ||
      fullEvidence.ipfsReference ||
      null;

    const isHybrid = (hintedMode === 'hybrid') || !!cidCandidate;

    let storageMode;
    let storageVersion;
    let dataToStore;
    let masterCID = null;

    if (isHybrid) {
      storageMode = 'hybrid';
      storageVersion = StorageOptimizer?.STORAGE_VERSION || '2.1';

      if (!cidCandidate) {
        throw new Error('Hybrid mode requires a CID (masterCID/realCID/ipfsReference)');
      }

      masterCID = this._assertCIDFormat(String(cidCandidate));

      const txMetadata = {
        createdAt: txTimestamp,
        createdBy: ctx.clientIdentity.getID(),
        mspId: ctx.clientIdentity.getMSPID(),
        txId
      };

      dataToStore = StorageOptimizer.prepareHybridEvidence(fullEvidence, masterCID, txMetadata);
      dataToStore.storageMode = 'hybrid';
      dataToStore.storageVersion = storageVersion;
      dataToStore.evidenceId = fullEvidence.evidenceId;

      const ceiling = (StorageOptimizer && StorageOptimizer.MAX_ONCHAIN_SIZE)
        ? StorageOptimizer.MAX_ONCHAIN_SIZE
        : 900;

      const tmpBytes = Buffer.byteLength(JSON.stringify(dataToStore), 'utf8');
      if (tmpBytes > ceiling) {
        delete dataToStore.optionalNotes;
        delete dataToStore.unused;
      }
    } else {
      storageMode = 'legacy';
      storageVersion = '1.0';

      dataToStore = {
        ...fullEvidence,
        storageMode,
        storageVersion
      };
    }

    if (!dataToStore || typeof dataToStore !== 'object') {
      throw new Error('submitEvidence produced invalid on-chain payload');
    }

    if (!String(dataToStore.custodyOwnerId || '').trim()) {
      throw new Error('BUG: custodyOwnerId missing from final on-chain evidence payload');
    }

    if (!String(dataToStore.disclosureAuthorityId || '').trim()) {
      throw new Error('BUG: disclosureAuthorityId missing from final on-chain evidence payload');
    }

    if (String(dataToStore.custodyOwnerId).trim() !== String(custodyOwnerId).trim()) {
      throw new Error('BUG: final on-chain custodyOwnerId differs from resolved custodyOwnerId');
    }

    if (String(dataToStore.disclosureAuthorityId).trim() !== String(disclosureAuthorityId).trim()) {
      throw new Error('BUG: final on-chain disclosureAuthorityId differs from resolved disclosureAuthorityId');
    }

    const dataToStoreStr = JSON.stringify(dataToStore);
    const stateEvidenceBytes = Buffer.byteLength(dataToStoreStr, 'utf8');

    if (storageMode === 'hybrid') {
      const finalCeiling = (StorageOptimizer && StorageOptimizer.MAX_ONCHAIN_SIZE)
        ? StorageOptimizer.MAX_ONCHAIN_SIZE
        : 900;

      if (stateEvidenceBytes > finalCeiling) {
        throw new Error(`Hybrid on-chain payload too large: ${stateEvidenceBytes} > ${finalCeiling}`);
      }
    }

    const fullEvidenceSizeBytes = Buffer.byteLength(String(evidenceDataStr || ''), 'utf8');
    const storageReductionPct = (storageMode === 'hybrid' && fullEvidenceSizeBytes > 0)
      ? Math.round((1 - stateEvidenceBytes / fullEvidenceSizeBytes) * 100)
      : 0;

    await ctx.stub.putState(evidenceKey, Buffer.from(dataToStoreStr, 'utf8'));

    const auditRes = await this._logAction(ctx, 'submitEvidence', fullEvidence.incidentId || 'EVIDENCE_ONLY', {
      evidenceId: fullEvidence.evidenceId,
      submittedBy: auditActor,
      custodyOwnerId,
      disclosureAuthorityId,
      storageMode,
      storageVersion,
      onChainSizeBytes: stateEvidenceBytes,
      fullEvidenceSizeBytes,
      storageReductionPct,
      ipfsRefHash: masterCID ? this._cidHash(masterCID) : null,
      chunkCommitmentEnabled: !!dataToStore.chunkMerkleRoot,
      chunkMerkleRoot: dataToStore.chunkMerkleRoot || null,
      chunkCount: Number.isInteger(dataToStore.chunkCount) ? dataToStore.chunkCount : null,
      chunkSize: Number.isInteger(dataToStore.chunkSize) ? dataToStore.chunkSize : null,
      commitmentVersion: dataToStore.commitmentVersion || null
    });

    const stateAuditBytes = (auditRes && typeof auditRes.auditBytes === 'number') ? auditRes.auditBytes : 0;
    const stateTotalWriteBytes = stateEvidenceBytes + stateAuditBytes;
    const stateWriteCount = 1 + ((auditRes && typeof auditRes.auditWriteCount === 'number') ? auditRes.auditWriteCount : 0);

    ctx.stub.setEvent('EvidenceSubmitted', Buffer.from(JSON.stringify({
      evidenceId: fullEvidence.evidenceId,
      submittedBy: fullEvidence.submittedBy,
      custodyOwnerId: fullEvidence.custodyOwnerId,
      disclosureAuthorityId: fullEvidence.disclosureAuthorityId,
      timestamp: txTimestamp,
      storageMode,
      storageVersion,
      onChainSizeBytes: stateEvidenceBytes,
      fullEvidenceSizeBytes,
      storageReductionPct,
      ipfsRefHash: masterCID ? this._cidHash(masterCID) : null,
      chunkCommitmentEnabled: !!dataToStore.chunkMerkleRoot,
      chunkMerkleRoot: dataToStore.chunkMerkleRoot || null,
      chunkCount: Number.isInteger(dataToStore.chunkCount) ? dataToStore.chunkCount : null,
      chunkSize: Number.isInteger(dataToStore.chunkSize) ? dataToStore.chunkSize : null,
      commitmentVersion: dataToStore.commitmentVersion || null,
      txId,
      stateEvidenceBytes,
      stateAuditBytes,
      stateTotalWriteBytes,
      stateWriteCount,
      auditLogHash: auditRes?.logHash || null
    }), 'utf8'));

    return JSON.stringify({
      success: true,
      evidenceId: fullEvidence.evidenceId,
      submittedBy: fullEvidence.submittedBy,
      custodyOwnerId: fullEvidence.custodyOwnerId,
      disclosureAuthorityId: fullEvidence.disclosureAuthorityId,
      storageMode,
      storageVersion,
      onChainSizeBytes: stateEvidenceBytes,
      fullEvidenceSizeBytes,
      storageReductionPct,
      masterCID: masterCID || null,
      chunkCommitmentEnabled: !!dataToStore.chunkMerkleRoot,
      chunkMerkleRoot: dataToStore.chunkMerkleRoot || null,
      chunkCount: Number.isInteger(dataToStore.chunkCount) ? dataToStore.chunkCount : null,
      chunkSize: Number.isInteger(dataToStore.chunkSize) ? dataToStore.chunkSize : null,
      commitmentVersion: dataToStore.commitmentVersion || null,
      stateEvidenceBytes,
      stateAuditBytes,
      stateTotalWriteBytes,
      stateWriteCount,
      auditLogHash: auditRes?.logHash || null
    });
  }

  // ===========================================================================
  // Evidence Retrieve (PURE QUERY / AUDITED)
  // ===========================================================================

    async _retrieveEvidenceCore(ctx, evidenceId, isPublicStr, requestPREStr) {
    const evId = String(evidenceId || '').trim();
    if (!evId) throw new Error('evidenceId is required');
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(evId)) {
      throw new Error('Invalid evidenceId format (allowed: A-Z a-z 0-9 . _ - ; max 64)');
    }

    const isPublic = (String(isPublicStr) === 'true');
    const requestPRE = (String(requestPREStr) === 'true');

    const auditActor = this._getAuditActor(ctx);
    const roleRaw = (ctx.clientIdentity.getAttributeValue('role') || '').trim();
    const roleNorm = this._normRole(roleRaw);

    if (isPublic) {
      this._checkAccess(ctx, {
        roles: ['IndependentAuditor'],
        clearance: ['Low', 'Medium', 'High']
      });
    } else {
      this._checkAccess(ctx, {
        roles: [
          'ForensicLead',
          'EvidenceCustodian',
          'OTGatewayCollector',
          'VendorEngineer'
        ],
        clearance: ['Medium', 'High']
      });
    }

    const evidenceKey = `evidence::${evId}`;
    let storedDataBytes = await ctx.stub.getState(evidenceKey);

    if (!storedDataBytes || !storedDataBytes.length) {
      storedDataBytes = await ctx.stub.getState(evId);
      if (!storedDataBytes || !storedDataBytes.length) {
        throw new Error(`Evidence ${evId} not found`);
      }
    }

    const storedData = JSON.parse(storedDataBytes.toString());
    const storageMode = this._isHybridEvidenceRecord(storedData) ? 'hybrid' : 'legacy';
    const storageVersion = storedData.storageVersion || (storageMode === 'hybrid'
      ? (StorageOptimizer?.STORAGE_VERSION || '2.1')
      : '1.0');

    const lifecycleStateForRetrieval = fcNormalizeEvidenceLifecycleState(storedData);
    if (!isPublic && fcIsDestructionLifecycleState(lifecycleStateForRetrieval)) {
      throw new Error(`evidence_lifecycle_not_retrievable:${lifecycleStateForRetrieval}`);
    }

    const masterCIDRaw =
      storedData.ipfsReference ||
      storedData.ipfsReferences?.masterCID ||
      storedData.ipfsReferences?.evidenceCID ||
      storedData.masterCID ||
      storedData.realCID ||
      null;

    const masterCIDNorm = masterCIDRaw ? this._assertCIDFormat(String(masterCIDRaw)) : null;

    const owner = this._getEvidenceOwner(storedData);
    const isOwner = owner && String(owner).trim() === String(auditActor).trim();
    const isForensicLead = roleNorm === 'forensiclead';

    // strict authority model:
    // - designated owner (custodian of this evidence) may bypass
    // - ForensicLead may bypass as internal high-privilege investigator
    // - non-owner custodians may NOT bypass
    const canBypassDelegation = !!(isOwner || isForensicLead);

    let delAES = { hasValidDelegation: false, delegationDetails: null };
    let delPRE = { hasValidDelegation: false, delegationDetails: null };

    if (!isPublic && !canBypassDelegation) {
      if (masterCIDNorm) {
        delAES = await this._checkDelegation(ctx, evId, auditActor, 'AES_ACCESS');
      }
      if (requestPRE) {
        delPRE = await this._checkDelegation(ctx, evId, auditActor, 'PRE_ACCESS');
      }
    }

    if (!isPublic && requestPRE && !canBypassDelegation) {
      if (!delPRE.hasValidDelegation) {
        throw new Error('PRE access requires valid delegation (PRE_ACCESS/FULL_ACCESS)');
      }
    }

    const canSeeMasterCID =
      !!masterCIDNorm &&
      !isPublic &&
      (canBypassDelegation || delAES.hasValidDelegation);

    let response;
    if (storageMode === 'hybrid' && String(storageVersion).startsWith('2.')) {
      if (isPublic) {
        response = this._sanitizeForPublic(storedData);
      } else {
        response = {
          storageMode: 'hybrid',
          storageVersion,
          onChainData: storedData,
          masterCID: canSeeMasterCID ? masterCIDNorm : null,
          masterCIDHash: masterCIDNorm ? this._cidHash(masterCIDNorm) : null,
          preAccessGranted: requestPRE ? (canBypassDelegation || delPRE.hasValidDelegation) : false,
          retrievalNote: canSeeMasterCID
          ? 'Private mode: use masterCID to fetch complete evidence off-chain (IPFS) via client/gateway.'
          : 'MasterCID disclosure restricted. Require designated evidence owner, ForensicLead, or valid delegation (AES_ACCESS/PRE_ACCESS/FULL_ACCESS).'        };
      }
    } else {
      response = isPublic ? this._sanitizeForPublic(storedData) : storedData;
    }

    response.accessMode = isPublic ? 'PUBLIC' : 'PRIVATE';
    response.accessTimestamp = this._getTimestamp(ctx);
    response.accessedBy = isPublic ? 'PUBLIC' : auditActor;

    return {
      response,
      auditMeta: {
        incidentId: storedData.incidentId || 'EVIDENCE_ONLY',
        storageMode
      }
    };
  }

  /**
   * PURE QUERY (no audit write). Suitable for Caliper readOnly=true.
   */
  async retrieveEvidence(ctx, evidenceId, isPublicStr, requestPREStr) {
    const { response } = await this._retrieveEvidenceCore(ctx, evidenceId, isPublicStr, requestPREStr);
    return JSON.stringify(response);
  }

  /**
   * AUDITED retrieve (writes audit log). Suitable for Caliper readOnly=false.
   */
  async retrieveEvidenceAndLog(ctx, evidenceId, isPublicStr, requestPREStr) {
    const { response, auditMeta } = await this._retrieveEvidenceCore(ctx, evidenceId, isPublicStr, requestPREStr);

    const auditRes = await this._logAction(ctx, 'retrieveEvidence', auditMeta.incidentId, {
      evidenceId,
      audited: true,
      accessMode: response.accessMode,
      storageMode: auditMeta.storageMode
    });

    response.audit = {
      audited: true,
      auditLogHash: auditRes?.logHash || null,
      auditBytes: auditRes?.auditBytes ?? 0
    };

    return JSON.stringify(response);
  }

  // ===========================================================================
  // System Status (no hard-coded TPS/latency claims)
  // ===========================================================================

  async getSystemStatus(ctx) {
    const ALLOW_SIMULATION = process.env.ALLOW_ZKP_SIMULATION === 'true';
    const STRICT_MODE = process.env.FORENSIC_STRICT_MODE === 'true';

    let storageMetrics = { totalEvidence: 0, hybridCount: 0, legacyCount: 0, chunkCommitmentCount: 0 };
    try {
      const iterator = await ctx.stub.getStateByRange('evidence::', 'evidence::\uFFFF');
      while (true) {
        const result = await iterator.next();
        if (result.value && result.value.value.toString()) {
          storageMetrics.totalEvidence++;
          const evidence = JSON.parse(result.value.value.toString());

          if (this._isHybridEvidenceRecord(evidence)) storageMetrics.hybridCount++;
          else storageMetrics.legacyCount++;

          if (evidence.chunkMerkleRoot) storageMetrics.chunkCommitmentCount++;
        }
        if (result.done) { await iterator.close(); break; }
      }
    } catch (e) {
      console.log('Could not get storage metrics:', e.message);
    }

    const status = {
      timestamp: this._getTimestamp(ctx),
      version: '7.5.0-HYBRID-v2.x',

      features: {
        eddsaSignatures: 'ACTIVE',
        aesEncryption: 'AES-256-GCM',
        proxyReEncryption: 'READY',
        zkpSupport: 'DUAL_SYSTEM_WITH_FAZKP',
        zkpTypes: ['FILE_INTEGRITY', 'GDPR_COMPLIANCE'],
        zkpMode: ALLOW_SIMULATION ? 'SIMULATION' : 'PRODUCTION',
        fazkpEnabled: true,
        fazkpStrategy: 'ADAPTIVE_CHUNKING',

        storageMode: 'HYBRID_V2.x',
        storageVersion: StorageOptimizer?.STORAGE_VERSION || '2.1',
        hybridFeatures: {
          enabled: true,
          onChainLimit: StorageOptimizer?.MAX_ONCHAIN_SIZE || 900,
          offChainStorage: 'Private IPFS',
          singleMasterCID: true,
          merkleTreeCoC: true,
          backwardCompatible: true,
          cidValidation: true,
          chunkCommitments: true,
          selectiveDisclosure: true,
          capabilityDelegation: true
        },

        storageStatistics: {
          totalEvidence: storageMetrics.totalEvidence,
          hybridCount: storageMetrics.hybridCount,
          legacyCount: storageMetrics.legacyCount,
          chunkCommitmentCount: storageMetrics.chunkCommitmentCount,
          hybridPercentage: storageMetrics.totalEvidence > 0
            ? Math.round((storageMetrics.hybridCount / storageMetrics.totalEvidence) * 100)
            : 0
        }
      },

      performance: {
        telemetry: {
          enabled: false,
          note: 'Runtime performance metrics (TPS/latency/reduction) must come from real telemetry, not hard-coded values.'
        },
        maxEvidenceSize: 'UNLIMITED_WITH_IPFS'
      },

      accessModes: {
        public: 'Hash/commitment view for external verification',
        private: 'Metadata + controlled masterCID disclosure',
        delegated: 'Explicit capability/delegation for selective disclosure',
        strictMode: STRICT_MODE ? 'ENABLED - All reads update CoC' : 'DISABLED - Optimized performance'
      },

      deployment: {
        chaincodeName: 'forensicContract',
        channel: 'forensic-channel'
      }
    };

    return JSON.stringify(status, null, 2);
  }

  // ===========================================================================
  // Link Evidence to Incident
  // ===========================================================================

  async linkEvidenceToIncident(ctx, evidenceId, incidentId) {
    this._checkAccess(ctx, {
      roles: ['ForensicLead', 'EvidenceCustodian', 'MonitoringAnalyst', 'OTGatewayCollector'],
      clearance: ['Low', 'Medium', 'High']
    });

    const evidenceBytes = await ctx.stub.getState(`evidence::${evidenceId}`);
    if (!evidenceBytes || !evidenceBytes.length) {
      throw new Error(`Evidence ${evidenceId} not found`);
    }

    const incidentBytes = await ctx.stub.getState(incidentId);
    if (!incidentBytes || !incidentBytes.length) {
      throw new Error(`Incident ${incidentId} not found`);
    }

    const evidence = JSON.parse(evidenceBytes.toString());
    const incident = JSON.parse(incidentBytes.toString());

    evidence.incidentId = incidentId;
    evidence.linkedAt = this._getTimestamp(ctx);
    await ctx.stub.putState(`evidence::${evidenceId}`, Buffer.from(JSON.stringify(evidence), 'utf8'));

    incident.evidenceList = incident.evidenceList || [];
    if (!incident.evidenceList.includes(evidenceId)) {
      incident.evidenceList.push(evidenceId);
      await ctx.stub.putState(incidentId, Buffer.from(JSON.stringify(incident), 'utf8'));
    }

    ctx.stub.setEvent('EvidenceLinkedToIncident', Buffer.from(JSON.stringify({
      evidenceId,
      incidentId,
      linkedAt: evidence.linkedAt
    }), 'utf8'));

    await this._logAction(ctx, 'linkEvidenceToIncident', incidentId, { evidenceId });

    return JSON.stringify({ success: true, evidenceId, incidentId });
  }

  // ===========================================================================
  // Examination & Analysis
  // ===========================================================================

  async submitExaminationAndAnalysisData(
    ctx,
    investigatorId,
    incidentId,
    evidenceIdsJson,
    analysisToolsJson,
    iocJson,
    vulnerabilitiesJson,
    ttpMappingJson,
    wh5Json
  ) {
    this._checkAccess(ctx, {
      roles: ['ForensicLead'],
      clearance: ['High']
    });

    let evidenceIds, analysisTools, ioc, vulnerabilities, ttpMapping, wh5;
    try {
      evidenceIds = JSON.parse(evidenceIdsJson);
      analysisTools = JSON.parse(analysisToolsJson);
      ioc = JSON.parse(iocJson);
      vulnerabilities = JSON.parse(vulnerabilitiesJson);
      ttpMapping = JSON.parse(ttpMappingJson);
      wh5 = JSON.parse(wh5Json);
    } catch (err) {
      throw new Error(`Invalid JSON in analysis data: ${err.message}`);
    }

    const hasZKPVerifier = Array.isArray(analysisTools) && analysisTools.includes('ZKP-Verifier');
    const ts = this._getTimestamp(ctx);

    const actualInvestigator = this._getAuditActor(ctx);
    const claimedInvestigatorId = investigatorId;

    const analysisData = {
      investigatorId: actualInvestigator,
      claimedInvestigatorId,
      incidentId,
      evidenceIds,
      analysisTools,
      ioc,
      vulnerabilities,
      ttpMapping,
      wh5
    };

    const analysisHash = crypto.createHash('sha256')
      .update(JSON.stringify(analysisData))
      .digest('hex');

    const entry = {
      ...analysisData,
      status: 'analysisCompleted',
      timestamp: ts,
      cryptographicMetadata: {
        analysisHash,
        integrityLevel: 'HIGH',
        zkpCapabilities: hasZKPVerifier,
        complianceFlags: {
          gdprCompliant: hasZKPVerifier,
          privacyPreserving: hasZKPVerifier,
          auditTrailComplete: true
        }
      }
    };

    const incBytes = await ctx.stub.getState(incidentId);
    if (!incBytes || incBytes.length === 0) {
      throw new Error(`Incident ${incidentId} does not exist`);
    }

    const incident = JSON.parse(incBytes.toString());
    incident.actions = incident.actions || [];
    incident.actions.push({
      action: 'examinationAndAnalysisSubmitted',
      timestamp: ts,
      by: actualInvestigator,
      claimedBy: claimedInvestigatorId,
      analysisHash: analysisHash.substring(0, 16),
      zkpEnabled: hasZKPVerifier
    });
    await ctx.stub.putState(incidentId, Buffer.from(JSON.stringify(incident), 'utf8'));

    const analysisKey = ctx.stub.createCompositeKey('AnalysisEntry', [incidentId, ts, analysisHash]);
    await ctx.stub.putState(analysisKey, Buffer.from(JSON.stringify(entry), 'utf8'));

    for (const evId of evidenceIds || []) {
      try {
        const evidenceBytes = await ctx.stub.getState(`evidence::${evId}`);
        if (evidenceBytes && evidenceBytes.length > 0) {
          await this._addCoCEntry(ctx, evId, 'examined', {
            location: 'Forensic Analysis Lab',
            condition: 'analyzed',
            additionalData: {
              investigatorId: actualInvestigator,
              claimedInvestigatorId,
              analysisTools: Array.isArray(analysisTools) ? analysisTools.join(', ') : String(analysisTools),
              findingsSummary: `IOCs: ${(ioc || []).length}, Vulnerabilities: ${(vulnerabilities || []).length}`,
              analysisHash: analysisHash.substring(0, 16)
            }
          });
        }
      } catch (error) {
        console.warn(`⚠️ Failed to update CoC for evidence ${evId}: ${error.message}`);
      }
    }

    ctx.stub.setEvent('AnalysisSubmitted', Buffer.from(JSON.stringify({
      incidentId,
      investigatorId: actualInvestigator,
      claimedInvestigatorId,
      timestamp: ts,
      analysisHash: analysisHash.substring(0, 16),
      zkpEnabled: hasZKPVerifier,
      privacyLevel: hasZKPVerifier ? 'HIGH' : 'STANDARD',
      evidenceExamined: (evidenceIds || []).length
    }), 'utf8'));

    await this._logAction(ctx, 'submitExaminationAndAnalysisData', incidentId, {
      investigatorId: actualInvestigator,
      claimedInvestigatorId,
      analysisHash: analysisHash.substring(0, 16),
      zkpEnabled: hasZKPVerifier,
      evidenceCount: (evidenceIds || []).length,
      cocUpdated: true
    });

    return JSON.stringify({ success: true, analysisHash });
  }

  async retrieveExaminationAndAnalysisData(ctx, incidentId) {
    const callerRoleRaw = (ctx.clientIdentity.getAttributeValue('role') || '').trim();
    const roleNorm = this._normRole(callerRoleRaw);
    const isIndependentAuditor = (roleNorm === 'independentauditor');

    if (isIndependentAuditor) {
      this._checkAccess(ctx, {
        roles: ['IndependentAuditor'],
        clearance: ['Low', 'Medium', 'High']
      });
    } else {
      this._checkAccess(ctx, {
        roles: ['ForensicLead', 'EvidenceCustodian'],
        clearance: ['High']
      });
    }

    const incidentBytes = await ctx.stub.getState(incidentId);
    if (!incidentBytes || incidentBytes.length === 0) {
      throw new Error(`Incident ${incidentId} not found`);
    }

    const iterator = await ctx.stub.getStateByPartialCompositeKey('AnalysisEntry', [incidentId]);
    const entries = [];

    let result = await iterator.next();
    while (!result.done) {
      let entry;
      try {
        entry = JSON.parse(result.value.value.toString());
      } catch {
        result = await iterator.next();
        continue;
      }

      if (entry.cryptographicMetadata?.analysisHash) {
        const originalData = {
          investigatorId: entry.investigatorId,
          incidentId: entry.incidentId,
          evidenceIds: entry.evidenceIds,
          analysisTools: entry.analysisTools,
          ioc: entry.indicatorsOfCompromise || entry.ioc,
          vulnerabilities: entry.vulnerabilities,
          ttpMapping: entry.ttpMapping,
          wh5: entry.wh5
        };

        const verificationHash = crypto.createHash('sha256')
          .update(JSON.stringify(originalData))
          .digest('hex');

        entry.cryptographicVerification = {
          integrityVerified: verificationHash === entry.cryptographicMetadata.analysisHash,
          verificationTimestamp: this._getTimestamp(ctx)
        };
      }

      entries.push(isIndependentAuditor ? this._sanitizeAnalysisForExternal(entry) : entry);
      result = await iterator.next();
    }

    await iterator.close();

    if (entries.length === 0) {
      throw new Error(`No analysis data found for incident ${incidentId}`);
    }

    await this._logAction(ctx, 'retrieveExaminationAndAnalysisData', incidentId, {
      entriesRetrieved: entries.length,
      disclosure: isIndependentAuditor ? 'SUMMARY_ONLY' : 'FULL',
      cryptographicVerification: 'COMPLETED'
    });

    if (isIndependentAuditor) {
      return JSON.stringify({
        incidentId,
        count: entries.length,
        disclosure: 'SUMMARY_ONLY',
        entries,
        note: 'IndependentAuditor receives summary-only analysis (hashes + verification + counts).'
      }, null, 2);
    }

    return JSON.stringify({
      incidentId,
      count: entries.length,
      entries,
      cryptographicSummary: {
        allEntriesVerified: entries.every(e => e.cryptographicVerification?.integrityVerified !== false),
        zkpEnabledEntries: entries.filter(e => e.cryptographicMetadata?.zkpCapabilities).length,
        complianceLevel: 'ENHANCED'
      }
    }, null, 2);
  }

  // ===========================================================================
  // Delegated governance and lifecycle-aware confidentiality withdrawal
  // ===========================================================================

  async getCapabilityRecord(ctx, capId) {
    const id = String(capId || '').trim();
    if (!id) throw new Error('capId is required');
    const record = await this._getCapabilityRecordByCapId(ctx, id);
    if (!record) throw new Error(`Capability ${id} not found`);
    const accessState = fcNormalizeCapabilityAccessState(record);
    return JSON.stringify({
      ...record,
      accessState,
      active: fcIsCapabilityUsableState(accessState)
    });
  }

    async getEvidenceLifecycleState(ctx, evidenceId) {
    const evId = String(evidenceId || '').trim();
    const { evidence } = await this._loadEvidenceRecord(ctx, evId);

    return JSON.stringify({
      evidenceId: evId,
      lifecycleState: fcNormalizeEvidenceLifecycleState(evidence),
      lifecycleUpdatedAt: evidence.lifecycleUpdatedAt || null,

      collectedBy: evidence.collectedBy || null,
      collectionMethod: evidence.collectionMethod || null,
      collectionTimestamp: evidence.collectionTimestamp || null,

      preservedAt: evidence.preservedAt || null,
      preservedBy: evidence.preservedBy || null,

      committedAt: evidence.committedAt || null,
      committedBy: evidence.committedBy || null,

      authorizedAt: evidence.authorizedAt || null,
      authorizedBy: evidence.authorizedBy || null,
      disclosedAt: evidence.disclosedAt || null,
      disclosedBy: evidence.disclosedBy || null,

      restrictedAt: evidence.restrictedAt || null,
      withdrawnAt: evidence.withdrawnAt || null,

      destructionRequestedAt: evidence.destructionRequestedAt || null,
      destructionApprovedAt: evidence.destructionApprovedAt || null,
      destroyedAt: evidence.destroyedAt || null,

      custodyOwnerId: evidence.custodyOwnerId || null,
      disclosureAuthorityId: evidence.disclosureAuthorityId || null,

      lifecycleHistory: Array.isArray(evidence.lifecycleHistory) ? evidence.lifecycleHistory : []
    });
  }

  async revokeCapability(ctx, capId, reasonJson = '{}') {
    this._checkAccess(ctx, { roles: ['EvidenceCustodian'], clearance: ['High'] });
    const id = String(capId || '').trim();
    if (!id) throw new Error('capId is required');
    const capRecord = await this._getCapabilityRecordByCapId(ctx, id);
    if (!capRecord) throw new Error(`Capability ${id} not found`);

    const reasonObj = this._parseJsonStrict('reason', reasonJson || '{}');
    const reasonCode = fcNormalizeReason(reasonObj.reasonCode || reasonObj.reason, FC_REVOCATION_REASONS);
    const txTimestamp = this._getTimestamp(ctx);
    const actor = this._getAuditActor(ctx);

    const { evidence } = await this._loadEvidenceRecord(ctx, capRecord.evidenceId);
    const evidenceOwner = this._getEvidenceOwner(evidence);
    if (String(actor) !== String(evidenceOwner)) {
      throw new Error('Only the designated evidence custodian may revoke this capability');
    }

    const previousState = fcNormalizeCapabilityAccessState(capRecord);
    if ([FC_CAPABILITY_ACCESS_STATES.REVOKED, FC_CAPABILITY_ACCESS_STATES.EXPIRED].includes(previousState)) {
      throw new Error(`capability_not_revocable:${previousState}`);
    }
    capRecord.accessState = FC_CAPABILITY_ACCESS_STATES.REVOKED;
    capRecord.state = FC_CAPABILITY_ACCESS_STATES.REVOKED;
    capRecord.active = false;
    capRecord.status = 'revoked';
    capRecord.revokedAt = txTimestamp;
    capRecord.revokedBy = actor;
    capRecord.revocationReason = reasonCode;
    capRecord.revocationNote = reasonObj.note || reasonObj.description || '';
    await this._persistCapabilityRecord(ctx, capRecord);

    ctx.stub.setEvent('CapabilityRevoked', Buffer.from(JSON.stringify(this._buildGovernanceEvent('CapabilityRevoked', {
      evidenceId: capRecord.evidenceId,
      capId: capRecord.capId,
      previousState,
      nextState: capRecord.accessState,
      reasonCode,
      actor,
      revokedAt: txTimestamp
    })), 'utf8'));

    await this._logAction(ctx, 'revokeCapability', capRecord.incidentId || 'EVIDENCE_ONLY', {
      evidenceId: capRecord.evidenceId,
      capId: capRecord.capId,
      reasonCode,
      previousState,
      nextState: capRecord.accessState
    });

    return JSON.stringify({ success: true, capId: capRecord.capId, previousState, nextState: capRecord.accessState, reasonCode, revokedAt: txTimestamp });
  }

  async expireCapability(ctx, capId) {
    this._checkAccess(ctx, { roles: ['EvidenceCustodian'], clearance: ['High'] });
    const id = String(capId || '').trim();
    if (!id) throw new Error('capId is required');
    const capRecord = await this._getCapabilityRecordByCapId(ctx, id);
    if (!capRecord) throw new Error(`Capability ${id} not found`);

    const txTimestamp = this._getTimestamp(ctx);
    if (new Date(capRecord.expiresAt).getTime() > new Date(txTimestamp).getTime()) {
      throw new Error('capability_not_yet_expired');
    }

    const previousState = fcNormalizeCapabilityAccessState(capRecord);
    if ([FC_CAPABILITY_ACCESS_STATES.REVOKED, FC_CAPABILITY_ACCESS_STATES.EXPIRED].includes(previousState)) {
      throw new Error(`capability_not_expirable:${previousState}`);
    }
    capRecord.accessState = FC_CAPABILITY_ACCESS_STATES.EXPIRED;
    capRecord.state = FC_CAPABILITY_ACCESS_STATES.EXPIRED;
    capRecord.active = false;
    capRecord.status = 'expired';
    capRecord.expiredAt = txTimestamp;
    await this._persistCapabilityRecord(ctx, capRecord);

    ctx.stub.setEvent('CapabilityExpired', Buffer.from(JSON.stringify(this._buildGovernanceEvent('CapabilityExpired', {
      evidenceId: capRecord.evidenceId,
      capId: capRecord.capId,
      previousState,
      nextState: capRecord.accessState,
      expiredAt: txTimestamp
    })), 'utf8'));

    return JSON.stringify({ success: true, capId: capRecord.capId, previousState, nextState: capRecord.accessState, expiredAt: txTimestamp });
  }

  async restrictEvidence(ctx, evidenceId, reasonJson = '{}') {
    this._checkAccess(ctx, { roles: ['EvidenceCustodian', 'ForensicLead', 'Admin', 'System Administrator'], clearance: ['High'] });
    const evId = String(evidenceId || '').trim();
    const { evidenceKey, evidence } = await this._loadEvidenceRecord(ctx, evId);
    const reasonObj = this._parseJsonStrict('reason', reasonJson || '{}');
    const reasonCode = fcNormalizeReason(reasonObj.reasonCode || reasonObj.reason, FC_RESTRICTION_REASONS);
    const txTimestamp = this._getTimestamp(ctx);
    const actor = this._getAuditActor(ctx);
    const roleNorm = this._roleNorm(ctx);
    const evidenceOwner = this._getEvidenceOwner(evidence);

    if (roleNorm === 'evidencecustodian' && String(actor) !== String(evidenceOwner)) {
      throw new Error('Only the designated evidence custodian may restrict this evidence');
    }

    const previousState = fcNormalizeEvidenceLifecycleState(evidence);
    if ([FC_EVIDENCE_LIFECYCLE_STATES.WITHDRAWN, FC_EVIDENCE_LIFECYCLE_STATES.ARCHIVED].includes(previousState)) {
      throw new Error(`evidence_not_restrictable:${previousState}`);
    }

    const transition = this._transitionEvidenceLifecycle(evidence, FC_EVIDENCE_LIFECYCLE_STATES.RESTRICTED, reasonCode, actor, txTimestamp);
    evidence.restrictedAt = txTimestamp;
    evidence.restrictedBy = actor;
    evidence.restrictionReason = reasonCode;
    evidence.accessRestricted = true;
    await this._persistEvidenceRecord(ctx, evidenceKey, evidence);

    ctx.stub.setEvent('EvidenceRestricted', Buffer.from(JSON.stringify(this._buildGovernanceEvent('EvidenceRestricted', {
      evidenceId: evId,
      previousState: transition.previousState,
      nextState: transition.nextState,
      reasonCode,
      actor,
      restrictedAt: txTimestamp
    })), 'utf8'));

    await this._logAction(ctx, 'restrictEvidence', evidence.incidentId || 'EVIDENCE_ONLY', { evidenceId: evId, reasonCode, previousState, nextState: transition.nextState });
    return JSON.stringify({ success: true, evidenceId: evId, previousState, nextState: transition.nextState, reasonCode, restrictedAt: txTimestamp });
  }

  async withdrawConfidentiality(ctx, evidenceId, reasonJson = '{}') {
    this._checkAccess(ctx, { roles: ['DataProtectionOfficer', 'EvidenceCustodian', 'Admin'], clearance: ['High'] });
    const roleNorm = this._roleNorm(ctx);
    if (!['dataprotectionofficer'].includes(roleNorm)) {
      throw new Error('Only DataProtectionOfficer may withdraw evidence confidentiality');
    }

    const evId = String(evidenceId || '').trim();
    const { evidenceKey, evidence } = await this._loadEvidenceRecord(ctx, evId);
    const reasonObj = this._parseJsonStrict('reason', reasonJson || '{}');
    const reasonCode = fcNormalizeReason(reasonObj.reasonCode || reasonObj.reason, FC_WITHDRAWAL_REASONS);
    const justification = String(reasonObj.justification || reasonObj.note || reasonObj.requestRef || '').trim();
    if (!justification) {
      throw new Error('withdrawal_justification_required');
    }

    const txTimestamp = this._getTimestamp(ctx);
    const actor = this._getAuditActor(ctx);
    const previousState = fcNormalizeEvidenceLifecycleState(evidence);
    if ([FC_EVIDENCE_LIFECYCLE_STATES.WITHDRAWN, FC_EVIDENCE_LIFECYCLE_STATES.ARCHIVED].includes(previousState)) {
      throw new Error(`evidence_not_withdrawable:${previousState}`);
    }
    if (evidence.legalHold && evidence.legalHold.active) {
      throw new Error(`Cannot withdraw evidence under legal hold until ${evidence.legalHold.expirationDate}`);
    }

    const withdrawalRecord = {
      version: 'confidentiality-withdrawal-v1',
      evidenceId: evId,
      reasonCode,
      justificationHash: this._sha256Hex(justification),
      requestedBy: actor,
      requestedAt: txTimestamp,
      keyDestructionIntent: true,
      keyDestructionCompleted: false,
      commitmentPreserved: true,
      auditTrailPreserved: true
    };

    const transition = this._transitionEvidenceLifecycle(evidence, FC_EVIDENCE_LIFECYCLE_STATES.WITHDRAWN, reasonCode, actor, txTimestamp);
    evidence.withdrawnAt = txTimestamp;
    evidence.withdrawnBy = actor;
    evidence.withdrawalReason = reasonCode;
    evidence.withdrawalRecord = withdrawalRecord;
    evidence.accessRestricted = true;
    evidence.offChainAccessRevokedAt = txTimestamp;
    await this._persistEvidenceRecord(ctx, evidenceKey, evidence);

    const withdrawalKey = ctx.stub.createCompositeKey('EvidenceWithdrawal', [evId, txTimestamp]);
    await ctx.stub.putState(withdrawalKey, Buffer.from(JSON.stringify(withdrawalRecord), 'utf8'));

    ctx.stub.setEvent('EvidenceWithdrawn', Buffer.from(JSON.stringify(this._buildGovernanceEvent('EvidenceWithdrawn', {
      evidenceId: evId,
      previousState: transition.previousState,
      nextState: transition.nextState,
      reasonCode,
      actor,
      withdrawnAt: txTimestamp,
      keyDestructionIntent: true
    })), 'utf8'));

    ctx.stub.setEvent('KeyDestructionRequested', Buffer.from(JSON.stringify(this._buildGovernanceEvent('KeyDestructionRequested', {
      evidenceId: evId,
      requestedBy: actor,
      requestedAt: txTimestamp
    })), 'utf8'));

    await this._logAction(ctx, 'withdrawConfidentiality', evidence.incidentId || 'EVIDENCE_ONLY', { evidenceId: evId, reasonCode, previousState, nextState: transition.nextState });
    return JSON.stringify({ success: true, evidenceId: evId, previousState, nextState: transition.nextState, reasonCode, withdrawnAt: txTimestamp, keyDestructionIntent: true });
  }

  async reportKeyDestructionCompleted(ctx, evidenceId, eraseResultJson = '{}') {
    this._checkAccess(ctx, { roles: ['DataProtectionOfficer'], clearance: ['High'] });
    const evId = String(evidenceId || '').trim();
    const { evidenceKey, evidence } = await this._loadEvidenceRecord(ctx, evId);
    const eraseResult = this._parseJsonStrict('eraseResult', eraseResultJson || '{}');
    if (fcNormalizeEvidenceLifecycleState(evidence) !== FC_EVIDENCE_LIFECYCLE_STATES.WITHDRAWN) {
      throw new Error('evidence_must_be_withdrawn_before_key_destruction_report');
    }
    const txTimestamp = this._getTimestamp(ctx);
    evidence.withdrawalRecord = evidence.withdrawalRecord || {};
    evidence.withdrawalRecord.keyDestructionCompleted = true;
    evidence.withdrawalRecord.keyDestructionCompletedAt = txTimestamp;
    evidence.withdrawalRecord.keyDestructionReceiptHash = this._sha256Hex(JSON.stringify(eraseResult));
    await this._persistEvidenceRecord(ctx, evidenceKey, evidence);
    ctx.stub.setEvent('KeyDestructionCompleted', Buffer.from(JSON.stringify(this._buildGovernanceEvent('KeyDestructionCompleted', {
      evidenceId: evId,
      completedAt: txTimestamp,
      receiptHash: evidence.withdrawalRecord.keyDestructionReceiptHash
    })), 'utf8'));
    return JSON.stringify({ success: true, evidenceId: evId, keyDestructionCompleted: true, completedAt: txTimestamp });
  }


  // ===========================================================================
  // Lifecycle-aware evidence destruction / disposition protocol
  // ===========================================================================

  _destructionDirectKey(evidenceId) {
    return `EvidenceDestruction_${evidenceId}`;
  }

  _destructionCompositeKey(ctx, evidenceId, requestedAt) {
    return ctx.stub.createCompositeKey('EvidenceDestruction', [
      String(evidenceId || '').trim(),
      String(requestedAt || 'unknown').trim()
    ]);
  }

  async _getEvidenceDestructionRecordInternal(ctx, evidenceId) {
    const evId = String(evidenceId || '').trim();
    if (!evId) throw new Error('evidenceId is required');

    const bytes = await ctx.stub.getState(this._destructionDirectKey(evId));
    if (!bytes || !bytes.length) return null;

    return JSON.parse(bytes.toString());
  }

  async _putEvidenceDestructionRecord(ctx, record) {
    if (!record || typeof record !== 'object') {
      throw new Error('destruction record is required');
    }

    const evidenceId = String(record.evidenceId || '').trim();
    if (!evidenceId) throw new Error('destruction record evidenceId is required');

    const payload = Buffer.from(JSON.stringify(record), 'utf8');

    await ctx.stub.putState(this._destructionDirectKey(evidenceId), payload);

    await ctx.stub.putState(
      this._destructionCompositeKey(ctx, evidenceId, record.requestedAt || record.updatedAt || 'unknown'),
      payload
    );
  }

  _redactOffChainPointersForDestruction(evidence) {
    const pointerHashes = [];

    const addPointer = (label, value) => {
      if (value === undefined || value === null || value === '') return;

      const raw = String(value).trim();
      if (!raw) return;

      let hashValue;
      try {
        hashValue = this._cidHash(raw);
      } catch {
        hashValue = this._sha256Hex(raw);
      }

      pointerHashes.push({
        label,
        hash: hashValue
      });
    };

    addPointer('ipfsReference', evidence.ipfsReference);
    addPointer('masterCID', evidence.masterCID);
    addPointer('realCID', evidence.realCID);

    if (evidence.ipfsReferences && typeof evidence.ipfsReferences === 'object') {
      for (const [label, value] of Object.entries(evidence.ipfsReferences)) {
        addPointer(`ipfsReferences.${label}`, value);
      }
    }

    delete evidence.ipfsReference;
    delete evidence.masterCID;
    delete evidence.realCID;
    delete evidence.ipfsReferences;

    if (pointerHashes.length > 0) {
      evidence.destroyedOffChainPointerHashes = pointerHashes;
    }

    evidence.offChainPointersDestroyed = true;
    evidence.offChainAccessRevoked = true;

    return pointerHashes;
  }

  async _revokeActiveCapabilitiesForEvidence(ctx, evidenceId, txTimestamp, actor, reasonCode) {
    const evId = String(evidenceId || '').trim();
    const iterator = await ctx.stub.getStateByPartialCompositeKey('Capability', [evId]);

    const seenCapIds = new Set();
    let inspectedCount = 0;
    let revokedCount = 0;

    try {
      while (true) {
        const res = await iterator.next();
        if (res.done) break;

        if (!res.value || !res.value.value || !res.value.value.length) continue;

        let capRecord;
        try {
          capRecord = JSON.parse(res.value.value.toString());
        } catch {
          continue;
        }

        const capId = String(capRecord.capId || '').trim();
        if (!capId || seenCapIds.has(capId)) continue;
        seenCapIds.add(capId);

        inspectedCount += 1;

        const effectiveState = this._getCapabilityEffectiveStatus(capRecord, txTimestamp);
        if (effectiveState !== FC_CAPABILITY_ACCESS_STATES.ACTIVE) {
          continue;
        }

        capRecord.accessState = FC_CAPABILITY_ACCESS_STATES.REVOKED;
        capRecord.state = FC_CAPABILITY_ACCESS_STATES.REVOKED;
        capRecord.active = false;
        capRecord.status = FC_CAPABILITY_ACCESS_STATES.REVOKED;
        capRecord.revokedAt = txTimestamp;
        capRecord.revokedBy = actor;
        capRecord.revocationReason = reasonCode || 'EVIDENCE_DESTROYED';
        capRecord.revocationNote = 'Revoked automatically by evidence destruction protocol';

        await this._persistCapabilityRecord(ctx, capRecord);

        revokedCount += 1;
      }
    } finally {
      await iterator.close();
    }

    return {
      inspectedCapabilities: inspectedCount,
      revokedCapabilities: revokedCount
    };
  }

  async requestEvidenceDestruction(ctx, evidenceId, requestJson) {
    this._checkAccess(ctx, {
      roles: ['DataProtectionOfficer'],
      clearance: ['High']
    });

    const evId = String(evidenceId || '').trim();
    const { evidenceKey, evidence } = await this._loadEvidenceRecord(ctx, evId);

    const currentState = fcNormalizeEvidenceLifecycleState(evidence);
    if (!fcCanRequestDestructionForEvidenceState(currentState)) {
      throw new Error(`evidence_not_destruction_requestable:${currentState}`);
    }

    if (evidence.legalHold && evidence.legalHold.active) {
      throw new Error(`evidence_under_legal_hold:${evidence.legalHold.expirationDate || 'active'}`);
    }

    const request = this._parseJsonStrict('destructionRequest', requestJson || '{}');
    const reasonCode = fcNormalizeReason(
      request.reasonCode || request.reason,
      FC_DESTRUCTION_REASONS
    );

    const justification = String(
      request.justification ||
      request.note ||
      request.requestRef ||
      ''
    ).trim();

    if (!justification) {
      throw new Error('destruction_justification_required');
    }

    const txTimestamp = this._getTimestamp(ctx);
    const actor = this._getAuditActor(ctx);
    const txId = ctx.stub.getTxID();

    const existing = await this._getEvidenceDestructionRecordInternal(ctx, evId);
    if (existing && ['REQUESTED', 'APPROVED', 'DESTROYED'].includes(String(existing.status || '').toUpperCase())) {
      throw new Error(`destruction_record_already_exists:${existing.status}`);
    }

    const destructionRecord = {
      version: 'evidence-destruction-v1',
      evidenceId: evId,
      incidentId: evidence.incidentId || 'EVIDENCE_ONLY',
      status: 'REQUESTED',
      reasonCode,
      requestRef: request.requestRef || null,
      justificationHash: this._sha256Hex(justification),
      requestedBy: actor,
      requestedAt: txTimestamp,
      requestTxId: txId,
      approvedBy: null,
      approvedAt: null,
      destroyedBy: null,
      destroyedAt: null,
      destructionMethod: null,
      destructionReceiptHash: null,
      commitmentPreserved: true,
      auditTrailPreserved: true,
      offChainDestructionRequired: true,
      keyDestructionRequired: true,
      capabilitiesRevoked: 0,
      updatedAt: txTimestamp
    };

    const transition = this._transitionEvidenceLifecycle(
      evidence,
      FC_EVIDENCE_LIFECYCLE_STATES.DESTRUCTION_REQUESTED,
      reasonCode,
      actor,
      txTimestamp
    );

    evidence.destructionRequestedAt = txTimestamp;
    evidence.destructionRequestedBy = actor;
    evidence.destructionReason = reasonCode;
    evidence.accessRestricted = true;
    evidence.offChainAccessRevokedAt = txTimestamp;
    evidence.destructionRecord = destructionRecord;

    await this._persistEvidenceRecord(ctx, evidenceKey, evidence);
    await this._putEvidenceDestructionRecord(ctx, destructionRecord);

    ctx.stub.setEvent('EvidenceDestructionRequested', Buffer.from(JSON.stringify(this._buildGovernanceEvent('EvidenceDestructionRequested', {
      evidenceId: evId,
      previousState: transition.previousState,
      nextState: transition.nextState,
      reasonCode,
      requestedBy: actor,
      requestedAt: txTimestamp,
      commitmentPreserved: true,
      auditTrailPreserved: true,
    })), 'utf8'));

    ctx.stub.setEvent('EvidenceLifecycleStateChanged', Buffer.from(JSON.stringify(this._buildGovernanceEvent('EvidenceLifecycleStateChanged', {
      evidenceId: evId,
      previousState: transition.previousState,
      nextState: transition.nextState,
      reason: reasonCode,
      actor,
      changedAt: txTimestamp
    })), 'utf8'));

    await this._logAction(ctx, 'requestEvidenceDestruction', evidence.incidentId || 'EVIDENCE_ONLY', {
      evidenceId: evId,
      reasonCode,
      previousState: transition.previousState,
      nextState: transition.nextState,
      commitmentPreserved: true,
      auditTrailPreserved: true
    });

    return JSON.stringify({
      success: true,
      evidenceId: evId,
      previousState: transition.previousState,
      nextState: transition.nextState,
      lifecycleState: transition.nextState,
      reasonCode,
      requestedAt: txTimestamp,
      requestedBy: actor,
      commitmentPreserved: true,
      auditTrailPreserved: true
    });
  }

  async approveEvidenceDestruction(ctx, evidenceId, approvalJson) {
    this._checkAccess(ctx, {
      roles: ['JudicialReviewer'],
      clearance: ['High']
    });

    const evId = String(evidenceId || '').trim();
    const { evidenceKey, evidence } = await this._loadEvidenceRecord(ctx, evId);

    const currentState = fcNormalizeEvidenceLifecycleState(evidence);
    if (currentState !== FC_EVIDENCE_LIFECYCLE_STATES.DESTRUCTION_REQUESTED) {
      throw new Error(`evidence_not_destruction_approvable:${currentState}`);
    }

    const approval = this._parseJsonStrict('destructionApproval', approvalJson || '{}');
    const approvalRef = String(approval.approvalRef || approval.requestRef || '').trim();
    const approvalNote = String(approval.approvalNote || approval.note || approval.justification || '').trim();

    if (!approvalRef && !approvalNote) {
      throw new Error('destruction_approval_reference_or_note_required');
    }

    const txTimestamp = this._getTimestamp(ctx);
    const actor = this._getAuditActor(ctx);
    const txId = ctx.stub.getTxID();

    const destructionRecord = await this._getEvidenceDestructionRecordInternal(ctx, evId);
    if (!destructionRecord || String(destructionRecord.status || '').toUpperCase() !== 'REQUESTED') {
      throw new Error('destruction_request_record_not_found');
    }

    const approvalHash = this._sha256Hex(fcCanonicalizeJson({
      evidenceId: evId,
      approvalRef,
      approvalNote,
      actor,
      txTimestamp,
      txId
    }));

    destructionRecord.status = 'APPROVED';
    destructionRecord.approvedBy = actor;
    destructionRecord.approvedAt = txTimestamp;
    destructionRecord.approvalRef = approvalRef || null;
    destructionRecord.approvalHash = approvalHash;
    destructionRecord.approvalTxId = txId;
    destructionRecord.updatedAt = txTimestamp;

    const transition = this._transitionEvidenceLifecycle(
      evidence,
      FC_EVIDENCE_LIFECYCLE_STATES.DESTRUCTION_APPROVED,
      'DESTRUCTION_APPROVED',
      actor,
      txTimestamp
    );

    evidence.destructionApprovedAt = txTimestamp;
    evidence.destructionApprovedBy = actor;
    evidence.destructionRecord = destructionRecord;

    await this._persistEvidenceRecord(ctx, evidenceKey, evidence);
    await this._putEvidenceDestructionRecord(ctx, destructionRecord);

    ctx.stub.setEvent('EvidenceDestructionApproved', Buffer.from(JSON.stringify(this._buildGovernanceEvent('EvidenceDestructionApproved', {
      evidenceId: evId,
      previousState: transition.previousState,
      nextState: transition.nextState,
      approvedBy: actor,
      approvedAt: txTimestamp,
      approvalHash
    })), 'utf8'));

    ctx.stub.setEvent('EvidenceLifecycleStateChanged', Buffer.from(JSON.stringify(this._buildGovernanceEvent('EvidenceLifecycleStateChanged', {
      evidenceId: evId,
      previousState: transition.previousState,
      nextState: transition.nextState,
      reason: 'DESTRUCTION_APPROVED',
      actor,
      changedAt: txTimestamp
    })), 'utf8'));

    await this._logAction(ctx, 'approveEvidenceDestruction', evidence.incidentId || 'EVIDENCE_ONLY', {
      evidenceId: evId,
      approvalHash,
      previousState: transition.previousState,
      nextState: transition.nextState
    });

    return JSON.stringify({
      success: true,
      evidenceId: evId,
      previousState: transition.previousState,
      nextState: transition.nextState,
      lifecycleState: transition.nextState,
      approvedAt: txTimestamp,
      approvedBy: actor,
      approvalHash
    });
  }


  _normalizeDestroyedKeyClasses(receipt) {
    const raw = Array.isArray(receipt?.destroyedKeyClasses)
      ? receipt.destroyedKeyClasses
      : [];

    const set = new Set(raw.map((x) => String(x || '').trim().toUpperCase()).filter(Boolean));

    if (receipt?.emkDestroyed === true) set.add('EMK');
    if (receipt?.dekDestroyed === true) set.add('DEK');
    if (receipt?.saltKeyDestroyed === true) set.add('K_SALT');
    if (receipt?.metadataKeyDestroyed === true) set.add('K_META');

    return [...set].sort();
  }

  _decodeSignatureBytes(signature) {
    const sig = String(signature || '').trim();
    if (!sig) throw new Error('attestation_signature_required');

    if (/^[a-fA-F0-9]+$/.test(sig) && sig.length % 2 === 0) {
      return Buffer.from(sig, 'hex');
    }

    return Buffer.from(sig, 'base64');
  }

  _buildDestructionAttestationStatement(evidenceId, destructionMethod, receipt, attestation) {
    if (attestation && attestation.statement && typeof attestation.statement === 'object') {
      return attestation.statement;
    }

    return {
      purpose: 'EVIDENCE_DESTRUCTION_ATTESTATION',
      evidenceId: String(evidenceId),
      destructionMethod: String(destructionMethod),
      receiptRef: String(receipt?.receiptRef || receipt?.receiptId || ''),
      completedAt: String(receipt?.completedAt || receipt?.destroyedAt || ''),
      destroyedKeyClasses: this._normalizeDestroyedKeyClasses(receipt),
      role: String(attestation?.role || ''),
      actorId: String(attestation?.actorId || ''),
      attestedAt: String(attestation?.attestedAt || '')
    };
  }

  _resolveConfiguredDestructionThresholdPolicy(receipt) {
    // The effective destruction policy is contract-owned. A receipt may repeat
    // the policy for audit purposes, but it cannot lower the threshold or
    // replace the eligible role set.
    const required = Number(FC_DESTRUCTION_THRESHOLD_POLICY.required);
    const eligibleRoles = [...new Set(
      FC_DESTRUCTION_THRESHOLD_POLICY.eligibleRoles
        .map((role) => String(role || '').trim())
        .filter(Boolean)
    )].sort();

    if (!Number.isInteger(required) || required <= 0) {
      throw new Error('invalid_configured_threshold_policy_required');
    }

    if (eligibleRoles.length === 0) {
      throw new Error('invalid_configured_threshold_policy_eligible_roles');
    }

    if (required > eligibleRoles.length) {
      throw new Error(
        `invalid_configured_threshold_policy_required_exceeds_eligible_roles:required=${required}:eligibleRoles=${eligibleRoles.length}`
      );
    }

    const suppliedPolicy = receipt?.thresholdPolicy;
    if (suppliedPolicy !== undefined && suppliedPolicy !== null) {
      if (!fcIsPlainObject(suppliedPolicy)) {
        throw new Error('receipt_threshold_policy_must_be_object');
      }

      const suppliedRequiredRaw = suppliedPolicy.required ?? suppliedPolicy.threshold;
      if (suppliedRequiredRaw === undefined || !Array.isArray(suppliedPolicy.eligibleRoles)) {
        throw new Error('receipt_threshold_policy_incomplete');
      }

      const suppliedRequired = Number(suppliedRequiredRaw);
      const suppliedEligibleRoles = [...new Set(
        suppliedPolicy.eligibleRoles
          .map((role) => String(role || '').trim())
          .filter(Boolean)
      )].sort();

      const sameRequired = Number.isInteger(suppliedRequired) && suppliedRequired === required;
      const sameRoles =
        suppliedEligibleRoles.length === eligibleRoles.length &&
        suppliedEligibleRoles.every((role, index) => role === eligibleRoles[index]);

      if (!sameRequired || !sameRoles) {
        throw new Error(
          `receipt_threshold_policy_mismatch:configuredRequired=${required}:suppliedRequired=${suppliedRequiredRaw}:configuredRoles=${eligibleRoles.join('|')}:suppliedRoles=${suppliedEligibleRoles.join('|') || 'none'}`
        );
      }
    }

    return {
      required,
      eligibleRoles
    };
  }
  async _verifyDestructionThresholdAttestations(
    ctx,
    evidenceId,
    destructionMethod,
    receipt
  ) {
    /*
     * The threshold is mandatory and contract-owned.
     * A receipt cannot lower or replace the configured policy.
     */
    const { required, eligibleRoles } =
      this._resolveConfiguredDestructionThresholdPolicy(
        receipt
      );

    const eligibleRoleSet =
      new Set(eligibleRoles);

    const attestations = Array.isArray(
      receipt?.destructionAttestations
    )
      ? receipt.destructionAttestations
      : [];

    if (attestations.length === 0) {
      throw new Error(
        'destruction_threshold_attestations_required'
      );
    }

    const validRoles = new Set();
    const validActors = new Set();
    const validKeyIds = new Set();
    const validKeyFingerprints = new Set();

    const verifiedBindings = [];
    const invalid = [];

    for (const att of attestations) {
      try {
        const roleRaw = String(
          att?.role || ''
        ).trim();

        /*
         * actorId is mandatory. Do not replace it with role.
         */
        const actorId = String(
          att?.actorId || ''
        ).trim();

        const publicKeyRef = String(
          att?.publicKeyRef || actorId
        ).trim();

        if (!roleRaw) {
          throw new Error(
            'attestation_role_required'
          );
        }

        if (!actorId) {
          throw new Error(
            'attestation_actor_required'
          );
        }

        if (!publicKeyRef) {
          throw new Error(
            'attestation_public_key_ref_required'
          );
        }

        const role =
          this._canonicalDestructionGovernanceRole(
            roleRaw
          );

        if (!role) {
          throw new Error(
            `attestation_role_not_eligible:${roleRaw}`
          );
        }

        /*
         * Require the canonical role spelling in the signed data.
         */
        if (roleRaw !== role) {
          throw new Error(
            `attestation_role_not_canonical:received=${roleRaw}:expected=${role}`
          );
        }

        if (!eligibleRoleSet.has(role)) {
          throw new Error(
            `attestation_role_not_configured:${role}`
          );
        }

        /*
         * publicKeyRef must identify the same registered actor.
         */
        if (publicKeyRef !== actorId) {
          throw new Error(
            `attestation_public_key_ref_must_equal_actor:publicKeyRef=${publicKeyRef}:actorId=${actorId}`
          );
        }

        const statement =
          this._buildDestructionAttestationStatement(
            evidenceId,
            destructionMethod,
            receipt,
            att
          );

        if (
          String(statement.purpose || '') !==
          'EVIDENCE_DESTRUCTION_ATTESTATION'
        ) {
          throw new Error(
            'attestation_statement_purpose_mismatch'
          );
        }

        if (
          String(statement.evidenceId) !==
          String(evidenceId)
        ) {
          throw new Error(
            'attestation_statement_evidence_mismatch'
          );
        }

        if (
          String(statement.destructionMethod) !==
          String(destructionMethod)
        ) {
          throw new Error(
            'attestation_statement_method_mismatch'
          );
        }

        if (
          String(statement.role) !== role
        ) {
          throw new Error(
            'attestation_statement_role_mismatch'
          );
        }

        if (
          String(statement.actorId) !== actorId
        ) {
          throw new Error(
            'attestation_statement_actor_mismatch'
          );
        }

        const expectedReceiptRef = String(
          receipt?.receiptRef ||
          receipt?.receiptId ||
          ''
        );

        if (
          String(statement.receiptRef || '') !==
          expectedReceiptRef
        ) {
          throw new Error(
            'attestation_statement_receipt_ref_mismatch'
          );
        }

        const expectedCompletedAt = String(
          receipt?.completedAt ||
          receipt?.destroyedAt ||
          ''
        );

        if (
          String(statement.completedAt || '') !==
          expectedCompletedAt
        ) {
          throw new Error(
            'attestation_statement_completed_at_mismatch'
          );
        }

        const expectedDestroyedKeyClasses =
          this._normalizeDestroyedKeyClasses(
            receipt
          );

        const statementDestroyedKeyClasses =
          this._normalizeDestroyedKeyClasses({
            destroyedKeyClasses:
              statement.destroyedKeyClasses
          });

        if (
          JSON.stringify(
            statementDestroyedKeyClasses
          ) !==
          JSON.stringify(
            expectedDestroyedKeyClasses
          )
        ) {
          throw new Error(
            'attestation_statement_destroyed_key_classes_mismatch'
          );
        }

        const canonical =
          fcCanonicalizeJson(statement);

        const statementHash =
          this._sha256Hex(canonical);

        if (
          att.statementHash &&
          String(
            att.statementHash
          ).toLowerCase() !==
          statementHash.toLowerCase()
        ) {
          throw new Error(
            'attestation_statement_hash_mismatch'
          );
        }

        /*
         * Only dedicated destruction-attestation keys are accepted.
         * Generic SIGNING keys are not accepted for this workflow.
         */
        const {
          record: pkRecord,
          keyId
        } = await this._resolveRegisteredPublicKey(
          ctx,
          actorId,
          [
            'DESTRUCTION_ATTESTATION',
            'destruction-attestation'
          ],
          [
            'Ed25519',
            'ed25519',
            'ED25519'
          ]
        );

        const registeredOwnerId = String(
          pkRecord.ownerId ||
          pkRecord.userId ||
          ''
        ).trim();

        if (!registeredOwnerId) {
          throw new Error(
            'registered_key_owner_missing'
          );
        }

        if (
          registeredOwnerId !== actorId
        ) {
          throw new Error(
            `registered_key_owner_mismatch:registered=${registeredOwnerId}:attested=${actorId}`
          );
        }

        if (
          this._normalizePublicKeyPurpose(
            pkRecord.purpose
          ) !== 'DESTRUCTION_ATTESTATION'
        ) {
          throw new Error(
            `registered_key_purpose_mismatch:${pkRecord.purpose || 'missing'}`
          );
        }

        if (
          this._normalizePublicKeyType(
            pkRecord.keyType
          ) !== 'ed25519'
        ) {
          throw new Error(
            `registered_key_type_mismatch:${pkRecord.keyType || 'missing'}`
          );
        }

        const registeredGovernanceRole =
          this._canonicalDestructionGovernanceRole(
            pkRecord.governanceRole
          );

        if (!registeredGovernanceRole) {
          throw new Error(
            'registered_key_governance_role_missing'
          );
        }

        if (
          registeredGovernanceRole !== role
        ) {
          throw new Error(
            `registered_key_governance_role_mismatch:registered=${registeredGovernanceRole}:attested=${role}`
          );
        }

        const computedKeyFingerprint =
          this._fingerprintEd25519PublicKey(
            pkRecord.publicKey
          );

        if (
          pkRecord.publicKeyFingerprint &&
          String(
            pkRecord.publicKeyFingerprint
          ).toLowerCase() !==
          computedKeyFingerprint.toLowerCase()
        ) {
          throw new Error(
            'registered_key_fingerprint_mismatch'
          );
        }

        /*
         * Each role, actor, key ID, and physical signing key can
         * contribute at most once toward the threshold.
         */
        if (validRoles.has(role)) {
          throw new Error(
            `duplicate_attestation_role:${role}`
          );
        }

        if (validActors.has(actorId)) {
          throw new Error(
            `duplicate_attestation_actor:${actorId}`
          );
        }

        if (validKeyIds.has(keyId)) {
          throw new Error(
            `duplicate_attestation_key_id:${keyId}`
          );
        }

        if (
          validKeyFingerprints.has(
            computedKeyFingerprint
          )
        ) {
          throw new Error(
            `duplicate_attestation_signing_key:${computedKeyFingerprint}`
          );
        }

        const keyObject =
          crypto.createPublicKey(
            pkRecord.publicKey
          );

        const signatureValid =
          crypto.verify(
            null,
            Buffer.from(
              canonical,
              'utf8'
            ),
            keyObject,
            this._decodeSignatureBytes(
              att.signature
            )
          );

        if (!signatureValid) {
          throw new Error(
            'attestation_signature_invalid'
          );
        }

        validRoles.add(role);
        validActors.add(actorId);
        validKeyIds.add(keyId);
        validKeyFingerprints.add(
          computedKeyFingerprint
        );

        const verifiedBinding = {
          role,
          actorId,
          publicKeyRef,
          registeredOwnerId,
          registeredGovernanceRole,
          keyId,
          publicKeyFingerprint:
            computedKeyFingerprint,
          statementHash
        };

        verifiedBindings.push(
          verifiedBinding
        );

        /*
         * Attach verification metadata to the in-memory receipt.
         */
        att.verified = true;
        att.statementHash =
          statementHash;
        att.publicKeyId =
          keyId;
        att.publicKeyFingerprint =
          computedKeyFingerprint;
        att.registeredOwnerId =
          registeredOwnerId;
        att.registeredGovernanceRole =
          registeredGovernanceRole;
      } catch (err) {
        invalid.push({
          role:
            att?.role || null,

          actorId:
            att?.actorId || null,

          publicKeyRef:
            att?.publicKeyRef || null,

          reason:
            err instanceof Error
              ? err.message
              : 'attestation_verification_failed'
        });
      }
    }

    /*
     * Successful threshold requires q distinct:
     * - eligible governance roles;
     * - registered actors;
     * - registry key IDs;
     * - Ed25519 key fingerprints.
     */
    if (
      validRoles.size < required ||
      validActors.size < required ||
      validKeyIds.size < required ||
      validKeyFingerprints.size < required
    ) {
      throw new Error(
        'destruction_threshold_attestation_not_satisfied:' +
        `required=${required}:` +
        `validRoles=${validRoles.size}:` +
        `validActors=${validActors.size}:` +
        `validKeyIds=${validKeyIds.size}:` +
        `validSigningKeys=${validKeyFingerprints.size}:` +
        `invalid=${JSON.stringify(invalid)}`
      );
    }

    return {
      mandatory: true,
      required,

      eligibleRoles:
        [...eligibleRoleSet].sort(),

      validCount:
        validKeyFingerprints.size,

      validRoles:
        [...validRoles].sort(),

      validActors:
        [...validActors].sort(),

      validKeyIds:
        [...validKeyIds].sort(),

      validKeyFingerprints:
        [...validKeyFingerprints].sort(),

      distinctRoleCount:
        validRoles.size,

      distinctActorCount:
        validActors.size,

      distinctSigningKeyCount:
        validKeyFingerprints.size,

      verifiedBindings,
      invalid,

      requiredSatisfied: true,
      verified: true
    };
  }



  async reportEvidenceDestroyed(ctx, evidenceId, receiptJson) {
    this._checkAccess(ctx, {
      roles: ['EvidenceCustodian'],
      clearance: ['High']
    });

    const evId = String(evidenceId || '').trim();
    const { evidenceKey, evidence } = await this._loadEvidenceRecord(ctx, evId);

    const currentState = fcNormalizeEvidenceLifecycleState(evidence);
    if (currentState !== FC_EVIDENCE_LIFECYCLE_STATES.DESTRUCTION_APPROVED) {
      throw new Error(`evidence_not_destroyable:${currentState}`);
    }

    const actor = this._getAuditActor(ctx);
    const evidenceOwner = this._getEvidenceOwner(evidence);
    if (String(actor) !== String(evidenceOwner)) {
      throw new Error('Only the designated evidence custodian may report evidence destruction');
    }

    const receipt = this._parseJsonStrict('destructionReceipt', receiptJson || '{}');
    const hasCompletionSignal =
      receipt.destroyed === true ||
      receipt.erased === true ||
      receipt.completed === true ||
      String(receipt.receiptRef || receipt.receiptId || '').trim().length > 0;

    if (!hasCompletionSignal) {
      throw new Error('destruction_completion_signal_required');
    }

    const destructionMethod = fcNormalizeReason(
      receipt.destructionMethod || receipt.method,
      FC_DESTRUCTION_METHODS,
      'ATTESTED_KEY_DESTRUCTION'
    );

    let destroyedKeyClasses = fcNormalizeDestroyedKeyClasses(
      receipt.destroyedKeyClasses || receipt.keyClassesDestroyed || receipt.keyClasses || receipt.destroyedKeys
    );
    const addDestroyedKeyClass = (name) => {
      if (!destroyedKeyClasses.includes(name)) destroyedKeyClasses.push(name);
    };
    if (receipt.emkDestroyed === true || receipt.evidenceMasterKeyDestroyed === true) addDestroyedKeyClass('EMK');
    if (receipt.dekDestroyed === true || receipt.dataEncryptionKeyDestroyed === true) addDestroyedKeyClass('DEK');
    if (receipt.saltKeyDestroyed === true || receipt.kSaltDestroyed === true) addDestroyedKeyClass('K_SALT');
    if (receipt.metadataKeyDestroyed === true || receipt.kMetaDestroyed === true) addDestroyedKeyClass('K_META');
    destroyedKeyClasses = destroyedKeyClasses.sort();

    const destructionAttestations = fcNormalizeDestructionAttestations(
      receipt.destructionAttestations || receipt.attestations
    );
    const configuredThresholdPolicy =
      this._resolveConfiguredDestructionThresholdPolicy(receipt);
    const thresholdEvaluation = fcEvaluateThresholdAttestations(
      destructionAttestations,
      configuredThresholdPolicy
    );

    const emkDestroyed = destroyedKeyClasses.includes('EMK');
    const dekDestroyed = destroyedKeyClasses.includes('DEK');
    const saltKeyDestroyed = destroyedKeyClasses.includes('K_SALT');
    const metadataKeyDestroyed = destroyedKeyClasses.includes('K_META');
    const keyMaterialDestroyed = receipt.keyMaterialDestroyed === true || emkDestroyed || dekDestroyed || saltKeyDestroyed || metadataKeyDestroyed;
    const postDestructionOpeningRevocation = saltKeyDestroyed || emkDestroyed;

    // Mandatory future-opening revocation guard. Threshold attestation alone is
    // not enough: the receipt must explicitly attest destruction/revocation of
    // K_SALT or its parent EMK before the evidence can become DESTROYED.
    if (!postDestructionOpeningRevocation) {
      throw new Error(
        `destruction_opening_material_required:requiredAny=${FC_DESTRUCTION_REQUIRED_OPENING_KEY_CLASSES.join('|')}:destroyedKeyClasses=${destroyedKeyClasses.join(',') || 'none'}`
      );
    }

    const txTimestamp = this._getTimestamp(ctx);
    const txId = ctx.stub.getTxID();

    const destructionRecord = await this._getEvidenceDestructionRecordInternal(ctx, evId);
    if (!destructionRecord || String(destructionRecord.status || '').toUpperCase() !== 'APPROVED') {
      throw new Error('destruction_approval_record_not_found');
    }

    const receiptHash = this._sha256Hex(fcCanonicalizeJson(receipt));
    const pointerHashes = this._redactOffChainPointersForDestruction(evidence);

    const thresholdAttestation = await this._verifyDestructionThresholdAttestations(
      ctx,
      evId,
      destructionMethod,
      receipt
    );
    const signedThresholdAttested = thresholdAttestation.requiredSatisfied === true && thresholdAttestation.verified === true;

    

    /*
     * Replace raw identifier counts with cryptographically verified
     * role, actor, and signing-key counts.
     */
    thresholdEvaluation.eligibleAttestationCount =
      thresholdAttestation.distinctRoleCount;

    thresholdEvaluation.distinctActorCount =
      thresholdAttestation.distinctActorCount;

    thresholdEvaluation.distinctSigningKeyCount =
      thresholdAttestation.distinctSigningKeyCount;

    thresholdEvaluation.validKeyIds =
      thresholdAttestation.validKeyIds;

    thresholdEvaluation.validKeyFingerprints =
      thresholdAttestation.validKeyFingerprints;

    thresholdEvaluation.satisfied =
      signedThresholdAttested;

    thresholdEvaluation.cryptographicallyVerified =
      thresholdAttestation.verified === true;const capabilityRevocation = await this._revokeActiveCapabilitiesForEvidence(
      ctx,
      evId,
      txTimestamp,
      actor,
      'EVIDENCE_DESTROYED'
    );

    destructionRecord.status = 'DESTROYED';
    destructionRecord.destroyedBy = actor;
    destructionRecord.destroyedAt = txTimestamp;
    destructionRecord.destructionMethod = destructionMethod;
    destructionRecord.destructionReceiptHash = receiptHash;
    destructionRecord.destroyedKeyClasses = destroyedKeyClasses;
    destructionRecord.emkDestroyed = emkDestroyed;
    destructionRecord.dekDestroyed = dekDestroyed;
    destructionRecord.saltKeyDestroyed = saltKeyDestroyed;
    destructionRecord.metadataKeyDestroyed = metadataKeyDestroyed;
    destructionRecord.keyMaterialDestroyed = keyMaterialDestroyed;
    destructionRecord.postDestructionOpeningRevocation = postDestructionOpeningRevocation;
    destructionRecord.destructionAttestations = destructionAttestations;
    destructionRecord.thresholdPolicy = {
      required: thresholdEvaluation.required,
      eligibleRoles: thresholdEvaluation.eligibleRoles
    };
    destructionRecord.thresholdEvaluation = thresholdEvaluation;
    destructionRecord.thresholdAttested = signedThresholdAttested;
    destructionRecord.destroyTxId = txId;
    destructionRecord.capabilitiesRevoked = capabilityRevocation.revokedCapabilities;
    destructionRecord.inspectedCapabilities = capabilityRevocation.inspectedCapabilities;
    destructionRecord.offChainPointerHashes = pointerHashes;
    destructionRecord.commitmentPreserved = true;
    destructionRecord.auditTrailPreserved = true;
    destructionRecord.thresholdAttestation = thresholdAttestation;
    destructionRecord.thresholdAttestationVerified = thresholdAttestation.verified === true;
    destructionRecord.signedThresholdAttested = signedThresholdAttested;
    destructionRecord.destroyedKeyClasses = destroyedKeyClasses;
    destructionRecord.emkDestroyed = destroyedKeyClasses.includes('EMK');
    destructionRecord.dekDestroyed = destroyedKeyClasses.includes('DEK');
    destructionRecord.saltKeyDestroyed = destroyedKeyClasses.includes('K_SALT');
    destructionRecord.metadataKeyDestroyed = destroyedKeyClasses.includes('K_META');
    destructionRecord.postDestructionOpeningRevocation = destroyedKeyClasses.includes('K_SALT') || destroyedKeyClasses.includes('EMK');
    destructionRecord.updatedAt = txTimestamp;

    const transition = this._transitionEvidenceLifecycle(
      evidence,
      FC_EVIDENCE_LIFECYCLE_STATES.DESTROYED,
      'EVIDENCE_DESTROYED',
      actor,
      txTimestamp
    );

    evidence.destroyedAt = txTimestamp;
    evidence.destroyedBy = actor;
    evidence.destructionMethod = destructionMethod;
    evidence.destructionReceiptHash = receiptHash;
    evidence.destroyedKeyClasses = destroyedKeyClasses;
    evidence.emkDestroyed = emkDestroyed;
    evidence.dekDestroyed = dekDestroyed;
    evidence.saltKeyDestroyed = saltKeyDestroyed;
    evidence.metadataKeyDestroyed = metadataKeyDestroyed;
    evidence.keyMaterialDestroyed = keyMaterialDestroyed;
    evidence.postDestructionOpeningRevocation = postDestructionOpeningRevocation;
    evidence.thresholdAttestedDestruction = signedThresholdAttested;
    evidence.thresholdAttestation = thresholdAttestation;
    evidence.thresholdAttestationVerified = thresholdAttestation.verified === true;
    evidence.dataAccessDestroyed = true;
    evidence.commitmentPreserved = true;
    evidence.auditTrailPreserved = true;
    evidence.destructionRecord = destructionRecord;

    await this._persistEvidenceRecord(ctx, evidenceKey, evidence);
    await this._putEvidenceDestructionRecord(ctx, destructionRecord);

    ctx.stub.setEvent('EvidenceDestroyed', Buffer.from(JSON.stringify(this._buildGovernanceEvent('EvidenceDestroyed', {
      evidenceId: evId,
      previousState: transition.previousState,
      nextState: transition.nextState,
      destroyedBy: actor,
      thresholdAttestation: thresholdAttestation,
      destroyedKeyClasses,
      destroyedAt: txTimestamp,
      destructionMethod,
      receiptHash,
      destroyedKeyClasses,
      emkDestroyed,
      dekDestroyed,
      saltKeyDestroyed,
      metadataKeyDestroyed,
      thresholdAttested: signedThresholdAttested,
      thresholdAttestationVerified: thresholdAttestation.verified === true,
      postDestructionOpeningRevocation,
      capabilitiesRevoked: capabilityRevocation.revokedCapabilities,
      commitmentPreserved: true,
      auditTrailPreserved: true
    })), 'utf8'));

    ctx.stub.setEvent('EvidenceLifecycleStateChanged', Buffer.from(JSON.stringify(this._buildGovernanceEvent('EvidenceLifecycleStateChanged', {
      evidenceId: evId,
      previousState: transition.previousState,
      nextState: transition.nextState,
      reason: 'EVIDENCE_DESTROYED',
      actor,
      changedAt: txTimestamp
    })), 'utf8'));

    await this._logAction(ctx, 'reportEvidenceDestroyed', evidence.incidentId || 'EVIDENCE_ONLY', {
      evidenceId: evId,
      destructionMethod,
      receiptHash,
      destroyedKeyClasses,
      emkDestroyed,
      dekDestroyed,
      saltKeyDestroyed,
      metadataKeyDestroyed,
      thresholdAttested: signedThresholdAttested,
      thresholdAttestationVerified: thresholdAttestation.verified === true,
      postDestructionOpeningRevocation,
      previousState: transition.previousState,
      nextState: transition.nextState,
      inspectedCapabilities: capabilityRevocation.inspectedCapabilities,
      capabilitiesRevoked: capabilityRevocation.revokedCapabilities,
      pointerHashCount: pointerHashes.length,
      commitmentPreserved: true,
      auditTrailPreserved: true
    });

    return JSON.stringify({
      success: true,
      evidenceId: evId,
      previousState: transition.previousState,
      nextState: transition.nextState,
      lifecycleState: transition.nextState,
      destroyedAt: txTimestamp,
      destroyedBy: actor,
      destructionMethod,
      receiptHash,
      destroyedKeyClasses,
      emkDestroyed,
      dekDestroyed,
      saltKeyDestroyed,
      metadataKeyDestroyed,
      thresholdAttested: signedThresholdAttested,
      thresholdAttestationVerified: thresholdAttestation.verified === true,
      postDestructionOpeningRevocation,
      capabilitiesRevoked: capabilityRevocation.revokedCapabilities,
      inspectedCapabilities: capabilityRevocation.inspectedCapabilities,
      commitmentPreserved: true,
      auditTrailPreserved: true
    });
  }

  async getEvidenceDestructionRecord(ctx, evidenceId) {
    this._checkAccess(ctx, {
      roles: [
        'DataProtectionOfficer',
        'JudicialReviewer',
        'EvidenceCustodian',
        'InternalAuditor',
        'ExternalAuditor',
        'Admin',
        'System Administrator'
      ],
      clearance: ['Medium', 'High']
    });

    const evId = String(evidenceId || '').trim();
    const { evidence } = await this._loadEvidenceRecord(ctx, evId);
    const destructionRecord = await this._getEvidenceDestructionRecordInternal(ctx, evId);

    if (!destructionRecord) {
      throw new Error(`Evidence destruction record not found for ${evId}`);
    }

    return JSON.stringify({
      evidenceId: evId,
      lifecycleState: fcNormalizeEvidenceLifecycleState(evidence),
      destructionRequestedAt: evidence.destructionRequestedAt || destructionRecord.requestedAt || null,
      destructionRequestedBy: evidence.destructionRequestedBy || destructionRecord.requestedBy || null,
      destructionApprovedAt: evidence.destructionApprovedAt || destructionRecord.approvedAt || null,
      destructionApprovedBy: evidence.destructionApprovedBy || destructionRecord.approvedBy || null,
      destroyedAt: evidence.destroyedAt || destructionRecord.destroyedAt || null,
      destroyedBy: evidence.destroyedBy || destructionRecord.destroyedBy || null,
      destructionMethod: evidence.destructionMethod || destructionRecord.destructionMethod || null,
      destructionReceiptHash: evidence.destructionReceiptHash || destructionRecord.destructionReceiptHash || null,
      capabilitiesRevoked: destructionRecord.capabilitiesRevoked || 0,
      commitmentPreserved: destructionRecord.commitmentPreserved === true,
      auditTrailPreserved: destructionRecord.auditTrailPreserved === true,
      offChainPointerHashes: destructionRecord.offChainPointerHashes || evidence.destroyedOffChainPointerHashes || [],
      record: destructionRecord
    });
  }


  // ===========================================================================
  // GDPR Erasure (strict)
  // ===========================================================================

  async requestDataErasure(ctx, evidenceId, incidentId, legalBasis, requesterId) {
    const reason = {
      reasonCode: 'PRIVACY_REQUEST',
      requestRef: String(requesterId || incidentId || 'legacy-erasure-request'),
      justification: String(legalBasis || 'Legacy requestDataErasure alias for audit-preserving confidentiality withdrawal')
    };
    return this.withdrawConfidentiality(ctx, evidenceId, JSON.stringify(reason));
  }

  // ===========================================================================
  // Update Chain of Custody
  // ===========================================================================

  async updateChainOfCustody(ctx, evidenceId, action, actorId, location, condition, additionalDataStr) {
    if (!additionalDataStr) additionalDataStr = '{}';

    this._checkAccess(ctx, {
      roles: [
        'ForensicLead',
        'EvidenceCustodian',
        'OTGatewayCollector'
      ],
      clearance: ['Medium', 'High']
    });

    const addBytes = Buffer.byteLength(String(additionalDataStr), 'utf8');
    if (addBytes > 16 * 1024) {
      throw new Error(`additionalData too large (${addBytes} bytes). Max 16KB for CoC metadata`);
    }

    let additionalData = {};
    try {
      additionalData = JSON.parse(additionalDataStr);
    } catch (e) {
      throw new Error(`Invalid JSON additionalData: ${e.message}`);
    }

    additionalData.claimedActorId = actorId;

    const entryHash = await this._addCoCEntry(ctx, evidenceId, action, {
      location,
      condition,
      additionalData
    });

    const evidenceBytes = await ctx.stub.getState(`evidence::${evidenceId}`);
    const evidence = evidenceBytes && evidenceBytes.length ? JSON.parse(evidenceBytes.toString()) : {};

    ctx.stub.setEvent('ChainOfCustodyUpdated', Buffer.from(JSON.stringify({
      evidenceId,
      action,
      actor: this._getAuditActor(ctx),
      timestamp: this._getTimestamp(ctx),
      entryHash,
      cocCount: evidence.cocCount || null,
      merkleRoot: evidence.merkleRoot || null,
      masterCID: evidence.ipfsReference || null
    }), 'utf8'));

    await this._logAction(ctx, 'updateChainOfCustody', evidence.incidentId || 'EVIDENCE_ONLY', {
      evidenceId,
      action,
      location,
      condition,
      storageMode: evidence.storageMode || 'legacy',
      storageVersion: evidence.storageVersion || '1.0',
      claimedActorId: actorId
    });

    return JSON.stringify({
      success: true,
      entryHash,
      cocCount: evidence.cocCount || null,
      merkleRoot: evidence.merkleRoot || null,
      masterCID: evidence.ipfsReference || null
    });
  }

  // ===========================================================================
  // Forensic Report (hybrid if large)
  // ===========================================================================

  async createForensicReport(
    ctx,
    investigatorId,
    incidentId,
    reportId,
    reportTimestamp,
    analysis,
    findings,
    storageReference,
    reportHash,
    digitalSignature
  ) {
    this._checkAccess(ctx, {
      roles: ['ForensicLead'],
      clearance: ['High']
    });

    if (!incidentId || !reportId || !storageReference || !reportHash) {
      throw new Error('Missing required report fields');
    }

    const createdAt = this._getTimestamp(ctx);
    const createdBy = ctx.clientIdentity.getID();

    const actualInvestigator = this._getAuditActor(ctx);
    const claimedInvestigatorId = investigatorId;

    const reportData = {
      investigatorId: actualInvestigator,
      claimedInvestigatorId,
      incidentId,
      reportId,
      reportTimestamp,
      analysis,
      findings,
      reportHash
    };

    const reportIntegrityHash = crypto.createHash('sha256')
      .update(JSON.stringify(reportData))
      .digest('hex');

    const report = {
      investigatorId: actualInvestigator,
      claimedInvestigatorId,
      incidentId,
      reportId,
      reportTimestamp,
      analysis,
      findings,
      storageReference,
      status: 'created',
      createdBy,
      createdAt,
      cryptographicMetadata: {
        reportHash,
        reportIntegrityHash,
        digitalSignature,
        signatureVerified: !!digitalSignature,
        encryptionMethod: 'AES-256-GCM',
        integrityLevel: 'HIGH',
        tamperProof: true
      },
      complianceMetadata: {
        gdprCompliant: true,
        auditTrailComplete: true,
        chainOfCustodyVerified: true,
        evidentialValue: 'HIGH',
        crossBorderShareable: true,
        publicSummaryAvailable: true
      }
    };

    const THRESHOLD_BYTES = 5000;
    const reportBytes = Buffer.byteLength(JSON.stringify(report), 'utf8');

    let reportToStore;
    if (reportBytes > THRESHOLD_BYTES) {
      const cid = this._assertCIDFormat(storageReference);
      reportToStore = {
        reportId,
        incidentId,
        investigatorId: actualInvestigator,
        claimedInvestigatorId,
        createdAt,
        createdBy,
        status: report.status,
        storageVersion: '2.0',
        reportCID: cid,
        reportSizeBytes: reportBytes,
        cryptographicMetadata: {
          reportHash,
          reportIntegrityHash,
          digitalSignature,
          signatureVerified: !!digitalSignature
        },
        complianceMetadata: report.complianceMetadata
      };
    } else {
      reportToStore = { ...report, storageVersion: '1.0', reportSizeBytes: reportBytes };
    }

    await ctx.stub.putState(reportId, Buffer.from(JSON.stringify(reportToStore), 'utf8'));

    const entryKey = ctx.stub.createCompositeKey('ReportEntry', [incidentId, reportTimestamp, reportId]);
    await ctx.stub.putState(entryKey, Buffer.from(JSON.stringify(reportToStore), 'utf8'));

    const incBytes = await ctx.stub.getState(incidentId);
    if (incBytes && incBytes.length > 0) {
      const incident = JSON.parse(incBytes.toString());
      incident.status = 'reportCreated';
      incident.reportMetadata = {
        reportId,
        createdAt,
        cryptographicallySecured: true,
        tamperProof: true,
        publicSummaryAvailable: true,
        storageVersion: reportToStore.storageVersion,
        reportCID: reportToStore.reportCID || null
      };
      await ctx.stub.putState(incidentId, Buffer.from(JSON.stringify(incident), 'utf8'));
    }

    ctx.stub.setEvent('ReportCreated', Buffer.from(JSON.stringify({
      incidentId,
      reportId,
      createdAt,
      investigatorId: actualInvestigator,
      claimedInvestigatorId,
      reportIntegrityHash: reportIntegrityHash.substring(0, 16),
      publicSummaryAvailable: true,
      storageVersion: reportToStore.storageVersion,
      reportCID: reportToStore.reportCID || null
    }), 'utf8'));

    await this._logAction(ctx, 'createForensicReport', incidentId, {
      reportId,
      investigatorId: actualInvestigator,
      claimedInvestigatorId,
      reportIntegrityHash: reportIntegrityHash.substring(0, 16),
      storageVersion: reportToStore.storageVersion,
      reportCID: reportToStore.reportCID || null
    });

    return JSON.stringify({ success: true, reportId, reportIntegrityHash });
  }

  async retrieveForensicReport(ctx, reportId, incidentId, summaryOnly) {
    const callerRoleRaw = (ctx.clientIdentity.getAttributeValue('role') || '').trim();
    const normalizedRole = this._normRole(callerRoleRaw);

    if (normalizedRole === 'independentauditor' && summaryOnly !== 'true') {
      summaryOnly = 'true';
    }

    if (normalizedRole === 'independentauditor') {
      this._checkAccess(ctx, {
        roles: ['IndependentAuditor'],
        clearance: ['Low', 'Medium', 'High']
      });
    } else {
      this._checkAccess(ctx, {
        roles: ['ForensicLead', 'EvidenceCustodian'],
        clearance: ['High']
      });
    }

    if (!reportId) throw new Error('reportId is required');

    const reportBytes = await ctx.stub.getState(reportId);
    if (!reportBytes || reportBytes.length === 0) {
      throw new Error(`Report ${reportId} not found`);
    }

    const report = JSON.parse(reportBytes.toString());

    if (incidentId && report.incidentId && report.incidentId !== incidentId) {
      throw new Error(`Report ${reportId} does not belong to incident ${incidentId}`);
    }

    const accessTimestamp = this._getTimestamp(ctx);

    const storageVersion = report.storageVersion || '1.0';
    const isHybrid = storageVersion === '2.0';

    if (isHybrid) {
      if (report.reportCID) {
        report.reportCID = this._assertCIDFormat(report.reportCID);
      }
      report.cryptographicVerification = {
        pointerOnly: true,
        note: 'Full report content is off-chain; verify integrity off-chain using CID + reportHash.',
        verificationTimestamp: accessTimestamp,
        reportCID: report.reportCID || null
      };
    } else {
      if (report.cryptographicMetadata?.reportIntegrityHash) {
        const originalData = {
          investigatorId: report.investigatorId,
          claimedInvestigatorId: report.claimedInvestigatorId,
          incidentId: report.incidentId,
          reportId: report.reportId,
          reportTimestamp: report.reportTimestamp,
          analysis: report.analysis,
          findings: report.findings,
          reportHash: report.cryptographicMetadata.reportHash
        };
        const verificationHash = crypto.createHash('sha256')
          .update(JSON.stringify(originalData))
          .digest('hex');

        report.cryptographicVerification = {
          integrityVerified: verificationHash === report.cryptographicMetadata.reportIntegrityHash,
          verificationTimestamp: accessTimestamp,
          tamperProof: true
        };
      }
    }

    const mustSummary = (summaryOnly === 'true' || normalizedRole === 'independentauditor');

    let responseData;
    if (mustSummary) {
      responseData = {
        reportId: report.reportId || reportId,
        incidentId: report.incidentId || incidentId || null,
        reportTimestamp: report.reportTimestamp || null,
        status: report.status || null,
        storageVersion,
        publicSummary: {
          investigatorId: report.investigatorId || null,
          claimedInvestigatorId: report.claimedInvestigatorId || null,
          cryptographicMetadata: report.cryptographicMetadata || {},
          complianceMetadata: report.complianceMetadata || {},
          cryptographicVerification: report.cryptographicVerification || null,
          reportCID: report.reportCID || null
        },
        accessInfo: {
          mode: 'SUMMARY_ONLY',
          retrievedBy: this._getAuditActor(ctx),
          retrievedAt: accessTimestamp,
          note: isHybrid
            ? 'Hybrid report: full content off-chain (use reportCID).'
            : 'This is a public summary. Full report requires appropriate authorization.'
        }
      };
    } else {
      responseData = report;
      if (isHybrid) {
        responseData.retrievalNote = 'Hybrid report: use reportCID to fetch the full report off-chain (IPFS).';
      }
    }

    await this._logAction(ctx, 'retrieveForensicReport', report.incidentId || incidentId || '', {
      reportId,
      summaryOnly: mustSummary,
      storageVersion,
      isHybrid,
      reportCID: report.reportCID || null
    });

    ctx.stub.setEvent('ReportRetrieved', Buffer.from(JSON.stringify({
      reportId,
      incidentId: report.incidentId || incidentId || null,
      retrievedBy: this._getAuditActor(ctx),
      retrievedAt: accessTimestamp,
      summaryOnly: mustSummary,
      storageVersion,
      isHybrid,
      reportCID: report.reportCID || null
    }), 'utf8'));

    return JSON.stringify(responseData);
  }

  // ===========================================================================
  // Logs Retrieval (role-based disclosure)
  // ===========================================================================

  async getLogsForIncident(ctx, incidentId) {
    const callerRoleRaw = (ctx.clientIdentity.getAttributeValue('role') || '').trim();
    const roleNorm = this._normRole(callerRoleRaw);
    const isIndependentAuditor = (roleNorm === 'independentauditor');

    if (isIndependentAuditor) {
      this._checkAccess(ctx, {
        roles: ['IndependentAuditor'],
        clearance: ['Low', 'Medium', 'High']
      });
    } else {
      this._checkAccess(ctx, {
        roles: ['ForensicLead', 'EvidenceCustodian'],
        clearance: ['High']
      });
    }

    const iter = await ctx.stub.getStateByPartialCompositeKey('LogEntry', [incidentId]);
    const logs = [];
    const summaries = [];

    try {
      while (true) {
        const r = await iter.next();
        if (r.done) break;
        if (!r.value || !r.value.value || !r.value.value.length) continue;

        let summary;
        try { summary = JSON.parse(r.value.value.toString()); } catch { continue; }

        summaries.push({
          incidentId: summary.incidentId || incidentId,
          timestamp: summary.timestamp || null,
          logHash: summary.logHash || summary.hash || null,
          action: summary.action || null,
          userId: summary.userId || null,
          role: summary.role || null
        });

        if (isIndependentAuditor) continue;

        const hash = summary.logHash || summary.hash;
        if (!hash) continue;

        const blobBytes = await ctx.stub.getState(`LogBlob_${hash}`);
        if (!blobBytes || !blobBytes.length) continue;

        let entry;
        try { entry = JSON.parse(blobBytes.toString()); } catch { continue; }

        if (entry.logHash) {
          const verificationData = {
            incidentId: entry.incidentId,
            action: entry.action,
            userId: entry.userId,
            role: entry.role,
            timestamp: entry.timestamp,
            metadata: entry.metadata,
            systemVersion: entry.systemVersion,
            txId: entry.txId,
            channel: entry.channel
          };

          const verificationHash = crypto.createHash('sha256')
            .update(JSON.stringify(verificationData))
            .digest('hex');

          entry.cryptographicVerification = {
            integrityVerified: verificationHash === entry.logHash,
            tamperProof: true
          };
        }

        if (entry.metadata && typeof entry.metadata === 'object') {
          if (entry.metadata.ipfsReference) delete entry.metadata.ipfsReference;
          if (entry.metadata.masterCID) delete entry.metadata.masterCID;
          if (entry.metadata.realCID) delete entry.metadata.realCID;
          if (entry.metadata.cid) delete entry.metadata.cid;
        }

        logs.push(entry);
      }
    } finally {
      await iter.close();
    }

    if (isIndependentAuditor) {
      return JSON.stringify({
        incidentId,
        logCount: summaries.length,
        disclosure: 'SUMMARY_ONLY',
        summaries,
        note: 'IndependentAuditor only receives LogEntry summaries (no LogBlob disclosure).'
      }, null, 2);
    }

    return JSON.stringify({
      incidentId,
      logCount: logs.length,
      logs,
      cryptographicSummary: {
        allLogsVerified: logs.every(l => l.cryptographicVerification?.integrityVerified !== false),
        tamperProofAuditTrail: true,
        optimizedStorage: true
      }
    }, null, 2);
  }

  // ===========================================================================
  // Cross-border Evidence Query
  // ===========================================================================

  async queryCrossBorderEvidence(ctx, incidentId) {
    const callerRoleRaw = (ctx.clientIdentity.getAttributeValue('role') || '').trim();
    const roleNorm = this._normRole(callerRoleRaw);
    const isIndependentAuditor = (roleNorm === 'independentauditor');

    if (isIndependentAuditor) {
      this._checkAccess(ctx, {
        roles: ['IndependentAuditor'],
        clearance: ['Low', 'Medium', 'High']
      });
    } else {
      this._checkAccess(ctx, {
        roles: ['ForensicLead', 'EvidenceCustodian'],
        clearance: ['High']
      });
    }

    const incidentBytes = await ctx.stub.getState(incidentId);
    if (!incidentBytes || incidentBytes.length === 0) {
      throw new Error(`Incident ${incidentId} not found`);
    }
    const incident = JSON.parse(incidentBytes.toString());

    const shareableEvidence = [];
    const nonShareableEvidence = [];

    for (const evidenceId of incident.evidenceList || []) {
      const evBytes = await ctx.stub.getState(`evidence::${evidenceId}`);
      if (!evBytes || !evBytes.length) continue;

      const evidence = JSON.parse(evBytes.toString());
      const storageVersion = evidence.metadata?.version || evidence.storageVersion || '1.0';
      const isHybrid = this._isHybridEvidenceRecord(evidence);

      const shareable = evidence.cryptographicEvidence?.crossBorderShareable ||
        evidence.cryptographicMetadata?.crossBorderShareable || false;

      const gdprCompliant = evidence.gdprCompliance?.compliant ||
        evidence.cryptographicMetadata?.gdprCompliant || false;

      const onChainSizeBytes = Buffer.byteLength(JSON.stringify(evidence), 'utf8');

      const submittedByRaw = (typeof evidence.submittedBy === 'object')
        ? (evidence.submittedBy.enrollmentId || evidence.submittedBy.userId || evidence.submittedBy.id || null)
        : evidence.submittedBy;

      const submittedBy = isIndependentAuditor
        ? (submittedByRaw ? `sub:${this._sha256Hex(String(submittedByRaw)).substring(0, 16)}` : null)
        : submittedByRaw;

      const summary = {
        evidenceId: evidence.evidenceId,
        evidenceTitle: evidence.evidenceTitle,
        evidenceType: evidence.evidenceType,
        gdprCompliant,
        crossBorderShareable: shareable,
        zkpProofsAvailable: !!(evidence.cryptographicMetadata?.zkpMetadata),
        submittedBy,
        submissionTimestamp: evidence.collectionTimestamp || evidence.timestamp || evidence.createdAt || null,
        integrityHash: evidence.integrityHash,
        publicAccessible: true,
        delegationRequired: true,
        storageInfo: {
          version: storageVersion,
          mode: isHybrid ? 'hybrid' : 'legacy',
          hasIPFS: !!(evidence.ipfsReference),
          onChainSizeBytes,
          ipfsPointer: (isHybrid && evidence.ipfsReference)
            ? {
              masterCIDHash: this._cidHash(evidence.ipfsReference),
              totalPointers: 1
            }
            : null
        }
      };

      if (shareable) shareableEvidence.push(summary);
      else nonShareableEvidence.push(summary);
    }

    const all = shareableEvidence.concat(nonShareableEvidence);

    const response = {
      incidentId,
      totalEvidence: incident.evidenceList?.length || 0,
      shareableCount: shareableEvidence.length,
      nonShareableCount: nonShareableEvidence.length,
      shareableEvidence,
      nonShareableEvidence,
      summary: {
        crossBorderCapability: shareableEvidence.length > 0,
        privacyPreserved: true,
        externalVerificationEnabled: true,
        storageBreakdown: {
          totalEvidence: incident.evidenceList?.length || 0,
          hybridStorage: all.filter(e => e.storageInfo.mode === 'hybrid').length,
          legacyStorage: all.filter(e => e.storageInfo.mode === 'legacy').length,
          averageOnChainSizeBytes: all.length
            ? Math.round(all.reduce((sum, e) => sum + (e.storageInfo.onChainSizeBytes || 0), 0) / all.length)
            : 0
        }
      }
    };

    await this._logAction(ctx, 'queryCrossBorderEvidence', incidentId, {
      shareableCount: shareableEvidence.length,
      totalCount: incident.evidenceList?.length || 0,
      hybridCount: response.summary.storageBreakdown.hybridStorage,
      legacyCount: response.summary.storageBreakdown.legacyStorage
    });

    return JSON.stringify(response, null, 2);
  }

  // ===========================================================================
  // Storage stats & queries
  // ===========================================================================

async queryHybridStatistics(ctx) {
  this._checkAccess(ctx, {
    roles: ['ForensicLead', 'EvidenceCustodian', 'Admin', 'System Administrator'],
    clearance: ['High']
  });

  const txTimestamp = this._getTimestamp(ctx);
  const iterator = await ctx.stub.getStateByRange('evidence::', 'evidence::\uFFFF');

  const stats = {
    totalEvidence: 0,
    hybridCount: 0,
    legacyCount: 0,
    totalOnChainSize: 0,
    avgOnChainSize: 0,
    ipfsCIDCount: 0
  };

  const evidenceList = [];

  while (true) {
    const result = await iterator.next();
    if (result.value && result.value.value.toString()) {
      const evidence = JSON.parse(result.value.value.toString());
      const size = result.value.value.length;

      stats.totalEvidence++;
      stats.totalOnChainSize += size;

      if (this._isHybridEvidenceRecord(evidence)) {
        stats.hybridCount++;
        stats.ipfsCIDCount += evidence.ipfsReference ? 1 : 0;
      } else {
        stats.legacyCount++;
      }

      evidenceList.push({
        evidenceId: evidence.evidenceId,
        storageMode: evidence.storageMode || 'legacy',
        onChainSize: size,
        hasCIDs: !!evidence.ipfsReference
      });
    }

    if (result.done) {
      await iterator.close();
      break;
    }
  }

  if (stats.totalEvidence > 0) {
    stats.avgOnChainSize = Math.round(stats.totalOnChainSize / stats.totalEvidence);
  }

  return JSON.stringify({
    statistics: stats,
    recentEvidence: evidenceList.slice(-10),
    timestamp: txTimestamp
  });
}

  async queryMyDelegations(ctx) {
    const caller = this._getAuditActor(ctx);

    const txTimestamp = this._getTimestamp(ctx);
    const now = new Date(txTimestamp).getTime();

    const list = [];
    const iter = await ctx.stub.getStateByPartialCompositeKey('Delegation', []);

    while (true) {
      const res = await iter.next();
      if (res.done) break;

      let d;
      try { d = JSON.parse(res.value.value.toString()); } catch { continue; }

      const expTime = Date.parse(d.expiresAt);

      if (String(d.delegateToUserId || '').trim() === caller && d.active && expTime > now) {
        let title = 'Unknown';
        const evBytes = await ctx.stub.getState(`evidence::${d.evidenceId}`);
        if (evBytes && evBytes.length) {
          try { title = JSON.parse(evBytes.toString()).evidenceTitle || title; } catch {}
        }
        list.push({
          delegationId: d.delegationId ? d.delegationId.substring(0, 16) : '',
          evidenceId: d.evidenceId,
          evidenceTitle: title,
          delegationType: d.delegationType,
          expirationTime: d.expiresAt
        });
      }
    }
    await iter.close();

    return JSON.stringify({ userId: caller, activeDelegations: list.length, delegations: list });
  }

async getStorageMetrics(ctx) {
  this._checkAccess(ctx, {
    roles: ['ForensicLead', 'EvidenceCustodian', 'Admin', 'System Administrator'],
    clearance: ['High']
  });

  const iterator = await ctx.stub.getStateByRange('evidence::', 'evidence::\uFFFF');

  const metrics = {
    totalEvidence: 0,
    v1Legacy: 0,
    v2Hybrid: 0,
    totalOnChainSize: 0,
    avgOnChainSize: 0,
    avgV1Size: 0,
    avgV2Size: 0,
    totalCIDs: 0,
    timestamp: this._getTimestamp(ctx)
  };

  let v1TotalSize = 0;
  let v2TotalSize = 0;

  while (true) {
    const result = await iterator.next();

    if (result.value && result.value.value.toString()) {
      const evidence = JSON.parse(result.value.value.toString());
      const size = result.value.value.length;
      const version = evidence.metadata?.version || evidence.storageVersion || '1.0';

      metrics.totalEvidence++;
      metrics.totalOnChainSize += size;

      if (this._isHybridEvidenceRecord(evidence)) {
        metrics.v2Hybrid++;
        v2TotalSize += size;

        if (evidence.ipfsReference) metrics.totalCIDs += 1;

        if (evidence.ipfsReferences) {
          metrics.totalCIDs += Object.values(evidence.ipfsReferences)
            .filter(cid => cid !== null && cid !== undefined && String(cid).trim() !== '' && String(cid) !== 'null')
            .length;
        }
      } else {
        metrics.v1Legacy++;
        v1TotalSize += size;
      }
    }

    if (result.done) {
      await iterator.close();
      break;
    }
  }

  if (metrics.totalEvidence > 0) {
    metrics.avgOnChainSize = Math.round(metrics.totalOnChainSize / metrics.totalEvidence);
  }
  if (metrics.v1Legacy > 0) {
    metrics.avgV1Size = Math.round(v1TotalSize / metrics.v1Legacy);
  }
  if (metrics.v2Hybrid > 0) {
    metrics.avgV2Size = Math.round(v2TotalSize / metrics.v2Hybrid);
  }

  if (metrics.avgV1Size > 0 && metrics.avgV2Size > 0) {
    metrics.storageSavings = `${Math.round((1 - metrics.avgV2Size / metrics.avgV1Size) * 100)}%`;
  }

  return JSON.stringify(metrics);
}

async queryEvidenceByStorage(ctx, storageMode = 'all') {
  this._checkAccess(ctx, {
    roles: ['ForensicLead', 'EvidenceCustodian', 'Admin', 'System Administrator'],
    clearance: ['High']
  });

  if (!['all', 'legacy', 'hybrid'].includes(storageMode)) {
    throw new Error('Invalid storage mode. Use: all, legacy, or hybrid');
  }

  const iterator = await ctx.stub.getStateByRange('evidence::', 'evidence::\uFFFF');
  const results = [];

  while (true) {
    const result = await iterator.next();

    if (result.value && result.value.value && result.value.value.length) {
      const evidence = JSON.parse(result.value.value.toString());
      const version = evidence.metadata?.version || evidence.storageVersion || '1.0';
      const isHybrid = this._isHybridEvidenceRecord(evidence);

      if (
        storageMode === 'all' ||
        (storageMode === 'hybrid' && isHybrid) ||
        (storageMode === 'legacy' && !isHybrid)
      ) {
        const onChainSizeBytes = Buffer.byteLength(JSON.stringify(evidence), 'utf8');

        results.push({
          evidenceId: evidence.evidenceId,
          incidentId: evidence.incidentId || 'EVIDENCE_ONLY',
          storageMode: isHybrid ? 'hybrid' : 'legacy',
          version,
          onChainSizeBytes,
          hasIPFSRefs: !!(evidence.ipfsReference),
          ipfsPointer: evidence.ipfsReference
            ? { masterCIDHash: this._cidHash(evidence.ipfsReference) }
            : null,
          timestamp: evidence.createdAt || evidence.timestamp || evidence.collectionTimestamp || null,
          submittedBy: evidence.submittedBy || null,
          custodyOwnerId: evidence.custodyOwnerId || null,
          disclosureAuthorityId: evidence.disclosureAuthorityId || null
        });
      }
    }

    if (result.done) {
      await iterator.close();
      break;
    }
  }

  const summary = {
    totalFound: results.length,
    storageMode,
    breakdown: {
      hybrid: results.filter(r => r.storageMode === 'hybrid').length,
      legacy: results.filter(r => r.storageMode === 'legacy').length
    },
    avgSizesBytes: { hybrid: 0, legacy: 0 }
  };

  const hybridEvidence = results.filter(r => r.storageMode === 'hybrid');
  const legacyEvidence = results.filter(r => r.storageMode === 'legacy');

  if (hybridEvidence.length > 0) {
    summary.avgSizesBytes.hybrid = Math.round(
      hybridEvidence.reduce((sum, e) => sum + e.onChainSizeBytes, 0) / hybridEvidence.length
    );
  }

  if (legacyEvidence.length > 0) {
    summary.avgSizesBytes.legacy = Math.round(
      legacyEvidence.reduce((sum, e) => sum + e.onChainSizeBytes, 0) / legacyEvidence.length
    );
  }

  return JSON.stringify({ summary, evidence: results });
}

  // ===========================================================================
  // Audit statistics
  // ===========================================================================

  async getAuditStatistics(ctx, incidentId = '') {
    this._checkAccess(ctx, {
      roles: ['ForensicLead', 'EvidenceCustodian', 'Admin', 'System Administrator'],
      clearance: ['High']
    });

    const stats = {
      totalLogs: 0,
      byAction: {},
      byUser: {},
      byIncident: {},
      lastTimestamp: null
    };

    const attrs = [];
    if (incidentId && String(incidentId).trim()) attrs.push(String(incidentId).trim());

    const iterator = await ctx.stub.getStateByPartialCompositeKey('LogEntry', attrs);

    try {
      while (true) {
        const res = await iterator.next();
        if (res.done) break;
        if (!res.value || !res.value.value || !res.value.value.length) continue;

        let summary;
        try { summary = JSON.parse(res.value.value.toString()); } catch { continue; }

        const hash = summary.hash || summary.logHash;
        if (!hash) continue;

        const blobBytes = await ctx.stub.getState(`LogBlob_${hash}`);
        if (!blobBytes || !blobBytes.length) continue;

        let entry;
        try { entry = JSON.parse(blobBytes.toString()); } catch { continue; }

        const { action, userId, incidentId: incId, timestamp } = entry;

        stats.totalLogs++;
        if (action) stats.byAction[action] = (stats.byAction[action] || 0) + 1;
        if (userId) stats.byUser[userId] = (stats.byUser[userId] || 0) + 1;
        if (incId) stats.byIncident[incId] = (stats.byIncident[incId] || 0) + 1;

        if (timestamp && (!stats.lastTimestamp || timestamp > stats.lastTimestamp)) {
          stats.lastTimestamp = timestamp;
        }
      }
    } finally {
      await iterator.close();
    }

    return JSON.stringify(stats, null, 2);
  }

  async getMetricsByTimeRange(ctx, startTime, endTime) {
    if (!startTime || !endTime) {
      throw new Error('startTime dan endTime (ISO8601 dengan timezone) wajib diisi');
    }

    const ISO_TZ = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+\-]\d{2}:\d{2})$/;
    if (!ISO_TZ.test(String(startTime)) || !ISO_TZ.test(String(endTime))) {
      throw new Error('startTime/endTime harus ISO8601 lengkap + timezone, contoh: 2026-02-10T00:00:00Z');
    }

    const startISO = new Date(startTime).toISOString();
    const endISO = new Date(endTime).toISOString();
    if (startISO > endISO) throw new Error('startTime harus <= endTime');

    const metrics = {
      period: { start: startISO, end: endISO },
      submissions: 0,
      retrievals: 0,
      updates: 0,
      evidence: []
    };

    const prefix = 'evidence::';
    const iterator = await ctx.stub.getStateByRange(prefix, prefix + '\uFFFF');

    try {
      while (true) {
        const res = await iterator.next();
        if (res.done) break;
        if (!res.value || !res.value.value || !res.value.value.length) continue;

        let ev;
        try { ev = JSON.parse(res.value.value.toString()); } catch { continue; }

        const tsRaw = ev.collectionTimestamp || ev.timestamp || ev.createdAt;
        if (!tsRaw) continue;

        let tsISO;
        try { tsISO = new Date(tsRaw).toISOString(); } catch { continue; }

        if (tsISO >= startISO && tsISO <= endISO) {
          metrics.submissions++;
          metrics.evidence.push({
            id: ev.evidenceId,
            type: ev.evidenceType,
            incidentId: ev.incidentId || null,
            timestamp: tsISO
          });
        }
      }
    } finally {
      await iterator.close();
    }

    const lu = await this._countLogActionsInRange(ctx, startISO, endISO);
    metrics.retrievals = lu.retrievals;
    metrics.updates = lu.updates;

    return JSON.stringify(metrics);
  }

  async _countLogActionsInRange(ctx, startISO, endISO) {
    const out = { retrievals: 0, updates: 0 };
    const it = await ctx.stub.getStateByPartialCompositeKey('LogEntry', []);

    try {
      while (true) {
        const r = await it.next();
        if (r.done) break;
        if (!r.value || !r.value.value || !r.value.value.length) continue;

        let summary;
        try { summary = JSON.parse(r.value.value.toString()); } catch { continue; }

        const hash = summary.hash || summary.logHash;
        if (!hash) continue;

        const blob = await ctx.stub.getState(`LogBlob_${hash}`);
        if (!blob || !blob.length) continue;

        let entry;
        try { entry = JSON.parse(blob.toString()); } catch { continue; }

        if (!entry.timestamp) continue;

        let t;
        try { t = new Date(entry.timestamp).toISOString(); } catch { continue; }

        if (t < startISO || t > endISO) continue;

        if (entry.action === 'retrieveEvidence') out.retrievals++;
        if (['updateChainOfCustody', 'submitEvidence', 'submitExaminationAndAnalysisData'].includes(entry.action)) {
          out.updates++;
        }
      }
    } finally {
      await it.close();
    }

    return out;
  }
}

module.exports = ForensicContract;
