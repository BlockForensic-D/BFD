// SPDX-License-Identifier: Apache-2.0
/**
 * Client-side disclosure workflow utilities.
 *
 * Responsibilities:
 * - validate capability tokens on the client side
 * - enforce disclosure scope before bundle construction
 * - build disclosure bundles for HASH_ONLY and chunk disclosure modes
 * - verify disclosure bundles on the client side
 *
 * Bundle format:
 * - top-level bundleHash
 * - manifest.version = manifest-v1
 * - bundle.version   = disclosure-bundle-v1
 * - disclosedChunks use dataBase64
 * - proofs use { index, leaf, proof, root, leafCount }
 */

import { performance } from 'perf_hooks';
import {
  computeCapHash,
  computeScopeDigest,
  checkScope,
  verifyCapabilityToken,
  SCOPE_TYPES,
  isCapabilityUsableAtTime,
} from './capability-manager.js';
import { isDisclosurePermissibleState, normalizeEvidenceLifecycleState } from './evidence-lifecycle-manager.js';
import { EvidenceChunker, DEFAULT_CHUNK_SIZE } from './evidence-chunker.js';
import {
  buildMerkleTreeFromLeafHashes,
  buildMerkleTreeFromLeafHashesV3,
  generateProof,
  generateProofsBatch,
  generateProofsBatchV3,
  verifyProofFromPayload,
  verifyProofFromPayloadWithOpeningV3,
} from './evidence-merkle.js';
import { canonicalizeJson, sha256Hex } from './forensic-crypto.js';

export const DISCLOSURE_BUNDLE_VERSION = 'disclosure-bundle-v1';
export const DISCLOSURE_MANIFEST_VERSION = 'manifest-v1';
export const DISCLOSURE_COMMITMENT_VERSION = 'chunk-merkle-v2';
export const DISCLOSURE_COMMITMENT_VERSION_V3 = 'chunk-merkle-v3-hmac-opening';

export const DISCLOSURE_TYPES = Object.freeze({
  HASH_ONLY: 'HASH_ONLY',
  CHUNK_DISCLOSURE: 'CHUNK_DISCLOSURE',
});

function nowIso() {
  return new Date().toISOString();
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function cloneJson(value) {
  if (typeof globalThis.structuredClone === 'function') {
    return globalThis.structuredClone(value);
  }
  return JSON.parse(JSON.stringify(value));
}

function normalizeBuffer(value, fieldName = 'value') {
  if (Buffer.isBuffer(value)) {
    return Buffer.from(value);
  }

  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }

  if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) {
    return Buffer.from(new Uint8Array(value));
  }

  if (
    typeof ArrayBuffer !== 'undefined' &&
    ArrayBuffer.isView(value) &&
    value?.buffer instanceof ArrayBuffer
  ) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }

  if (Array.isArray(value)) {
    for (const b of value) {
      if (!Number.isInteger(b) || b < 0 || b > 255) {
        throw new TypeError(`${fieldName} array must contain only byte values (0..255)`);
      }
    }
    return Buffer.from(value);
  }

  if (typeof value === 'string') {
    return Buffer.from(value, 'utf8');
  }

  if (isPlainObject(value)) {
    if (value.type === 'Buffer' && Array.isArray(value.data)) {
      return normalizeBuffer(value.data, `${fieldName}.data`);
    }

    for (const key of ['dataBase64', 'base64', 'payloadBase64', 'contentBase64', 'chunkBase64']) {
      if (typeof value[key] === 'string') {
        return Buffer.from(value[key], 'base64');
      }
    }

    for (const key of ['hex', 'dataHex', 'payloadHex', 'contentHex', 'chunkHex']) {
      if (typeof value[key] === 'string') {
        const hex = value[key].trim();
        if (/^[a-fA-F0-9]+$/.test(hex) && hex.length % 2 === 0) {
          return Buffer.from(hex, 'hex');
        }
      }
    }

    for (const key of ['data', 'payload', 'buffer', 'bytes', 'raw', 'chunk', 'content', 'value', 'chunkData']) {
      if (value[key] != null) {
        if (typeof value[key] === 'string' && typeof value.encoding === 'string') {
          const enc = value.encoding.toLowerCase();
          if (enc === 'base64') return Buffer.from(value[key], 'base64');
          if (enc === 'hex') return Buffer.from(value[key], 'hex');
        }
        return normalizeBuffer(value[key], `${fieldName}.${key}`);
      }
    }
  }

  throw new TypeError(
    `${fieldName} must be Buffer, Uint8Array, ArrayBuffer, typed-array view, byte array, string, or object carrying binary payload`
  );
}

function normalizeNonEmptyString(value, fieldName) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new TypeError(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function normalizeOptionalString(value) {
  if (value == null) return '';
  return String(value).trim();
}

function normalizeChunkIndices(indices, fieldName = 'requestedChunkIndices') {
  if (!Array.isArray(indices)) {
    throw new TypeError(`${fieldName} must be an array`);
  }

  const normalized = [...new Set(indices.map((n) => {
    const parsed = typeof n === 'string' && n.trim() !== '' ? Number(n) : n;
    if (!Number.isSafeInteger(parsed) || parsed < 0) {
      throw new TypeError(`${fieldName} must contain only non-negative safe integers`);
    }
    return parsed;
  }))];

  normalized.sort((a, b) => a - b);
  return normalized;
}

function normalizeDigestHex(digest, fieldName) {
  const value = String(digest || '').trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(value)) {
    throw new TypeError(`${fieldName} must be a valid SHA-256 hex digest`);
  }
  return value;
}

function normalizeCommitmentVersionForDisclosure(version) {
  const value = normalizeOptionalString(version) || DISCLOSURE_COMMITMENT_VERSION;
  if (value === 'chunk-merkle-v2-integrity') return DISCLOSURE_COMMITMENT_VERSION;
  if (![DISCLOSURE_COMMITMENT_VERSION, DISCLOSURE_COMMITMENT_VERSION_V3].includes(value)) {
    throw new TypeError(`Unsupported disclosure commitmentVersion: ${value}`);
  }
  return value;
}

function isV3DisclosureCommitment(version) {
  return normalizeCommitmentVersionForDisclosure(version) === DISCLOSURE_COMMITMENT_VERSION_V3;
}

function isSupportedDisclosureCommitmentVersion(version) {
  try {
    normalizeCommitmentVersionForDisclosure(version);
    return true;
  } catch {
    return false;
  }
}

function normalizePositiveSafeInt(value, fieldName) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n <= 0) {
    throw new TypeError(`${fieldName} must be a positive safe integer`);
  }
  return n;
}

function normalizeNonNegativeSafeInt(value, fieldName) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new TypeError(`${fieldName} must be a non-negative safe integer`);
  }
  return n;
}

function jsonSizeBytes(value) {
  return Buffer.byteLength(JSON.stringify(value), 'utf8');
}

function normalizeNow(now) {
  const d = now == null ? new Date() : new Date(now);
  if (Number.isNaN(d.getTime())) {
    throw new TypeError('now must be a valid date/time');
  }
  return d;
}

function resolveCapabilityToken(capabilityLike) {
  if (isPlainObject(capabilityLike) && isPlainObject(capabilityLike.scope)) {
    return capabilityLike;
  }

  if (
    isPlainObject(capabilityLike) &&
    isPlainObject(capabilityLike.payload) &&
    isPlainObject(capabilityLike.payload.scope)
  ) {
    return capabilityLike.payload;
  }

  if (
    isPlainObject(capabilityLike) &&
    isPlainObject(capabilityLike.capabilityToken) &&
    isPlainObject(capabilityLike.capabilityToken.scope)
  ) {
    return capabilityLike.capabilityToken;
  }

  throw new TypeError('capabilityToken must be an object with a valid scope');
}

function resolveScopeType({ capabilityToken = null, scopeType = '', scope = null } = {}) {
  if (normalizeOptionalString(scopeType)) {
    return normalizeOptionalString(scopeType).toUpperCase();
  }

  if (capabilityToken && isPlainObject(capabilityToken.scope) && capabilityToken.scope.type) {
    return normalizeNonEmptyString(capabilityToken.scope.type, 'scope.type').toUpperCase();
  }

  if (scope && isPlainObject(scope) && scope.type) {
    return normalizeNonEmptyString(scope.type, 'scope.type').toUpperCase();
  }

  throw new TypeError('scope.type must be a non-empty string');
}

function resolveRequestedChunkIndices(params) {
  if (Array.isArray(params.requestedChunkIndices)) {
    return normalizeChunkIndices(params.requestedChunkIndices, 'requestedChunkIndices');
  }
  if (Array.isArray(params.requestedChunks)) {
    return normalizeChunkIndices(params.requestedChunks, 'requestedChunks');
  }
  return [];
}

function resolveDisclosedChunkIndices(params, requestedChunkIndices) {
  if (Array.isArray(params.disclosedChunkIndices)) {
    return normalizeChunkIndices(params.disclosedChunkIndices, 'disclosedChunkIndices');
  }
  return [...requestedChunkIndices];
}

function resolveMerkleRoot(tree) {
  const candidates = [
    tree?.root,
    tree?.merkleRoot,
    tree?.rootHash,
  ];

  for (const candidate of candidates) {
    if (typeof candidate === 'string') {
      return normalizeDigestHex(candidate, 'tree.root');
    }
  }

  throw new TypeError('buildMerkleTreeFromLeafHashes() did not return a valid root');
}

function buildProofRecord(chunkHashes, index, root) {
  const proofObj = generateProof(chunkHashes, index);

  if (Array.isArray(proofObj)) {
    return {
      index,
      leaf: chunkHashes[index],
      proof: proofObj,
      root,
      leafCount: chunkHashes.length,
    };
  }

  if (!proofObj || typeof proofObj !== 'object') {
    throw new TypeError(`generateProof(${index}) returned invalid value`);
  }

  return {
    index,
    leaf: normalizeDigestHex(
      proofObj.leaf ?? proofObj.leafHash ?? chunkHashes[index],
      `proofs[${index}].leaf`
    ),
    proof: Array.isArray(proofObj.proof) ? proofObj.proof : [],
    root: normalizeDigestHex(proofObj.root ?? root, `proofs[${index}].root`),
    leafCount: Number.isSafeInteger(proofObj.leafCount) ? proofObj.leafCount : chunkHashes.length,
  };
}

function buildSerializedChunk(rawChunk, meta, chunkHash, fallbackIndex, chunkSize, options = {}) {
  const safeMeta = isPlainObject(meta) ? meta : {};
  const commitmentVersion = normalizeCommitmentVersionForDisclosure(
    options.commitmentVersion ?? safeMeta.commitmentVersion
  );
  const index = Number.isSafeInteger(safeMeta.index) ? safeMeta.index : fallbackIndex;
  const offset = Number.isSafeInteger(safeMeta.offset) ? safeMeta.offset : (fallbackIndex * chunkSize);
  const length = Number.isSafeInteger(safeMeta.length) ? safeMeta.length : rawChunk.length;

  if (commitmentVersion === DISCLOSURE_COMMITMENT_VERSION_V3) {
    const salt = normalizeOptionalString(options.salt ?? safeMeta.salt ?? options.chunk?.salt);
    if (!/^[a-fA-F0-9]{64}$/.test(salt)) {
      throw new TypeError(`disclosedChunks[${fallbackIndex}].salt must be a 32-byte hex string for v3`);
    }
    return {
      index,
      offset,
      length,
      actualLength: length,
      commitmentVersion,
      salt: salt.toLowerCase(),
      dataBase64: rawChunk.toString('base64'),
    };
  }

  return {
    index,
    offset,
    length,
    hash: normalizeDigestHex(chunkHash, `disclosedChunks[${fallbackIndex}].hash`),
    dataBase64: rawChunk.toString('base64'),
  };
}

function deriveChunkMetadata(chunks, chunkSize) {
  return chunks.map((chunk, index) => ({
    index,
    offset: index * chunkSize,
    length: chunk.length,
  }));
}

function resolveChunkBuffers(chunked) {
  const candidates = [
    ['chunkBuffers', chunked?.chunkBuffers],
    ['buffers', chunked?.buffers],
    ['payloadChunks', chunked?.payloadChunks],
    ['parts', chunked?.parts],
    ['chunks', chunked?.chunks],
  ];

  for (const [label, candidate] of candidates) {
    if (!Array.isArray(candidate)) continue;

    try {
      return candidate.map((value, index) => normalizeBuffer(value, `${label}[${index}]`));
    } catch {
      // try next candidate
    }
  }

  return null;
}

function resolveChunkHashes(chunked) {
  const candidates = [
    chunked?.chunkHashes,
    chunked?.leafHashes,
    chunked?.hashes,
  ];

  const found = candidates.find(Array.isArray);
  if (!found) return null;

  return found.map((value, index) => normalizeDigestHex(value, `chunkHash[${index}]`));
}

function resolveChunkMetadata(chunked, chunks, chunkSize) {
  const candidates = [
    chunked?.chunkMetadata,
    chunked?.metadata,
    chunked?.chunkMeta,
  ];

  const found = candidates.find(Array.isArray);
  if (found) {
    return found.map((meta, index) => {
      const rawChunk = chunks?.[index];
      return {
        index: Number.isSafeInteger(meta?.index) ? meta.index : index,
        offset: Number.isSafeInteger(meta?.offset) ? meta.offset : (index * chunkSize),
        length: Number.isSafeInteger(meta?.length)
          ? meta.length
          : (rawChunk ? rawChunk.length : chunkSize),
        ...(meta?.commitmentVersion ? { commitmentVersion: meta.commitmentVersion } : {}),
        ...(meta?.salt ? { salt: meta.salt } : {}),
        ...(meta?.actualLength ? { actualLength: meta.actualLength } : {})
      };
    });
  }

  if (Array.isArray(chunks)) {
    return deriveChunkMetadata(chunks, chunkSize);
  }

  return null;
}

function normalizeChunkedResult(chunked, fileBuffer, requestedChunkSize) {
  if (!isPlainObject(chunked)) {
    throw new TypeError('EvidenceChunker.chunk() must return an object');
  }

  const chunkSize = Number.isSafeInteger(chunked.chunkSize) && chunked.chunkSize > 0
    ? chunked.chunkSize
    : Number(requestedChunkSize);

  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
    throw new TypeError('Unable to resolve valid chunkSize from EvidenceChunker.chunk()');
  }

  const chunkHashes = resolveChunkHashes(chunked);
  if (!chunkHashes) {
    throw new TypeError(
      'EvidenceChunker.chunk() did not provide chunk hashes (expected chunkHashes/leafHashes/hashes)'
    );
  }

  const chunks = resolveChunkBuffers(chunked);
  const chunkMetadata = resolveChunkMetadata(chunked, chunks, chunkSize);

  const totalChunks = Number.isSafeInteger(chunked.totalChunks) && chunked.totalChunks >= 0
    ? chunked.totalChunks
    : (chunks?.length ?? chunkHashes.length);

  const fileSize = Number.isSafeInteger(chunked.fileSize) && chunked.fileSize >= 0
    ? chunked.fileSize
    : fileBuffer.length;

  const fileHash = chunked.fileHash
    ? normalizeDigestHex(chunked.fileHash, 'fileHash')
    : normalizeDigestHex(sha256Hex(fileBuffer), 'fileHash');

  if (chunkHashes.length !== totalChunks) {
    throw new Error(
      `Chunk hash count mismatch: chunkHashes=${chunkHashes.length}, totalChunks=${totalChunks}`
    );
  }

  if (chunks && chunks.length !== totalChunks) {
    throw new Error(
      `Chunk payload count mismatch: chunks=${chunks.length}, totalChunks=${totalChunks}`
    );
  }

  if (chunkMetadata && chunkMetadata.length !== totalChunks) {
    throw new Error(
      `Chunk metadata count mismatch: chunkMetadata=${chunkMetadata.length}, totalChunks=${totalChunks}`
    );
  }

  return {
    chunks,
    chunkMetadata,
    chunkHashes,
    totalChunks,
    chunkSize,
    fileSize,
    fileHash,
  };
}

function ensureRootMatch(expectedOnChainRoot, computedRoot) {
  if (expectedOnChainRoot == null || String(expectedOnChainRoot).trim() === '') {
    return;
  }

  const expected = normalizeDigestHex(expectedOnChainRoot, 'expectedOnChainRoot');
  const actual = normalizeDigestHex(computedRoot, 'computedRoot');

  if (expected !== actual) {
    throw new Error('chunk_merkle_root_mismatch');
  }
}

function verifyCapabilityOrThrow(capabilityToken, issuerPublicKey, now) {
  if (!issuerPublicKey) {
    throw new TypeError('issuerPublicKey is required');
  }

  const token = resolveCapabilityToken(capabilityToken);
  const verification = verifyCapabilityToken(token, issuerPublicKey, normalizeNow(now));

  if (!verification.valid) {
    throw new Error(`invalid_capability_token:${verification.reason}`);
  }

  return { token, verification };
}

function checkHolderBindingOrThrow(token, requesterId) {
  const normalizedRequester = normalizeOptionalString(requesterId);
  if (!normalizedRequester) return;

  const granteeId = normalizeNonEmptyString(token.granteeId, 'capabilityToken.granteeId');
  if (normalizedRequester !== granteeId) {
    throw new Error('holder_identity_mismatch');
  }
}

function checkScopeOrThrow(scopeOrToken, requestedChunkIndices) {
  const normalizedRequested = normalizeChunkIndices(
    requestedChunkIndices,
    'requestedChunkIndices'
  );

  const scope =
    isPlainObject(scopeOrToken?.scope)
      ? scopeOrToken.scope
      : (isPlainObject(scopeOrToken) ? scopeOrToken : null);

  if (!scope) {
    throw new TypeError('scope.type must be a non-empty string');
  }

  const scopeCheck = checkScope(scope, normalizedRequested);

  if (!scopeCheck.allowed) {
    throw new Error(`scope_check_failed:${scopeCheck.reason}`);
  }

  return (
    scopeCheck.normalizedRequested ??
    scopeCheck.normalizedRequestedChunks ??
    scopeCheck.requestedChunkIndices ??
    normalizedRequested
  );
}

/**
 * Bundle hash canonical:
 * - ignore top-level bundleHash
 * - ignore localEvidenceInfo
 * - ignore legacy manifest.bundleHash if present
 */
export function computeBundleHash(bundle) {
  if (!isPlainObject(bundle)) {
    throw new TypeError('bundle must be a non-null object');
  }

  const cloned = cloneJson(bundle);
  delete cloned.bundleHash;
  delete cloned.localEvidenceInfo;

  if (isPlainObject(cloned.manifest)) {
    delete cloned.manifest.bundleHash;
  }

  return sha256Hex(canonicalizeJson(cloned));
}

export function buildDisclosureManifest(params) {
  if (!isPlainObject(params)) {
    throw new TypeError('params must be a non-null object');
  }

  const capabilityToken = params.capabilityToken != null
    ? resolveCapabilityToken(params.capabilityToken)
    : null;

  const evidenceId = normalizeNonEmptyString(params.evidenceId, 'evidenceId');
  const evidenceType = normalizeOptionalString(params.evidenceType);

  const scopeType = resolveScopeType({
    capabilityToken,
    scopeType: params.scopeType,
    scope: params.scope,
  });

  const requestedChunkIndices = resolveRequestedChunkIndices(params);
  const disclosedChunkIndices = resolveDisclosedChunkIndices(params, requestedChunkIndices);

  const disclosureType = normalizeOptionalString(params.disclosureType)
    ? normalizeOptionalString(params.disclosureType).toUpperCase()
    : (scopeType === SCOPE_TYPES.HASH_ONLY
      ? DISCLOSURE_TYPES.HASH_ONLY
      : DISCLOSURE_TYPES.CHUNK_DISCLOSURE);

  const totalChunks = normalizeNonNegativeSafeInt(
    params.totalChunks ?? params.chunkCount,
    'totalChunks'
  );

  const chunkSize = normalizePositiveSafeInt(params.chunkSize, 'chunkSize');

  const capId = normalizeNonEmptyString(
    params.capId ?? capabilityToken?.capId,
    'capId'
  );

  const issuerId = normalizeNonEmptyString(
    params.issuerId ?? capabilityToken?.issuerId,
    'issuerId'
  );

  const granteeId = normalizeNonEmptyString(
    params.granteeId ?? capabilityToken?.granteeId,
    'granteeId'
  );

  const requesterId = normalizeOptionalString(params.requesterId) || granteeId;
  const purpose = normalizeOptionalString(params.purpose ?? capabilityToken?.purpose);

  const capHash = normalizeDigestHex(
    params.capHash ?? (capabilityToken ? computeCapHash(capabilityToken) : ''),
    'capHash'
  );

  const scopeDigest = normalizeDigestHex(
    params.scopeDigest
      ?? (capabilityToken
        ? computeScopeDigest(capabilityToken.scope)
        : (params.scope ? computeScopeDigest(params.scope) : '')),
    'scopeDigest'
  );

  const fileHash = normalizeDigestHex(
    params.fileHash ?? params.integrityHash,
    'fileHash'
  );

  const chunkMerkleRoot = normalizeDigestHex(
    params.chunkMerkleRoot ?? params.merkleRoot,
    'chunkMerkleRoot'
  );

  const commitmentVersion = normalizeOptionalString(params.commitmentVersion)
    || DISCLOSURE_COMMITMENT_VERSION;

  const generatedAt = new Date(params.generatedAt ?? params.createdAt ?? nowIso()).toISOString();
  const disclosureTxId = normalizeOptionalString(params.disclosureTxId ?? params.txId);
  const disclosedAt = params.disclosedAt
    ? new Date(params.disclosedAt).toISOString()
    : generatedAt;
  const disclosureEventHash = normalizeOptionalString(params.disclosureEventHash);
  const blockNumber = params.blockNumber == null ? null : Number(params.blockNumber);

  return {
    version: DISCLOSURE_MANIFEST_VERSION,
    evidenceId,
    evidenceType,
    capId,
    capHash,
    scopeDigest,
    scopeType,
    disclosureType,
    issuerId,
    granteeId,
    requesterId,
    purpose,
    fileHash,
    chunkMerkleRoot,
    commitmentVersion,
    totalChunks,
    chunkSize,
    requestedChunkIndices,
    disclosedChunkIndices,
    generatedAt,
    disclosedAt,
    ...(disclosureTxId ? { disclosureTxId } : {}),
    ...(disclosureEventHash ? { disclosureEventHash } : {}),
    ...(Number.isFinite(blockNumber) ? { blockNumber } : {}),
  };
}

function buildChunkDisclosureCore(params) {
  if (!isPlainObject(params)) {
    throw new TypeError('params must be a non-null object');
  }

  const started = performance.now();

  const { token, verification } = verifyCapabilityOrThrow(
    params.capabilityToken,
    params.issuerPublicKey,
    params.now
  );

  checkHolderBindingOrThrow(token, params.requesterId);

  const requestedChunkIndices = checkScopeOrThrow(
    token,
    resolveRequestedChunkIndices(params)
  );

  const evidenceId = normalizeNonEmptyString(
    params.evidenceId ?? token.evidenceId,
    'evidenceId'
  );

  const evidenceType = normalizeOptionalString(params.evidenceType);
  const generatedAt = new Date(params.generatedAt ?? nowIso()).toISOString();
  const commitmentVersion = normalizeCommitmentVersionForDisclosure(
    params.commitmentVersion ?? token.commitmentVersion
  );
  const useV3Commitment = isV3DisclosureCommitment(commitmentVersion);

  const fileBuffer = normalizeBuffer(params.evidenceBuffer, 'evidenceBuffer');
  const requestedChunkSize = Number(params.chunkSize ?? DEFAULT_CHUNK_SIZE);

  const rawChunked = EvidenceChunker.chunk(fileBuffer, requestedChunkSize, {
    commitmentVersion,
    evidenceId,
    emk: params.emk ?? params.evidenceMasterKey,
    evidenceMasterKey: params.evidenceMasterKey,
    kSalt: params.kSalt,
    saltKey: params.saltKey,
    chunkSalts: params.chunkSalts,
  });
  const chunked = normalizeChunkedResult(rawChunked, fileBuffer, requestedChunkSize);

  const tree = useV3Commitment
    ? buildMerkleTreeFromLeafHashesV3(chunked.chunkHashes)
    : buildMerkleTreeFromLeafHashes(chunked.chunkHashes);
  const merkleRoot = resolveMerkleRoot(tree);

  ensureRootMatch(params.expectedOnChainRoot ?? params.onChainMerkleRoot, merkleRoot);

  if (!Array.isArray(chunked.chunks)) {
    throw new TypeError(
      'EvidenceChunker.chunk() did not provide raw chunk payloads needed for chunk disclosure'
    );
  }

  if (!Array.isArray(chunked.chunkMetadata)) {
    throw new TypeError('Unable to resolve chunk metadata for chunk disclosure');
  }

  // IMPORTANT:
  // Build all proofs in one batch so we do not rebuild the Merkle tree
  // once per disclosed chunk.
  const batchProofs = useV3Commitment
    ? generateProofsBatchV3(chunked.chunkHashes, requestedChunkIndices)
    : generateProofsBatch(chunked.chunkHashes, requestedChunkIndices);
  const proofMap = new Map(batchProofs.map((proofObj) => [proofObj.index, proofObj]));

  const disclosedChunks = [];
  const proofs = [];

  for (const idx of requestedChunkIndices) {
    if (idx >= chunked.totalChunks) {
      throw new RangeError(
        `requested chunk index ${idx} out of bounds for totalChunks=${chunked.totalChunks}`
      );
    }

    const rawChunk = chunked.chunks[idx];
    const meta = chunked.chunkMetadata[idx];
    const chunkHash = chunked.chunkHashes[idx];

    if (!rawChunk) {
      throw new Error(`chunk_material_missing: chunks[${idx}] is undefined`);
    }
    if (!meta) {
      throw new Error(`chunk_material_missing: chunkMetadata[${idx}] is undefined`);
    }
    if (!chunkHash) {
      throw new Error(`chunk_material_missing: chunkHashes[${idx}] is undefined`);
    }

    const proofRecord = proofMap.get(idx);
    if (!proofRecord) {
      throw new Error(`proof_material_missing: proof for index ${idx} is undefined`);
    }

    disclosedChunks.push(
      buildSerializedChunk(rawChunk, meta, chunkHash, idx, chunked.chunkSize, {
        commitmentVersion,
        chunk: chunked.chunks?.[idx],
        salt: chunked.chunks?.[idx]?.salt ?? meta?.salt
      })
    );

    const proofOut = {
      index: proofRecord.index,
      proof: Array.isArray(proofRecord.proof) ? proofRecord.proof : [],
      root: normalizeDigestHex(
        proofRecord.root ?? merkleRoot,
        `proofs[${idx}].root`
      ),
      leafCount: Number.isSafeInteger(proofRecord.leafCount)
        ? proofRecord.leafCount
        : chunked.chunkHashes.length,
    };

    if (!useV3Commitment) {
      proofOut.leaf = normalizeDigestHex(
        proofRecord.leaf ?? chunked.chunkHashes[idx],
        `proofs[${idx}].leaf`
      );
    }

    proofs.push(proofOut);
  }

  const bundle = {
    version: DISCLOSURE_BUNDLE_VERSION,
    manifest: buildDisclosureManifest({
      evidenceId,
      evidenceType,
      capabilityToken: token,
      capHash: verification.capHash,
      scopeDigest: verification.scopeDigest,
      disclosureType: DISCLOSURE_TYPES.CHUNK_DISCLOSURE,
      requesterId: normalizeOptionalString(params.requesterId) || token.granteeId,
      fileHash: chunked.fileHash,
      chunkMerkleRoot: merkleRoot,
      commitmentVersion,
      totalChunks: chunked.totalChunks,
      chunkSize: chunked.chunkSize,
      requestedChunkIndices,
      disclosedChunkIndices: requestedChunkIndices,
      generatedAt,
      disclosedAt: params.disclosedAt,
      disclosureTxId: params.disclosureTxId ?? params.txId,
      disclosureEventHash: params.disclosureEventHash,
      blockNumber: params.blockNumber,
    }),
    disclosedChunks,
    proofs,
    metrics: {
      fileSize: chunked.fileSize,
      chunkSize: chunked.chunkSize,
      totalChunks: chunked.totalChunks,
      disclosedChunkCount: disclosedChunks.length,
      proofCount: proofs.length,
      disclosureRatio: chunked.totalChunks === 0
        ? 0
        : disclosedChunks.length / chunked.totalChunks,
    },
  };

  if (params.includeCapabilityToken !== false) {
    bundle.capabilityToken = cloneJson(token);
  }

  bundle.metrics.generationTimeMs = performance.now() - started;
  bundle.bundleHash = computeBundleHash(bundle);

  return bundle;
}

export function buildDisclosureBundle(params) {
  return buildChunkDisclosureCore(params);
}

export function executeHashOnlyDisclosure(params) {
  if (!isPlainObject(params)) {
    throw new TypeError('params must be a non-null object');
  }

  const started = performance.now();

  const { token, verification } = verifyCapabilityOrThrow(
    params.capabilityToken,
    params.issuerPublicKey,
    params.now
  );

  checkHolderBindingOrThrow(token, params.requesterId);
  checkScopeOrThrow(token, []);

  const evidenceId = normalizeNonEmptyString(
    params.evidenceId ?? token.evidenceId,
    'evidenceId'
  );

  const evidenceType = normalizeOptionalString(params.evidenceType);
  const generatedAt = new Date(params.generatedAt ?? nowIso()).toISOString();
  const commitmentVersion = normalizeCommitmentVersionForDisclosure(
    params.commitmentVersion ?? token.commitmentVersion
  );
  const useV3Commitment = isV3DisclosureCommitment(commitmentVersion);

  const fileBuffer = normalizeBuffer(params.evidenceBuffer, 'evidenceBuffer');
  const requestedChunkSize = Number(params.chunkSize ?? DEFAULT_CHUNK_SIZE);

  const rawChunked = EvidenceChunker.chunk(fileBuffer, requestedChunkSize, {
    commitmentVersion,
    evidenceId,
    emk: params.emk ?? params.evidenceMasterKey,
    evidenceMasterKey: params.evidenceMasterKey,
    kSalt: params.kSalt,
    saltKey: params.saltKey,
    chunkSalts: params.chunkSalts,
  });
  const chunked = normalizeChunkedResult(rawChunked, fileBuffer, requestedChunkSize);

  const tree = useV3Commitment
    ? buildMerkleTreeFromLeafHashesV3(chunked.chunkHashes)
    : buildMerkleTreeFromLeafHashes(chunked.chunkHashes);
  const merkleRoot = resolveMerkleRoot(tree);

  ensureRootMatch(params.expectedOnChainRoot ?? params.onChainMerkleRoot, merkleRoot);

  const bundle = {
    version: DISCLOSURE_BUNDLE_VERSION,
    manifest: buildDisclosureManifest({
      evidenceId,
      evidenceType,
      capabilityToken: token,
      capHash: verification.capHash,
      scopeDigest: verification.scopeDigest,
      disclosureType: DISCLOSURE_TYPES.HASH_ONLY,
      requesterId: normalizeOptionalString(params.requesterId) || token.granteeId,
      fileHash: chunked.fileHash,
      chunkMerkleRoot: merkleRoot,
      commitmentVersion,
      totalChunks: chunked.totalChunks,
      chunkSize: chunked.chunkSize,
      requestedChunkIndices: [],
      disclosedChunkIndices: [],
      generatedAt,
      disclosedAt: params.disclosedAt,
      disclosureTxId: params.disclosureTxId ?? params.txId,
      disclosureEventHash: params.disclosureEventHash,
      blockNumber: params.blockNumber,
    }),
    disclosedChunks: [],
    proofs: [],
    metrics: {
      fileSize: chunked.fileSize,
      chunkSize: chunked.chunkSize,
      totalChunks: chunked.totalChunks,
      disclosedChunkCount: 0,
      proofCount: 0,
      disclosureRatio: 0,
    },
  };

  if (params.includeCapabilityToken !== false) {
    bundle.capabilityToken = cloneJson(token);
  }

  bundle.metrics.generationTimeMs = performance.now() - started;
  bundle.bundleHash = computeBundleHash(bundle);

  return bundle;
}

function resolveProofLeafHash(proofObj) {
  const candidates = [
    proofObj?.leafHash,
    proofObj?.leaf,
    proofObj?.chunkHash,
  ];

  for (const candidate of candidates) {
    if (typeof candidate === 'string' && /^[a-fA-F0-9]{64}$/.test(candidate.trim())) {
      return candidate.trim().toLowerCase();
    }
  }

  return null;
}

function resolveVerificationLeafHash(verification, payloadBytes) {
  const candidates = [
    verification?.leafHash,
    verification?.computedLeafHash,
    verification?.payloadHash,
    verification?.chunkHash,
    verification?.leaf,
  ];

  for (const candidate of candidates) {
    if (typeof candidate === 'string' && /^[a-fA-F0-9]{64}$/.test(candidate.trim())) {
      return candidate.trim().toLowerCase();
    }
  }

  return EvidenceChunker.hashChunk(payloadBytes).toLowerCase();
}

function resolveVerificationValid(verification) {
  if (typeof verification === 'boolean') return verification;
  if (!verification || typeof verification !== 'object') return false;
  if (typeof verification.valid === 'boolean') return verification.valid;
  if (typeof verification.ok === 'boolean') return verification.ok;
  if (typeof verification.verified === 'boolean') return verification.verified;
  return false;
}

function verifyProofFromPayloadCompat(payloadBytes, proofObj, expectedRoot) {
  const attempts = [
    () => verifyProofFromPayload(payloadBytes, proofObj?.proof, expectedRoot),
    () => verifyProofFromPayload(payloadBytes, proofObj, expectedRoot),
    () => verifyProofFromPayload(payloadBytes, proofObj?.proof),
    () => verifyProofFromPayload(payloadBytes, proofObj),
  ];

  let lastError = null;

  for (const attempt of attempts) {
    try {
      const raw = attempt();
      return {
        valid: resolveVerificationValid(raw),
        leafHash: resolveVerificationLeafHash(raw, payloadBytes),
        raw,
      };
    } catch (err) {
      lastError = err;
    }
  }

  if (lastError) {
    throw lastError;
  }

  return {
    valid: false,
    leafHash: EvidenceChunker.hashChunk(payloadBytes).toLowerCase(),
    raw: null,
  };
}

export function verifyDisclosureBundleClientSide(bundle, expectedRootOrOptions = undefined) {
  const started = performance.now();

  if (!isPlainObject(bundle)) {
    throw new TypeError('bundle must be a non-null object');
  }

  const options = typeof expectedRootOrOptions === 'string'
    ? { expectedRoot: expectedRootOrOptions }
    : (expectedRootOrOptions ?? {});

  const expectedRoot = normalizeDigestHex(
    options.expectedRoot
      ?? bundle.manifest?.chunkMerkleRoot
      ?? bundle.chunkMerkleRoot
      ?? bundle.merkleRoot,
    'expectedRoot'
  );

  const evidenceId = normalizeOptionalString(
    bundle.manifest?.evidenceId ?? bundle.evidenceId
  );

  const baseResult = {
    evidenceId,
    valid: false,
    bundleHashValid: false,
    rootMatch: false,
    capabilityValid: false,
    failedIndices: [],
    results: [],
    reason: 'verification_failed',
  };

  const recomputedBundleHash = computeBundleHash(bundle);
  const bundleHashValid =
    normalizeOptionalString(bundle.bundleHash).toLowerCase() === recomputedBundleHash;

  if (!bundleHashValid) {
    return {
      ...baseResult,
      reason: 'bundle_hash_mismatch',
      recomputedBundleHash,
      metrics: {
        verificationTimeMs: performance.now() - started,
        proofSizeBytes: jsonSizeBytes(bundle.proofs ?? []),
        hashOperations: 0,
      },
    };
  }

  const manifestRoot = normalizeDigestHex(
    bundle.manifest?.chunkMerkleRoot ?? expectedRoot,
    'manifest.chunkMerkleRoot'
  );

  const rootMatch = manifestRoot === expectedRoot;

  if (!rootMatch) {
    return {
      ...baseResult,
      bundleHashValid: true,
      rootMatch: false,
      capabilityValid: false,
      reason: 'manifest_root_mismatch',
      recomputedBundleHash,
      metrics: {
        verificationTimeMs: performance.now() - started,
        proofSizeBytes: jsonSizeBytes(bundle.proofs ?? []),
        hashOperations: 0,
      },
    };
  }

  const rawCommitmentVersion = bundle.manifest?.commitmentVersion ?? DISCLOSURE_COMMITMENT_VERSION;

  if (
    bundle.manifest?.commitmentVersion &&
    !isSupportedDisclosureCommitmentVersion(bundle.manifest.commitmentVersion)
  ) {
    return {
      ...baseResult,
      bundleHashValid: true,
      rootMatch: true,
      capabilityValid: false,
      reason: 'manifest_commitment_version_mismatch',
      recomputedBundleHash,
      metrics: {
        verificationTimeMs: performance.now() - started,
        proofSizeBytes: jsonSizeBytes(bundle.proofs ?? []),
        hashOperations: 0,
      },
    };
  }

  const commitmentVersion = normalizeCommitmentVersionForDisclosure(rawCommitmentVersion);
  const useV3Commitment = isV3DisclosureCommitment(commitmentVersion);

  let capabilityValid = true;
  if (bundle.capabilityToken && options.issuerPublicKey) {
    const capVerification = verifyCapabilityToken(
      bundle.capabilityToken,
      options.issuerPublicKey,
      options.now ?? new Date()
    );

    capabilityValid = !!capVerification.valid;

    if (!capabilityValid) {
      return {
        ...baseResult,
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: false,
        reason: `invalid_capability_token:${capVerification.reason}`,
        recomputedBundleHash,
        metrics: {
          verificationTimeMs: performance.now() - started,
          proofSizeBytes: jsonSizeBytes(bundle.proofs ?? []),
          hashOperations: 0,
        },
      };
    }

    const manifestCapHash = normalizeOptionalString(bundle.manifest?.capHash).toLowerCase();
    const computedCapHash = computeCapHash(bundle.capabilityToken).toLowerCase();

    if (manifestCapHash && manifestCapHash !== computedCapHash) {
      return {
        ...baseResult,
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: false,
        reason: 'manifest_caphash_mismatch',
        recomputedBundleHash,
        metrics: {
          verificationTimeMs: performance.now() - started,
          proofSizeBytes: jsonSizeBytes(bundle.proofs ?? []),
          hashOperations: 0,
        },
      };
    }

    const manifestScopeDigest = normalizeOptionalString(bundle.manifest?.scopeDigest).toLowerCase();
    const computedScopeDigest = computeScopeDigest(bundle.capabilityToken.scope).toLowerCase();

    if (manifestScopeDigest && manifestScopeDigest !== computedScopeDigest) {
      return {
        ...baseResult,
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid: false,
        reason: 'manifest_scopedigest_mismatch',
        recomputedBundleHash,
        metrics: {
          verificationTimeMs: performance.now() - started,
          proofSizeBytes: jsonSizeBytes(bundle.proofs ?? []),
          hashOperations: 0,
        },
      };
    }
  }

  const disclosureType =
    normalizeOptionalString(bundle.manifest?.disclosureType).toUpperCase()
    || (bundle.disclosedChunks?.length
      ? DISCLOSURE_TYPES.CHUNK_DISCLOSURE
      : DISCLOSURE_TYPES.HASH_ONLY);

  if (disclosureType === DISCLOSURE_TYPES.HASH_ONLY) {
    const noChunks = Array.isArray(bundle.disclosedChunks) && bundle.disclosedChunks.length === 0;
    const noProofs = Array.isArray(bundle.proofs) && bundle.proofs.length === 0;
    const valid = bundleHashValid && rootMatch && capabilityValid && noChunks && noProofs;

    return {
      evidenceId,
      valid,
      bundleHashValid,
      rootMatch,
      capabilityValid,
      failedIndices: [],
      results: [],
      reason: valid ? null : 'hash_only_bundle_must_not_contain_chunks_or_proofs',
      recomputedBundleHash,
      metrics: {
        verificationTimeMs: performance.now() - started,
        proofSizeBytes: jsonSizeBytes(bundle.proofs ?? []),
        hashOperations: 0,
      },
    };
  }

  if (!Array.isArray(bundle.disclosedChunks) || !Array.isArray(bundle.proofs)) {
    return {
      ...baseResult,
      bundleHashValid: true,
      rootMatch: true,
      capabilityValid,
      reason: 'missing_disclosed_chunks_or_proofs',
      recomputedBundleHash,
      metrics: {
        verificationTimeMs: performance.now() - started,
        proofSizeBytes: jsonSizeBytes(bundle.proofs ?? []),
        hashOperations: 0,
      },
    };
  }

  const manifestIndices = normalizeChunkIndices(
    bundle.manifest?.disclosedChunkIndices ?? [],
    'manifest.disclosedChunkIndices'
  );

  const actualIndices = normalizeChunkIndices(
    bundle.disclosedChunks.map((c) => c.index),
    'disclosedChunks.index'
  );

  if (JSON.stringify(manifestIndices) !== JSON.stringify(actualIndices)) {
    return {
      ...baseResult,
      bundleHashValid: true,
      rootMatch: true,
      capabilityValid,
      reason: 'manifest_disclosed_indices_mismatch',
      recomputedBundleHash,
      metrics: {
        verificationTimeMs: performance.now() - started,
        proofSizeBytes: jsonSizeBytes(bundle.proofs ?? []),
        hashOperations: 0,
      },
    };
  }

  if (bundle.capabilityToken) {
    try {
      const scopeChecked = checkScope(
        bundle.capabilityToken.scope,
        actualIndices
      );

      if (!scopeChecked.allowed) {
        return {
          ...baseResult,
          bundleHashValid: true,
          rootMatch: true,
          capabilityValid,
          reason: `scope_check_failed:${scopeChecked.reason}`,
          recomputedBundleHash,
          metrics: {
            verificationTimeMs: performance.now() - started,
            proofSizeBytes: jsonSizeBytes(bundle.proofs ?? []),
            hashOperations: 0,
          },
        };
      }
    } catch (err) {
      return {
        ...baseResult,
        bundleHashValid: true,
        rootMatch: true,
        capabilityValid,
        reason: err instanceof Error ? err.message : 'scope_check_failed',
        recomputedBundleHash,
        metrics: {
          verificationTimeMs: performance.now() - started,
          proofSizeBytes: jsonSizeBytes(bundle.proofs ?? []),
          hashOperations: 0,
        },
      };
    }
  }

  const proofMap = new Map(
    bundle.proofs.map((proofObj) => [proofObj.index ?? proofObj.chunkIndex, proofObj])
  );

  const failedIndices = [];
  const results = [];
  let hashOperations = 0;

  for (const disclosed of bundle.disclosedChunks) {
    const proofObj = proofMap.get(disclosed.index);

    if (!proofObj) {
      failedIndices.push(disclosed.index);
      results.push({
        chunkIndex: disclosed.index,
        valid: false,
        reason: 'missing_proof_for_chunk',
      });
      continue;
    }

    const payloadBytes = Buffer.from(
      String(disclosed.dataBase64 ?? ''),
      'base64'
    );

    const verification = useV3Commitment
      ? verifyProofFromPayloadWithOpeningV3(
        payloadBytes,
        {
          evidenceId,
          index: disclosed.index,
          actualLength: disclosed.actualLength ?? disclosed.length,
          salt: disclosed.salt,
        },
        proofObj,
        expectedRoot
      )
      : verifyProofFromPayloadCompat(
        payloadBytes,
        proofObj,
        expectedRoot
      );

    const computedLeafHash = verification.leafHash;

    const declaredHash = disclosed.hash
      ? String(disclosed.hash).toLowerCase()
      : null;

    const proofLeafHash = resolveProofLeafHash(proofObj);

    let valid = verification.valid;
    let reason = null;

    if (!useV3Commitment && declaredHash && declaredHash !== computedLeafHash) {
      valid = false;
      reason = 'payload_hash_mismatch';
    } else if (!useV3Commitment && proofLeafHash && proofLeafHash !== computedLeafHash) {
      valid = false;
      reason = 'proof_leaf_mismatch';
    } else if (!verification.valid) {
      valid = false;
      reason = useV3Commitment ? 'invalid_v3_opening_or_merkle_path' : 'invalid_merkle_path';
    }

    if (!valid) {
      failedIndices.push(disclosed.index);
    }

    results.push({
      chunkIndex: disclosed.index,
      valid,
      reason,
    });

    hashOperations += 1 + (Array.isArray(proofObj.proof) ? proofObj.proof.length : 0);
  }

  const valid = bundleHashValid && rootMatch && capabilityValid && failedIndices.length === 0;

  return {
    evidenceId,
    valid,
    bundleHashValid,
    rootMatch,
    capabilityValid,
    failedIndices,
    results,
    reason: valid ? null : 'chunk_or_proof_verification_failed',
    recomputedBundleHash,
    metrics: {
      verificationTimeMs: performance.now() - started,
      proofSizeBytes: jsonSizeBytes(bundle.proofs),
      hashOperations,
    },
  };
}

export function buildDisclosureRequestPayload({
  evidenceId,
  capabilityToken,
  requestedChunkIndices = [],
}) {
  const token = resolveCapabilityToken(capabilityToken);
  const normalizedIndices = normalizeChunkIndices(
    requestedChunkIndices,
    'requestedChunkIndices'
  );

  const resolvedEvidenceId = normalizeNonEmptyString(
    evidenceId ?? token.evidenceId,
    'evidenceId'
  );

  return {
    evidenceId: resolvedEvidenceId,
    capabilityToken: cloneJson(token),
    requestedChunkIndices: normalizedIndices,
    capabilityTokenJson: JSON.stringify(token),
    requestedChunkIndicesJson: JSON.stringify(normalizedIndices),
  };
}

export function summarizeDisclosureBundle(bundle) {
  if (!isPlainObject(bundle)) {
    throw new TypeError('bundle must be a non-null object');
  }

  const manifest = isPlainObject(bundle.manifest) ? bundle.manifest : {};

  const disclosedChunkIndices = Array.isArray(manifest.disclosedChunkIndices)
    ? normalizeChunkIndices(manifest.disclosedChunkIndices, 'manifest.disclosedChunkIndices')
    : (Array.isArray(bundle.disclosedChunks)
      ? normalizeChunkIndices(bundle.disclosedChunks.map((c) => c.index), 'disclosedChunks.index')
      : []);

  const requestedChunkIndices = Array.isArray(manifest.requestedChunkIndices)
    ? normalizeChunkIndices(manifest.requestedChunkIndices, 'manifest.requestedChunkIndices')
    : [...disclosedChunkIndices];

  const proofCount = Array.isArray(bundle.proofs) ? bundle.proofs.length : 0;

  const totalChunks = Number(
    bundle.metrics?.totalChunks ??
    manifest.totalChunks ??
    manifest.chunkCount ??
    0
  );

  const disclosedChunkCount = disclosedChunkIndices.length;
  const requestedChunkCount = requestedChunkIndices.length;

  return {
    version: normalizeOptionalString(bundle.version),
    evidenceId: normalizeOptionalString(manifest.evidenceId),
    evidenceType: normalizeOptionalString(manifest.evidenceType),
    capId: normalizeOptionalString(manifest.capId),
    scopeType: normalizeOptionalString(manifest.scopeType),
    disclosureType: normalizeOptionalString(manifest.disclosureType),
    commitmentVersion: normalizeOptionalString(manifest.commitmentVersion),

    requestedChunkIndices,
    disclosedChunkIndices,

    requestedChunkCount,
    disclosedChunkCount,
    proofCount,
    chunkCount: disclosedChunkCount,

    totalChunks,
    disclosureRatio: Number(
      bundle.metrics?.disclosureRatio ??
      (totalChunks > 0 ? disclosedChunkCount / totalChunks : 0)
    ),

    chunkMerkleRoot: normalizeOptionalString(manifest.chunkMerkleRoot),
    bundleHash: normalizeOptionalString(bundle.bundleHash),
  };
}


export function checkBundlePreconditions({ evidenceLifecycleState, capabilityRecord, capabilityToken, now = new Date() } = {}) {
  const lifecycleState = normalizeEvidenceLifecycleState(evidenceLifecycleState);
  if (!isDisclosurePermissibleState(lifecycleState)) {
    return {
      ok: false,
      reason: `evidence_lifecycle_not_disclosure_permissible:${lifecycleState}`,
      lifecycleState,
    };
  }

  const capSource = capabilityRecord || capabilityToken;
  if (capSource) {
    const usable = isCapabilityUsableAtTime(capSource, now);
    if (!usable.usable) {
      return {
        ok: false,
        reason: usable.reason,
        lifecycleState,
        capabilityState: usable.state,
      };
    }
    return {
      ok: true,
      reason: null,
      lifecycleState,
      capabilityState: usable.state,
    };
  }

  return { ok: true, reason: null, lifecycleState, capabilityState: null };
}

export function assertBundlePreconditions(params = {}) {
  const result = checkBundlePreconditions(params);
  if (!result.ok) {
    throw new Error(result.reason);
  }
  return result;
}

export function executeDisclosure(params) {
  const token = resolveCapabilityToken(params.capabilityToken);
  assertBundlePreconditions({
    evidenceLifecycleState: params.evidenceLifecycleState,
    capabilityRecord: params.capabilityRecord || token,
    capabilityToken: token,
    now: params.now,
  });
  const scopeType = resolveScopeType({ capabilityToken: token });

  if (scopeType === SCOPE_TYPES.HASH_ONLY) {
    const bundle = executeHashOnlyDisclosure(params);

    return {
      success: true,
      phase: 'hash_only',
      capability: {
        id: token.capId,
        scope: scopeType,
        grantee: token.granteeId,
        capHash: computeCapHash(token),
      },
      disclosure: {
        totalChunks: bundle.metrics.totalChunks,
        disclosedCount: 0,
        disclosureRatio: 0,
        disclosedChunks: [],
      },
      verification: verifyDisclosureBundleClientSide(bundle, {
        expectedRoot: bundle.manifest.chunkMerkleRoot,
        issuerPublicKey: params.issuerPublicKey,
        now: params.now,
      }),
      bundle,
      metrics: {
        totalTimeMs: bundle.metrics.generationTimeMs,
        hashOperations: 0,
        proofSizeBytes: 0,
        disclosedDataBytes: 0,
        dataReductionPct: 100,
      },
    };
  }

  const bundle = buildDisclosureBundle(params);

  const verification = verifyDisclosureBundleClientSide(bundle, {
    expectedRoot: bundle.manifest.chunkMerkleRoot,
    issuerPublicKey: params.issuerPublicKey,
    now: params.now,
  });

  return {
    success: verification.valid,
    phase: 'disclosure',
    capability: {
      id: token.capId,
      scope: scopeType,
      grantee: token.granteeId,
      capHash: computeCapHash(token),
    },
    disclosure: {
      totalChunks: bundle.metrics.totalChunks,
      disclosedCount: bundle.metrics.disclosedChunkCount,
      disclosureRatio: bundle.metrics.disclosureRatio,
      disclosedChunks: bundle.manifest.disclosedChunkIndices,
    },
    verification,
    bundle,
    metrics: {
      totalTimeMs:
        bundle.metrics.generationTimeMs
        + (verification.metrics?.verificationTimeMs ?? 0),
      hashOperations: verification.metrics?.hashOperations ?? 0,
      proofSizeBytes: verification.metrics?.proofSizeBytes ?? 0,
      disclosedDataBytes: bundle.disclosedChunks.reduce((sum, c) => sum + (c.length ?? c.byteLength ?? Buffer.byteLength(c.dataBase64 || '', 'base64')), 0),
      dataReductionPct: 100 - (bundle.metrics.disclosureRatio * 100),
    },
  };
}

export default {
  DISCLOSURE_BUNDLE_VERSION,
  DISCLOSURE_MANIFEST_VERSION,
  DISCLOSURE_COMMITMENT_VERSION,
  DISCLOSURE_COMMITMENT_VERSION_V3,
  DISCLOSURE_TYPES,
  computeBundleHash,
  buildDisclosureManifest,
  buildDisclosureBundle,
  verifyDisclosureBundleClientSide,
  executeHashOnlyDisclosure,
  buildDisclosureRequestPayload,
  summarizeDisclosureBundle,
  checkBundlePreconditions,
  assertBundlePreconditions,
  executeDisclosure,
};