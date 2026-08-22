'use strict';

import {
  toBuffer,
  sha256Hex,
  isSha256Hex,
  hexToBytes,
  bytesToHex,
  uint32be,
  uint64be,
  lengthPrefixedUtf8,
  hmacSha256Bytes,
  hkdfSha256Hex,
  normalizeSecretKey
} from './forensic-crypto.js';

const DEFAULT_CHUNK_SIZE = 4096;
const MIN_CHUNK_SIZE = 1;
const MAX_CHUNK_SIZE = 65536;

const COMMITMENT_VERSION_V2 = 'chunk-merkle-v2';
const COMMITMENT_VERSION_V2_INTEGRITY = 'chunk-merkle-v2-integrity';
const COMMITMENT_VERSION_V3_HMAC = 'chunk-merkle-v3-hmac-opening';

const FDEM_CHUNK_V3_DOMAIN = Buffer.from('FDEM-CHUNK-v3', 'ascii');
const FDEM_LEAF_V3_DOMAIN = Buffer.from('FDEM-LEAF-v3', 'ascii');
const FDEM_SALT_V3_DOMAIN = Buffer.from('FDEM-SALT-v3', 'ascii');
const FDEM_HKDF_SALT_V3_DOMAIN = Buffer.from('FDEM-HKDF-SALT-v3', 'ascii');

/**
 * Domain byte for chunk payload hashing.
 * Leaf hash = SHA-256(0x00 || raw_chunk_bytes)
 */
const LEAF_HASH_DOMAIN = Buffer.from([0x00]);

function normalizeBuffer(input, fieldName = 'value') {
  try {
    return Buffer.from(toBuffer(input));
  } catch (err) {
    throw new TypeError(`${fieldName} could not be converted to Buffer: ${err.message}`);
  }
}

function validateChunkSize(chunkSize) {
  if (!Number.isInteger(chunkSize)) {
    throw new TypeError('chunkSize must be an integer');
  }

  if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE) {
    throw new RangeError(
      `chunkSize must be between ${MIN_CHUNK_SIZE} and ${MAX_CHUNK_SIZE}`
    );
  }

  return chunkSize;
}

/**
 * Hash a chunk payload with leaf-domain separation.
 * chunkHash = SHA-256(0x00 || chunk_bytes)
 */
function hashChunk(chunkBuffer) {
  const buf = normalizeBuffer(chunkBuffer, 'chunkBuffer');
  return sha256Hex(Buffer.concat([LEAF_HASH_DOMAIN, buf]));
}

/**
 * File hash remains a direct SHA-256 over raw file bytes.
 * This is intentionally separate from chunk leaf hashing.
 */
function hashFile(fileBuffer) {
  return sha256Hex(normalizeBuffer(fileBuffer, 'fileBuffer'));
}

function normalizeCommitmentVersion(version) {
  const value = String(version || COMMITMENT_VERSION_V2).trim();
  if (value === COMMITMENT_VERSION_V2_INTEGRITY) {
    return COMMITMENT_VERSION_V2;
  }
  if (![COMMITMENT_VERSION_V2, COMMITMENT_VERSION_V3_HMAC].includes(value)) {
    throw new TypeError(`Unsupported commitmentVersion: ${value}`);
  }
  return value;
}

function isV3CommitmentVersion(version) {
  return normalizeCommitmentVersion(version) === COMMITMENT_VERSION_V3_HMAC;
}

function normalizeEvidenceId(evidenceId) {
  if (typeof evidenceId !== 'string' || evidenceId.trim().length === 0) {
    throw new TypeError('evidenceId is required for chunk-merkle-v3-hmac-opening');
  }
  return evidenceId.trim();
}

function normalizeIndex(value, fieldName = 'chunkIndex') {
  const n = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new TypeError(`${fieldName} must be a non-negative safe integer`);
  }
  return n;
}

function normalizeActualLength(value, fieldName = 'actualLength') {
  const n = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) {
    throw new TypeError(`${fieldName} must be an unsigned 32-bit safe integer`);
  }
  return n;
}

function normalizeSaltBytes(salt, fieldName = 'salt') {
  let bytes;
  if (typeof salt === 'string') {
    const value = salt.trim();
    if (!/^[a-fA-F0-9]{64}$/.test(value)) {
      throw new TypeError(`${fieldName} must be a 32-byte hex string`);
    }
    bytes = hexToBytes(value);
  } else {
    bytes = normalizeBuffer(salt, fieldName);
  }
  if (bytes.length !== 32) {
    throw new TypeError(`${fieldName} must be exactly 32 bytes`);
  }
  return bytes;
}

function buildEvidenceContext(evidenceId, chunkIndex, actualLength) {
  const normalizedEvidenceId = normalizeEvidenceId(evidenceId);
  const normalizedIndex = normalizeIndex(chunkIndex);
  const normalizedLength = normalizeActualLength(actualLength);

  return Buffer.concat([
    lengthPrefixedUtf8(normalizedEvidenceId),
    uint64be(normalizedIndex),
    uint32be(normalizedLength)
  ]);
}

function deriveEvidenceKeys(emk, evidenceId) {
  const normalizedEvidenceId = normalizeEvidenceId(evidenceId);
  const hkdfSalt = Buffer.concat([
    FDEM_HKDF_SALT_V3_DOMAIN,
    lengthPrefixedUtf8(normalizedEvidenceId)
  ]);

  const info = (label) => Buffer.concat([
    Buffer.from(label, 'ascii'),
    lengthPrefixedUtf8(normalizedEvidenceId)
  ]);

  return {
    commitmentVersion: COMMITMENT_VERSION_V3_HMAC,
    evidenceId: normalizedEvidenceId,
    emkHash: sha256Hex(normalizeSecretKey(emk)),
    dek: hkdfSha256Hex(emk, { salt: hkdfSalt, info: info('FDEM-DEK-v3'), length: 32 }),
    kSalt: hkdfSha256Hex(emk, { salt: hkdfSalt, info: info('FDEM-KSALT-v3'), length: 32 }),
    kMeta: hkdfSha256Hex(emk, { salt: hkdfSalt, info: info('FDEM-META-v3'), length: 32 })
  };
}

function resolveKSalt(options = {}) {
  if (options.kSalt != null) return normalizeSecretKey(options.kSalt);
  if (options.saltKey != null) return normalizeSecretKey(options.saltKey);
  if (options.emk != null || options.evidenceMasterKey != null) {
    const emk = options.emk ?? options.evidenceMasterKey;
    const keys = deriveEvidenceKeys(emk, options.evidenceId);
    return normalizeSecretKey(keys.kSalt);
  }
  throw new TypeError('kSalt, saltKey, emk, or evidenceMasterKey is required for v3 salt derivation');
}

function deriveChunkSalt(options = {}) {
  const evidenceId = normalizeEvidenceId(options.evidenceId);
  const chunkIndex = normalizeIndex(options.chunkIndex);
  const actualLength = normalizeActualLength(options.actualLength);
  const kSalt = resolveKSalt(options);

  const message = Buffer.concat([
    FDEM_SALT_V3_DOMAIN,
    buildEvidenceContext(evidenceId, chunkIndex, actualLength)
  ]);

  return bytesToHex(hmacSha256Bytes(kSalt, message));
}

function hashChunkDigestV3(chunkBuffer, actualLength = undefined) {
  const buf = normalizeBuffer(chunkBuffer, 'chunkBuffer');
  const resolvedLength = normalizeActualLength(actualLength ?? buf.length);
  if (resolvedLength !== buf.length) {
    throw new Error(`actualLength mismatch: expected ${resolvedLength}, got ${buf.length}`);
  }
  return sha256Hex(Buffer.concat([
    FDEM_CHUNK_V3_DOMAIN,
    uint32be(resolvedLength),
    buf
  ]));
}

function hashChunkCommitmentV3(chunkBuffer, options = {}) {
  const buf = normalizeBuffer(chunkBuffer, 'chunkBuffer');
  const evidenceId = normalizeEvidenceId(options.evidenceId);
  const chunkIndex = normalizeIndex(options.chunkIndex);
  const actualLength = normalizeActualLength(options.actualLength ?? buf.length);
  if (actualLength !== buf.length) {
    throw new Error(`actualLength mismatch: expected ${actualLength}, got ${buf.length}`);
  }

  const saltBytes = options.salt != null
    ? normalizeSaltBytes(options.salt)
    : normalizeSaltBytes(deriveChunkSalt({ ...options, evidenceId, chunkIndex, actualLength }));

  const chunkDigest = hashChunkDigestV3(buf, actualLength);
  const leafHash = sha256Hex(Buffer.concat([
    FDEM_LEAF_V3_DOMAIN,
    buildEvidenceContext(evidenceId, chunkIndex, actualLength),
    saltBytes,
    hexToBytes(chunkDigest)
  ]));

  return {
    commitmentVersion: COMMITMENT_VERSION_V3_HMAC,
    evidenceId,
    chunkIndex,
    actualLength,
    salt: bytesToHex(saltBytes),
    chunkDigest,
    leafHash,
    hash: leafHash
  };
}

function chunk(fileBuffer, chunkSize = DEFAULT_CHUNK_SIZE, options = {}) {
  const normalizedChunkSize = validateChunkSize(chunkSize);
  const buf = normalizeBuffer(fileBuffer, 'fileBuffer');

  const includeData = options.includeData !== false;
  const includeBase64 = options.includeBase64 === true;
  const commitmentVersion = normalizeCommitmentVersion(options.commitmentVersion);
  const isV3 = commitmentVersion === COMMITMENT_VERSION_V3_HMAC;
  const evidenceId = isV3 ? normalizeEvidenceId(options.evidenceId) : null;

  if (isV3) {
    // Fail fast before expensive chunking if the caller cannot derive openings.
    resolveKSalt({
      evidenceId,
      kSalt: options.kSalt,
      saltKey: options.saltKey,
      emk: options.emk,
      evidenceMasterKey: options.evidenceMasterKey
    });
  }

  const fileSize = buf.length;
  const fileHash = hashFile(buf);

  if (fileSize === 0) {
    return {
      fileSize: 0,
      fileHash,
      chunkSize: normalizedChunkSize,
      totalChunks: 0,
      commitmentVersion,
      evidenceId,
      chunks: [],
      chunkBuffers: [],
      chunkMetadata: [],
      chunkHashes: [],
      leafHashes: [],
      hashes: []
    };
  }

  const chunks = [];
  const chunkBuffers = [];
  const chunkMetadata = [];
  const chunkHashes = [];

  let index = 0;
  for (let offset = 0; offset < fileSize; offset += normalizedChunkSize) {
    const end = Math.min(offset + normalizedChunkSize, fileSize);
    const slice = Buffer.from(buf.subarray(offset, end));

    let hash;
    let opening = null;

    if (isV3) {
      const saltOverride = Array.isArray(options.chunkSalts) ? options.chunkSalts[index] : undefined;
      opening = hashChunkCommitmentV3(slice, {
        evidenceId,
        chunkIndex: index,
        actualLength: slice.length,
        salt: saltOverride,
        kSalt: options.kSalt,
        saltKey: options.saltKey,
        emk: options.emk,
        evidenceMasterKey: options.evidenceMasterKey
      });
      hash = opening.leafHash;
    } else {
      hash = hashChunk(slice);
    }

    const chunkObj = {
      index,
      offset,
      length: slice.length,
      hash,
      leafHash: hash,
      commitmentVersion
    };

    if (opening) {
      chunkObj.salt = opening.salt;
      chunkObj.opening = {
        salt: opening.salt,
        actualLength: opening.actualLength,
        commitmentVersion: opening.commitmentVersion
      };
    }

    if (includeData) {
      chunkObj.data = Buffer.from(slice);
    }

    if (includeBase64) {
      chunkObj.dataBase64 = slice.toString('base64');
      chunkObj.base64 = chunkObj.dataBase64; // compatibility alias
    }

    chunks.push(chunkObj);
    chunkBuffers.push(slice);
    chunkMetadata.push({
      index,
      offset,
      length: slice.length,
      chunkHash: hash,
      leafHash: hash,
      commitmentVersion,
      salt: opening?.salt
    });
    chunkHashes.push(hash);
    index += 1;
  }

  return {
    fileSize,
    fileHash,
    chunkSize: normalizedChunkSize,
    totalChunks: chunks.length,
    commitmentVersion,
    evidenceId,
    chunks,
    chunkBuffers,
    chunkMetadata,
    chunkHashes,
    leafHashes: [...chunkHashes],
    hashes: [...chunkHashes]
  };
}

function buildLeafHashes(chunksOrBuffers) {
  if (!Array.isArray(chunksOrBuffers)) {
    throw new TypeError('buildLeafHashes expects an array');
  }

  return chunksOrBuffers.map((item, idx) => {
    if (item && typeof item === 'object') {
      if (typeof item.hash === 'string') {
        const hash = item.hash.toLowerCase();
        if (!isSha256Hex(hash)) {
          throw new TypeError(`Invalid chunk hash at index ${idx}`);
        }
        return hash;
      }

      if (typeof item.chunkHash === 'string') {
        const hash = item.chunkHash.toLowerCase();
        if (!isSha256Hex(hash)) {
          throw new TypeError(`Invalid chunkHash at index ${idx}`);
        }
        return hash;
      }

      if (item.dataBase64 != null) {
        return hashChunk(Buffer.from(String(item.dataBase64), 'base64'));
      }

      if (item.base64 != null) {
        return hashChunk(Buffer.from(String(item.base64), 'base64'));
      }

      if (item.data != null) {
        return hashChunk(item.data);
      }
    }

    try {
      return hashChunk(item);
    } catch (err) {
      throw new TypeError(`Invalid chunk/buffer at index ${idx}: ${err.message}`);
    }
  });
}

function getChunkByIndex(chunkResult, index) {
  if (!chunkResult || !Array.isArray(chunkResult.chunks)) {
    throw new TypeError('Invalid chunkResult');
  }
  if (!Number.isInteger(index) || index < 0 || index >= chunkResult.chunks.length) {
    throw new RangeError('Chunk index out of range');
  }
  return chunkResult.chunks[index];
}

function selectChunks(chunkResult, indices) {
  if (!Array.isArray(indices)) {
    throw new TypeError('indices must be an array');
  }

  const uniqueSorted = [...new Set(indices)].sort((a, b) => a - b);
  return uniqueSorted.map((idx) => getChunkByIndex(chunkResult, idx));
}

function serializeChunksForDisclosure(chunks) {
  if (!Array.isArray(chunks)) {
    throw new TypeError('chunks must be an array');
  }

  return chunks.map((chunkObj, idx) => {
    if (!chunkObj || typeof chunkObj !== 'object') {
      throw new TypeError(`Chunk at index ${idx} is invalid`);
    }

    const hasBufferData = Buffer.isBuffer(chunkObj.data);
    const hasBase64Data = typeof chunkObj.dataBase64 === 'string'
      || typeof chunkObj.base64 === 'string';

    if (!hasBufferData && !hasBase64Data) {
      throw new Error(
        `Chunk at index ${idx} must contain either "data" Buffer or base64 payload`
      );
    }

    const dataBase64 = hasBufferData
      ? chunkObj.data.toString('base64')
      : String(chunkObj.dataBase64 ?? chunkObj.base64);

    const serialized = {
      index: chunkObj.index,
      offset: chunkObj.offset,
      length: chunkObj.length,
      hash: chunkObj.hash,
      dataBase64
    };

    if (chunkObj.commitmentVersion) serialized.commitmentVersion = chunkObj.commitmentVersion;
    if (chunkObj.salt) serialized.salt = chunkObj.salt;
    if (chunkObj.opening?.salt) serialized.salt = chunkObj.opening.salt;

    return serialized;
  });
}

function deserializeChunkPayload(serializedChunk) {
  if (!serializedChunk || typeof serializedChunk !== 'object') {
    throw new TypeError('serializedChunk must be an object');
  }

  if (typeof serializedChunk.dataBase64 !== 'string') {
    throw new TypeError('serializedChunk.dataBase64 must be a string');
  }

  return Buffer.from(serializedChunk.dataBase64, 'base64');
}

function validateSerializedChunk(serializedChunk) {
  if (!serializedChunk || typeof serializedChunk !== 'object') {
    throw new TypeError('serializedChunk must be an object');
  }

  const payload = deserializeChunkPayload(serializedChunk);
  const computedHash = hashChunk(payload);
  const declaredHash = typeof serializedChunk.hash === 'string'
    ? serializedChunk.hash.toLowerCase()
    : null;

  return {
    valid: declaredHash ? computedHash === declaredHash : true,
    computedHash,
    declaredHash
  };
}

const EvidenceChunker = {
  DEFAULT_CHUNK_SIZE,
  MIN_CHUNK_SIZE,
  MAX_CHUNK_SIZE,
  COMMITMENT_VERSION_V2,
  COMMITMENT_VERSION_V2_INTEGRITY,
  COMMITMENT_VERSION_V3_HMAC,
  FDEM_CHUNK_V3_DOMAIN,
  FDEM_LEAF_V3_DOMAIN,
  FDEM_SALT_V3_DOMAIN,
  LEAF_HASH_DOMAIN,
  normalizeBuffer,
  validateChunkSize,
  hashChunk,
  hashFile,
  normalizeCommitmentVersion,
  isV3CommitmentVersion,
  deriveEvidenceKeys,
  deriveChunkSalt,
  hashChunkDigestV3,
  hashChunkCommitmentV3,
  chunk,
  buildLeafHashes,
  getChunkByIndex,
  selectChunks,
  serializeChunksForDisclosure,
  deserializeChunkPayload,
  validateSerializedChunk
};

export {
  DEFAULT_CHUNK_SIZE,
  MIN_CHUNK_SIZE,
  MAX_CHUNK_SIZE,
  COMMITMENT_VERSION_V2,
  COMMITMENT_VERSION_V2_INTEGRITY,
  COMMITMENT_VERSION_V3_HMAC,
  FDEM_CHUNK_V3_DOMAIN,
  FDEM_LEAF_V3_DOMAIN,
  FDEM_SALT_V3_DOMAIN,
  LEAF_HASH_DOMAIN,
  normalizeBuffer,
  validateChunkSize,
  hashChunk,
  hashFile,
  normalizeCommitmentVersion,
  isV3CommitmentVersion,
  deriveEvidenceKeys,
  deriveChunkSalt,
  hashChunkDigestV3,
  hashChunkCommitmentV3,
  chunk,
  buildLeafHashes,
  getChunkByIndex,
  selectChunks,
  serializeChunksForDisclosure,
  deserializeChunkPayload,
  validateSerializedChunk,
  EvidenceChunker
};