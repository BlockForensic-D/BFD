'use strict';

import { sha256Hex, hexToBytes, isSha256Hex } from './forensic-crypto.js';
import {
  hashChunk,
  deserializeChunkPayload,
  hashChunkCommitmentV3,
  COMMITMENT_VERSION_V3_HMAC
} from './evidence-chunker.js';

const EMPTY_TREE_SENTINEL = 'empty';

/**
 * Internal node hash = SHA-256(0x01 || left_digest_bytes || right_digest_bytes)
 */
const NODE_HASH_DOMAIN = Buffer.from([0x01]);
const NODE_HASH_V3_DOMAIN = Buffer.from('FDEM-NODE-v3', 'ascii');

/**
 * Empty root hash = SHA-256(0xFF || "empty")
 */
const EMPTY_ROOT_DOMAIN = Buffer.from([0xFF]);

function getEmptyRoot() {
  return sha256Hex(
    Buffer.concat([
      EMPTY_ROOT_DOMAIN,
      Buffer.from(EMPTY_TREE_SENTINEL, 'utf8')
    ])
  );
}

function validateLeafHashes(leafHashes) {
  if (!Array.isArray(leafHashes)) {
    throw new TypeError('leafHashes must be an array');
  }

  for (let i = 0; i < leafHashes.length; i += 1) {
    if (!isSha256Hex(leafHashes[i])) {
      throw new TypeError(`leafHashes[${i}] must be a valid 64-char SHA-256 hex string`);
    }
  }

  return leafHashes.map((hash) => hash.toLowerCase());
}

function computeParentHash(leftDigestHex, rightDigestHex) {
  if (!isSha256Hex(leftDigestHex)) {
    throw new TypeError('leftDigestHex must be a valid SHA-256 hex string');
  }
  if (!isSha256Hex(rightDigestHex)) {
    throw new TypeError('rightDigestHex must be a valid SHA-256 hex string');
  }

  const leftBytes = hexToBytes(leftDigestHex);
  const rightBytes = hexToBytes(rightDigestHex);

  return sha256Hex(
    Buffer.concat([NODE_HASH_DOMAIN, leftBytes, rightBytes])
  );
}

function computeParentHashV3(leftDigestHex, rightDigestHex) {
  if (!isSha256Hex(leftDigestHex)) {
    throw new TypeError('leftDigestHex must be a valid SHA-256 hex string');
  }
  if (!isSha256Hex(rightDigestHex)) {
    throw new TypeError('rightDigestHex must be a valid SHA-256 hex string');
  }

  const leftBytes = hexToBytes(leftDigestHex);
  const rightBytes = hexToBytes(rightDigestHex);

  return sha256Hex(
    Buffer.concat([NODE_HASH_V3_DOMAIN, leftBytes, rightBytes])
  );
}

function buildMerkleLevelsWithParent(leafHashes, parentHasher) {
  const leaves = validateLeafHashes(leafHashes);

  if (leaves.length === 0) {
    const emptyRoot = getEmptyRoot();
    return {
      levels: [[emptyRoot]],
      root: emptyRoot
    };
  }

  const levels = [leaves.slice()];
  let current = leaves.slice();

  while (current.length > 1) {
    const next = [];

    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : current[i];
      next.push(parentHasher(left, right));
    }

    levels.push(next);
    current = next;
  }

  return {
    levels,
    root: levels[levels.length - 1][0]
  };
}

function buildMerkleLevels(leafHashes) {
  const leaves = validateLeafHashes(leafHashes);

  if (leaves.length === 0) {
    const emptyRoot = getEmptyRoot();
    return {
      levels: [[emptyRoot]],
      root: emptyRoot
    };
  }

  const levels = [leaves.slice()];
  let current = leaves.slice();

  while (current.length > 1) {
    const next = [];

    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : current[i];
      next.push(computeParentHash(left, right));
    }

    levels.push(next);
    current = next;
  }

  return {
    levels,
    root: levels[levels.length - 1][0]
  };
}

function buildMerkleTreeFromLeafHashes(leafHashes) {
  const validated = validateLeafHashes(leafHashes);
  const { levels, root } = buildMerkleLevels(validated);

  return {
    root,
    levels,
    leafCount: validated.length,
    isEmpty: validated.length === 0,
    duplicateOddLeaves: true
  };
}

function buildMerkleLevelsV3(leafHashes) {
  return buildMerkleLevelsWithParent(leafHashes, computeParentHashV3);
}

function buildMerkleTreeFromLeafHashesV3(leafHashes) {
  const validated = validateLeafHashes(leafHashes);
  const { levels, root } = buildMerkleLevelsV3(validated);

  return {
    root,
    levels,
    leafCount: validated.length,
    isEmpty: validated.length === 0,
    duplicateOddLeaves: true,
    commitmentVersion: COMMITMENT_VERSION_V3_HMAC,
    nodeHashDomain: 'FDEM-NODE-v3'
  };
}

function buildMerkleTree(leafHashes) {
  return buildMerkleTreeFromLeafHashes(leafHashes);
}

/**
 * Extract a single proof from pre-built levels.
 * This keeps proof semantics identical to generateProof():
 *   { position: 'left'|'right', data: <hex> }
 */
function extractProofFromLevels(levels, leafHashes, index) {
  if (!Array.isArray(levels) || levels.length === 0) {
    throw new TypeError('levels must be a non-empty array');
  }

  if (!Array.isArray(leafHashes)) {
    throw new TypeError('leafHashes must be an array');
  }

  if (!Number.isInteger(index) || index < 0 || index >= leafHashes.length) {
    throw new RangeError('index out of range');
  }

  const proof = [];
  let currentIndex = index;

  for (let level = 0; level < levels.length - 1; level += 1) {
    const currentLevel = levels[level];
    const isRightNode = currentIndex % 2 === 1;

    const siblingIndex = isRightNode
      ? currentIndex - 1
      : (currentIndex + 1 < currentLevel.length ? currentIndex + 1 : currentIndex);

    const siblingHash = currentLevel[siblingIndex];

    proof.push({
      position: isRightNode ? 'left' : 'right',
      data: siblingHash
    });

    currentIndex = Math.floor(currentIndex / 2);
  }

  return {
    index,
    leaf: leafHashes[index],
    proof,
    root: levels[levels.length - 1][0],
    leafCount: leafHashes.length
  };
}

function generateProof(leafHashes, index) {
  const validated = validateLeafHashes(leafHashes);

  if (!Number.isInteger(index) || index < 0 || index >= validated.length) {
    throw new RangeError('index out of range');
  }

  const { levels } = buildMerkleLevels(validated);
  return extractProofFromLevels(levels, validated, index);
}

/**
 * True batch-proof generation:
 * - validates/sorts/deduplicates indices
 * - builds Merkle levels exactly once
 * - extracts all requested proofs from the same tree
 */
function generateProofsBatch(leafHashes, indices) {
  const validated = validateLeafHashes(leafHashes);

  if (!Array.isArray(indices)) {
    throw new TypeError('indices must be an array');
  }

  const uniqueSorted = [...new Set(indices.map((idx) => {
    const parsed = typeof idx === 'string' && idx.trim() !== '' ? Number(idx) : idx;
    if (!Number.isInteger(parsed) || parsed < 0 || parsed >= validated.length) {
      throw new RangeError(`index out of range: ${idx}`);
    }
    return parsed;
  }))].sort((a, b) => a - b);

  if (validated.length === 0) {
    if (uniqueSorted.length > 0) {
      throw new RangeError('cannot generate proofs for empty leaf set');
    }
    return [];
  }

  const { levels } = buildMerkleLevels(validated);
  return uniqueSorted.map((idx) => extractProofFromLevels(levels, validated, idx));
}

function generateProofs(leafHashes, indices) {
  return generateProofsBatch(leafHashes, indices);
}

function generateProofV3(leafHashes, index) {
  const validated = validateLeafHashes(leafHashes);

  if (!Number.isInteger(index) || index < 0 || index >= validated.length) {
    throw new RangeError('index out of range');
  }

  const { levels } = buildMerkleLevelsV3(validated);
  return extractProofFromLevels(levels, validated, index);
}

function generateProofsBatchV3(leafHashes, indices) {
  const validated = validateLeafHashes(leafHashes);

  if (!Array.isArray(indices)) {
    throw new TypeError('indices must be an array');
  }

  const uniqueSorted = [...new Set(indices.map((idx) => {
    const parsed = typeof idx === 'string' && idx.trim() !== '' ? Number(idx) : idx;
    if (!Number.isInteger(parsed) || parsed < 0 || parsed >= validated.length) {
      throw new RangeError(`index out of range: ${idx}`);
    }
    return parsed;
  }))].sort((a, b) => a - b);

  if (validated.length === 0) {
    if (uniqueSorted.length > 0) {
      throw new RangeError('cannot generate proofs for empty leaf set');
    }
    return [];
  }

  const { levels } = buildMerkleLevelsV3(validated);
  return uniqueSorted.map((idx) => extractProofFromLevels(levels, validated, idx));
}

function generateProofsV3(leafHashes, indices) {
  return generateProofsBatchV3(leafHashes, indices);
}

function verifyProofFromLeafHash(leafHash, proof, expectedRoot) {
  if (!isSha256Hex(leafHash)) {
    throw new TypeError('leafHash must be a valid SHA-256 hex string');
  }

  if (!Array.isArray(proof)) {
    throw new TypeError('proof must be an array');
  }

  if (!isSha256Hex(expectedRoot)) {
    throw new TypeError('expectedRoot must be a valid SHA-256 hex string');
  }

  let computed = leafHash.toLowerCase();

  for (let i = 0; i < proof.length; i += 1) {
    const step = proof[i];

    if (!step || typeof step !== 'object') {
      throw new TypeError(`proof[${i}] must be an object`);
    }

    if (!['left', 'right'].includes(step.position)) {
      throw new TypeError(`proof[${i}].position must be 'left' or 'right'`);
    }

    if (!isSha256Hex(step.data)) {
      throw new TypeError(`proof[${i}].data must be a valid SHA-256 hex string`);
    }

    if (step.position === 'left') {
      computed = computeParentHash(step.data, computed);
    } else {
      computed = computeParentHash(computed, step.data);
    }
  }

  return computed === expectedRoot.toLowerCase();
}

function verifyProofFromPayload(payload, proof, expectedRoot) {
  const leafHash = hashChunk(payload);

  const valid = verifyProofFromLeafHash(leafHash, proof, expectedRoot);

  return {
    valid,
    leafHash,
    computedLeafHash: leafHash
  };
}

function verifyProofFromLeafHashV3(leafHash, proof, expectedRoot) {
  if (!isSha256Hex(leafHash)) {
    throw new TypeError('leafHash must be a valid SHA-256 hex string');
  }

  if (!Array.isArray(proof)) {
    throw new TypeError('proof must be an array');
  }

  if (!isSha256Hex(expectedRoot)) {
    throw new TypeError('expectedRoot must be a valid SHA-256 hex string');
  }

  let computed = leafHash.toLowerCase();

  for (let i = 0; i < proof.length; i += 1) {
    const step = proof[i];

    if (!step || typeof step !== 'object') {
      throw new TypeError(`proof[${i}] must be an object`);
    }

    if (!['left', 'right'].includes(step.position)) {
      throw new TypeError(`proof[${i}].position must be 'left' or 'right'`);
    }

    if (!isSha256Hex(step.data)) {
      throw new TypeError(`proof[${i}].data must be a valid SHA-256 hex string`);
    }

    if (step.position === 'left') {
      computed = computeParentHashV3(step.data, computed);
    } else {
      computed = computeParentHashV3(computed, step.data);
    }
  }

  return computed === expectedRoot.toLowerCase();
}

function resolveOpeningIndex(opening, proofObj) {
  const value = opening?.index ?? opening?.chunkIndex ?? proofObj?.index ?? proofObj?.chunkIndex;
  const parsed = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new TypeError('opening index must be a non-negative safe integer');
  }
  return parsed;
}

function resolveOpeningLength(opening, payload) {
  const value = opening?.actualLength ?? opening?.length ?? opening?.byteLength ?? payload.length;
  const parsed = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 0xffffffff) {
    throw new TypeError('opening actualLength must be an unsigned 32-bit safe integer');
  }
  return parsed;
}

function verifyProofFromPayloadWithOpeningV3(payload, opening, proofObj, expectedRoot, options = {}) {
  const payloadBytes = Buffer.from(payload);
  const safeOpening = opening && typeof opening === 'object' ? opening : {};
  const safeProofObj = proofObj && typeof proofObj === 'object' ? proofObj : {};
  const evidenceId = safeOpening.evidenceId ?? options.evidenceId;
  const index = resolveOpeningIndex(safeOpening, safeProofObj);
  const actualLength = resolveOpeningLength(safeOpening, payloadBytes);
  const salt = safeOpening.salt ?? options.salt;

  const commitment = hashChunkCommitmentV3(payloadBytes, {
    evidenceId,
    chunkIndex: index,
    actualLength,
    salt
  });

  const proof = Array.isArray(safeProofObj.proof) ? safeProofObj.proof : safeProofObj;
  const valid = verifyProofFromLeafHashV3(commitment.leafHash, proof, expectedRoot);

  return {
    valid,
    commitmentVersion: COMMITMENT_VERSION_V3_HMAC,
    leafHash: commitment.leafHash,
    computedLeafHash: commitment.leafHash,
    chunkDigest: commitment.chunkDigest,
    salt: commitment.salt,
    index,
    actualLength
  };
}

function verifySerializedDisclosureChunkV3(serializedChunk, proofObj, expectedRoot, options = {}) {
  if (!serializedChunk || typeof serializedChunk !== 'object') {
    throw new TypeError('serializedChunk must be an object');
  }

  const payload = deserializeChunkPayload(serializedChunk);
  const opening = {
    evidenceId: serializedChunk.evidenceId ?? options.evidenceId,
    index: serializedChunk.index,
    actualLength: serializedChunk.actualLength ?? serializedChunk.length,
    salt: serializedChunk.salt
  };

  const verification = verifyProofFromPayloadWithOpeningV3(
    payload,
    opening,
    proofObj,
    expectedRoot,
    options
  );

  return {
    valid: verification.valid,
    computedLeafHash: verification.leafHash,
    declaredLeafHash: null,
    reason: verification.valid ? undefined : 'invalid_merkle_path',
    commitmentVersion: COMMITMENT_VERSION_V3_HMAC,
    chunkDigest: verification.chunkDigest
  };
}

function verifySerializedDisclosureChunk(serializedChunk, proofObj, expectedRoot) {
  if (!serializedChunk || typeof serializedChunk !== 'object') {
    throw new TypeError('serializedChunk must be an object');
  }

  if (!proofObj || typeof proofObj !== 'object') {
    throw new TypeError('proofObj must be an object');
  }

  const payload = deserializeChunkPayload(serializedChunk);
  const computedLeafHash = hashChunk(payload);
  const declaredLeafHash = typeof serializedChunk.hash === 'string'
    ? serializedChunk.hash.toLowerCase()
    : null;
  const proofLeaf = typeof proofObj.leaf === 'string'
    ? proofObj.leaf.toLowerCase()
    : null;

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

  const valid = verifyProofFromLeafHash(
    computedLeafHash,
    proofObj.proof,
    expectedRoot
  );

  return {
    valid,
    computedLeafHash,
    declaredLeafHash: proofLeaf || declaredLeafHash,
    reason: valid ? undefined : 'invalid_merkle_path'
  };
}

function computeRootFromPayloadChunks(rawChunks) {
  if (!Array.isArray(rawChunks)) {
    throw new TypeError('rawChunks must be an array');
  }

  const leafHashes = rawChunks.map((chunk) => hashChunk(chunk));
  return buildMerkleTreeFromLeafHashes(leafHashes).root;
}

function isValidProofObject(proofObj) {
  if (!proofObj || typeof proofObj !== 'object') {
    return false;
  }

  if (!isSha256Hex(proofObj.leaf)) {
    return false;
  }

  if (!Array.isArray(proofObj.proof)) {
    return false;
  }

  if (proofObj.root != null && !isSha256Hex(proofObj.root)) {
    return false;
  }

  if (proofObj.leafCount != null && (!Number.isInteger(proofObj.leafCount) || proofObj.leafCount < 0)) {
    return false;
  }

  for (const step of proofObj.proof) {
    if (
      !step ||
      typeof step !== 'object' ||
      !['left', 'right'].includes(step.position) ||
      !isSha256Hex(step.data)
    ) {
      return false;
    }
  }

  return true;
}

export {
  EMPTY_TREE_SENTINEL,
  NODE_HASH_DOMAIN,
  NODE_HASH_V3_DOMAIN,
  EMPTY_ROOT_DOMAIN,
  getEmptyRoot,
  validateLeafHashes,
  computeParentHash,
  computeParentHashV3,
  buildMerkleLevels,
  buildMerkleLevelsV3,
  buildMerkleTreeFromLeafHashes,
  buildMerkleTreeFromLeafHashesV3,
  buildMerkleTree,
  generateProof,
  generateProofV3,
  generateProofsBatch,
  generateProofsBatchV3,
  generateProofs,
  generateProofsV3,
  verifyProofFromLeafHash,
  verifyProofFromLeafHashV3,
  verifyProofFromPayload,
  verifyProofFromPayloadWithOpeningV3,
  verifySerializedDisclosureChunk,
  verifySerializedDisclosureChunkV3,
  computeRootFromPayloadChunks,
  isValidProofObject
};