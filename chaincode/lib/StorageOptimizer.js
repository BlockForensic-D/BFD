'use strict';

const crypto = require('crypto');

// Optional dependency (fallback to internal merkle if not available)
let MerkleTreeLib = null;
try {
  // eslint-disable-next-line global-require
  MerkleTreeLib = require('merkletreejs');
} catch (_) {
  MerkleTreeLib = null;
}

// =============================================================================
// Deterministic helpers
// =============================================================================

function stableStringify(x) {
  if (x === null || x === undefined) return 'null';
  if (typeof x !== 'object') return JSON.stringify(x);

  if (Array.isArray(x)) {
    return '[' + x.map(stableStringify).join(',') + ']';
  }

  const keys = Object.keys(x).sort();
  const parts = keys.map(k => JSON.stringify(k) + ':' + stableStringify(x[k]));
  return '{' + parts.join(',') + '}';
}

function sha256Buf(data) {
  return crypto.createHash('sha256').update(data).digest();
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function byteLenUtf8(s) {
  return Buffer.byteLength(String(s), 'utf8');
}

// =============================================================================
// Storage optimizer
// =============================================================================

/**
 * Storage optimizer for a hybrid evidence storage workflow.
 *
 * Hybrid principle:
 * - On-chain: minimal baseline + ipfsReference (masterCID) + integrityHash
 * - Off-chain (master object at masterCID): metadata + optional encryption
 *   envelope + chain-of-custody + references
 *
 * Optional chunk commitment metadata may be attached to the on-chain baseline:
 * - chunkMerkleRoot
 * - chunkCount
 * - chunkSize
 * - commitmentVersion
 */
class StorageOptimizer {
  static STORAGE_VERSION = '2.1';

  /**
   * Engineering ceiling for the on-chain baseline payload.
   * Must stay aligned with ForensicContract.js.
   */
  static MAX_ONCHAIN_SIZE = 900; // bytes

  static IPFS_PREFIX = 'ipfs://';

  // Off-chain master object schema marker
  static MASTER_SCHEMA = 'hades-master-v1';

  static DEFAULT_ENC_ALG = 'AES-256-GCM';

  // Chunk commitment defaults
  static DEFAULT_CHUNK_SIZE = 4096;
  static CHUNK_COMMITMENT_VERSION = 'chunk-merkle-v2';

  /**
   * Strict denylist: MUST NOT appear in the on-chain hybrid baseline.
   */
  static DENY_FIELDS = new Set([
    'data', 'payload', 'content', 'raw', 'blob', 'file', 'bytes',
    'evidenceData', 'evidencePayload', 'evidenceContent',
    'pcap', 'video', 'image', 'dump',
    'chunks', 'chunkList',
    'chainOfCustody', 'actions', 'logs',
    'analysis', 'findings', 'report', 'reportData', 'fullReport',
    'ipfsReferences',
    'masterObject',
    'fullEvidence'
  ]);

  /**
   * Deterministic trimming order if the baseline somehow exceeds budget.
   * Important fields for chaincode authority and disclosure are intentionally
   * excluded from trimming.
   */
  static TRIM_ORDER = [
    'collectorType',
    'metadata',
    'evidenceType',
    'submittedBy',
    'incidentId'
  ];

  // ---------------------------------------------------------------------------
  // Generic validation / normalization helpers
  // ---------------------------------------------------------------------------

  static isNonEmptyString(x) {
    return typeof x === 'string' && x.trim().length > 0;
  }

  static isValidSha256Hex(x) {
    return typeof x === 'string' && /^[a-fA-F0-9]{64}$/.test(x);
  }

  static normalizeSha256Hex(x, fieldName) {
    if (!StorageOptimizer.isValidSha256Hex(x)) {
      throw new Error(`${fieldName} must be a valid 64-char SHA-256 hex string`);
    }
    return String(x).toLowerCase();
  }

  static normalizeNonNegativeInt(x, fieldName) {
    if (!Number.isInteger(x) || x < 0) {
      throw new Error(`${fieldName} must be a non-negative integer`);
    }
    return x;
  }

  static normalizePositiveInt(x, fieldName) {
    if (!Number.isInteger(x) || x <= 0) {
      throw new Error(`${fieldName} must be a positive integer`);
    }
    return x;
  }

  static normalizeOptionalString(x) {
    if (x === null || x === undefined) return undefined;
    const s = String(x).trim();
    return s.length ? s : undefined;
  }

  // ---------------------------------------------------------------------------
  // CID utilities
  // ---------------------------------------------------------------------------

  static normalizeCID(cid) {
    if (!cid) return '';
    let s = String(cid).trim();

    s = s.replace(/^ipfs:\/\//i, '');
    s = s.replace(/^ipfs\//i, '');
    s = s.replace(/^\/?ipfs\//i, '');

    return s.split('/')[0].trim();
  }

  static ensureIpfsUri(cid) {
    const base = StorageOptimizer.normalizeCID(cid);
    return base ? `${StorageOptimizer.IPFS_PREFIX}${base}` : '';
  }

  /**
   * Validate IPFS CID format (supports both v0 and v1).
   */
  static isValidCID(cidString) {
    if (!cidString || typeof cidString !== 'string') return false;
    const cid = StorageOptimizer.normalizeCID(cidString);

    const v0Pattern = /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/;
    const v1Pattern = /^bafy[a-z2-7]{20,}$/i;

    return v0Pattern.test(cid) || v1Pattern.test(cid);
  }

  // ---------------------------------------------------------------------------
  // Compact / guard utilities
  // ---------------------------------------------------------------------------

  static _compactInPlace(obj) {
    if (!obj || typeof obj !== 'object') return;
    for (const k of Object.keys(obj)) {
      const v = obj[k];
      const emptyObj = v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 0;
      const emptyArr = Array.isArray(v) && v.length === 0;
      if (v === undefined || v === null || v === '' || emptyObj || emptyArr) {
        delete obj[k];
      }
    }
  }

  static _assertNoDenyFields(obj) {
    const walk = (x) => {
      if (!x || typeof x !== 'object') return;
      for (const k of Object.keys(x)) {
        if (StorageOptimizer.DENY_FIELDS.has(k)) {
          throw new Error(`Hybrid baseline contains denylisted field: ${k}`);
        }
        walk(x[k]);
      }
    };
    walk(obj);
  }

  static estimateOnChainBytes(obj) {
    return byteLenUtf8(JSON.stringify(obj));
  }

  static _trimToFit(obj, maxBytes) {
    const out = JSON.parse(JSON.stringify(obj));
    let bytes = StorageOptimizer.estimateOnChainBytes(out);
    if (bytes <= maxBytes) return out;

    for (const field of StorageOptimizer.TRIM_ORDER) {
      if (out[field] !== undefined) {
        delete out[field];
        StorageOptimizer._compactInPlace(out);
        bytes = StorageOptimizer.estimateOnChainBytes(out);
        if (bytes <= maxBytes) return out;
      }
    }

    return out;
  }

  // ---------------------------------------------------------------------------
  // Chunk commitment extraction / validation
  // ---------------------------------------------------------------------------

  /**
   * Accepted shapes:
   * - flat:
   *   fullEvidence.chunkMerkleRoot
   *   fullEvidence.chunkCount
   *   fullEvidence.chunkSize
   *   fullEvidence.commitmentVersion
   *
   * - nested:
   *   fullEvidence.chunkCommitment = {
   *     chunkMerkleRoot, chunkCount, chunkSize, commitmentVersion
   *   }
   */
  static extractChunkCommitment(fullEvidence) {
    const nested = fullEvidence?.chunkCommitment || {};

    const chunkMerkleRoot =
      nested.chunkMerkleRoot ||
      fullEvidence?.chunkMerkleRoot ||
      '';

    const chunkCount =
      nested.chunkCount !== undefined
        ? nested.chunkCount
        : fullEvidence?.chunkCount;

    const chunkSize =
      nested.chunkSize !== undefined
        ? nested.chunkSize
        : fullEvidence?.chunkSize;

    const commitmentVersion =
      nested.commitmentVersion ||
      fullEvidence?.commitmentVersion ||
      '';

    const anyPresent =
      StorageOptimizer.isNonEmptyString(chunkMerkleRoot) ||
      chunkCount !== undefined ||
      chunkSize !== undefined ||
      StorageOptimizer.isNonEmptyString(commitmentVersion);

    if (!anyPresent) {
      return {
        enabled: false,
        chunkMerkleRoot: '',
        chunkCount: 0,
        chunkSize: 0,
        commitmentVersion: ''
      };
    }

    if (!StorageOptimizer.isNonEmptyString(chunkMerkleRoot)) {
      throw new Error('Chunk commitment incomplete: chunkMerkleRoot is required when chunk commitment is enabled');
    }
    if (chunkCount === undefined) {
      throw new Error('Chunk commitment incomplete: chunkCount is required when chunk commitment is enabled');
    }
    if (chunkSize === undefined) {
      throw new Error('Chunk commitment incomplete: chunkSize is required when chunk commitment is enabled');
    }

    return {
      enabled: true,
      chunkMerkleRoot: StorageOptimizer.normalizeSha256Hex(chunkMerkleRoot, 'chunkMerkleRoot'),
      chunkCount: StorageOptimizer.normalizeNonNegativeInt(chunkCount, 'chunkCount'),
      chunkSize: StorageOptimizer.normalizePositiveInt(chunkSize, 'chunkSize'),
      commitmentVersion: StorageOptimizer.isNonEmptyString(commitmentVersion)
        ? String(commitmentVersion).trim()
        : StorageOptimizer.CHUNK_COMMITMENT_VERSION
    };
  }

  // ---------------------------------------------------------------------------
  // Encryption envelope
  // ---------------------------------------------------------------------------

  static extractEncryptionEnvelope(fullEvidence) {
    const src =
      fullEvidence?.encryptionEnvelope ||
      fullEvidence?.cryptoEnvelope ||
      fullEvidence?.encryption ||
      {};

    const cipherCID =
      src.cipherCID ||
      src.cipherCid ||
      fullEvidence?.cipherCID ||
      fullEvidence?.cipherCid ||
      '';

    const iv =
      src.iv ||
      src.encryptionIV ||
      fullEvidence?.encryptionIV ||
      '';

    const tag =
      src.tag ||
      src.authTag ||
      src.encryptionAuthTag ||
      fullEvidence?.encryptionAuthTag ||
      '';

    const encAlg =
      src.encAlg ||
      src.encAlgorithm ||
      src.algorithm ||
      fullEvidence?.encAlg ||
      fullEvidence?.encAlgId ||
      StorageOptimizer.DEFAULT_ENC_ALG;

    const enabled = StorageOptimizer.isNonEmptyString(cipherCID);

    if (!enabled) {
      return {
        enabled: false,
        encAlg: StorageOptimizer.DEFAULT_ENC_ALG,
        cipherCID: '',
        iv: '',
        tag: ''
      };
    }

    if (!StorageOptimizer.isNonEmptyString(iv) || !StorageOptimizer.isNonEmptyString(tag)) {
      throw new Error(
        'Encryption envelope incomplete: cipherCID present but iv/tag missing. ' +
        'Store {cipherCID, iv, tag, encAlg} in the master object.'
      );
    }

    const normCipher = StorageOptimizer.normalizeCID(cipherCID);
    if (normCipher && !StorageOptimizer.isValidCID(normCipher)) {
      throw new Error(`Invalid cipherCID format: ${cipherCID}`);
    }

    return {
      enabled: true,
      encAlg: String(encAlg),
      cipherCID: normCipher,
      iv: String(iv),
      tag: String(tag)
    };
  }

  /**
   * Prevent accidental storage of sensitive cryptographic material in the
   * master object. Keep only policy flags + proof descriptors.
   */
  static sanitizeCryptographicMetadataForMaster(meta) {
    if (!meta || typeof meta !== 'object') return {};

    const safe = JSON.parse(JSON.stringify(meta));

    const SENSITIVE_KEYS = [
      'aesKey', 'aesKeyEncrypted', 'symmetricKey', 'secretKey',
      'privateKey', 'kmsKeyId', 'keyId',
      'encryptionIV', 'encryptionAuthTag', 'iv', 'tag'
    ];

    for (const k of SENSITIVE_KEYS) {
      if (k in safe) delete safe[k];
    }

    StorageOptimizer._compactInPlace(safe);
    return safe;
  }

  // ---------------------------------------------------------------------------
  // On-chain preparation
  // ---------------------------------------------------------------------------

  /**
   * Prepare a hybrid evidence baseline (minimal + deterministic).
   *
   * Alignment with ForensicContract.js:
   * - ipfsReference stored as ipfs://<cid>
   * - collectionTimestamp preferred
   * - custodyOwnerId + disclosureAuthorityId preserved on-chain
   * - optional chunk commitment metadata preserved on-chain
   */
  static prepareHybridEvidence(fullEvidence, masterCID, txMetadata = {}) {
    if (!fullEvidence || typeof fullEvidence !== 'object') {
      throw new Error('prepareHybridEvidence: fullEvidence must be an object');
    }
    if (!fullEvidence.evidenceId) {
      throw new Error('prepareHybridEvidence: evidenceId is required');
    }
    if (!fullEvidence.integrityHash && !fullEvidence.fileHash) {
      throw new Error('prepareHybridEvidence: integrityHash (or fileHash) is required');
    }
    if (!masterCID) {
      throw new Error('prepareHybridEvidence: masterCID is required');
    }

    const masterBase = StorageOptimizer.normalizeCID(masterCID);
    if (!StorageOptimizer.isValidCID(masterBase)) {
      throw new Error(`prepareHybridEvidence: invalid masterCID: ${masterCID}`);
    }
    const masterUri = StorageOptimizer.ensureIpfsUri(masterBase);

    const createdAt =
      fullEvidence.collectionTimestamp ||
      fullEvidence.createdAt ||
      txMetadata.createdAt ||
      '1970-01-01T00:00:00.000Z';

    const chunkCommitment = StorageOptimizer.extractChunkCommitment(fullEvidence);

    const baseline = {
      evidenceId: String(fullEvidence.evidenceId),
      incidentId: fullEvidence.incidentId ? String(fullEvidence.incidentId) : 'EVIDENCE_ONLY',
      evidenceType: StorageOptimizer.normalizeOptionalString(fullEvidence.evidenceType),

      integrityHash: String(fullEvidence.integrityHash || fullEvidence.fileHash),

      collectionTimestamp: String(fullEvidence.collectionTimestamp || createdAt),

      submittedBy: StorageOptimizer.normalizeOptionalString(fullEvidence.submittedBy),
      collectorType: StorageOptimizer.normalizeOptionalString(fullEvidence.collectorType),

      custodyOwnerId: StorageOptimizer.normalizeOptionalString(fullEvidence.custodyOwnerId),
      disclosureAuthorityId: StorageOptimizer.normalizeOptionalString(fullEvidence.disclosureAuthorityId),

      storageMode: 'hybrid',
      storageVersion: StorageOptimizer.STORAGE_VERSION,
      ipfsReference: masterUri,

      cryptographicMetadata: {
        gdprCompliant: !!(fullEvidence.cryptographicMetadata?.gdprCompliant || fullEvidence.gdprCompliant),
        crossBorderShareable: !!(fullEvidence.cryptographicMetadata?.crossBorderShareable || fullEvidence.crossBorderShareable)
      },

      metadata: {
        version: StorageOptimizer.STORAGE_VERSION,
        schema: 'HADES-HYBRID-BASELINE',
        createdAt: String(createdAt),
        createdBy: txMetadata.createdBy ? String(txMetadata.createdBy) : undefined,
        mspId: txMetadata.mspId ? String(txMetadata.mspId) : undefined,
        txId: txMetadata.txId ? String(txMetadata.txId) : undefined
      }
    };

    if (chunkCommitment.enabled) {
      baseline.chunkMerkleRoot = chunkCommitment.chunkMerkleRoot;
      baseline.chunkCount = chunkCommitment.chunkCount;
      baseline.chunkSize = chunkCommitment.chunkSize;
      baseline.commitmentVersion = chunkCommitment.commitmentVersion;
    }

    StorageOptimizer._compactInPlace(baseline);
    StorageOptimizer._assertNoDenyFields(baseline);

    const trimmed = StorageOptimizer._trimToFit(baseline, StorageOptimizer.MAX_ONCHAIN_SIZE);
    StorageOptimizer._compactInPlace(trimmed);

    const bytes = StorageOptimizer.estimateOnChainBytes(trimmed);
    if (bytes > StorageOptimizer.MAX_ONCHAIN_SIZE) {
      throw new Error(
        `Hybrid baseline exceeds MAX_ONCHAIN_SIZE: ${bytes} > ${StorageOptimizer.MAX_ONCHAIN_SIZE}`
      );
    }

    return trimmed;
  }

  // ---------------------------------------------------------------------------
  // Off-chain master object
  // ---------------------------------------------------------------------------

  /**
   * Create the master IPFS object.
   * - masterCID points to this JSON object
   * - offChain.encryption references ciphertext CID + iv/tag/alg (no key)
   * - chunk commitment metadata duplicated off-chain for reproducibility/debugging
   */
  static createMasterIPFSObject(fullEvidence) {
    if (!fullEvidence || typeof fullEvidence !== 'object') {
      throw new Error('createMasterIPFSObject: fullEvidence must be an object');
    }
    if (!fullEvidence.evidenceId) {
      throw new Error('createMasterIPFSObject: evidenceId required');
    }

    const envelope = StorageOptimizer.extractEncryptionEnvelope(fullEvidence);
    const chunkCommitment = StorageOptimizer.extractChunkCommitment(fullEvidence);

    const evidenceCore = {
      evidenceId: fullEvidence.evidenceId,
      incidentId: fullEvidence.incidentId || 'EVIDENCE_ONLY',
      submittedBy: fullEvidence.submittedBy,
      custodyOwnerId: fullEvidence.custodyOwnerId,
      disclosureAuthorityId: fullEvidence.disclosureAuthorityId,
      collectionTimestamp: fullEvidence.collectionTimestamp,
      evidenceType: fullEvidence.evidenceType,
      evidenceTitle: fullEvidence.evidenceTitle,
      evidenceDescription: fullEvidence.evidenceDescription
    };

    StorageOptimizer._compactInPlace(evidenceCore);

    const masterObject = {
      schema: StorageOptimizer.MASTER_SCHEMA,

      evidence: evidenceCore,

      offChain: {
        byteStore: 'ipfs',
        encryption: {
          enabled: envelope.enabled,
          encAlg: envelope.encAlg,
          cipherCID: envelope.cipherCID,
          iv: envelope.iv,
          tag: envelope.tag
        }
      },

      chunkCommitment: chunkCommitment.enabled
        ? {
            enabled: true,
            chunkMerkleRoot: chunkCommitment.chunkMerkleRoot,
            chunkCount: chunkCommitment.chunkCount,
            chunkSize: chunkCommitment.chunkSize,
            commitmentVersion: chunkCommitment.commitmentVersion,
            leafHashAlg: 'SHA-256(0x00 || chunk_bytes)',
            parentHashAlg: 'SHA-256(0x01 || left_digest_bytes || right_digest_bytes)',
            emptyRootAlg: 'SHA-256(0xFF || "empty")',
            duplicateOddLeaves: true
          }
        : {
            enabled: false
          },

      zkpProofs: {
        integrity: fullEvidence.cryptographicMetadata?.zkpMetadata?.integrityProof,
        compliance: fullEvidence.cryptographicMetadata?.zkpMetadata?.complianceProof,
        fazkp: fullEvidence.cryptographicMetadata?.zkpMetadata?.fazkp
      },

      chainOfCustody: fullEvidence.chainOfCustody || [],

      metadata: {
        toolsUsed: fullEvidence.toolsUsed,
        deviceContext: fullEvidence.deviceContext,
        collectorInfo: fullEvidence.collectorInfo,
        tags: fullEvidence.tags,
        location: fullEvidence.location,
        fileSize: fullEvidence.fileSize
      },

      cryptographicMetadata: StorageOptimizer.sanitizeCryptographicMetadataForMaster(
        fullEvidence.cryptographicMetadata
      ),

      storageInfo: {
        originalSize: byteLenUtf8(stableStringify(fullEvidence)),
        timestamp:
          fullEvidence.createdAt ||
          fullEvidence.timestamp ||
          fullEvidence.collectionTimestamp ||
          '1970-01-01T00:00:00.000Z',
        version: StorageOptimizer.STORAGE_VERSION,
        singleMasterCID: true,
        option: 'ledger-minimal-master-offchain'
      }
    };

    StorageOptimizer._compactInPlace(masterObject.metadata);
    StorageOptimizer._compactInPlace(masterObject.zkpProofs);
    StorageOptimizer._compactInPlace(masterObject);
    return masterObject;
  }

  // ---------------------------------------------------------------------------
  // Metrics & size accounting
  // ---------------------------------------------------------------------------

  /**
   * Calculate on-chain size for evidence (world-state write payload size).
   */
  static calculateOnChainSize(evidenceData, masterCID = null, txMetadata = null) {
    if (masterCID) {
      const meta =
        txMetadata || {
          createdAt:
            evidenceData.collectionTimestamp ||
            evidenceData.createdAt ||
            '1970-01-01T00:00:00.000Z',
          createdBy: evidenceData.submittedBy || '',
          mspId: evidenceData.mspId || '',
          txId: ''
        };

      const onChainData = StorageOptimizer.prepareHybridEvidence(evidenceData, masterCID, meta);
      return byteLenUtf8(JSON.stringify(onChainData));
    }

    return byteLenUtf8(JSON.stringify(evidenceData));
  }

  /**
   * Reconstruct full evidence from hybrid storage.
   * Returns the encryption envelope but does not decrypt.
   */
  static async reconstructEvidence(onChainData, offChainData) {
    if (!offChainData) {
      return {
        ...onChainData,
        offChainWarning: 'Off-chain data unavailable'
      };
    }

    const envelope =
      offChainData?.offChain?.encryption ||
      offChainData?.encryption ||
      null;

    return {
      evidenceId: onChainData.evidenceId,
      incidentId: onChainData.incidentId || 'EVIDENCE_ONLY',
      integrityHash: onChainData.integrityHash,
      submittedBy: onChainData.submittedBy,
      custodyOwnerId: onChainData.custodyOwnerId,
      disclosureAuthorityId: onChainData.disclosureAuthorityId,
      collectionTimestamp: onChainData.collectionTimestamp || onChainData.timestamp,

      chunkMerkleRoot: onChainData.chunkMerkleRoot,
      chunkCount: onChainData.chunkCount,
      chunkSize: onChainData.chunkSize,
      commitmentVersion: onChainData.commitmentVersion,

      ...(offChainData.evidence || {}),
      zkpProofs: offChainData.zkpProofs || {},
      chainOfCustody: offChainData.chainOfCustody || [],
      metadata: offChainData.metadata || {},
      cryptographicMetadata: offChainData.cryptographicMetadata || {},

      encryptionEnvelope: envelope,

      storageMode: onChainData.storageMode,
      storageVersion: onChainData.storageVersion,
      ipfsReference: onChainData.ipfsReference
    };
  }

  static generateStorageMetrics(originalSize, onChainSize, masterCID = null, createdAt = null, evidenceData = null) {
    let hasChunkCommitment = false;
    if (evidenceData && typeof evidenceData === 'object') {
      const cc = StorageOptimizer.extractChunkCommitment(evidenceData);
      hasChunkCommitment = !!cc.enabled;
    }

    return {
      originalSize,
      onChainSize,
      storageReduction: originalSize > 0 ? Math.round((1 - onChainSize / originalSize) * 100) : 0,
      hasMasterCID: !!masterCID,
      hasChunkCommitment,
      timestamp: createdAt || '1970-01-01T00:00:00.000Z',
      version: StorageOptimizer.STORAGE_VERSION
    };
  }

  // ---------------------------------------------------------------------------
  // Strategy selection
  // ---------------------------------------------------------------------------

  /**
   * Determine storage strategy based on evidence size.
   * Strategy is heuristic; callers may override it explicitly.
   */
  static determineStorageStrategy(evidenceData) {
    const fullSize = byteLenUtf8(JSON.stringify(evidenceData));

    if (fullSize <= StorageOptimizer.MAX_ONCHAIN_SIZE * 2) {
      return {
        mode: 'legacy',
        reason: 'Evidence small enough for on-chain storage',
        fullSize,
        onChainSize: fullSize
      };
    }

    const dummyCID = `Qm${'a'.repeat(44)}`;
    const onChainSize = StorageOptimizer.calculateOnChainSize(evidenceData, dummyCID);

    return {
      mode: 'hybrid',
      reason: 'Evidence requires off-chain storage',
      fullSize,
      onChainSize,
      reduction: Math.round((1 - onChainSize / fullSize) * 100)
    };
  }
}

// =============================================================================
// MerkleTreeManager (legacy chain-of-custody integrity helper)
// NOTE:
// Kept intentionally close to existing legacy behavior to avoid regression.
// This is separate from the chunk commitment flow used for evidence disclosure.
// =============================================================================

class MerkleTreeManager {
  static _leafHash(entry) {
    const canonical = {
      timestamp: entry?.timestamp || '',
      actor: entry?.actor || entry?.actorId || '',
      action: entry?.action || '',
      location: entry?.location || '',
      condition: entry?.condition || '',
      txId: entry?.txId || entry?.transactionId || ''
    };
    return sha256Buf(stableStringify(canonical));
  }

  static generateMerkleRoot(entries) {
    if (!Array.isArray(entries) || entries.length === 0) {
      return sha256Hex('empty');
    }

    const leaves = entries.map(e => MerkleTreeManager._leafHash(e));

    if (MerkleTreeLib?.MerkleTree) {
      const { MerkleTree } = MerkleTreeLib;
      const tree = new MerkleTree(leaves, sha256Buf, { sortPairs: true, duplicateOdd: true });
      return tree.getRoot().toString('hex');
    }

    // Legacy fallback behavior preserved to avoid regression
    let layer = leaves.map(b => b.toString('hex'));
    while (layer.length > 1) {
      const next = [];
      for (let i = 0; i < layer.length; i += 2) {
        const left = layer[i];
        const right = (i + 1 < layer.length) ? layer[i + 1] : layer[i];
        next.push(sha256Hex(left + right));
      }
      layer = next;
    }
    return layer[0];
  }

  static generateProof(entries, index) {
    if (!Array.isArray(entries) || entries.length === 0) {
      throw new Error('Invalid entries for proof generation');
    }
    if (index < 0 || index >= entries.length) {
      throw new Error('Invalid index for proof generation');
    }

    const leaves = entries.map(e => MerkleTreeManager._leafHash(e));
    const leaf = leaves[index].toString('hex');
    const root = MerkleTreeManager.generateMerkleRoot(entries);

    if (MerkleTreeLib?.MerkleTree) {
      const { MerkleTree } = MerkleTreeLib;
      const tree = new MerkleTree(leaves, sha256Buf, { sortPairs: true, duplicateOdd: true });

      const proof = tree.getProof(leaves[index]).map(p => ({
        position: p.position,
        data: p.data.toString('hex')
      }));

      return { proof, root, leaf };
    }

    // Legacy fallback behavior preserved to avoid regression
    let idx = index;
    let layer = leaves.map(b => b.toString('hex'));
    const proof = [];

    while (layer.length > 1) {
      const isRight = (idx % 2) === 1;
      const pairIdx = isRight ? idx - 1 : idx + 1;
      const sibling = layer[pairIdx] ?? layer[idx];

      proof.push({
        position: isRight ? 'left' : 'right',
        data: sibling
      });

      const next = [];
      for (let i = 0; i < layer.length; i += 2) {
        const left = layer[i];
        const right = (i + 1 < layer.length) ? layer[i + 1] : layer[i];
        next.push(sha256Hex(left + right));
      }

      layer = next;
      idx = Math.floor(idx / 2);
    }

    return { proof, root, leaf };
  }

  static verifyProof(leafHex, proof, rootHex) {
    if (!leafHex || !rootHex) return false;

    if (MerkleTreeLib?.MerkleTree && Array.isArray(proof)) {
      try {
        const { MerkleTree } = MerkleTreeLib;
        const leafBuffer = Buffer.from(leafHex, 'hex');
        const rootBuffer = Buffer.from(rootHex, 'hex');
        const proofBuffers = proof.map(p => ({
          position: p.position,
          data: Buffer.from(p.data, 'hex')
        }));

        const tree = new MerkleTree([], sha256Buf, { sortPairs: true, duplicateOdd: true });
        return tree.verify(proofBuffers, leafBuffer, rootBuffer);
      } catch (_) {
        return false;
      }
    }

    if (!Array.isArray(proof)) return false;

    let h = String(leafHex).toLowerCase();
    for (const step of proof) {
      if (!step || !step.data || !step.position) return false;
      const sib = String(step.data).toLowerCase();

      h = (step.position === 'left')
        ? sha256Hex(sib + h)
        : sha256Hex(h + sib);
    }
    return h === String(rootHex).toLowerCase();
  }
}

module.exports = { StorageOptimizer, MerkleTreeManager };