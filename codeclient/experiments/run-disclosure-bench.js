#!/usr/bin/env node
'use strict';

import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import { performance } from 'perf_hooks';
import { fileURLToPath } from 'url';

import {
  buildCapabilityPayload,
  signCapability,
  createCapId,
  generateNonceHex,
  SCOPE_TYPES
} from '../capability-manager.js';

import {
  buildDisclosureBundle,
  executeHashOnlyDisclosure,
  verifyDisclosureBundleClientSide
} from '../disclosure-protocol.js';

import {
  COMMITMENT_VERSION_V2,
  COMMITMENT_VERSION_V3_HMAC
} from '../evidence-chunker.js';

import {
  normalizeMetricRecord,
  recordsToCsv
} from './metrics-schema.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DEFAULT_CONFIG = Object.freeze({
  datasetName: 'local-benchmark',
  chunkSizes: [512, 1024, 2048, 4096, 8192],
  disclosureModes: ['HASH_ONLY', 'CHUNK_SET', 'FULL_CHUNKS'],
  disclosedChunkSets: [
    [0],
    [0, 1, 2],
    [0, 1, 2, 3, 4, 5, 6, 7]
  ],
  disclosedChunkPolicies: [],
  commitmentVersions: ['chunk-merkle-v2', 'chunk-merkle-v3-hmac-opening'],
  repetitions: 3,
  warmupRepetitions: 0,
  platform: 'host',
  evidenceType: 'binary'
});

function printHelp() {
  console.log(`
Disclosure benchmark runner

Usage:
  node experiments/run-disclosure-bench.js [options]

Options:
  --inputManifest <jsonFile>   JSON array of evidence descriptors
  --config <jsonFile>          Benchmark config JSON
  --outputJson <jsonFile>      Output raw JSON results
  --outputCsv <csvFile>        Output CSV results
  --group <string>             Experiment group label (default: Group-B)
  --scenarioPrefix <string>    Scenario prefix (default: disclosure-bench)
  --help

Input manifest format:
[
  {
    "evidence_id": "EVID-001",
    "file_name": "sample.bin",
    "file_path": "/absolute/or/relative/path/to/sample.bin",
    "evidence_type": "pcap"
  }
]

Config format:
{
  "datasetName": "Edge-IIoTset",
  "chunkSizes": [1024, 2048, 4096],
  "disclosureModes": ["HASH_ONLY", "CHUNK_SET", "FULL_CHUNKS"],
  "disclosedChunkSets": [[0], [0,1,2]],
  "disclosedChunkPolicies": [
    { "name": "vendor-first-8", "type": "firstN", "n": 8 },
    { "name": "vendor-32kb-window", "type": "byteRange", "offsetBytes": 0, "lengthBytes": 32768 },
    { "name": "vendor-5pct", "type": "percentage", "ratio": 0.05, "strategy": "firstN" }
  ],
  "commitmentVersions": ["chunk-merkle-v2", "chunk-merkle-v3-hmac-opening"],
  "repetitions": 5,
  "warmupRepetitions": 2,
  "platform": "host"
}
`);
}

function parseArgs(argv) {
  const out = { _: [] };
  let i = 0;

  while (i < argv.length) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const key = token.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        out[key] = true;
        i += 1;
      } else {
        out[key] = next;
        i += 2;
      }
    } else {
      out._.push(token);
      i += 1;
    }
  }

  return out;
}

function getArg(args, name, defaultValue = undefined) {
  return args[name] === undefined ? defaultValue : args[name];
}

function requireArg(args, name) {
  const value = getArg(args, name);
  if (value === undefined || value === null || value === '') {
    throw new Error(`Missing required option --${name}`);
  }
  return value;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

async function readJsonFile(filePath) {
  return JSON.parse(await fs.readFile(filePath, 'utf8'));
}

async function readBinaryFile(filePath) {
  return fs.readFile(filePath);
}

async function ensureParentDir(filePath) {
  await fs.mkdir(path.dirname(path.resolve(filePath)), { recursive: true });
}

async function writeJsonFile(filePath, value) {
  await ensureParentDir(filePath);
  await fs.writeFile(filePath, JSON.stringify(value, null, 2), 'utf8');
}

async function writeTextFile(filePath, text) {
  await ensureParentDir(filePath);
  await fs.writeFile(filePath, text, 'utf8');
}

function mergeConfig(userConfig) {
  const config = {
    ...DEFAULT_CONFIG,
    ...(userConfig || {})
  };

  if (!Array.isArray(config.chunkSizes) || config.chunkSizes.length === 0) {
    throw new Error('config.chunkSizes must be a non-empty array');
  }

  if (!Array.isArray(config.disclosureModes) || config.disclosureModes.length === 0) {
    throw new Error('config.disclosureModes must be a non-empty array');
  }

  if (!Array.isArray(config.disclosedChunkSets)) {
    throw new Error('config.disclosedChunkSets must be an array');
  }

  if (!Array.isArray(config.disclosedChunkPolicies)) {
    throw new Error('config.disclosedChunkPolicies must be an array when provided');
  }

  if (config.disclosedChunkSets.length === 0 && config.disclosedChunkPolicies.length === 0) {
    throw new Error('config.disclosedChunkSets or config.disclosedChunkPolicies must be non-empty');
  }

  if (!Array.isArray(config.commitmentVersions) || config.commitmentVersions.length === 0) {
    throw new Error('config.commitmentVersions must be a non-empty array');
  }

  const allowedVersions = new Set([COMMITMENT_VERSION_V2, COMMITMENT_VERSION_V3_HMAC]);
  config.commitmentVersions = config.commitmentVersions.map((version) => String(version).trim());
  for (const version of config.commitmentVersions) {
    if (!allowedVersions.has(version)) {
      throw new Error(`Unsupported commitment version: ${version}`);
    }
  }

  if (!Number.isInteger(config.repetitions) || config.repetitions <= 0) {
    throw new Error('config.repetitions must be a positive integer');
  }

  if (!Number.isInteger(config.warmupRepetitions) || config.warmupRepetitions < 0) {
    throw new Error('config.warmupRepetitions must be a non-negative integer');
  }

  config.disclosedChunkPolicies = normalizeDisclosurePolicies(config);

  return config;
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function jsonSizeBytes(value) {
  return Buffer.byteLength(JSON.stringify(value), 'utf8');
}

function snapshotMemoryUsageBytes() {
  const mem = process.memoryUsage();
  const resource = typeof process.resourceUsage === 'function'
    ? process.resourceUsage()
    : null;

  // On Linux, Node reports resourceUsage().maxRSS in kilobytes.
  const resourcePeakBytes = resource && Number.isFinite(Number(resource.maxRSS))
    ? Number(resource.maxRSS) * 1024
    : 0;

  return {
    rss_bytes: Number(mem.rss || 0),
    heap_used_bytes: Number(mem.heapUsed || 0),
    peak_memory_bytes: Math.max(Number(mem.rss || 0), resourcePeakBytes)
  };
}

function buildScalingResourceMetrics({ evidenceBytes, wallclockStartedMs, memoryBefore }) {
  const memoryAfter = snapshotMemoryUsageBytes();
  const wallclockTotalMs = performance.now() - wallclockStartedMs;
  const wallclockTotalSeconds = wallclockTotalMs / 1000;
  const evidenceMiB = Number(evidenceBytes || 0) / (1024 * 1024);

  return {
    wallclock_total_ms: wallclockTotalMs,
    wallclock_total_seconds: wallclockTotalSeconds,
    throughput_mib_per_sec: wallclockTotalSeconds > 0 ? evidenceMiB / wallclockTotalSeconds : 0,
    peak_memory_bytes: Math.max(
      Number(memoryBefore?.peak_memory_bytes || 0),
      Number(memoryAfter.peak_memory_bytes || 0),
      Number(memoryBefore?.rss_bytes || 0),
      Number(memoryAfter.rss_bytes || 0)
    ),
    rss_before_bytes: Number(memoryBefore?.rss_bytes || 0),
    rss_after_bytes: Number(memoryAfter.rss_bytes || 0),
    heap_used_before_bytes: Number(memoryBefore?.heap_used_bytes || 0),
    heap_used_after_bytes: Number(memoryAfter.heap_used_bytes || 0)
  };
}


function normalizeManifestEntries(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error('input manifest must be a non-empty array');
  }

  return entries.map((entry, index) => {
    if (!isPlainObject(entry)) {
      throw new Error(`manifest entry ${index} must be an object`);
    }

    const evidenceId = String(
      entry.evidence_id ?? entry.evidenceId ?? ''
    ).trim();

    const fileName = String(
      entry.file_name ?? entry.fileName ?? path.basename(String(entry.file_path ?? entry.filePath ?? ''))
    ).trim();

    const filePathRaw = String(
      entry.file_path ?? entry.filePath ?? ''
    ).trim();

    const evidenceType = String(
      entry.evidence_type ?? entry.evidenceType ?? DEFAULT_CONFIG.evidenceType
    ).trim();

    if (!evidenceId) {
      throw new Error(`manifest entry ${index} missing evidence_id`);
    }

    if (!filePathRaw) {
      throw new Error(`manifest entry ${index} missing file_path`);
    }

    return {
      evidence_id: evidenceId,
      file_name: fileName || path.basename(filePathRaw),
      file_path: path.resolve(filePathRaw),
      evidence_type: evidenceType || DEFAULT_CONFIG.evidenceType
    };
  });
}

function buildCapabilityToken({
  evidenceId,
  granteeId,
  issuerId,
  scope,
  privateKeyPem,
  purpose = 'benchmark',
  version = 'cap-v3',
  commitmentVersion = null,
  chunkMerkleRoot = null,
  lifecycleStateAtIssuance = 'COMMITTED',
  evidenceLifecycleEpoch = 0,
  allowedLifecycleStates = ['COMMITTED', 'AUTHORIZED', 'DISCLOSED']
}) {
  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const nonce = generateNonceHex(8);

  const payload = buildCapabilityPayload({
    capId: createCapId({ evidenceId, granteeId, nonce }),
    evidenceId,
    issuerId,
    granteeId,
    scope,
    purpose,
    issuedAt,
    expiresAt,
    nonce,
    version,
    ...(commitmentVersion ? { commitmentVersion } : {}),
    ...(chunkMerkleRoot ? { chunkMerkleRoot } : {}),
    lifecycleStateAtIssuance,
    evidenceLifecycleEpoch,
    allowedLifecycleStates
  });

  return signCapability(payload, privateKeyPem);
}

function generateIssuerKeyPairPem() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

  return {
    publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }),
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' })
  };
}

function clampDisclosedIndices(disclosedSet, totalChunks) {
  if (!Array.isArray(disclosedSet)) {
    throw new TypeError('disclosedSet must be an array');
  }

  const unique = [...new Set(disclosedSet)]
    .map((x) => Number(x))
    .filter((x) => Number.isInteger(x) && x >= 0 && x < totalChunks)
    .sort((a, b) => a - b);

  return unique;
}

function sanitizePolicyName(value, fallback = 'policy') {
  const raw = String(value ?? '').trim();
  const sanitized = raw.replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^-+|-+$/g, '');
  return sanitized || fallback;
}

function normalizeDisclosurePolicies(config) {
  const policies = [];

  for (const [idx, disclosedSet] of (config.disclosedChunkSets || []).entries()) {
    if (!Array.isArray(disclosedSet)) {
      throw new TypeError(`disclosedChunkSets[${idx}] must be an array`);
    }
    policies.push({
      name: `indices-${idx + 1}-dc${disclosedSet.length}`,
      type: 'indices',
      indices: [...disclosedSet]
    });
  }

  for (const [idx, rawPolicy] of (config.disclosedChunkPolicies || []).entries()) {
    if (!isPlainObject(rawPolicy)) {
      throw new TypeError(`disclosedChunkPolicies[${idx}] must be an object`);
    }

    const type = String(rawPolicy.type || '').trim();
    if (!['indices', 'firstN', 'byteRange', 'percentage'].includes(type)) {
      throw new Error(`Unsupported disclosedChunkPolicies[${idx}].type: ${type}`);
    }

    const name = sanitizePolicyName(rawPolicy.name, `${type}-${idx + 1}`);
    policies.push({ ...rawPolicy, name, type });
  }

  if (policies.length === 0) {
    throw new Error('At least one disclosure policy is required for CHUNK_SET benchmarks');
  }

  return policies;
}

function resolveDisclosurePolicy(policy, { totalChunks, chunkSize, fileSizeBytes }) {
  const type = String(policy.type || 'indices');
  let indices = [];

  if (type === 'indices') {
    indices = clampDisclosedIndices(policy.indices || [], totalChunks);
  } else if (type === 'firstN') {
    const n = Math.max(0, Number.parseInt(policy.n, 10) || 0);
    indices = Array.from({ length: Math.min(n, totalChunks) }, (_, index) => index);
  } else if (type === 'byteRange') {
    const offsetBytes = Math.max(0, Number(policy.offsetBytes ?? 0));
    const lengthBytes = Math.max(0, Number(policy.lengthBytes ?? 0));
    if (lengthBytes > 0 && totalChunks > 0) {
      const startChunk = Math.floor(Math.min(offsetBytes, Math.max(fileSizeBytes - 1, 0)) / chunkSize);
      const endExclusiveByte = Math.min(offsetBytes + lengthBytes, fileSizeBytes);
      const endChunk = Math.floor(Math.max(endExclusiveByte - 1, 0) / chunkSize);
      for (let idx = startChunk; idx <= endChunk && idx < totalChunks; idx += 1) {
        if (idx >= 0) indices.push(idx);
      }
    }
  } else if (type === 'percentage') {
    const ratio = Math.min(Math.max(Number(policy.ratio ?? policy.percent ?? 0), 0), 1);
    const minChunks = Math.max(0, Number.parseInt(policy.minChunks ?? 1, 10) || 0);
    const maxChunks = policy.maxChunks == null
      ? totalChunks
      : Math.max(0, Number.parseInt(policy.maxChunks, 10) || 0);
    const count = Math.min(
      Math.max(Math.ceil(totalChunks * ratio), minChunks),
      maxChunks,
      totalChunks
    );
    const strategy = String(policy.strategy || 'firstN');
    if (strategy === 'evenly_spaced' && count > 1) {
      const selected = new Set();
      for (let i = 0; i < count; i += 1) {
        selected.add(Math.min(totalChunks - 1, Math.floor((i * totalChunks) / count)));
      }
      indices = [...selected].sort((a, b) => a - b);
    } else {
      indices = Array.from({ length: count }, (_, index) => index);
    }
  }

  return {
    name: sanitizePolicyName(policy.name, `${type}-policy`),
    type,
    indices: clampDisclosedIndices(indices, totalChunks)
  };
}

async function computeChunkMetadata(buffer, chunkSize, options = {}) {
  const {
    chunk,
    COMMITMENT_VERSION_V3_HMAC: CHUNKER_COMMITMENT_VERSION_V3_HMAC
  } = await import(path.resolve(__dirname, '../evidence-chunker.js'));
  const {
    buildMerkleTreeFromLeafHashes,
    buildMerkleTreeFromLeafHashesV3
  } = await import(path.resolve(__dirname, '../evidence-merkle.js'));

  const commitmentVersion = String(options.commitmentVersion ?? COMMITMENT_VERSION_V2);
  const chunkOptions = {
    commitmentVersion,
    evidenceId: options.evidenceId,
    evidenceMasterKey: options.evidenceMasterKey,
    emk: options.emk,
    kSalt: options.kSalt,
    saltKey: options.saltKey
  };
  const chunked = chunk(buffer, chunkSize, chunkOptions);
  const tree = commitmentVersion === CHUNKER_COMMITMENT_VERSION_V3_HMAC
    ? buildMerkleTreeFromLeafHashesV3(chunked.chunkHashes)
    : buildMerkleTreeFromLeafHashes(chunked.chunkHashes);

  return {
    fileHash: chunked.fileHash,
    chunkSize: chunked.chunkSize,
    totalChunks: chunked.totalChunks,
    chunkHashes: chunked.chunkHashes,
    commitmentVersion,
    chunked,
    tree
  };
}

function commitmentVersionLabel(version) {
  return String(version).replace(/^chunk-merkle-/, '').replace(/[^a-zA-Z0-9]+/g, '-');
}

function buildHashOnlyScenarioName(prefix, chunkSize, commitmentVersion) {
  return `${prefix}-${commitmentVersionLabel(commitmentVersion)}-hash-only-cs${chunkSize}`;
}

function buildChunkSetScenarioName(prefix, chunkSize, disclosedCount, commitmentVersion, policyName = null) {
  const policySuffix = policyName ? `-${sanitizePolicyName(policyName)}` : `dc${disclosedCount}`;
  return `${prefix}-${commitmentVersionLabel(commitmentVersion)}-chunk-set-cs${chunkSize}-${policySuffix}-dc${disclosedCount}`;
}

function buildFullChunksScenarioName(prefix, chunkSize, totalChunks, commitmentVersion) {
  return `${prefix}-${commitmentVersionLabel(commitmentVersion)}-full-chunks-cs${chunkSize}-tc${totalChunks}`;
}

function createEvidenceMasterKeyHex() {
  return crypto.randomBytes(32).toString('hex');
}

function getProofSizeBytes(bundle) {
  return jsonSizeBytes(bundle.proofs ?? []);
}

function getOpeningSizeBytes(bundle) {
  const disclosedChunks = Array.isArray(bundle.disclosedChunks) ? bundle.disclosedChunks : [];
  const openings = disclosedChunks.map((chunk) => ({
    index: chunk.index,
    actualLength: chunk.actualLength ?? chunk.length,
    salt: chunk.salt ?? null
  }));
  return jsonSizeBytes(openings);
}

function getBundlePartSizes(bundle) {
  return {
    manifestSizeBytes: jsonSizeBytes(bundle.manifest ?? {}),
    capabilitySizeBytes: jsonSizeBytes(bundle.capabilityToken ?? null),
    proofSizeBytes: getProofSizeBytes(bundle),
    openingSizeBytes: getOpeningSizeBytes(bundle)
  };
}

async function runHashOnlyMeasurement({
  evidenceId,
  evidenceType,
  evidenceBuffer,
  issuerPublicKeyPem,
  issuerPrivateKeyPem,
  chunkSize,
  commitmentVersion,
  evidenceMasterKey,
  scenario,
  datasetName,
  fileName,
  platform,
  experimentGroup
}) {
  const wallclockStartedMs = performance.now();
  const memoryBefore = snapshotMemoryUsageBytes();

  const precomputed = await computeChunkMetadata(evidenceBuffer, chunkSize, {
    commitmentVersion,
    evidenceId,
    evidenceMasterKey
  });

  const token = buildCapabilityToken({
    evidenceId,
    granteeId: 'benchmark-verifier',
    issuerId: 'benchmark-issuer',
    scope: { type: SCOPE_TYPES.HASH_ONLY },
    privateKeyPem: issuerPrivateKeyPem,
    commitmentVersion,
    chunkMerkleRoot: precomputed.tree.root
  });

  const generationStarted = performance.now();
  const bundle = executeHashOnlyDisclosure({
    evidenceId,
    evidenceType,
    evidenceBuffer,
    capabilityToken: token,
    issuerPublicKey: issuerPublicKeyPem,
    requesterId: 'benchmark-verifier',
    chunkSize,
    commitmentVersion,
    evidenceMasterKey,
    expectedOnChainRoot: precomputed.tree.root,
    generatedAt: new Date().toISOString(),
    now: new Date()
  });
  const generationTimeMs = performance.now() - generationStarted;

  const verificationStarted = performance.now();
  const verification = verifyDisclosureBundleClientSide(bundle, {
    expectedRoot: precomputed.tree.root,
    issuerPublicKey: issuerPublicKeyPem,
    now: new Date()
  });
  const verificationTimeMs = performance.now() - verificationStarted;

  const resourceMetrics = buildScalingResourceMetrics({

    evidenceBytes: evidenceBuffer.length,

    wallclockStartedMs,

    memoryBefore

  });


  const record = normalizeMetricRecord({
    experiment_id: crypto.randomUUID(),
    experiment_group: experimentGroup,
    scenario,
    dataset_name: datasetName,
    evidence_id: evidenceId,
    file_name: fileName,
    commitment_version: commitmentVersion,
    disclosure_mode: 'HASH_ONLY',
    disclosure_policy: null,
    file_size_bytes: evidenceBuffer.length,
    chunk_size: chunkSize,
    total_chunks: precomputed.totalChunks,
    disclosed_chunk_count: 0,
    withheld_chunk_count: precomputed.totalChunks,
    disclosure_ratio: 0,
    withheld_ratio: 1,
    bundle_size_bytes: jsonSizeBytes(bundle),
    proof_size_bytes: getBundlePartSizes(bundle).proofSizeBytes,
    opening_size_bytes: getBundlePartSizes(bundle).openingSizeBytes,
    manifest_size_bytes: getBundlePartSizes(bundle).manifestSizeBytes,
    capability_size_bytes: getBundlePartSizes(bundle).capabilitySizeBytes,
    disclosed_data_bytes: 0,
    withheld_data_bytes: evidenceBuffer.length,
    disclosure_expansion_ratio: 0,
    generation_time_ms: generationTimeMs,
    verification_time_ms: verificationTimeMs,
    total_time_ms: generationTimeMs + verificationTimeMs,
    ...resourceMetrics,
    valid: verification.valid,
    failure_reason: verification.reason ?? null,
    tamper_type: null,
    platform,
    timestamp: new Date().toISOString()
  });

  return { record, bundle, verification };
}

async function runChunkSetMeasurement({
  evidenceId,
  evidenceType,
  evidenceBuffer,
  issuerPublicKeyPem,
  issuerPrivateKeyPem,
  chunkSize,
  commitmentVersion,
  evidenceMasterKey,
  disclosedSet = null,
  disclosurePolicy = null,
  scenario,
  datasetName,
  fileName,
  platform,
  experimentGroup
}) {
  const wallclockStartedMs = performance.now();
  const memoryBefore = snapshotMemoryUsageBytes();

  const precomputed = await computeChunkMetadata(evidenceBuffer, chunkSize, {
    commitmentVersion,
    evidenceId,
    evidenceMasterKey
  });
  const resolvedPolicy = disclosurePolicy
    ? resolveDisclosurePolicy(disclosurePolicy, {
      totalChunks: precomputed.totalChunks,
      chunkSize,
      fileSizeBytes: evidenceBuffer.length
    })
    : {
      name: Array.isArray(disclosedSet) ? `indices-dc${disclosedSet.length}` : 'indices',
      type: 'indices',
      indices: clampDisclosedIndices(disclosedSet || [], precomputed.totalChunks)
    };
  const requestedChunkIndices = resolvedPolicy.indices;

  if (requestedChunkIndices.length === 0) {
    throw new Error(
      `Scenario ${scenario} produced zero valid disclosed indices for totalChunks=${precomputed.totalChunks}`
    );
  }

  const token = buildCapabilityToken({
    evidenceId,
    granteeId: 'benchmark-verifier',
    issuerId: 'benchmark-issuer',
    scope: {
      type: SCOPE_TYPES.CHUNK_SET,
      indices: requestedChunkIndices
    },
    privateKeyPem: issuerPrivateKeyPem,
    commitmentVersion,
    chunkMerkleRoot: precomputed.tree.root
  });

  const generationStarted = performance.now();
  const bundle = buildDisclosureBundle({
    evidenceId,
    evidenceType,
    evidenceBuffer,
    capabilityToken: token,
    issuerPublicKey: issuerPublicKeyPem,
    requesterId: 'benchmark-verifier',
    requestedChunkIndices,
    chunkSize,
    commitmentVersion,
    evidenceMasterKey,
    expectedOnChainRoot: precomputed.tree.root,
    generatedAt: new Date().toISOString(),
    now: new Date()
  });
  const generationTimeMs = performance.now() - generationStarted;

  const verificationStarted = performance.now();
  const verification = verifyDisclosureBundleClientSide(bundle, {
    expectedRoot: precomputed.tree.root,
    issuerPublicKey: issuerPublicKeyPem,
    now: new Date()
  });
  const verificationTimeMs = performance.now() - verificationStarted;

  const disclosedDataBytes = Array.isArray(bundle.disclosedChunks)
    ? bundle.disclosedChunks.reduce((sum, chunk) => sum + Number(chunk.length || 0), 0)
    : 0;

  const resourceMetrics = buildScalingResourceMetrics({

    evidenceBytes: evidenceBuffer.length,

    wallclockStartedMs,

    memoryBefore

  });


  const record = normalizeMetricRecord({
    experiment_id: crypto.randomUUID(),
    experiment_group: experimentGroup,
    scenario,
    dataset_name: datasetName,
    evidence_id: evidenceId,
    file_name: fileName,
    commitment_version: commitmentVersion,
    disclosure_mode: 'CHUNK_SET',
    disclosure_policy: resolvedPolicy.name,
    file_size_bytes: evidenceBuffer.length,
    chunk_size: chunkSize,
    total_chunks: precomputed.totalChunks,
    disclosed_chunk_count: requestedChunkIndices.length,
    withheld_chunk_count: Math.max(precomputed.totalChunks - requestedChunkIndices.length, 0),
    disclosure_ratio: precomputed.totalChunks > 0
      ? requestedChunkIndices.length / precomputed.totalChunks
      : 0,
    withheld_ratio: precomputed.totalChunks > 0
      ? Math.max(precomputed.totalChunks - requestedChunkIndices.length, 0) / precomputed.totalChunks
      : 0,
    bundle_size_bytes: jsonSizeBytes(bundle),
    proof_size_bytes: getBundlePartSizes(bundle).proofSizeBytes,
    opening_size_bytes: getBundlePartSizes(bundle).openingSizeBytes,
    manifest_size_bytes: getBundlePartSizes(bundle).manifestSizeBytes,
    capability_size_bytes: getBundlePartSizes(bundle).capabilitySizeBytes,
    disclosed_data_bytes: disclosedDataBytes,
    withheld_data_bytes: Math.max(evidenceBuffer.length - disclosedDataBytes, 0),
    disclosure_expansion_ratio: disclosedDataBytes > 0 ? jsonSizeBytes(bundle) / disclosedDataBytes : 0,
    generation_time_ms: generationTimeMs,
    verification_time_ms: verificationTimeMs,
    total_time_ms: generationTimeMs + verificationTimeMs,
    ...resourceMetrics,
    valid: verification.valid,
    failure_reason: verification.reason ?? null,
    tamper_type: null,
    platform,
    timestamp: new Date().toISOString()
  });

  return { record, bundle, verification };
}


async function runFullChunksMeasurement({
  evidenceId,
  evidenceType,
  evidenceBuffer,
  issuerPublicKeyPem,
  issuerPrivateKeyPem,
  chunkSize,
  commitmentVersion,
  evidenceMasterKey,
  scenario,
  datasetName,
  fileName,
  platform,
  experimentGroup
}) {
  const wallclockStartedMs = performance.now();
  const memoryBefore = snapshotMemoryUsageBytes();

  const precomputed = await computeChunkMetadata(evidenceBuffer, chunkSize, {
    commitmentVersion,
    evidenceId,
    evidenceMasterKey
  });
  const requestedChunkIndices = Array.from({ length: precomputed.totalChunks }, (_, index) => index);

  const token = buildCapabilityToken({
    evidenceId,
    granteeId: 'benchmark-verifier',
    issuerId: 'benchmark-issuer',
    scope: { type: SCOPE_TYPES.FULL_CHUNKS },
    privateKeyPem: issuerPrivateKeyPem,
    commitmentVersion,
    chunkMerkleRoot: precomputed.tree.root
  });

  const generationStarted = performance.now();
  const bundle = buildDisclosureBundle({
    evidenceId,
    evidenceType,
    evidenceBuffer,
    capabilityToken: token,
    issuerPublicKey: issuerPublicKeyPem,
    requesterId: 'benchmark-verifier',
    requestedChunkIndices,
    chunkSize,
    commitmentVersion,
    evidenceMasterKey,
    expectedOnChainRoot: precomputed.tree.root,
    generatedAt: new Date().toISOString(),
    now: new Date()
  });
  const generationTimeMs = performance.now() - generationStarted;

  const verificationStarted = performance.now();
  const verification = verifyDisclosureBundleClientSide(bundle, {
    expectedRoot: precomputed.tree.root,
    issuerPublicKey: issuerPublicKeyPem,
    now: new Date()
  });
  const verificationTimeMs = performance.now() - verificationStarted;

  const disclosedDataBytes = Array.isArray(bundle.disclosedChunks)
    ? bundle.disclosedChunks.reduce((sum, chunk) => sum + Number(chunk.length || 0), 0)
    : 0;
  const partSizes = getBundlePartSizes(bundle);
  const bundleSizeBytes = jsonSizeBytes(bundle);

  const resourceMetrics = buildScalingResourceMetrics({

    evidenceBytes: evidenceBuffer.length,

    wallclockStartedMs,

    memoryBefore

  });


  const record = normalizeMetricRecord({
    experiment_id: crypto.randomUUID(),
    experiment_group: experimentGroup,
    scenario,
    dataset_name: datasetName,
    evidence_id: evidenceId,
    file_name: fileName,
    commitment_version: commitmentVersion,
    disclosure_mode: 'FULL_CHUNKS',
    disclosure_policy: null,
    file_size_bytes: evidenceBuffer.length,
    chunk_size: chunkSize,
    total_chunks: precomputed.totalChunks,
    disclosed_chunk_count: requestedChunkIndices.length,
    withheld_chunk_count: 0,
    disclosure_ratio: 1,
    withheld_ratio: 0,
    bundle_size_bytes: bundleSizeBytes,
    proof_size_bytes: partSizes.proofSizeBytes,
    opening_size_bytes: partSizes.openingSizeBytes,
    manifest_size_bytes: partSizes.manifestSizeBytes,
    capability_size_bytes: partSizes.capabilitySizeBytes,
    disclosed_data_bytes: disclosedDataBytes,
    withheld_data_bytes: Math.max(evidenceBuffer.length - disclosedDataBytes, 0),
    disclosure_expansion_ratio: disclosedDataBytes > 0 ? bundleSizeBytes / disclosedDataBytes : 0,
    generation_time_ms: generationTimeMs,
    verification_time_ms: verificationTimeMs,
    total_time_ms: generationTimeMs + verificationTimeMs,
    ...resourceMetrics,
    valid: verification.valid,
    failure_reason: verification.reason ?? null,
    tamper_type: null,
    platform,
    timestamp: new Date().toISOString()
  });

  return { record, bundle, verification };
}

async function runBenchmarkForEvidence(entry, config, runOptions) {
  const evidenceBuffer = await readBinaryFile(entry.file_path);
  const results = [];

  // Reuse issuer keypair across repetitions to avoid measuring Ed25519 key-generation noise.
  const { publicKeyPem, privateKeyPem } = generateIssuerKeyPairPem();

  for (const chunkSize of config.chunkSizes) {
    for (const commitmentVersion of config.commitmentVersions) {
      const evidenceMasterKey = commitmentVersion === COMMITMENT_VERSION_V3_HMAC
        ? createEvidenceMasterKeyHex()
        : undefined;

      const warmupRepetitions = Number(config.warmupRepetitions || 0);

      // Per-mode warmup: exercise each disclosure path before recording measurements.
      // Warmup records are discarded so they do not affect final metrics.
      for (let warmupRep = 0; warmupRep < warmupRepetitions; warmupRep += 1) {
        const rep = warmupRep;
        const isWarmup = true;
        const recordedRep = rep;
        const warmupResultsBefore = results.length;
        if (config.disclosureModes.includes('HASH_ONLY')) {
          const scenario = buildHashOnlyScenarioName(
            runOptions.scenarioPrefix,
            chunkSize,
            commitmentVersion
          );

          const { record } = await runHashOnlyMeasurement({
            evidenceId: entry.evidence_id,
            evidenceType: entry.evidence_type,
            evidenceBuffer,
            issuerPublicKeyPem: publicKeyPem,
            issuerPrivateKeyPem: privateKeyPem,
            chunkSize,
            commitmentVersion,
            evidenceMasterKey,
            scenario,
            datasetName: config.datasetName,
            fileName: entry.file_name,
            platform: config.platform,
            experimentGroup: runOptions.experimentGroup
          });

          if (!isWarmup) {
            results.push({
              ...record,
              experiment_id: `${record.experiment_id}-r${recordedRep}`
            });
          }
        }
        if (config.disclosureModes.includes('CHUNK_SET')) {
          for (const disclosurePolicy of config.disclosedChunkPolicies) {
            const precomputedForPolicy = await computeChunkMetadata(evidenceBuffer, chunkSize, {
              commitmentVersion,
              evidenceId: entry.evidence_id,
              evidenceMasterKey
            });
            const resolvedPolicy = resolveDisclosurePolicy(disclosurePolicy, {
              totalChunks: precomputedForPolicy.totalChunks,
              chunkSize,
              fileSizeBytes: evidenceBuffer.length
            });
            if (resolvedPolicy.indices.length === 0) continue;

            const scenario = buildChunkSetScenarioName(
              runOptions.scenarioPrefix,
              chunkSize,
              resolvedPolicy.indices.length,
              commitmentVersion,
              resolvedPolicy.name
            );

            const { record } = await runChunkSetMeasurement({
              evidenceId: entry.evidence_id,
              evidenceType: entry.evidence_type,
              evidenceBuffer,
              issuerPublicKeyPem: publicKeyPem,
              issuerPrivateKeyPem: privateKeyPem,
              chunkSize,
              commitmentVersion,
              evidenceMasterKey,
              disclosurePolicy,
              scenario,
              datasetName: config.datasetName,
              fileName: entry.file_name,
              platform: config.platform,
              experimentGroup: runOptions.experimentGroup
            });

            if (!isWarmup) {
              results.push({
                ...record,
                experiment_id: `${record.experiment_id}-r${recordedRep}`
              });
            }
          }
        }
        if (config.disclosureModes.includes('FULL_CHUNKS')) {
          const precomputed = await computeChunkMetadata(evidenceBuffer, chunkSize, {
            commitmentVersion,
            evidenceId: entry.evidence_id,
            evidenceMasterKey
          });
          const scenario = buildFullChunksScenarioName(
            runOptions.scenarioPrefix,
            chunkSize,
            precomputed.totalChunks,
            commitmentVersion
          );

          const { record } = await runFullChunksMeasurement({
            evidenceId: entry.evidence_id,
            evidenceType: entry.evidence_type,
            evidenceBuffer,
            issuerPublicKeyPem: publicKeyPem,
            issuerPrivateKeyPem: privateKeyPem,
            chunkSize,
            commitmentVersion,
            evidenceMasterKey,
            scenario,
            datasetName: config.datasetName,
            fileName: entry.file_name,
            platform: config.platform,
            experimentGroup: runOptions.experimentGroup
          });

          if (!isWarmup) {
            results.push({
              ...record,
              experiment_id: `${record.experiment_id}-r${recordedRep}`
            });
          }
        }
        results.length = warmupResultsBefore;
      }

      for (let rep = 0; rep < config.repetitions; rep += 1) {
        const isWarmup = false;
        const recordedRep = rep;
        // Counterbalanced measurement order to reduce first-mode/JIT/cache bias.
        // Even repetitions run CHUNK_SET before HASH_ONLY; odd repetitions run HASH_ONLY before CHUNK_SET.
        if (rep % 2 === 0) {
          if (config.disclosureModes.includes('CHUNK_SET')) {
            for (const disclosurePolicy of config.disclosedChunkPolicies) {
              const precomputedForPolicy = await computeChunkMetadata(evidenceBuffer, chunkSize, {
                commitmentVersion,
                evidenceId: entry.evidence_id,
                evidenceMasterKey
              });
              const resolvedPolicy = resolveDisclosurePolicy(disclosurePolicy, {
                totalChunks: precomputedForPolicy.totalChunks,
                chunkSize,
                fileSizeBytes: evidenceBuffer.length
              });
              if (resolvedPolicy.indices.length === 0) continue;

              const scenario = buildChunkSetScenarioName(
                runOptions.scenarioPrefix,
                chunkSize,
                resolvedPolicy.indices.length,
                commitmentVersion,
                resolvedPolicy.name
              );

              const { record } = await runChunkSetMeasurement({
                evidenceId: entry.evidence_id,
                evidenceType: entry.evidence_type,
                evidenceBuffer,
                issuerPublicKeyPem: publicKeyPem,
                issuerPrivateKeyPem: privateKeyPem,
                chunkSize,
                commitmentVersion,
                evidenceMasterKey,
                disclosurePolicy,
                scenario,
                datasetName: config.datasetName,
                fileName: entry.file_name,
                platform: config.platform,
                experimentGroup: runOptions.experimentGroup
              });

              if (!isWarmup) {
                results.push({
                  ...record,
                  experiment_id: `${record.experiment_id}-r${recordedRep}`
                });
              }
            }
          }
          if (config.disclosureModes.includes('HASH_ONLY')) {
            const scenario = buildHashOnlyScenarioName(
              runOptions.scenarioPrefix,
              chunkSize,
              commitmentVersion
            );

            const { record } = await runHashOnlyMeasurement({
              evidenceId: entry.evidence_id,
              evidenceType: entry.evidence_type,
              evidenceBuffer,
              issuerPublicKeyPem: publicKeyPem,
              issuerPrivateKeyPem: privateKeyPem,
              chunkSize,
              commitmentVersion,
              evidenceMasterKey,
              scenario,
              datasetName: config.datasetName,
              fileName: entry.file_name,
              platform: config.platform,
              experimentGroup: runOptions.experimentGroup
            });

            if (!isWarmup) {
              results.push({
                ...record,
                experiment_id: `${record.experiment_id}-r${recordedRep}`
              });
            }
          }
        } else {
          if (config.disclosureModes.includes('HASH_ONLY')) {
            const scenario = buildHashOnlyScenarioName(
              runOptions.scenarioPrefix,
              chunkSize,
              commitmentVersion
            );

            const { record } = await runHashOnlyMeasurement({
              evidenceId: entry.evidence_id,
              evidenceType: entry.evidence_type,
              evidenceBuffer,
              issuerPublicKeyPem: publicKeyPem,
              issuerPrivateKeyPem: privateKeyPem,
              chunkSize,
              commitmentVersion,
              evidenceMasterKey,
              scenario,
              datasetName: config.datasetName,
              fileName: entry.file_name,
              platform: config.platform,
              experimentGroup: runOptions.experimentGroup
            });

            if (!isWarmup) {
              results.push({
                ...record,
                experiment_id: `${record.experiment_id}-r${recordedRep}`
              });
            }
          }
          if (config.disclosureModes.includes('CHUNK_SET')) {
            for (const disclosurePolicy of config.disclosedChunkPolicies) {
              const precomputedForPolicy = await computeChunkMetadata(evidenceBuffer, chunkSize, {
                commitmentVersion,
                evidenceId: entry.evidence_id,
                evidenceMasterKey
              });
              const resolvedPolicy = resolveDisclosurePolicy(disclosurePolicy, {
                totalChunks: precomputedForPolicy.totalChunks,
                chunkSize,
                fileSizeBytes: evidenceBuffer.length
              });
              if (resolvedPolicy.indices.length === 0) continue;

              const scenario = buildChunkSetScenarioName(
                runOptions.scenarioPrefix,
                chunkSize,
                resolvedPolicy.indices.length,
                commitmentVersion,
                resolvedPolicy.name
              );

              const { record } = await runChunkSetMeasurement({
                evidenceId: entry.evidence_id,
                evidenceType: entry.evidence_type,
                evidenceBuffer,
                issuerPublicKeyPem: publicKeyPem,
                issuerPrivateKeyPem: privateKeyPem,
                chunkSize,
                commitmentVersion,
                evidenceMasterKey,
                disclosurePolicy,
                scenario,
                datasetName: config.datasetName,
                fileName: entry.file_name,
                platform: config.platform,
                experimentGroup: runOptions.experimentGroup
              });

              if (!isWarmup) {
                results.push({
                  ...record,
                  experiment_id: `${record.experiment_id}-r${recordedRep}`
                });
              }
            }
          }
        }

        if (config.disclosureModes.includes('FULL_CHUNKS')) {
          const precomputed = await computeChunkMetadata(evidenceBuffer, chunkSize, {
            commitmentVersion,
            evidenceId: entry.evidence_id,
            evidenceMasterKey
          });
          const scenario = buildFullChunksScenarioName(
            runOptions.scenarioPrefix,
            chunkSize,
            precomputed.totalChunks,
            commitmentVersion
          );

          const { record } = await runFullChunksMeasurement({
            evidenceId: entry.evidence_id,
            evidenceType: entry.evidence_type,
            evidenceBuffer,
            issuerPublicKeyPem: publicKeyPem,
            issuerPrivateKeyPem: privateKeyPem,
            chunkSize,
            commitmentVersion,
            evidenceMasterKey,
            scenario,
            datasetName: config.datasetName,
            fileName: entry.file_name,
            platform: config.platform,
            experimentGroup: runOptions.experimentGroup
          });

          if (!isWarmup) {
            results.push({
              ...record,
              experiment_id: `${record.experiment_id}-r${recordedRep}`
            });
          }
        }
      }
    }
  }

  return results;
}

function percentile(values, p) {
  const numeric = values.filter((v) => Number.isFinite(Number(v))).map(Number).sort((a, b) => a - b);
  if (numeric.length === 0) return 0;
  if (numeric.length === 1) return numeric[0];
  const rank = (numeric.length - 1) * p;
  const lo = Math.floor(rank);
  const hi = Math.ceil(rank);
  if (lo === hi) return numeric[lo];
  return numeric[lo] + (numeric[hi] - numeric[lo]) * (rank - lo);
}

function median(values) {
  return percentile(values, 0.5);
}

function summarizeGroup(records) {
  const summary = {
    total_runs: records.length,
    valid_runs: records.filter((r) => r.valid).length,
    invalid_runs: records.filter((r) => !r.valid).length,
    avg_generation_time_ms: 0,
    avg_verification_time_ms: 0,
    avg_total_time_ms: 0,
    median_generation_time_ms: 0,
    median_verification_time_ms: 0,
    median_total_time_ms: 0,
    p95_total_time_ms: 0,
    avg_bundle_size_bytes: 0,
    avg_proof_size_bytes: 0,
    avg_opening_size_bytes: 0,
    avg_disclosed_data_bytes: 0,
    avg_withheld_data_bytes: 0,
    avg_disclosure_ratio: 0,
    avg_withheld_ratio: 0,
    avg_disclosure_expansion_ratio: 0
  };

  if (records.length === 0) return summary;

  const sum = (field) => records.reduce((acc, item) => acc + Number(item[field] || 0), 0);
  const values = (field) => records.map((item) => Number(item[field] || 0));

  summary.avg_generation_time_ms = sum('generation_time_ms') / records.length;
  summary.avg_verification_time_ms = sum('verification_time_ms') / records.length;
  summary.avg_total_time_ms = sum('total_time_ms') / records.length;
  summary.avg_wallclock_total_ms = sum('wallclock_total_ms') / records.length;
  summary.avg_wallclock_total_seconds = sum('wallclock_total_seconds') / records.length;
  summary.avg_throughput_mib_per_sec = sum('throughput_mib_per_sec') / records.length;
  summary.max_peak_memory_bytes = records.reduce(
    (max, item) => Math.max(max, Number(item.peak_memory_bytes || 0)),
    0
  );
  summary.median_generation_time_ms = median(values('generation_time_ms'));
  summary.median_verification_time_ms = median(values('verification_time_ms'));
  summary.median_total_time_ms = median(values('total_time_ms'));
  summary.p95_total_time_ms = percentile(values('total_time_ms'), 0.95);
  summary.avg_bundle_size_bytes = sum('bundle_size_bytes') / records.length;
  summary.avg_proof_size_bytes = sum('proof_size_bytes') / records.length;
  summary.avg_opening_size_bytes = sum('opening_size_bytes') / records.length;
  summary.avg_disclosed_data_bytes = sum('disclosed_data_bytes') / records.length;
  summary.avg_withheld_data_bytes = sum('withheld_data_bytes') / records.length;
  summary.avg_disclosure_ratio = sum('disclosure_ratio') / records.length;
  summary.avg_withheld_ratio = sum('withheld_ratio') / records.length;
  summary.avg_disclosure_expansion_ratio = sum('disclosure_expansion_ratio') / records.length;

  return summary;
}

function groupRecords(records, keyFn) {
  const groups = new Map();
  for (const record of records) {
    const key = keyFn(record);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(record);
  }
  return Object.fromEntries([...groups.entries()].map(([key, group]) => [key, summarizeGroup(group)]));
}

function summarizeResults(records) {
  return {
    overall: summarizeGroup(records),
    by_commitment_version: groupRecords(records, (r) => r.commitment_version || 'unknown'),
    by_disclosure_mode: groupRecords(records, (r) => r.disclosure_mode || 'unknown'),
    by_disclosure_policy: groupRecords(records, (r) => r.disclosure_policy || 'none'),
    by_commitment_and_mode: groupRecords(
      records,
      (r) => `${r.commitment_version || 'unknown'}::${r.disclosure_mode || 'unknown'}`
    ),
    by_scenario: groupRecords(records, (r) => r.scenario || 'unknown')
  };
}

async function main() {
  const benchmarkWallclockStartedMs = performance.now();
  const args = parseArgs(process.argv.slice(2));

  if (args.help || args.h || args._[0] === 'help') {
    printHelp();
    return;
  }

  const inputManifestFile = requireArg(args, 'inputManifest');
  const configFile = getArg(args, 'config');
  const outputJson = requireArg(args, 'outputJson');
  const outputCsv = requireArg(args, 'outputCsv');

  const experimentGroup = getArg(args, 'group', 'Group-B');
  const scenarioPrefix = getArg(args, 'scenarioPrefix', 'disclosure-bench');

  const manifestEntries = normalizeManifestEntries(await readJsonFile(inputManifestFile));
  const config = mergeConfig(configFile ? await readJsonFile(configFile) : {});

  const allResults = [];

  for (const entry of manifestEntries) {
    const perEvidenceResults = await runBenchmarkForEvidence(entry, config, {
      experimentGroup,
      scenarioPrefix
    });

    allResults.push(...perEvidenceResults);
  }

  const summary = summarizeResults(allResults);
  summary.benchmark_wallclock_total_seconds = (performance.now() - benchmarkWallclockStartedMs) / 1000;
  summary.process_peak_memory_bytes = Math.max(
    Number(summary.max_peak_memory_bytes || 0),
    Number(snapshotMemoryUsageBytes().peak_memory_bytes || 0)
  );

  await writeJsonFile(outputJson, {
    config,
    summary,
    records: allResults
  });

  await writeTextFile(outputCsv, recordsToCsv(allResults));

  console.log(JSON.stringify({
    success: true,
    output_json: path.resolve(outputJson),
    output_csv: path.resolve(outputCsv),
    summary
  }, null, 2));
}

main().catch((err) => {
  console.error(err instanceof Error ? err.stack || err.message : String(err));
  process.exitCode = 1;
});