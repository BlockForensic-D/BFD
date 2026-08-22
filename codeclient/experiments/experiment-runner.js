#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { computeStreamingMerkleForFile } from './core/streaming-merkle.js';
import { chunk as chunkFile } from '../evidence-chunker.js';
import { buildMerkleTreeFromLeafHashes } from '../evidence-merkle.js';
import { buildStreamingChunkDisclosureBundle } from './core/streaming-chunk-disclosure.js';
import {
  buildDisclosureBundle,
  verifyDisclosureBundleClientSide
} from '../disclosure-protocol.js';

import { getStakeholderProfile } from './profiles/stakeholder-profiles.js';
import { selectDisclosure } from './core/selection-policy.js';
import { buildRunRecord, appendJsonlRecord } from './core/result-writer.js';
import { buildCaseBundle, verifyCaseBundle } from './core/case-bundle.js';
import { SwatA6Adapter } from './adapters/swat-a6-adapter.js';
import { EdgeIiotsetAdapter } from './adapters/edge-iiotset-adapter.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_MANIFEST_PATH = path.resolve(__dirname, 'config', 'experiment-manifest.json');
const TWO_GIB_MINUS_ONE = 2 * 1024 * 1024 * 1024 - 1;

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

function loadManifest(manifestPath) {
  return JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
}

function resolveRepoRoot(manifestPath, repoRootArg) {
  return repoRootArg ? path.resolve(repoRootArg) : path.resolve(path.dirname(manifestPath), '..', '..');
}

function getGitCommitHashSafe(repoRoot) {
  try {
    return execSync('git rev-parse HEAD', {
      cwd: repoRoot,
      stdio: ['ignore', 'pipe', 'ignore'],
      encoding: 'utf8'
    }).trim();
  } catch {
    return null;
  }
}

function nowIso() {
  return new Date().toISOString();
}

function createIssuerKeyPair() {
  return crypto.generateKeyPairSync('ed25519');
}

function getResultsFilePath(manifest, experimentId) {
  const mapping = {
    E1_functional_validation: 'e1-functional.jsonl',
    E2_swat_wave2_contextual_case_study: 'e2-swat-wave2-contextual.jsonl',
    E3_edge_scaling: 'e3-edge-scaling.jsonl',
    E4_chunk_size_sensitivity: 'e4-chunk-sensitivity.jsonl',
    E5_disclosure_ratio_sensitivity: 'e5-ratio-sensitivity.jsonl'
  };
  const fileName = mapping[experimentId] ?? `${experimentId}.jsonl`;
  return path.resolve(manifest.results.rawDir, fileName);
}

async function prepareFile(adapter, fileId, chunkSizeBytes, commitmentVersion) {
  const fileDescriptor = await adapter.getFileDescriptor(fileId);

  const streamed = await computeStreamingMerkleForFile(
    fileDescriptor.absolutePath,
    chunkSizeBytes,
    fileDescriptor.sizeBytes
  );

  return {
    fileId,
    fileName: fileDescriptor.fileName,
    fileSize: streamed.fileSize,
    chunkSize: streamed.chunkSize,
    chunkCount: streamed.chunkCount,
    merkleRoot: streamed.merkleRoot,
    commitmentVersion
  };
}

function getIterationConfig(manifest, experiment, runType) {
  if (runType === 'pilot') {
    return {
      warmupIterations: manifest.defaults.pilotWarmupIterations ?? 0,
      measuredIterations: manifest.defaults.pilotMeasuredIterations ?? 3
    };
  }

  return {
    warmupIterations: manifest.defaults.warmupIterations ?? 2,
    measuredIterations: experiment.timingIterations ?? manifest.defaults.timingIterations ?? 20
  };
}

function warnOnFirstMeasuredSlowdown(measuredTimes, label) {
  if (!Array.isArray(measuredTimes) || measuredTimes.length < 3) return;

  const numeric = measuredTimes.filter((v) => typeof v === 'number' && Number.isFinite(v));
  if (numeric.length < 3) return;

  const [first, ...rest] = numeric;
  const sortedRest = [...rest].sort((a, b) => a - b);
  const medianRest = sortedRest[Math.floor(sortedRest.length / 2)];

  if (medianRest > 0 && first > medianRest * 1.25) {
    console.warn(`[warn] first measured run for ${label} is >1.25x slower than the median of later runs`);
  }
}

function summarizeInvariantKey(preparedFiles, mode, chunkSizeBytes, disclosureRatioTarget, disclosedChunkCount, disclosedBytesRaw) {
  return JSON.stringify({
    fileIds: preparedFiles.map((f) => f.fileId),
    mode,
    chunkSizeBytes,
    disclosureRatioTarget,
    disclosedChunkCount,
    disclosedBytesRaw
  });
}

function assertInvariantsStable(values, label) {
  const unique = new Set(values);
  if (unique.size > 1) {
    console.warn(`[warn] invariant fields changed across measured runs for ${label}`);
  }
}

function computeSelectionConstraintInfo(selectionParams, targetRatio, realizedRatio) {
  const info = {
    flags: [],
    note: null
  };

  if (
    typeof targetRatio !== 'number' ||
    !Number.isFinite(targetRatio) ||
    typeof realizedRatio !== 'number' ||
    !Number.isFinite(realizedRatio)
  ) {
    return info;
  }

  const minChunks = selectionParams?.minChunks ?? null;
  const maxChunks = selectionParams?.maxChunks ?? null;

  if (minChunks != null && realizedRatio > targetRatio * 1.5) {
    info.flags.push('MIN_CHUNKS_DOMINATES_TARGET');
  }

  if (maxChunks != null && realizedRatio < targetRatio * 0.5) {
    info.flags.push('MAX_CHUNKS_CAPS_TARGET');
  }

  if (info.flags.length > 0) {
    info.note =
      'Realized disclosure ratio deviates from nominal target due to bounded selection constraints (minimum/maximum chunk floor/cap).';
  }

  return info;
}

function getDatasetNameFromFileId(fileId) {
  return String(fileId).startsWith('swat_') ? 'swat' : 'edge';
}

function getAdapterForFileId(fileId, adapters) {
  return getDatasetNameFromFileId(fileId) === 'swat' ? adapters.swat : adapters.edge;
}

function normalizeSelectionParams(baseParams, manifest) {
  return {
    disclosureRatio: baseParams?.disclosureRatio ?? manifest.defaults.disclosureRatio,
    chunkSizeBytes: baseParams?.chunkSizeBytes ?? manifest.defaults.chunkSizeBytes,
    minChunks: baseParams?.minChunks,
    maxChunks: baseParams?.maxChunks
  };
}

function assertNonEmptyString(value, fieldName) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
}

function assertArray(value, fieldName) {
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array`);
  }
}

function validateSameArtifactCaseStudyExperiment(experiment) {
  assertNonEmptyString(experiment.id, 'experiment.id');
  assertNonEmptyString(experiment.focalFileId, `${experiment.id}.focalFileId`);
  assertArray(experiment.cases, `${experiment.id}.cases`);

  if (experiment.cases.length === 0) {
    throw new Error(`${experiment.id}.cases must not be empty`);
  }

  const allowedModes = new Set(['FULL_CHUNKS', 'CHUNK_SET', 'HASH_ONLY']);

  for (const caseConfig of experiment.cases) {
    assertNonEmptyString(caseConfig.id, `${experiment.id}.cases[].id`);
    assertNonEmptyString(caseConfig.stakeholderId, `${caseConfig.id}.stakeholderId`);
    assertNonEmptyString(caseConfig.mode, `${caseConfig.id}.mode`);

    if (!allowedModes.has(caseConfig.mode)) {
      throw new Error(`${caseConfig.id}.mode unsupported: ${caseConfig.mode}`);
    }

    if (caseConfig.mode === 'FULL_CHUNKS') {
      if (caseConfig.selectionPolicy && caseConfig.selectionPolicy !== 'same_artifact_full') {
        throw new Error(`${caseConfig.id}: FULL_CHUNKS should use selectionPolicy "same_artifact_full" or omit it`);
      }
    }

    if (caseConfig.mode === 'HASH_ONLY') {
      if (caseConfig.selectionPolicy && caseConfig.selectionPolicy !== 'same_artifact_hash_only') {
        throw new Error(`${caseConfig.id}: HASH_ONLY should use selectionPolicy "same_artifact_hash_only" or omit it`);
      }
    }

    if (caseConfig.mode === 'CHUNK_SET') {
      if (caseConfig.selectionPolicy !== 'ratio_uniform') {
        throw new Error(`${caseConfig.id}: CHUNK_SET currently requires selectionPolicy "ratio_uniform"`);
      }
      if (!caseConfig.selectionParams || typeof caseConfig.selectionParams !== 'object') {
        throw new Error(`${caseConfig.id}: CHUNK_SET requires selectionParams`);
      }
    }
  }
}

function validateExperimentConfig(experiment) {
  if (experiment.type === 'same_artifact_stakeholder_case_study') {
    validateSameArtifactCaseStudyExperiment(experiment);
  }
}

function buildChunkExperimentMetadata({
  experiment,
  selectionParams = null,
  result,
  extra = {}
}) {
  return {
    comparisonScope: 'same_artifact',
    selectionPolicy: experiment.selectionPolicy ?? null,
    timingSemantics: 'chunk_bundle_generation_and_client_verification',
    selectionParams,
    interpretationCaveats: experiment.interpretationCaveats ?? [],
    timingBreakdown: result.timingBreakdown,
    caveatFlags: result.caveatFlags,
    caveatNote: result.caveatNote,
    ...extra
  };
}

async function executeHashOnlyDisclosure({
  fileId,
  adapter,
  stakeholderProfile,
  manifest,
  issuerPrivateKey,
  issuerPublicKey,
  purpose = 'same_artifact_hash_only_experiment'
}) {
  const chunkSizeBytes = manifest.defaults.chunkSizeBytes;

  const prepStart = performance.now();
  const prepared = await prepareFile(
    adapter,
    fileId,
    chunkSizeBytes,
    manifest.protocol.commitmentVersion
  );
  const precomputeMs = performance.now() - prepStart;

  const bundle = buildCaseBundle({
    caseId: fileId,
    mode: 'HASH_ONLY',
    granteeId: stakeholderProfile.role,
    issuerPrivateKey,
    preparedFiles: [prepared],
    commitmentVersion: manifest.protocol.commitmentVersion,
    purpose
  });

  const expectedEntriesByFileId = new Map([
    [prepared.fileId, { merkleRoot: prepared.merkleRoot }]
  ]);

  const verification = verifyCaseBundle(bundle, issuerPublicKey, expectedEntriesByFileId);
  const disclosedBytesBundle = bundle.metrics.transferBytes;

  return {
    fileId,
    fileName: prepared.fileName,
    fileSizeBytes: prepared.fileSize,
    totalChunks: prepared.chunkCount,
    disclosureRatioTarget: 0,
    disclosureRatioRealized: 0,
    disclosedChunkCount: 0,
    disclosedBytesRaw: 0,
    disclosedBytesBundle,
    bundleGenerationTimeMs: bundle.metrics.generationTimeMs,
    verificationTimeMs: verification.metrics.verificationTimeMs,
    proofSizeBytes: 0,
    bundleSizeBytes: disclosedBytesBundle,
    valid: verification.valid,
    failureReason: verification.reason,
    timingBreakdown: {
      precomputeMs,
      bundleAssemblyMs: bundle.metrics.generationTimeMs,
      verificationMs: verification.metrics.verificationTimeMs
    },
    caveatFlags: [],
    caveatNote: null,
    commitmentEntryCount: 1,
    hashOnlyMode: 'MERKLE_ROOT_ONLY'
  };
}

async function executeFullChunksDisclosure({
  fileId,
  adapter,
  stakeholderProfile,
  manifest,
  issuerPrivateKey,
  issuerPublicKey,
  purpose = 'same_artifact_full_scope_experiment'
}) {
  const chunkSizeBytes = manifest.defaults.chunkSizeBytes;
  const prepared = await prepareFile(
    adapter,
    fileId,
    chunkSizeBytes,
    manifest.protocol.commitmentVersion
  );

  const bundle = buildCaseBundle({
    caseId: fileId,
    mode: 'FULL_CHUNKS',
    granteeId: stakeholderProfile.role,
    issuerPrivateKey,
    preparedFiles: [prepared],
    commitmentVersion: manifest.protocol.commitmentVersion,
    purpose
  });

  const expectedEntriesByFileId = new Map([
    [prepared.fileId, { merkleRoot: prepared.merkleRoot }]
  ]);

  const verification = verifyCaseBundle(bundle, issuerPublicKey, expectedEntriesByFileId);
  const disclosedBytesRaw = prepared.fileSize;
  const disclosedBytesBundle = bundle.metrics.transferBytes;

  return {
    fileId,
    fileName: prepared.fileName,
    fileSizeBytes: prepared.fileSize,
    totalChunks: prepared.chunkCount,
    disclosureRatioTarget: 1,
    disclosureRatioRealized: 1,
    disclosedChunkCount: prepared.chunkCount,
    disclosedBytesRaw,
    disclosedBytesBundle,
    bundleGenerationTimeMs: bundle.metrics.generationTimeMs,
    verificationTimeMs: verification.metrics.verificationTimeMs,
    proofSizeBytes: 0,
    bundleSizeBytes: disclosedBytesBundle,
    valid: verification.valid,
    failureReason: verification.reason,
    timingBreakdown: {
      bundleAssemblyMs: bundle.metrics.generationTimeMs,
      verificationMs: verification.metrics.verificationTimeMs
    },
    caveatFlags: [],
    caveatNote: null,
    commitmentEntryCount: 1,
    hashOnlyMode: null
  };
}

async function runWindowAwareCase({
  manifest,
  experiment,
  caseConfig,
  adapters,
  issuerPrivateKey,
  issuerPublicKey,
  outputPath,
  gitCommitHash,
  runType,
  hostLabel,
  fullCorpusRawBytes
}) {
  const stakeholderProfile = getStakeholderProfile(caseConfig.stakeholderId);
  const adapter = adapters.swat;
  const chunkSizeBytes = manifest.defaults.chunkSizeBytes;
  const commitmentVersion = manifest.protocol.commitmentVersion;
  const { warmupIterations, measuredIterations } = getIterationConfig(manifest, experiment, runType);

  const preparedFiles = [];
  for (const fileId of caseConfig.files) {
    preparedFiles.push(await prepareFile(adapter, fileId, chunkSizeBytes, commitmentVersion));
  }

  const expectedEntriesByFileId = new Map(
    preparedFiles.map((f) => [f.fileId, { merkleRoot: f.merkleRoot }])
  );

  const measuredGenerationTimes = [];
  const invariantSnapshots = [];
  const contextualRawBytes = preparedFiles.reduce((sum, f) => sum + f.fileSize, 0);

  const totalRuns = warmupIterations + measuredIterations;
  for (let i = 0; i < totalRuns; i += 1) {
    const isWarmup = i < warmupIterations;
    const iterationIndex = i;
    const timestampStart = nowIso();

    const bundle = buildCaseBundle({
      caseId: caseConfig.id,
      mode: caseConfig.mode,
      granteeId: stakeholderProfile.role,
      issuerPrivateKey,
      preparedFiles,
      commitmentVersion,
      purpose: caseConfig.purpose
    });

    const verification = verifyCaseBundle(bundle, issuerPublicKey, expectedEntriesByFileId);

    const disclosedBytesRaw = caseConfig.mode === 'HASH_ONLY'
      ? 0
      : contextualRawBytes;

    const disclosedBytesBundle = bundle.metrics.transferBytes;
    const disclosedChunkCount = caseConfig.mode === 'HASH_ONLY'
      ? 0
      : preparedFiles.reduce((sum, f) => sum + f.chunkCount, 0);

    const record = buildRunRecord({
      experimentId: experiment.id,
      caseId: caseConfig.id,
      iterationIndex,
      isWarmup,
      runType,
      timestampStart,
      timestampEnd: nowIso(),
      gitCommitHash,
      datasetName: 'swat',
      fileIds: preparedFiles.map((f) => f.fileId),
      fileNames: preparedFiles.map((f) => f.fileName),
      fileSizeBytes: contextualRawBytes,
      stakeholderLabel: stakeholderProfile.role,
      mode: caseConfig.mode,
      chunkSizeBytes,
      totalChunks: preparedFiles.reduce((sum, f) => sum + f.chunkCount, 0),
      disclosureRatioTarget: caseConfig.mode === 'HASH_ONLY' ? 0 : 1,
      disclosureRatioRealized: caseConfig.mode === 'HASH_ONLY' ? 0 : 1,
      disclosedChunkCount,
      disclosedBytesRaw,
      disclosedBytesBundle,
      bundleGenerationTimeMs: bundle.metrics.generationTimeMs,
      verificationTimeMs: verification.metrics.verificationTimeMs,
      proofSizeBytes: 0,
      bundleSizeBytes: disclosedBytesBundle,
      valid: verification.valid,
      failureReason: verification.reason,
      hostLabel,
      metadata: {
        selectionPolicy: caseConfig.selectionPolicy,
        fullCorpusRawBytes,
        contextualRawBytes,
        commitmentEntryCount: preparedFiles.length,
        hashOnlyMode: caseConfig.mode === 'HASH_ONLY' ? 'MERKLE_ROOT_ONLY' : null
      }
    });

    appendJsonlRecord(outputPath, record);

    if (!isWarmup) {
      measuredGenerationTimes.push(bundle.metrics.generationTimeMs);
      invariantSnapshots.push(
        summarizeInvariantKey(
          preparedFiles,
          caseConfig.mode,
          chunkSizeBytes,
          caseConfig.mode === 'HASH_ONLY' ? 0 : 1,
          disclosedChunkCount,
          disclosedBytesRaw
        )
      );
    }

    console.log(`[${experiment.id}] ${caseConfig.id} ${i + 1}/${totalRuns}${isWarmup ? ' [warmup]' : ''}`);
  }

  assertInvariantsStable(invariantSnapshots, caseConfig.id);
  warnOnFirstMeasuredSlowdown(measuredGenerationTimes, caseConfig.id);
}

async function executeChunkDisclosure({
  fileId,
  adapter,
  stakeholderProfile,
  manifest,
  selectionPolicy,
  selectionParams,
  chunkSizeBytes,
  issuerPrivateKey,
  issuerPublicKey,
  preparedLargeFileMeta = null
}) {
  const fileDescriptor = await adapter.getFileDescriptor(fileId);
  const capabilityManager = await import('../capability-manager.js');

  const shouldUseStreamingPath = fileDescriptor.sizeBytes > TWO_GIB_MINUS_ONE;

  if (shouldUseStreamingPath) {
    const selectionStart = performance.now();

    const streamedMeta = preparedLargeFileMeta ?? await computeStreamingMerkleForFile(
      fileDescriptor.absolutePath,
      chunkSizeBytes,
      fileDescriptor.sizeBytes
    );

    const selection = selectDisclosure({
      selectionPolicy,
      selectionParams,
      files: [fileId],
      totalChunks: streamedMeta.chunkCount
    });

    const selectionMs = performance.now() - selectionStart;

    const signStart = performance.now();
    const capabilityToken = capabilityManager.signCapability({
      evidenceId: fileId,
      issuerId: 'EvidenceCustodian',
      granteeId: stakeholderProfile.role,
      scope: {
        type: 'CHUNK_SET',
        indices: selection.selectedChunkIndexes
      },
      purpose: 'disclosure_chunk_experiment',
      issuedAt: nowIso(),
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      version: 'cap-v1'
    }, issuerPrivateKey);
    const capabilitySignMs = performance.now() - signStart;

    const bundle = await buildStreamingChunkDisclosureBundle({
      capabilityToken,
      issuerPublicKey,
      requesterId: stakeholderProfile.role,
      evidenceId: fileId,
      evidenceType: 'PCAP',
      filePath: fileDescriptor.absolutePath,
      fileSize: fileDescriptor.sizeBytes,
      chunkSize: chunkSizeBytes,
      expectedOnChainRoot: streamedMeta.merkleRoot,
      requestedChunkIndices: selection.selectedChunkIndexes,
      commitmentVersion: manifest.protocol.commitmentVersion,
      precomputedMeta: streamedMeta
    });

    const verification = verifyDisclosureBundleClientSide(bundle, {
      expectedRoot: streamedMeta.merkleRoot,
      issuerPublicKey
    });

    const disclosedBytesRaw = bundle.disclosedChunks.reduce(
      (sum, disclosureChunk) => sum + Number(disclosureChunk.length || 0),
      0
    );
    const disclosedBytesBundle = Buffer.byteLength(JSON.stringify(bundle), 'utf8');

    const constraintInfo = computeSelectionConstraintInfo(
      selectionParams,
      selection.disclosureRatioTarget,
      selection.disclosureRatioRealized
    );

    return {
      fileId,
      fileName: fileDescriptor.fileName,
      fileSizeBytes: fileDescriptor.sizeBytes,
      totalChunks: streamedMeta.chunkCount,
      disclosureRatioTarget: selection.disclosureRatioTarget,
      disclosureRatioRealized: selection.disclosureRatioRealized,
      disclosedChunkCount: bundle.disclosedChunks.length,
      disclosedBytesRaw,
      disclosedBytesBundle,
      bundleGenerationTimeMs: bundle.metrics?.generationTimeMs ?? null,
      verificationTimeMs: verification.metrics?.verificationTimeMs ?? null,
      proofSizeBytes: verification.metrics?.proofSizeBytes ?? 0,
      bundleSizeBytes: disclosedBytesBundle,
      valid: verification.valid,
      failureReason: verification.reason,
      timingBreakdown: {
        selectionMs,
        capabilitySignMs,
        verificationMs: verification.metrics?.verificationTimeMs ?? null,
        ...bundle.metrics?.timingBreakdown
      },
      caveatFlags: constraintInfo.flags,
      caveatNote: constraintInfo.note,
      commitmentEntryCount: 1,
      hashOnlyMode: null
    };
  }

  const timingBreakdown = {
    fileReadMs: 0,
    chunkingMs: 0,
    merkleBuildMs: 0,
    selectionMs: 0,
    capabilitySignMs: 0,
    bundleBuildMs: 0,
    verificationMs: 0
  };

  const readStart = performance.now();
  const fileBuffer = await adapter.readFileBuffer(fileId);
  timingBreakdown.fileReadMs = performance.now() - readStart;

  const chunkingStart = performance.now();
  const chunked = chunkFile(fileBuffer, chunkSizeBytes);
  timingBreakdown.chunkingMs = performance.now() - chunkingStart;

  const treeStart = performance.now();
  const tree = buildMerkleTreeFromLeafHashes(chunked.chunkHashes);
  timingBreakdown.merkleBuildMs = performance.now() - treeStart;

  const selectionStart = performance.now();
  const selection = selectDisclosure({
    selectionPolicy,
    selectionParams,
    files: [fileId],
    totalChunks: chunked.totalChunks
  });
  timingBreakdown.selectionMs = performance.now() - selectionStart;

  const signStart = performance.now();
  const capabilityToken = capabilityManager.signCapability({
    evidenceId: fileId,
    issuerId: 'EvidenceCustodian',
    granteeId: stakeholderProfile.role,
    scope: {
      type: 'CHUNK_SET',
      indices: selection.selectedChunkIndexes
    },
    purpose: 'disclosure_chunk_experiment',
    issuedAt: nowIso(),
    expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    version: 'cap-v1'
  }, issuerPrivateKey);
  timingBreakdown.capabilitySignMs = performance.now() - signStart;

  const bundleStart = performance.now();
  const bundle = buildDisclosureBundle({
    capabilityToken,
    issuerPublicKey,
    requesterId: stakeholderProfile.role,
    evidenceId: fileId,
    evidenceType: 'PCAP',
    evidenceBuffer: fileBuffer,
    expectedOnChainRoot: tree.root,
    chunkSize: chunkSizeBytes,
    requestedChunkIndices: selection.selectedChunkIndexes,
    commitmentVersion: manifest.protocol.commitmentVersion
  });
  timingBreakdown.bundleBuildMs = performance.now() - bundleStart;

  const verificationStart = performance.now();
  const verification = verifyDisclosureBundleClientSide(bundle, {
    expectedRoot: tree.root,
    issuerPublicKey
  });
  timingBreakdown.verificationMs = performance.now() - verificationStart;

  const disclosedBytesRaw = bundle.disclosedChunks.reduce(
    (sum, disclosureChunk) => sum + Number(disclosureChunk.length || 0),
    0
  );
  const disclosedBytesBundle = Buffer.byteLength(JSON.stringify(bundle), 'utf8');

  const constraintInfo = computeSelectionConstraintInfo(
    selectionParams,
    selection.disclosureRatioTarget,
    selection.disclosureRatioRealized
  );

  return {
    fileId,
    fileName: fileDescriptor.fileName,
    fileSizeBytes: fileDescriptor.sizeBytes,
    totalChunks: chunked.totalChunks,
    disclosureRatioTarget: selection.disclosureRatioTarget,
    disclosureRatioRealized: selection.disclosureRatioRealized,
    disclosedChunkCount: bundle.disclosedChunks.length,
    disclosedBytesRaw,
    disclosedBytesBundle,
    bundleGenerationTimeMs: bundle.metrics?.generationTimeMs ?? null,
    verificationTimeMs: verification.metrics?.verificationTimeMs ?? null,
    proofSizeBytes: verification.metrics?.proofSizeBytes ?? 0,
    bundleSizeBytes: disclosedBytesBundle,
    valid: verification.valid,
    failureReason: verification.reason,
    timingBreakdown,
    caveatFlags: constraintInfo.flags,
    caveatNote: constraintInfo.note,
    commitmentEntryCount: 1,
    hashOnlyMode: null
  };
}

async function runSameArtifactStakeholderCaseStudy({
  manifest,
  experiment,
  adapters,
  issuerPrivateKey,
  issuerPublicKey,
  outputPath,
  gitCommitHash,
  runType,
  hostLabel,
  fullCorpusRawBytes
}) {
  validateSameArtifactCaseStudyExperiment(experiment);

  const { warmupIterations, measuredIterations } = getIterationConfig(manifest, experiment, runType);
  const totalRuns = warmupIterations + measuredIterations;
  const focalFileId = experiment.focalFileId;

  const adapter = getAdapterForFileId(focalFileId, adapters);
  const focalDescriptor = await adapter.getFileDescriptor(focalFileId);

  for (const caseConfig of experiment.cases) {
    const stakeholderProfile = getStakeholderProfile(caseConfig.stakeholderId);
    const measuredGenerationTimes = [];
    const invariantSnapshots = [];

    for (let i = 0; i < totalRuns; i += 1) {
      const isWarmup = i < warmupIterations;
      const timestampStart = nowIso();
      const chunkSizeBytes =
        caseConfig.selectionParams?.chunkSizeBytes ??
        manifest.defaults.chunkSizeBytes;

      let result;

      if (caseConfig.mode === 'FULL_CHUNKS') {
        result = await executeFullChunksDisclosure({
          fileId: focalFileId,
          adapter,
          stakeholderProfile,
          manifest,
          issuerPrivateKey,
          issuerPublicKey,
          purpose: caseConfig.purpose
        });
      } else if (caseConfig.mode === 'HASH_ONLY') {
        result = await executeHashOnlyDisclosure({
          fileId: focalFileId,
          adapter,
          stakeholderProfile,
          manifest,
          issuerPrivateKey,
          issuerPublicKey,
          purpose: caseConfig.purpose
        });
      } else if (caseConfig.mode === 'CHUNK_SET') {
        result = await executeChunkDisclosure({
          fileId: focalFileId,
          adapter,
          stakeholderProfile,
          manifest,
          selectionPolicy: caseConfig.selectionPolicy,
          selectionParams: normalizeSelectionParams(caseConfig.selectionParams, manifest),
          chunkSizeBytes,
          issuerPrivateKey,
          issuerPublicKey
        });
      } else {
        throw new Error(`Unsupported E2 case mode: ${caseConfig.mode}`);
      }

      const exposureReductionVsFull =
        focalDescriptor.sizeBytes > 0
          ? 1 - (result.disclosedBytesRaw / focalDescriptor.sizeBytes)
          : 0;

      const record = buildRunRecord({
        experimentId: experiment.id,
        caseId: caseConfig.id,
        iterationIndex: i,
        isWarmup,
        runType,
        timestampStart,
        timestampEnd: nowIso(),
        gitCommitHash,
        datasetName: getDatasetNameFromFileId(focalFileId),
        fileIds: [result.fileId],
        fileNames: [result.fileName],
        fileSizeBytes: result.fileSizeBytes,
        stakeholderLabel: stakeholderProfile.role,
        mode: caseConfig.mode,
        chunkSizeBytes,
        totalChunks: result.totalChunks,
        disclosureRatioTarget: result.disclosureRatioTarget,
        disclosureRatioRealized: result.disclosureRatioRealized,
        disclosedChunkCount: result.disclosedChunkCount,
        disclosedBytesRaw: result.disclosedBytesRaw,
        disclosedBytesBundle: result.disclosedBytesBundle,
        bundleGenerationTimeMs: result.bundleGenerationTimeMs,
        verificationTimeMs: result.verificationTimeMs,
        proofSizeBytes: result.proofSizeBytes,
        bundleSizeBytes: result.bundleSizeBytes,
        valid: result.valid,
        failureReason: result.failureReason,
        hostLabel,
        metadata: {
          experimentType: experiment.type,
          focalFileId,
          comparisonBasis: experiment.caseStudyDesign?.comparisonBasis ?? 'same_artifact_same_commitment',
          primaryClaim: experiment.caseStudyDesign?.primaryClaim ?? null,
          antiOverclaimNote: experiment.caseStudyDesign?.antiOverclaimNote ?? null,
          selectionPolicy: caseConfig.selectionPolicy,
          comparisonScope: 'same_artifact',
          timingSemantics: 'case_bundle_assembly_or_case_bundle_verification',
          purpose: caseConfig.purpose ?? null,
          timingBreakdown: result.timingBreakdown,
          caveatFlags: result.caveatFlags,
          caveatNote: result.caveatNote,
          fullCorpusRawBytes,
          focalArtifactRawBytes: focalDescriptor.sizeBytes,
          commitmentEntryCount: result.commitmentEntryCount ?? 1,
          hashOnlyMode: result.hashOnlyMode ?? null,
          exposureReductionVsFull
        }
      });

      appendJsonlRecord(outputPath, record);

      if (!isWarmup) {
        measuredGenerationTimes.push(result.bundleGenerationTimeMs);
        invariantSnapshots.push(JSON.stringify({
          focalFileId,
          mode: caseConfig.mode,
          chunkSizeBytes,
          totalChunks: result.totalChunks,
          disclosedChunkCount: result.disclosedChunkCount,
          disclosedBytesRaw: result.disclosedBytesRaw,
          disclosureRatioTarget: result.disclosureRatioTarget,
          disclosureRatioRealized: result.disclosureRatioRealized,
          proofSizeBytes: result.proofSizeBytes
        }));
      }

      console.log(`[${experiment.id}] ${caseConfig.id} ${i + 1}/${totalRuns}${isWarmup ? ' [warmup]' : ''}`);
    }

    assertInvariantsStable(invariantSnapshots, `${experiment.id}:${caseConfig.id}`);
    warnOnFirstMeasuredSlowdown(measuredGenerationTimes, `${experiment.id}:${caseConfig.id}`);
  }
}

async function runSingleFileChunkExperiment({
  manifest,
  experiment,
  adapters,
  issuerPrivateKey,
  issuerPublicKey,
  outputPath,
  gitCommitHash,
  runType,
  hostLabel
}) {
  const stakeholderProfile = getStakeholderProfile(experiment.stakeholderId);
  const { warmupIterations, measuredIterations } = getIterationConfig(manifest, experiment, runType);
  const totalRuns = warmupIterations + measuredIterations;

  for (const fileId of experiment.files) {
    const adapter = getAdapterForFileId(fileId, adapters);
    const measuredGenerationTimes = [];
    const invariantSnapshots = [];

    for (let i = 0; i < totalRuns; i += 1) {
      const isWarmup = i < warmupIterations;
      const timestampStart = nowIso();
      const effectiveSelectionParams = normalizeSelectionParams(experiment.selectionParams, manifest);
      const effectiveChunkSize =
        effectiveSelectionParams.chunkSizeBytes ??
        experiment.chunkSizeBytes ??
        manifest.defaults.chunkSizeBytes;

      const result = await executeChunkDisclosure({
        fileId,
        adapter,
        stakeholderProfile,
        manifest,
        selectionPolicy: experiment.selectionPolicy,
        selectionParams: effectiveSelectionParams,
        chunkSizeBytes: effectiveChunkSize,
        issuerPrivateKey,
        issuerPublicKey
      });

      const record = buildRunRecord({
        experimentId: experiment.id,
        caseId: fileId,
        iterationIndex: i,
        isWarmup,
        runType,
        timestampStart,
        timestampEnd: nowIso(),
        gitCommitHash,
        datasetName: getDatasetNameFromFileId(fileId),
        fileIds: [result.fileId],
        fileNames: [result.fileName],
        fileSizeBytes: result.fileSizeBytes,
        stakeholderLabel: stakeholderProfile.role,
        mode: experiment.mode,
        chunkSizeBytes: effectiveChunkSize,
        totalChunks: result.totalChunks,
        disclosureRatioTarget: result.disclosureRatioTarget,
        disclosureRatioRealized: result.disclosureRatioRealized,
        disclosedChunkCount: result.disclosedChunkCount,
        disclosedBytesRaw: result.disclosedBytesRaw,
        disclosedBytesBundle: result.disclosedBytesBundle,
        bundleGenerationTimeMs: result.bundleGenerationTimeMs,
        verificationTimeMs: result.verificationTimeMs,
        proofSizeBytes: result.proofSizeBytes,
        bundleSizeBytes: result.bundleSizeBytes,
        valid: result.valid,
        failureReason: result.failureReason,
        hostLabel,
        metadata: buildChunkExperimentMetadata({
          experiment,
          selectionParams: effectiveSelectionParams,
          result
        })
      });

      appendJsonlRecord(outputPath, record);

      if (!isWarmup) {
        measuredGenerationTimes.push(result.bundleGenerationTimeMs);
        invariantSnapshots.push(
          JSON.stringify({
            fileId,
            totalChunks: result.totalChunks,
            disclosedChunkCount: result.disclosedChunkCount,
            disclosedBytesRaw: result.disclosedBytesRaw,
            disclosureRatioTarget: result.disclosureRatioTarget
          })
        );
      }

      console.log(`[${experiment.id}] ${fileId} ${i + 1}/${totalRuns}${isWarmup ? ' [warmup]' : ''}`);
    }

    assertInvariantsStable(invariantSnapshots, `${experiment.id}:${fileId}`);
    warnOnFirstMeasuredSlowdown(measuredGenerationTimes, `${experiment.id}:${fileId}`);
  }
}

async function runChunkTradeoff({
  manifest,
  experiment,
  adapters,
  issuerPrivateKey,
  issuerPublicKey,
  outputPath,
  gitCommitHash,
  runType,
  hostLabel
}) {
  const stakeholderProfile = getStakeholderProfile(experiment.stakeholderId);
  const { warmupIterations, measuredIterations } = getIterationConfig(manifest, experiment, runType);
  const totalRuns = warmupIterations + measuredIterations;

  for (const fileId of experiment.files) {
    const adapter = getAdapterForFileId(fileId, adapters);

    const chunkSizesForFile =
      experiment.perFileChunkSizes?.[fileId] ??
      experiment.chunkSizesBytes;

    const selectionParamsForFileRaw =
      experiment.perFileSelectionParams?.[fileId] ??
      experiment.selectionParams;

    const selectionParamsForFile = normalizeSelectionParams(selectionParamsForFileRaw, manifest);

    for (const chunkSizeBytes of chunkSizesForFile) {
      console.log(`[${experiment.id}] preparing ${fileId} chunk=${chunkSizeBytes}`);

      const fileDescriptor = await adapter.getFileDescriptor(fileId);
      const useStreamingPrecompute = fileDescriptor.sizeBytes > TWO_GIB_MINUS_ONE;

      let preparedLargeFileMeta = null;

      if (useStreamingPrecompute) {
        preparedLargeFileMeta = await computeStreamingMerkleForFile(
          fileDescriptor.absolutePath,
          chunkSizeBytes,
          fileDescriptor.sizeBytes
        );
      }

      const measuredGenerationTimes = [];
      const invariantSnapshots = [];

      for (let i = 0; i < totalRuns; i += 1) {
        const isWarmup = i < warmupIterations;
        const timestampStart = nowIso();

        const result = await executeChunkDisclosure({
          fileId,
          adapter,
          stakeholderProfile,
          manifest,
          selectionPolicy: experiment.selectionPolicy,
          selectionParams: selectionParamsForFile,
          chunkSizeBytes,
          issuerPrivateKey,
          issuerPublicKey,
          preparedLargeFileMeta
        });

        const record = buildRunRecord({
          experimentId: experiment.id,
          caseId: `${fileId}_${chunkSizeBytes}`,
          iterationIndex: i,
          isWarmup,
          runType,
          timestampStart,
          timestampEnd: nowIso(),
          gitCommitHash,
          datasetName: getDatasetNameFromFileId(fileId),
          fileIds: [result.fileId],
          fileNames: [result.fileName],
          fileSizeBytes: result.fileSizeBytes,
          stakeholderLabel: stakeholderProfile.role,
          mode: experiment.mode,
          chunkSizeBytes,
          totalChunks: result.totalChunks,
          disclosureRatioTarget: result.disclosureRatioTarget,
          disclosureRatioRealized: result.disclosureRatioRealized,
          disclosedChunkCount: result.disclosedChunkCount,
          disclosedBytesRaw: result.disclosedBytesRaw,
          disclosedBytesBundle: result.disclosedBytesBundle,
          bundleGenerationTimeMs: result.bundleGenerationTimeMs,
          verificationTimeMs: result.verificationTimeMs,
          proofSizeBytes: result.proofSizeBytes,
          bundleSizeBytes: result.bundleSizeBytes,
          valid: result.valid,
          failureReason: result.failureReason,
          hostLabel,
          metadata: buildChunkExperimentMetadata({
            experiment,
            selectionParams: {
              ...selectionParamsForFile,
              chunkSizeBytes
            },
            result,
            extra: {
              usedStreamingPrecompute: useStreamingPrecompute
            }
          })
        });

        appendJsonlRecord(outputPath, record);

        if (!isWarmup) {
          measuredGenerationTimes.push(result.bundleGenerationTimeMs);
          invariantSnapshots.push(
            JSON.stringify({
              fileId,
              chunkSizeBytes,
              totalChunks: result.totalChunks,
              disclosedChunkCount: result.disclosedChunkCount,
              disclosedBytesRaw: result.disclosedBytesRaw
            })
          );
        }

        console.log(`[${experiment.id}] ${fileId} chunk=${chunkSizeBytes} ${i + 1}/${totalRuns}${isWarmup ? ' [warmup]' : ''}`);
      }

      assertInvariantsStable(invariantSnapshots, `${experiment.id}:${fileId}:${chunkSizeBytes}`);
      warnOnFirstMeasuredSlowdown(measuredGenerationTimes, `${experiment.id}:${fileId}:${chunkSizeBytes}`);
    }
  }
}

async function runRatioTradeoff({
  manifest,
  experiment,
  adapters,
  issuerPrivateKey,
  issuerPublicKey,
  outputPath,
  gitCommitHash,
  runType,
  hostLabel
}) {
  const stakeholderProfile = getStakeholderProfile(experiment.stakeholderId);
  const { warmupIterations, measuredIterations } = getIterationConfig(manifest, experiment, runType);
  const totalRuns = warmupIterations + measuredIterations;

  for (const fileId of experiment.files) {
    const adapter = getAdapterForFileId(fileId, adapters);

    for (const disclosureRatio of experiment.disclosureRatios) {
      const measuredGenerationTimes = [];
      const invariantSnapshots = [];
      const selectionParams = normalizeSelectionParams(
        {
          disclosureRatio,
          minChunks: 1,
          chunkSizeBytes: experiment.chunkSizeBytes
        },
        manifest
      );

      for (let i = 0; i < totalRuns; i += 1) {
        const isWarmup = i < warmupIterations;
        const timestampStart = nowIso();

        const result = await executeChunkDisclosure({
          fileId,
          adapter,
          stakeholderProfile,
          manifest,
          selectionPolicy: experiment.selectionPolicy,
          selectionParams,
          chunkSizeBytes: selectionParams.chunkSizeBytes,
          issuerPrivateKey,
          issuerPublicKey
        });

        const record = buildRunRecord({
          experimentId: experiment.id,
          caseId: `${fileId}_${disclosureRatio}`,
          iterationIndex: i,
          isWarmup,
          runType,
          timestampStart,
          timestampEnd: nowIso(),
          gitCommitHash,
          datasetName: getDatasetNameFromFileId(fileId),
          fileIds: [result.fileId],
          fileNames: [result.fileName],
          fileSizeBytes: result.fileSizeBytes,
          stakeholderLabel: stakeholderProfile.role,
          mode: experiment.mode,
          chunkSizeBytes: selectionParams.chunkSizeBytes,
          totalChunks: result.totalChunks,
          disclosureRatioTarget: result.disclosureRatioTarget,
          disclosureRatioRealized: result.disclosureRatioRealized,
          disclosedChunkCount: result.disclosedChunkCount,
          disclosedBytesRaw: result.disclosedBytesRaw,
          disclosedBytesBundle: result.disclosedBytesBundle,
          bundleGenerationTimeMs: result.bundleGenerationTimeMs,
          verificationTimeMs: result.verificationTimeMs,
          proofSizeBytes: result.proofSizeBytes,
          bundleSizeBytes: result.bundleSizeBytes,
          valid: result.valid,
          failureReason: result.failureReason,
          hostLabel,
          metadata: buildChunkExperimentMetadata({
            experiment,
            selectionParams,
            result
          })
        });

        appendJsonlRecord(outputPath, record);

        if (!isWarmup) {
          measuredGenerationTimes.push(result.bundleGenerationTimeMs);
          invariantSnapshots.push(
            JSON.stringify({
              fileId,
              disclosureRatio,
              totalChunks: result.totalChunks,
              disclosedChunkCount: result.disclosedChunkCount,
              disclosedBytesRaw: result.disclosedBytesRaw
            })
          );
        }

        console.log(`[${experiment.id}] ${fileId} ratio=${disclosureRatio} ${i + 1}/${totalRuns}${isWarmup ? ' [warmup]' : ''}`);
      }

      assertInvariantsStable(invariantSnapshots, `${experiment.id}:${fileId}:${disclosureRatio}`);
      warnOnFirstMeasuredSlowdown(measuredGenerationTimes, `${experiment.id}:${fileId}:${disclosureRatio}`);
    }
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const manifestPath = path.resolve(getArg(args, 'manifest', DEFAULT_MANIFEST_PATH));
  const manifest = loadManifest(manifestPath);
  const repoRoot = resolveRepoRoot(manifestPath, getArg(args, 'repo-root'));
  const runType = getArg(args, 'run-type', 'pilot');
  const onlyExperimentId = getArg(args, 'experiment');
  const gitCommitHash = getGitCommitHashSafe(repoRoot);
  const hostLabel = `${os.hostname()}:${process.platform}`;

  const adapters = {
    swat: new SwatA6Adapter({ manifest, repoRoot }),
    edge: new EdgeIiotsetAdapter({ manifest, repoRoot })
  };

  const swatFullCorpusRawBytes = (await adapters.swat.getAggregateStats(
    adapters.swat.listFiles().map((f) => f.id)
  )).totalBytes;

  const { privateKey: issuerPrivateKey, publicKey: issuerPublicKey } = createIssuerKeyPair();

  const selectedExperiments = manifest.experiments
    .filter((exp) => exp.enabled)
    .filter((exp) => !onlyExperimentId || exp.id === onlyExperimentId);

  if (selectedExperiments.length === 0) {
    throw new Error('No enabled experiments selected');
  }

  for (const experiment of selectedExperiments) {
    validateExperimentConfig(experiment);

    const outputPath = getResultsFilePath(manifest, experiment.id);

    if (experiment.type === 'existing_test_suite_summary') {
      console.log(`[${experiment.id}] use existing tests for Table 1; runner skips execution`);
      continue;
    }

    if (experiment.type === 'window_aware_stakeholder_case_study') {
      for (const caseConfig of experiment.cases) {
        await runWindowAwareCase({
          manifest,
          experiment,
          caseConfig,
          adapters,
          issuerPrivateKey,
          issuerPublicKey,
          outputPath,
          gitCommitHash,
          runType,
          hostLabel,
          fullCorpusRawBytes: swatFullCorpusRawBytes
        });
      }
      continue;
    }

    if (experiment.type === 'same_artifact_stakeholder_case_study') {
      await runSameArtifactStakeholderCaseStudy({
        manifest,
        experiment,
        adapters,
        issuerPrivateKey,
        issuerPublicKey,
        outputPath,
        gitCommitHash,
        runType,
        hostLabel,
        fullCorpusRawBytes: swatFullCorpusRawBytes
      });
      continue;
    }

    if (experiment.type === 'file_size_scaling') {
      await runSingleFileChunkExperiment({
        manifest,
        experiment,
        adapters,
        issuerPrivateKey,
        issuerPublicKey,
        outputPath,
        gitCommitHash,
        runType,
        hostLabel
      });
      continue;
    }

    if (experiment.type === 'chunk_size_tradeoff') {
      await runChunkTradeoff({
        manifest,
        experiment,
        adapters,
        issuerPrivateKey,
        issuerPublicKey,
        outputPath,
        gitCommitHash,
        runType,
        hostLabel
      });
      continue;
    }

    if (experiment.type === 'ratio_tradeoff') {
      await runRatioTradeoff({
        manifest,
        experiment,
        adapters,
        issuerPrivateKey,
        issuerPublicKey,
        outputPath,
        gitCommitHash,
        runType,
        hostLabel
      });
      continue;
    }

    throw new Error(`Unsupported experiment type: ${experiment.type}`);
  }

  console.log('All selected experiments completed.');
}

main().catch((err) => {
  console.error('Experiment runner failed:', err);
  process.exitCode = 1;
});