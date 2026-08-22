#!/usr/bin/env node
import { performance } from 'node:perf_hooks';
import fs from 'node:fs';
import path from 'node:path';
import {
  hashChunk,
  hashChunkCommitmentV3,
  COMMITMENT_VERSION_V3_HMAC,
} from './evidence-chunker.js';

function parseArg(name, fallback) {
  const flag = `--${name}`;
  const idx = process.argv.indexOf(flag);
  if (idx === -1 || idx + 1 >= process.argv.length) return fallback;
  return process.argv[idx + 1];
}

function parseIntArg(name, fallback) {
  const value = parseArg(name, null);
  if (value == null) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`--${name} must be a positive integer`);
  }
  return parsed;
}

const dictionarySize = parseIntArg('dictionary-size', 100000);
const evidenceId = parseArg('evidence-id', 'EV-ICS-DICT-001');
const chunkIndex = parseIntArg('chunk-index', 7);
const emk = parseArg('emk', '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
const outPath = parseArg('out', '/mnt/data/v3-dictionary-attack-results.json');

function candidateAt(i) {
  const templates = [
    (n) => `valve_status=${n % 2 === 0 ? 'OPEN' : 'CLOSED'};seq=${n}\n`,
    (n) => `pump_status=${n % 2 === 0 ? 'ON' : 'OFF'};seq=${n}\n`,
    (n) => `function_code=${String(n % 8).padStart(2, '0')};seq=${n}\n`,
    (n) => `register=${40000 + (n % 512)};seq=${n}\n`,
    (n) => `alarm=${n % 2 === 0 ? 'false' : 'true'};seq=${n}\n`,
    (n) => `temperature=${20 + (n % 60)};seq=${n}\n`,
    (n) => `pressure=${90 + (n % 40)}.${n % 10};seq=${n}\n`,
    (n) => `coil=${n % 2};seq=${n}\n`,
  ];
  return templates[i % templates.length](Math.floor(i / templates.length));
}

function buildDictionary(size, target) {
  const dictionary = [];
  const seen = new Set();
  for (let i = 0; dictionary.length < size - 1; i += 1) {
    const candidate = candidateAt(i);
    if (candidate === target || seen.has(candidate)) continue;
    seen.add(candidate);
    dictionary.push(candidate);
  }
  const insertAt = Math.max(0, Math.floor(size * 0.73));
  dictionary.splice(insertAt, 0, target);
  return dictionary.slice(0, size);
}

function attackV2(targetLeaf, dictionary) {
  const started = performance.now();
  let attempts = 0;
  for (const candidate of dictionary) {
    attempts += 1;
    if (hashChunk(Buffer.from(candidate, 'utf8')) === targetLeaf) {
      const elapsedMs = performance.now() - started;
      return { matched: true, attempts, elapsedMs, throughputAttemptsPerSec: attempts / (elapsedMs / 1000), matchedCandidate: candidate };
    }
  }
  const elapsedMs = performance.now() - started;
  return { matched: false, attempts, elapsedMs, throughputAttemptsPerSec: attempts / (elapsedMs / 1000), matchedCandidate: null };
}

function attackV3PublicOnly(targetLeaf, dictionary) {
  const started = performance.now();
  let attempts = 0;
  for (const candidate of dictionary) {
    attempts += 1;
    const bytes = Buffer.from(candidate, 'utf8');
    const publicOnlyGuess = hashChunkCommitmentV3(bytes, {
      evidenceId,
      chunkIndex,
      actualLength: bytes.length,
      salt: '00'.repeat(32),
    }).leafHash;
    if (publicOnlyGuess === targetLeaf) {
      const elapsedMs = performance.now() - started;
      return { matched: true, attempts, elapsedMs, throughputAttemptsPerSec: attempts / (elapsedMs / 1000), matchedCandidate: candidate };
    }
  }
  const elapsedMs = performance.now() - started;
  return { matched: false, attempts, elapsedMs, throughputAttemptsPerSec: attempts / (elapsedMs / 1000), matchedCandidate: null };
}

function attackV3SaltLeaked(targetLeaf, dictionary, salt) {
  const started = performance.now();
  let attempts = 0;
  for (const candidate of dictionary) {
    attempts += 1;
    const bytes = Buffer.from(candidate, 'utf8');
    const guess = hashChunkCommitmentV3(bytes, {
      evidenceId,
      chunkIndex,
      actualLength: bytes.length,
      salt,
    }).leafHash;
    if (guess === targetLeaf) {
      const elapsedMs = performance.now() - started;
      return { matched: true, attempts, elapsedMs, throughputAttemptsPerSec: attempts / (elapsedMs / 1000), matchedCandidate: candidate };
    }
  }
  const elapsedMs = performance.now() - started;
  return { matched: false, attempts, elapsedMs, throughputAttemptsPerSec: attempts / (elapsedMs / 1000), matchedCandidate: null };
}

const target = parseArg('target', 'function_code=03\n');
const dictionary = buildDictionary(dictionarySize, target);
const targetBytes = Buffer.from(target, 'utf8');
const v2TargetLeaf = hashChunk(targetBytes);
const v3Target = hashChunkCommitmentV3(targetBytes, {
  evidenceId,
  chunkIndex,
  actualLength: targetBytes.length,
  emk,
});

const results = {
  experiment: 'v3-dictionary-attack-simulation',
  generatedAt: new Date().toISOString(),
  commitmentVersion: COMMITMENT_VERSION_V3_HMAC,
  evidenceId,
  chunkIndex,
  dictionarySize,
  targetLength: targetBytes.length,
  assumptions: {
    v2: 'deterministic leaf/hash is observable',
    v3WithoutSalt: 'attacker observes leaf/root but not the per-chunk opening salt',
    v3WithSaltLeak: 'limitation case where the correct opening salt leaks',
  },
  v2Deterministic: attackV2(v2TargetLeaf, dictionary),
  v3WithoutSalt: attackV3PublicOnly(v3Target.leafHash, dictionary),
  v3WithSaltLeak: attackV3SaltLeaked(v3Target.leafHash, dictionary, v3Target.salt),
};

fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
