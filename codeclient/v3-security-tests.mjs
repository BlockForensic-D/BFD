import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  EvidenceChunker,
  COMMITMENT_VERSION_V3_HMAC,
  hashChunk,
  hashChunkCommitmentV3,
} from './evidence-chunker.js';
import {
  buildMerkleTreeFromLeafHashesV3,
  generateProofsBatchV3,
  verifyProofFromPayloadWithOpeningV3,
} from './evidence-merkle.js';
import {
  buildCapabilityPayload,
  CAPABILITY_VERSION_V3,
  SCOPE_TYPES,
  CAPABILITY_ACCESS_STATES,
  evaluateCapabilityValidity,
  signCapability,
  verifyCapabilityToken,
} from './capability-manager.js';

const EMK = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
const EVIDENCE_ID = 'EV-ICS-SEC-001';
const CHUNK_SIZE = 24;
const ICS_LINES = [
  'valve_status=OPEN\n',
  'pump_status=OFF\n',
  'function_code=03\n',
  'register=40001\n',
  'pressure=101.2\n',
  'alarm=false\n',
  'valve_status=CLOSED\n',
  'pump_status=ON\n',
];
const ICS_EVIDENCE = Buffer.from(ICS_LINES.join(''), 'utf8');

function buildFixture() {
  const chunked = EvidenceChunker.chunk(ICS_EVIDENCE, CHUNK_SIZE, {
    commitmentVersion: COMMITMENT_VERSION_V3_HMAC,
    evidenceId: EVIDENCE_ID,
    emk: EMK,
  });
  const tree = buildMerkleTreeFromLeafHashesV3(chunked.chunkHashes);
  const proofs = generateProofsBatchV3(
    chunked.chunkHashes,
    chunked.chunks.map((chunk) => chunk.index),
  );
  return { chunked, tree, proofs };
}

function proofByIndex(proofs, index) {
  const proof = proofs.find((p) => p.index === index);
  assert.ok(proof, `proof for index ${index} not found`);
  return proof;
}

function verifyChunkOpening({ chunk, proof, root, evidenceId = EVIDENCE_ID, salt = chunk.salt, index = chunk.index, actualLength = chunk.length, payload = chunk.data }) {
  return verifyProofFromPayloadWithOpeningV3(
    payload,
    { evidenceId, index, actualLength, salt },
    proof,
    root,
  );
}

function buildHistoricalBundle({ chunk, proof, root, destroyedAt = null }) {
  const disclosedAt = '2026-05-14T01:00:00.000Z';
  return {
    bundleVersion: 'disclosure-bundle-v3-test',
    evidenceId: EVIDENCE_ID,
    commitmentVersion: COMMITMENT_VERSION_V3_HMAC,
    chunkMerkleRoot: root,
    disclosureTxId: 'tx-pre-destroy-001',
    disclosedAt,
    destroyedAt,
    openings: [
      {
        index: chunk.index,
        actualLength: chunk.length,
        dataBase64: Buffer.from(chunk.data).toString('base64'),
        salt: chunk.salt,
        proof: proof.proof,
      },
    ],
  };
}

function verifyHistoricalBundle(bundle) {
  if (!bundle || typeof bundle !== 'object') return { valid: false, reason: 'bundle_not_object' };
  if (!Array.isArray(bundle.openings) || bundle.openings.length === 0) {
    return { valid: false, reason: 'missing_openings' };
  }
  if (bundle.destroyedAt && new Date(bundle.disclosedAt).getTime() >= new Date(bundle.destroyedAt).getTime()) {
    return { valid: false, reason: 'disclosure_not_pre_destruction' };
  }

  for (const opening of bundle.openings) {
    const payload = Buffer.from(opening.dataBase64, 'base64');
    const result = verifyProofFromPayloadWithOpeningV3(
      payload,
      {
        evidenceId: bundle.evidenceId,
        index: opening.index,
        actualLength: opening.actualLength,
        salt: opening.salt,
      },
      { index: opening.index, proof: opening.proof },
      bundle.chunkMerkleRoot,
    );
    if (!result.valid) return { valid: false, reason: 'invalid_opening', openingIndex: opening.index };
  }
  return { valid: true, reason: null };
}

function canGenerateNewOpeningAfterDestruction({ lifecycleState, keyMaterialDestroyed, saltKeyDestroyed, disclosedBefore }) {
  if (lifecycleState === 'DESTROYED' && (keyMaterialDestroyed || saltKeyDestroyed) && !disclosedBefore) {
    return { allowed: false, reason: 'post_destruction_opening_revoked' };
  }
  if (lifecycleState === 'DESTROYED') {
    return { allowed: false, reason: 'evidence_destroyed_new_disclosure_denied' };
  }
  return { allowed: true, reason: null };
}

function dictionaryAttackV2(targetLeaf, dictionary) {
  const started = performance.now();
  let attempts = 0;
  for (const candidate of dictionary) {
    attempts += 1;
    if (hashChunk(Buffer.from(candidate, 'utf8')) === targetLeaf) {
      return { matched: true, candidate, attempts, elapsedMs: performance.now() - started };
    }
  }
  return { matched: false, candidate: null, attempts, elapsedMs: performance.now() - started };
}

function dictionaryAttackV3WithoutSalt(targetLeaf, dictionary, evidenceId, index, actualLength) {
  const started = performance.now();
  let attempts = 0;
  // This models a weak adversary transformation over public values only. Without
  // the undisclosed salt/opening, the adversary cannot compute the true v3 leaf.
  for (const candidate of dictionary) {
    attempts += 1;
    const publicOnlyGuess = hashChunkCommitmentV3(Buffer.from(candidate, 'utf8'), {
      evidenceId,
      chunkIndex: index,
      actualLength: Buffer.byteLength(candidate, 'utf8'),
      salt: '00'.repeat(32),
    }).leafHash;
    if (actualLength === Buffer.byteLength(candidate, 'utf8') && publicOnlyGuess === targetLeaf) {
      return { matched: true, candidate, attempts, elapsedMs: performance.now() - started };
    }
  }
  return { matched: false, candidate: null, attempts, elapsedMs: performance.now() - started };
}

function dictionaryAttackV3WithSalt(targetLeaf, dictionary, evidenceId, index, salt) {
  const started = performance.now();
  let attempts = 0;
  for (const candidate of dictionary) {
    attempts += 1;
    const bytes = Buffer.from(candidate, 'utf8');
    const guess = hashChunkCommitmentV3(bytes, {
      evidenceId,
      chunkIndex: index,
      actualLength: bytes.length,
      salt,
    }).leafHash;
    if (guess === targetLeaf) {
      return { matched: true, candidate, attempts, elapsedMs: performance.now() - started };
    }
  }
  return { matched: false, candidate: null, attempts, elapsedMs: performance.now() - started };
}

test('1. valid v3 opening verifies', () => {
  const { chunked, tree, proofs } = buildFixture();
  const chunk = chunked.chunks[2];
  const result = verifyChunkOpening({ chunk, proof: proofByIndex(proofs, chunk.index), root: tree.root });
  assert.equal(result.valid, true);
});

test('2. wrong payload fails', () => {
  const { chunked, tree, proofs } = buildFixture();
  const chunk = chunked.chunks[1];
  const result = verifyChunkOpening({
    chunk,
    proof: proofByIndex(proofs, chunk.index),
    root: tree.root,
    payload: Buffer.concat([Buffer.from([chunk.data[0] ^ 0xff]), chunk.data.subarray(1)]),
  });
  assert.equal(result.valid, false);
});

test('3. wrong salt fails', () => {
  const { chunked, tree, proofs } = buildFixture();
  const chunk = chunked.chunks[1];
  const result = verifyChunkOpening({
    chunk,
    proof: proofByIndex(proofs, chunk.index),
    root: tree.root,
    salt: 'ff'.repeat(32),
  });
  assert.equal(result.valid, false);
});

test('4. wrong index fails', () => {
  const { chunked, tree, proofs } = buildFixture();
  const chunk = chunked.chunks[1];
  const result = verifyChunkOpening({
    chunk,
    proof: proofByIndex(proofs, chunk.index),
    root: tree.root,
    index: chunk.index + 1,
  });
  assert.equal(result.valid, false);
});

test('5. wrong actual length fails safely', () => {
  const { chunked, tree, proofs } = buildFixture();
  const chunk = chunked.chunks[1];
  assert.throws(() => verifyChunkOpening({
    chunk,
    proof: proofByIndex(proofs, chunk.index),
    root: tree.root,
    actualLength: chunk.length + 1,
  }), /actualLength mismatch/);
});

test('6. cross-evidence proof reuse fails', () => {
  const { chunked, tree, proofs } = buildFixture();
  const chunk = chunked.chunks[1];
  const result = verifyChunkOpening({
    chunk,
    proof: proofByIndex(proofs, chunk.index),
    root: tree.root,
    evidenceId: 'EV-OTHER-CASE',
  });
  assert.equal(result.valid, false);
});

test('7. chunk substitution fails', () => {
  const { chunked, tree, proofs } = buildFixture();
  const chunk = chunked.chunks[1];
  const substitute = chunked.chunks[3];
  const result = verifyChunkOpening({
    chunk,
    proof: proofByIndex(proofs, chunk.index),
    root: tree.root,
    payload: substitute.data,
  });
  assert.equal(result.valid, false);
});

test('8. deterministic v2 leaf is vulnerable to dictionary matching', () => {
  const target = 'function_code=03\n';
  const targetLeaf = hashChunk(Buffer.from(target, 'utf8'));
  const dictionary = ['pump_status=OFF\n', 'register=40001\n', target, 'alarm=false\n'];
  const attack = dictionaryAttackV2(targetLeaf, dictionary);
  assert.equal(attack.matched, true);
  assert.equal(attack.candidate, target);
});

test('9. v3 leaf does not match dictionary guesses without the opening salt', () => {
  const target = 'function_code=03\n';
  const index = 7;
  const targetCommitment = hashChunkCommitmentV3(Buffer.from(target, 'utf8'), {
    evidenceId: EVIDENCE_ID,
    chunkIndex: index,
    actualLength: Buffer.byteLength(target, 'utf8'),
    emk: EMK,
  });
  const dictionary = ['pump_status=OFF\n', 'register=40001\n', target, 'alarm=false\n'];
  const attack = dictionaryAttackV3WithoutSalt(
    targetCommitment.leafHash,
    dictionary,
    EVIDENCE_ID,
    index,
    Buffer.byteLength(target, 'utf8'),
  );
  assert.equal(attack.matched, false);
});

test('10. v3 becomes matchable if the correct opening salt leaks', () => {
  const target = 'function_code=03\n';
  const index = 7;
  const targetCommitment = hashChunkCommitmentV3(Buffer.from(target, 'utf8'), {
    evidenceId: EVIDENCE_ID,
    chunkIndex: index,
    actualLength: Buffer.byteLength(target, 'utf8'),
    emk: EMK,
  });
  const dictionary = ['pump_status=OFF\n', 'register=40001\n', target, 'alarm=false\n'];
  const attack = dictionaryAttackV3WithSalt(
    targetCommitment.leafHash,
    dictionary,
    EVIDENCE_ID,
    index,
    targetCommitment.salt,
  );
  assert.equal(attack.matched, true);
  assert.equal(attack.candidate, target);
});

test('11. pre-destruction bundle remains historically verifiable after destruction', () => {
  const { chunked, tree, proofs } = buildFixture();
  const chunk = chunked.chunks[1];
  const bundle = buildHistoricalBundle({
    chunk,
    proof: proofByIndex(proofs, chunk.index),
    root: tree.root,
    destroyedAt: '2026-05-14T02:00:00.000Z',
  });
  const result = verifyHistoricalBundle(bundle);
  assert.deepEqual(result, { valid: true, reason: null });
});

test('12. new opening generation for never-disclosed chunk is denied after key destruction', () => {
  const decision = canGenerateNewOpeningAfterDestruction({
    lifecycleState: 'DESTROYED',
    keyMaterialDestroyed: true,
    saltKeyDestroyed: true,
    disclosedBefore: false,
  });
  assert.equal(decision.allowed, false);
  assert.equal(decision.reason, 'post_destruction_opening_revoked');
});

test('13. forged historical bundle without correct salt/proof fails', () => {
  const { chunked, tree, proofs } = buildFixture();
  const chunk = chunked.chunks[1];
  const bundle = buildHistoricalBundle({
    chunk,
    proof: proofByIndex(proofs, chunk.index),
    root: tree.root,
    destroyedAt: '2026-05-14T02:00:00.000Z',
  });
  bundle.openings[0].salt = '00'.repeat(32);
  const result = verifyHistoricalBundle(bundle);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'invalid_opening');
});

test('14. bundle disclosed after destruction is rejected as historical audit evidence', () => {
  const { chunked, tree, proofs } = buildFixture();
  const chunk = chunked.chunks[1];
  const bundle = buildHistoricalBundle({
    chunk,
    proof: proofByIndex(proofs, chunk.index),
    root: tree.root,
    destroyedAt: '2026-05-14T00:30:00.000Z',
  });
  const result = verifyHistoricalBundle(bundle);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'disclosure_not_pre_destruction');
});

test('15. lifecycle-bound capability authorization fails after destroyed state', () => {
  const { chunked, tree } = buildFixture();
  const token = buildCapabilityPayload({
    capId: 'cap-sec-001',
    evidenceId: EVIDENCE_ID,
    issuerId: 'EvidenceCustodian',
    granteeId: 'ExternalAuditor',
    scope: { type: SCOPE_TYPES.CHUNK_SET, indices: [1, 2] },
    purpose: 'third-party audit',
    issuedAt: '2026-05-14T00:00:00.000Z',
    expiresAt: '2026-05-15T00:00:00.000Z',
    nonce: 'aa'.repeat(16),
    version: CAPABILITY_VERSION_V3,
    commitmentVersion: COMMITMENT_VERSION_V3_HMAC,
    chunkMerkleRoot: tree.root,
    lifecycleStateAtIssuance: 'COMMITTED',
    evidenceLifecycleEpoch: 3,
    allowedLifecycleStates: ['COMMITTED', 'AUTHORIZED', 'DISCLOSED'],
    capabilityState: CAPABILITY_ACCESS_STATES.ACTIVE,
  });

  const before = evaluateCapabilityValidity(token, {
    now: '2026-05-14T01:00:00.000Z',
    actorId: 'ExternalAuditor',
    evidenceId: EVIDENCE_ID,
    commitmentVersion: COMMITMENT_VERSION_V3_HMAC,
    chunkMerkleRoot: tree.root,
    evidenceLifecycleEpoch: 3,
    currentLifecycleState: 'COMMITTED',
    requestedChunkIndices: [1],
  });
  assert.equal(before.valid, true);

  const after = evaluateCapabilityValidity(token, {
    now: '2026-05-14T01:00:00.000Z',
    actorId: 'ExternalAuditor',
    evidenceId: EVIDENCE_ID,
    commitmentVersion: COMMITMENT_VERSION_V3_HMAC,
    chunkMerkleRoot: tree.root,
    evidenceLifecycleEpoch: 3,
    currentLifecycleState: 'DESTROYED',
    requestedChunkIndices: [1],
  });
  assert.equal(after.valid, false);
  assert.match(after.reason, /^lifecycle_state_not_allowed:DESTROYED$/);

  const epochMismatch = evaluateCapabilityValidity(token, {
    now: '2026-05-14T01:00:00.000Z',
    actorId: 'ExternalAuditor',
    evidenceId: EVIDENCE_ID,
    commitmentVersion: COMMITMENT_VERSION_V3_HMAC,
    chunkMerkleRoot: tree.root,
    evidenceLifecycleEpoch: 4,
    currentLifecycleState: 'COMMITTED',
    requestedChunkIndices: [1],
  });
  assert.equal(epochMismatch.valid, false);
  assert.equal(epochMismatch.reason, 'lifecycle_epoch_mismatch');

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const signed = signCapability(token, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const sigCheck = verifyCapabilityToken(signed, publicKey.export({ type: 'spki', format: 'pem' }), '2026-05-14T01:00:00.000Z');
  assert.equal(sigCheck.valid, true, sigCheck.reason);

  const signedButDestroyed = evaluateCapabilityValidity(signed, {
    now: '2026-05-14T01:00:00.000Z',
    actorId: 'ExternalAuditor',
    evidenceId: EVIDENCE_ID,
    commitmentVersion: COMMITMENT_VERSION_V3_HMAC,
    chunkMerkleRoot: tree.root,
    evidenceLifecycleEpoch: 3,
    currentLifecycleState: 'DESTROYED',
    requestedChunkIndices: [1],
  });
  assert.equal(signedButDestroyed.valid, false);
  assert.match(signedButDestroyed.reason, /^lifecycle_state_not_allowed:DESTROYED$/);
});
