'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const {
  send,
  getIdentityConfig
} = require('./caliper-utils');

const DEFAULT_POLICY = Object.freeze({
  required: 2,
  eligibleRoles: Object.freeze([
    'DataProtectionOfficer',
    'JudicialReviewer',
    'EvidenceCustodian'
  ])
});

const ATTESTERS = Object.freeze([
  {
    role: 'DataProtectionOfficer',
    actorId: 'DataProtectionOfficer',
    logicalIdentity: 'DataProtectionOfficer',
    privateKeyFile: 'config/destruction-attestation-keys/dpo-destruction-attestation-private.pem',
    publicKeyFile: 'config/destruction-attestation-keys/dpo-destruction-attestation-public.pem'
  },
  {
    role: 'JudicialReviewer',
    actorId: 'JudicialReviewer',
    logicalIdentity: 'JudicialReviewer',
    privateKeyFile: 'config/destruction-attestation-keys/judge-destruction-attestation-private.pem',
    publicKeyFile: 'config/destruction-attestation-keys/judge-destruction-attestation-public.pem'
  },
  {
    role: 'EvidenceCustodian',
    actorId: 'EvidenceCustodian',
    logicalIdentity: 'EvidenceCustodian',
    privateKeyFile: 'config/destruction-attestation-keys/custodian-destruction-attestation-private.pem',
    publicKeyFile: 'config/destruction-attestation-keys/custodian-destruction-attestation-public.pem'
  }
]);

const registeredInProcess = new Set();

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }

  if (value && typeof value === 'object' && !Buffer.isBuffer(value)) {
    const keys = Object.keys(value)
      .filter((k) => typeof value[k] !== 'undefined')
      .sort();

    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }

  return JSON.stringify(value);
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

function writeAtomic(file, data) {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, file);
}

async function ensureKeyPair(privateKeyFile, publicKeyFile) {
  fs.mkdirSync(path.dirname(privateKeyFile), { recursive: true });

  if (fs.existsSync(privateKeyFile) && fs.existsSync(publicKeyFile)) {
    return;
  }

  const lockFile = `${privateKeyFile}.lock`;
  let lockFd = null;

  try {
    lockFd = fs.openSync(lockFile, 'wx');

    if (!fs.existsSync(privateKeyFile) || !fs.existsSync(publicKeyFile)) {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

      writeAtomic(
        privateKeyFile,
        privateKey.export({ type: 'pkcs8', format: 'pem' })
      );

      writeAtomic(
        publicKeyFile,
        publicKey.export({ type: 'spki', format: 'pem' })
      );
    }
  } catch (err) {
    if (err && err.code !== 'EEXIST') {
      throw err;
    }

    const deadline = Date.now() + 30000;
    while (Date.now() < deadline) {
      if (fs.existsSync(privateKeyFile) && fs.existsSync(publicKeyFile)) {
        return;
      }
      await sleep(250);
    }

    throw new Error(`timeout_waiting_for_attestation_keypair:${privateKeyFile}`);
  } finally {
    if (lockFd !== null) {
      try { fs.closeSync(lockFd); } catch {}
      try { fs.unlinkSync(lockFile); } catch {}
    }
  }
}

function normalizeDestroyedKeyClasses(receipt) {
  const raw = Array.isArray(receipt?.destroyedKeyClasses)
    ? receipt.destroyedKeyClasses
    : [];

  const set = new Set(
    raw.map((x) => String(x || '').trim().toUpperCase()).filter(Boolean)
  );

  if (receipt?.emkDestroyed === true) set.add('EMK');
  if (receipt?.dekDestroyed === true) set.add('DEK');
  if (receipt?.saltKeyDestroyed === true) set.add('K_SALT');
  if (receipt?.metadataKeyDestroyed === true) set.add('K_META');

  if (set.size === 0) {
    set.add('DEK');
    set.add('EMK');
    set.add('K_META');
    set.add('K_SALT');
  }

  return [...set].sort();
}

async function buildSignedAttestation(attester, receipt, evidenceId) {
  await ensureKeyPair(attester.privateKeyFile, attester.publicKeyFile);

  const privateKeyPem = fs.readFileSync(attester.privateKeyFile, 'utf8');

  const statement = {
    purpose: 'EVIDENCE_DESTRUCTION_ATTESTATION',
    evidenceId: String(evidenceId),
    destructionMethod: String(receipt.destructionMethod),
    receiptRef: String(receipt.receiptRef || receipt.receiptId || ''),
    completedAt: String(receipt.completedAt || receipt.destroyedAt || ''),
    destroyedKeyClasses: normalizeDestroyedKeyClasses(receipt),
    role: attester.role,
    actorId: attester.actorId,
    attestedAt: String(receipt.completedAt || receipt.destroyedAt || '')
  };

  const canonical = canonicalize(statement);
  const signature = crypto
    .sign(null, Buffer.from(canonical, 'utf8'), privateKeyPem)
    .toString('hex');

  return {
    role: attester.role,
    actorId: attester.actorId,
    attestedAt: statement.attestedAt,
    publicKeyRef: attester.actorId,
    statement,
    statementHash: sha256Hex(canonical),
    signature
  };
}

async function withMandatoryThresholdDestructionReceipt(baseReceipt, evidenceId) {
  const receipt = {
    ...(baseReceipt || {})
  };

  receipt.destroyed = true;
  receipt.destructionMethod = receipt.destructionMethod || receipt.method || 'HYBRID_CRYPTO_SHREDDING';
  receipt.receiptRef = receipt.receiptRef || receipt.receiptId || `RECEIPT-DESTRUCTION-${evidenceId}`;
  receipt.completedAt = receipt.completedAt || receipt.destroyedAt || new Date().toISOString();

  receipt.destroyedKeyClasses = normalizeDestroyedKeyClasses(receipt);

  receipt.emkDestroyed = true;
  receipt.dekDestroyed = true;
  receipt.saltKeyDestroyed = true;
  receipt.metadataKeyDestroyed = true;
  receipt.keyMaterialDestroyed = true;
  receipt.offChainAccessDestroyed = true;
  receipt.rawEvidenceAccessRevoked = true;

  receipt.requireThresholdAttestation = true;
  receipt.thresholdRequired = true;
  receipt.thresholdPolicy = {
    required: DEFAULT_POLICY.required,
    eligibleRoles: [...DEFAULT_POLICY.eligibleRoles]
  };

  receipt.destructionAttestations = [];
  for (const attester of ATTESTERS) {
    receipt.destructionAttestations.push(
      await buildSignedAttestation(attester, receipt, evidenceId)
    );
  }

  assertMandatoryThresholdDestructionReceipt(receipt, evidenceId);

  return receipt;
}

function assertMandatoryThresholdDestructionReceipt(receipt, evidenceId) {
  if (!receipt || typeof receipt !== 'object') {
    throw new Error(`missing destructionReceipt for ${evidenceId}`);
  }

  const policy = receipt.thresholdPolicy || {};
  const required = Number(policy.required || DEFAULT_POLICY.required);
  const eligible = new Set(policy.eligibleRoles || DEFAULT_POLICY.eligibleRoles);
  const attestations = Array.isArray(receipt.destructionAttestations)
    ? receipt.destructionAttestations
    : [];

  if (!Number.isInteger(required) || required < 2) {
    throw new Error(`invalid mandatory threshold required=${required} for ${evidenceId}`);
  }

  if (attestations.length < required) {
    throw new Error(`threshold destructionReceipt missing attestations for ${evidenceId}`);
  }

  const roles = new Set();
  const actors = new Set();

  for (const att of attestations) {
    if (!att.role || !att.actorId || !att.publicKeyRef || !att.statementHash || !att.signature) {
      throw new Error(`invalid threshold attestation fields for ${evidenceId}`);
    }

    if (!eligible.has(att.role)) {
      throw new Error(`attestation role not eligible for ${evidenceId}: ${att.role}`);
    }

    roles.add(att.role);
    actors.add(att.actorId);
  }

  if (roles.size < required) {
    throw new Error(`not enough distinct attestation roles for ${evidenceId}: required=${required}, roles=${roles.size}`);
  }

  if (actors.size < required) {
    throw new Error(`not enough distinct attestation actors for ${evidenceId}: required=${required}, actors=${actors.size}`);
  }
}

async function registerOneKey(sutAdapter, contractId, attester) {
  await ensureKeyPair(attester.privateKeyFile, attester.publicKeyFile);

  const publicKeyPem = fs.readFileSync(attester.publicKeyFile, 'utf8');

  try {
    await send(sutAdapter, {
      contractId,
      identity: getIdentityConfig(attester.logicalIdentity).caliperIdentity,
      fcn: 'registerPublicKey',
      args: [
        attester.actorId,
        'Ed25519',
        publicKeyPem,
        'DESTRUCTION_ATTESTATION'
      ],
      readOnly: false
    });
  } catch (err) {
    const msg = String(err && (err.message || err.stack || err));
    if (
      msg.includes('already') ||
      msg.includes('exists') ||
      msg.includes('duplicate') ||
      msg.includes('MVCC_READ_CONFLICT')
    ) {
      return;
    }
    throw err;
  }
}

async function registerDestructionAttestationKeys(sutAdapter, contractId, opts = {}) {
  const workerIndex = Number(opts.workerIndex || 0);
  const cacheKey = `${process.pid}:${contractId || 'forensicContract'}`;

  if (registeredInProcess.has(cacheKey)) {
    return;
  }

  for (const attester of ATTESTERS) {
    await ensureKeyPair(attester.privateKeyFile, attester.publicKeyFile);
  }

  if (workerIndex === 0) {
    for (const attester of ATTESTERS) {
      await registerOneKey(sutAdapter, contractId, attester);
    }

    await sleep(Number(opts.afterRegisterWaitMs || 3000));
  } else {
    await sleep(Number(opts.waitForWorker0Ms || 10000));
  }

  registeredInProcess.add(cacheKey);
}

module.exports = {
  DEFAULT_POLICY,
  ATTESTERS,
  withMandatoryThresholdDestructionReceipt,
  assertMandatoryThresholdDestructionReceipt,
  registerDestructionAttestationKeys
};
