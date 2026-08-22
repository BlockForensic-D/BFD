#!/usr/bin/env node
'use strict';

import { connect, hash, signers } from '@hyperledger/fabric-gateway';
import grpc from '@grpc/grpc-js';
import fs from 'fs';
import fsp from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import { TextDecoder } from 'util';
import { fileURLToPath } from 'url';

import {
  buildCapabilityPayload,
  signCapability,
  createCapId,
  generateNonceHex
} from './capability-manager.js';

import {
  buildDisclosureBundle,
  executeHashOnlyDisclosure
} from './disclosure-protocol.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const decoder = new TextDecoder();

const channelName = process.env.FABRIC_CHANNEL || 'forensic-channel';
const chaincodeName = process.env.FABRIC_CHAINCODE || 'forensicContract';

// ============================================================================
// Identity config
// ============================================================================

const identities = {
  acquisition: {
    certId: 'AcquisitionOperator',
    role: 'AcquisitionOperator',
    clearance: 'Medium',
    org: 'org1',
    mspId: 'Org1MSP'
  },

  gateway: {
    certId: 'GatewayCollector',
    role: 'GatewayCollector',
    clearance: 'Medium',
    org: 'org1',
    mspId: 'Org1MSP'
  },

  gateway_collector: {
    certId: 'GatewayCollector',
    role: 'GatewayCollector',
    clearance: 'Medium',
    org: 'org1',
    mspId: 'Org1MSP'
  },

  manual_collector: {
    certId: 'ManualCollector',
    role: 'ManualCollector',
    clearance: 'Medium',
    org: 'org1',
    mspId: 'Org1MSP'
  },

  collector: {
    certId: 'ManualCollector',
    role: 'ManualCollector',
    clearance: 'Medium',
    org: 'org1',
    mspId: 'Org1MSP'
  },

  custodian: {
    certId: 'EvidenceCustodian',
    role: 'EvidenceCustodian',
    clearance: 'High',
    org: 'org1',
    mspId: 'Org1MSP'
  },

  forensic: {
    certId: 'ForensicInvestigator',
    role: 'ForensicInvestigator',
    clearance: 'High',
    org: 'org1',
    mspId: 'Org1MSP'
  },

  judge: {
    certId: 'JudicialReviewer',
    role: 'JudicialReviewer',
    clearance: 'High',
    org: 'org2',
    mspId: 'Org2MSP'
  },

  dpo: {
    certId: 'DataProtectionOfficer',
    role: 'DataProtectionOfficer',
    clearance: 'High',
    org: 'org2',
    mspId: 'Org2MSP'
  },

  internal_auditor: {
    certId: 'InternalAuditor',
    role: 'InternalAuditor',
    clearance: 'Medium',
    org: 'org2',
    mspId: 'Org2MSP'
  },

  vendor: {
    certId: 'ExternalVendor',
    role: 'ExternalVendor',
    clearance: 'Medium',
    org: 'org3',
    mspId: 'Org3MSP'
  },

  external_vendor: {
    certId: 'ExternalVendor',
    role: 'ExternalVendor',
    clearance: 'Medium',
    org: 'org3',
    mspId: 'Org3MSP'
  },

  external_auditor: {
    certId: 'ExternalAuditor',
    role: 'ExternalAuditor',
    clearance: 'Medium',
    org: 'org3',
    mspId: 'Org3MSP'
  },

  admin1: {
    certId: 'Admin',
    role: 'Admin',
    clearance: 'High',
    org: 'org1',
    mspId: 'Org1MSP'
  },

  admin2: {
    certId: 'Admin',
    role: 'Admin',
    clearance: 'High',
    org: 'org2',
    mspId: 'Org2MSP'
  },

  admin3: {
    certId: 'Admin',
    role: 'Admin',
    clearance: 'High',
    org: 'org3',
    mspId: 'Org3MSP'
  },

  // Backward-compatible aliases for older scripts/experiments.
  monitoring: {
    certId: 'AcquisitionOperator',
    role: 'AcquisitionOperator',
    clearance: 'Medium',
    org: 'org1',
    mspId: 'Org1MSP'
  },

  gateway_legacy: {
    certId: 'AcquisitionOperator',
    role: 'AcquisitionOperator',
    clearance: 'Medium',
    org: 'org1',
    mspId: 'Org1MSP'
  },

  auditor: {
    certId: 'ExternalAuditor',
    role: 'ExternalAuditor',
    clearance: 'Medium',
    org: 'org3',
    mspId: 'Org3MSP'
  },

  external: {
    certId: 'ExternalAuditor',
    role: 'ExternalAuditor',
    clearance: 'Medium',
    org: 'org3',
    mspId: 'Org3MSP'
  }
};

for (const key of Object.keys(identities)) {
  const identity = identities[key];
  const orgName = identity.org;

  const orgCryptoBase = path.resolve(
    __dirname,
    '..',
    'fabric-samples',
    'test-network',
    'organizations',
    'peerOrganizations',
    `${orgName}.example.com`
  );

  const base = path.join(
    orgCryptoBase,
    'users',
    `${identity.certId}@${orgName}.example.com`,
    'msp'
  );

  identity.certPath = path.join(base, 'signcerts', 'cert.pem');
  identity.keyDir = path.join(base, 'keystore');

  const gatewayPeerOrg = process.env.FABRIC_GATEWAY_PEER_ORG || orgName;

  identity.peerEndpoint =
    gatewayPeerOrg === 'org1'
      ? 'localhost:7051'
      : (gatewayPeerOrg === 'org2' ? 'localhost:9051' : 'localhost:11051');

  identity.peerHost = `peer0.${gatewayPeerOrg}.example.com`;

  const gatewayOrgCryptoBase = path.resolve(
    __dirname,
    '..',
    'fabric-samples',
    'test-network',
    'organizations',
    'peerOrganizations',
    `${gatewayPeerOrg}.example.com`
  );

  identity.tlsCertPath = path.join(
    gatewayOrgCryptoBase,
    'peers',
    `peer0.${gatewayPeerOrg}.example.com`,
    'tls',
    'ca.crt'
  );

}

// ============================================================================
// CLI helpers
// ============================================================================

function printHelp() {
  console.log(`
Selective disclosure client (Fabric Gateway)

Usage:
  node paper3-client.js <command> [options]

Commands:
  preserve-evidence
  commit-preserved-evidence
  submit-evidence
  register-public-key
  create-capability-token
  issue-capability
  get-commitment
  request-disclosure
  build-bundle
  verify-disclosure
  request-destruction
  approve-destruction
  report-destroyed
  query-destruction-record
  revoke-capability
  expire-capability
  restrict-evidence
  destroy-evidence
  evidence-destruction
  withdraw-confidentiality
  report-key-destruction
  query-evidence-lifecycle
  query-capability-state
  help

Common identities:
  --identity <gateway|gateway_collector|manual_collector|collector|acquisition|custodian|forensic|judge|dpo|internal_auditor|vendor|external_auditor|admin1|admin2|admin3>

preserve-evidence
  --identity <gateway|manual_collector|acquisition>
  --input <jsonFile>
  --output <jsonFile>

commit-preserved-evidence
  --identity <custodian>
  --evidenceId <string>
  --input <jsonFile>
  --output <jsonFile>

submit-evidence
  --identity <idKey>
  --input <jsonFile>
  --output <jsonFile>

register-public-key
  --identity <idKey>
  --userId <string>
  --publicKeyFile <pemFile>
  --purpose <string>         default: DISCLOSURE_CAPABILITY
  --keyType <string>         default: Ed25519
  --output <jsonFile>

create-capability-token
  --input <jsonFile>
  --privateKeyFile <pemFile>
  --output <jsonFile>

issue-capability
  --identity <idKey>
  --tokenFile <jsonFile>
  --output <jsonFile>

get-commitment
  --identity <idKey>
  --evidenceId <string>
  --output <jsonFile>

request-disclosure
  --identity <idKey>
  --evidenceId <string>
  --tokenFile <jsonFile>
  --indices <jsonArray>      e.g. '[0,1,2]'
  --output <jsonFile>

build-bundle
  --tokenFile <jsonFile>
  --requestFile <jsonFile>
  --issuerPublicKeyFile <pemFile>
  --evidenceFile <binFile>
  --evidenceType <string>
  --generatedAt <isoTime>    optional
  --now <isoTime>            optional
  --debugInfoOutput <json>   optional; save local file debug info separately
  --output <jsonFile>

verify-disclosure
  --identity <idKey>
  --evidenceId <string>
  --bundleFile <jsonFile>
  --output <jsonFile>

request-destruction
  --identity <dpo>
  --evidenceId <string>
  --input <jsonFile>
  --output <jsonFile>

approve-destruction
  --identity <judge>
  --evidenceId <string>
  --input <jsonFile>
  --output <jsonFile>

report-destroyed
  --identity <custodian>
  --evidenceId <string>
  --receiptFile <jsonFile>
  --output <jsonFile>

query-destruction-record
  --identity <idKey>
  --evidenceId <string>
  --output <jsonFile>

revoke-capability
  --identity <custodian>
  --capId <string>
  --reason <string>          default: ADMINISTRATIVE
  --note <string>
  --output <jsonFile>

expire-capability
  --identity <custodian>
  --capId <string>
  --output <jsonFile>

restrict-evidence
  --identity <custodian|admin1>
  --evidenceId <string>
  --reason <string>          default: ADMINISTRATIVE
  --note <string>
  --output <jsonFile>

destroy-evidence / evidence-destruction
  --identity <dpo>
  --evidenceId <string>
  --reason <string>          default: PRIVACY_REQUEST
  --requestRef <string>      optional
  --justification <string>   required by chaincode semantics
  --output <jsonFile>

withdraw-confidentiality
  --identity <dpo>
  --evidenceId <string>
  --reason <string>          default: PRIVACY_REQUEST
  --requestRef <string>
  --justification <string>
  --output <jsonFile>

report-key-destruction
  --identity <dpo>
  --evidenceId <string>
  --receiptFile <jsonFile>   optional
  --method <string>          default: CRYPTOGRAPHIC_KEY_DESTRUCTION
  --note <string>            optional
  --output <jsonFile>

query-evidence-lifecycle
  --identity <idKey>
  --evidenceId <string>
  --output <jsonFile>

query-capability-state
  --identity <idKey>
  --capId <string>
  --output <jsonFile>
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

function parseJsonString(label, s) {
  try {
    return JSON.parse(s);
  } catch (e) {
    throw new Error(`Invalid JSON for ${label}: ${e.message}`);
  }
}

function parseIsoTime(label, value) {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) {
    throw new Error(`${label} must be a valid ISO timestamp`);
  }
  return d;
}

// ============================================================================
// File helpers
// ============================================================================

async function readJsonFile(filePath) {
  return JSON.parse(await fsp.readFile(filePath, 'utf8'));
}

async function readTextFile(filePath) {
  return fsp.readFile(filePath, 'utf8');
}

async function readBinaryFile(filePath) {
  return fsp.readFile(filePath);
}

async function ensureParentDir(filePath) {
  await fsp.mkdir(path.dirname(path.resolve(filePath)), { recursive: true });
}

async function writeJsonFile(filePath, data) {
  await ensureParentDir(filePath);
  await fsp.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
}

function printResult(result) {
  console.log(
    typeof result === 'string'
      ? result
      : JSON.stringify(result, null, 2)
  );
}

// ============================================================================
// Canonical JSON / bundle hash helpers
// ============================================================================

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function normalizeForCanonicalJson(value) {
  if (Array.isArray(value)) {
    return value.map(normalizeForCanonicalJson);
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (isPlainObject(value)) {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      const v = value[key];
      if (typeof v !== 'undefined') {
        out[key] = normalizeForCanonicalJson(v);
      }
    }
    return out;
  }

  return value;
}

function canonicalizeJson(obj) {
  return JSON.stringify(normalizeForCanonicalJson(obj));
}

function computeCanonicalBundleHash(bundle) {
  if (!isPlainObject(bundle)) {
    throw new TypeError('bundle must be a plain object');
  }

  const cloned = JSON.parse(JSON.stringify(bundle));
  delete cloned.bundleHash;
  delete cloned.localEvidenceInfo;

  if (isPlainObject(cloned.manifest)) {
    delete cloned.manifest.bundleHash;
  }

  return crypto.createHash('sha256')
    .update(canonicalizeJson(cloned), 'utf8')
    .digest('hex');
}

function sanitizeBundleForLedgerVerification(bundle) {
  if (!isPlainObject(bundle)) {
    throw new TypeError('bundle must be a plain object');
  }

  const sanitized = JSON.parse(JSON.stringify(bundle));

  delete sanitized.localEvidenceInfo;

  if (isPlainObject(sanitized.manifest)) {
    delete sanitized.manifest.bundleHash;
  }

  sanitized.bundleHash = computeCanonicalBundleHash(sanitized);
  return sanitized;
}

// ============================================================================
// Fabric Gateway helpers
// ============================================================================

async function setupClient(idKey) {
  const info = identities[idKey];
  if (!info) {
    throw new Error(`Unknown identity key: ${idKey}`);
  }

  if (!fs.existsSync(info.certPath)) {
    throw new Error(`Certificate not found for identity "${idKey}": ${info.certPath}`);
  }
  if (!fs.existsSync(info.keyDir)) {
    throw new Error(`Key directory not found for identity "${idKey}": ${info.keyDir}`);
  }
  if (!fs.existsSync(info.tlsCertPath)) {
    throw new Error(`TLS cert not found for identity "${idKey}": ${info.tlsCertPath}`);
  }

  const cert = fs.readFileSync(info.certPath);
  const keyFiles = fs.readdirSync(info.keyDir);
  if (!keyFiles.length) {
    throw new Error(`No private key file found in ${info.keyDir}`);
  }
  const key = fs.readFileSync(path.join(info.keyDir, keyFiles[0]));

  const identity = {
    mspId: info.mspId,
    credentials: cert
  };

  const signer = signers.newPrivateKeySigner(crypto.createPrivateKey(key));
  const tlsCreds = grpc.credentials.createSsl(fs.readFileSync(info.tlsCertPath));

  const client = new grpc.Client(
    info.peerEndpoint,
    tlsCreds,
    { 'grpc.ssl_target_name_override': info.peerHost }
  );

  const gateway = connect({
    client,
    identity,
    signer,
    hash: hash.sha256
  });

  return {
    gateway,
    client,
    contract: gateway.getNetwork(channelName).getContract(chaincodeName)
  };
}

async function withContract(identityKey, fn) {
  const { gateway, client, contract } = await setupClient(identityKey);
  try {
    return await fn(contract);
  } finally {
    try { gateway.close(); } catch {}
    try { client.close(); } catch {}
  }
}

function decodeChaincodeResponse(resultBytes) {
  if (!resultBytes) return null;
  const text = decoder.decode(resultBytes);
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function wrapTransactionError(kind, identityKey, fnName, err) {
  const wrapped = new Error(`${kind.toUpperCase()} ${fnName} failed for identity ${identityKey}`);
  wrapped.cause = err;
  wrapped.txContext = {
    kind,
    identityKey,
    fnName,
    channelName,
    chaincodeName
  };
  return wrapped;
}

async function submitTx(identityKey, fnName, ...args) {
  try {
    return await withContract(identityKey, async (contract) => {
      const result = await contract.submitTransaction(fnName, ...args);
      return decodeChaincodeResponse(result);
    });
  } catch (err) {
    throw wrapTransactionError('submit', identityKey, fnName, err);
  }
}

async function evaluateTx(identityKey, fnName, ...args) {
  try {
    return await withContract(identityKey, async (contract) => {
      const result = await contract.evaluateTransaction(fnName, ...args);
      return decodeChaincodeResponse(result);
    });
  } catch (err) {
    throw wrapTransactionError('evaluate', identityKey, fnName, err);
  }
}

// ============================================================================
// Error diagnostics
// ============================================================================

function pushUniqueLine(lines, seenLines, line) {
  const normalized = String(line || '').trim();
  if (!normalized) return;
  if (!seenLines.has(normalized)) {
    seenLines.add(normalized);
    lines.push(normalized);
  }
}

function tryStringify(value) {
  try {
    if (typeof value === 'string') return value;
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function maybePushKV(lines, seenLines, label, value) {
  if (value === undefined || value === null || value === '') return;
  pushUniqueLine(lines, seenLines, `${label}${tryStringify(value)}`);
}

function collectErrorDiagnostics(err, lines, seenLines, seenObjects = new Set(), depth = 0, branch = 'error') {
  if (!err || depth > 6) return;

  if (typeof err !== 'object') {
    pushUniqueLine(lines, seenLines, `${branch}: ${String(err)}`);
    return;
  }

  if (seenObjects.has(err)) return;
  seenObjects.add(err);

  if (err instanceof Error) {
    pushUniqueLine(lines, seenLines, `${branch}: ${err.name}: ${err.message}`);
  }

  if (typeof err.message === 'string') {
    pushUniqueLine(lines, seenLines, `${branch}.message: ${err.message}`);
  }

  if (typeof err.details === 'string') {
    pushUniqueLine(lines, seenLines, `${branch}.details: ${err.details}`);
  }

  if (typeof err.code === 'number') {
    const codeName = grpc.status?.[err.code];
    pushUniqueLine(
      lines,
      seenLines,
      `${branch}.grpcCode: ${err.code}${codeName ? ` (${codeName})` : ''}`
    );
  }

  maybePushKV(lines, seenLines, `${branch}.status: `, err.status);
  maybePushKV(lines, seenLines, `${branch}.transactionId: `, err.transactionId);
  maybePushKV(lines, seenLines, `${branch}.peer: `, err.peer);
  maybePushKV(lines, seenLines, `${branch}.address: `, err.address);
  maybePushKV(lines, seenLines, `${branch}.mspId: `, err.mspId);

  if (Array.isArray(err.details)) {
    err.details.forEach((item, idx) => {
      if (typeof item === 'string') {
        pushUniqueLine(lines, seenLines, `${branch}.details[${idx}]: ${item}`);
      } else if (item && typeof item === 'object') {
        maybePushKV(lines, seenLines, `${branch}.details[${idx}].address: `, item.address);
        maybePushKV(lines, seenLines, `${branch}.details[${idx}].mspId: `, item.mspId);
        maybePushKV(lines, seenLines, `${branch}.details[${idx}].message: `, item.message);
        maybePushKV(lines, seenLines, `${branch}.details[${idx}].status: `, item.status);
        maybePushKV(lines, seenLines, `${branch}.details[${idx}].payload: `, item.payload);
        collectErrorDiagnostics(item, lines, seenLines, seenObjects, depth + 1, `${branch}.details[${idx}]`);
      }
    });
  }

  const responseArrays = [
    ['responses', err.responses],
    ['errors', err.errors],
    ['errorDetails', err.errorDetails],
    ['endorseErrors', err.endorseErrors]
  ];

  for (const [label, value] of responseArrays) {
    if (Array.isArray(value)) {
      value.forEach((item, idx) => {
        if (typeof item === 'string') {
          pushUniqueLine(lines, seenLines, `${branch}.${label}[${idx}]: ${item}`);
        } else if (item && typeof item === 'object') {
          maybePushKV(lines, seenLines, `${branch}.${label}[${idx}].address: `, item.address);
          maybePushKV(lines, seenLines, `${branch}.${label}[${idx}].mspId: `, item.mspId);
          maybePushKV(lines, seenLines, `${branch}.${label}[${idx}].message: `, item.message);
          maybePushKV(lines, seenLines, `${branch}.${label}[${idx}].status: `, item.status);
          maybePushKV(lines, seenLines, `${branch}.${label}[${idx}].peer: `, item.peer);
          collectErrorDiagnostics(item, lines, seenLines, seenObjects, depth + 1, `${branch}.${label}[${idx}]`);
        }
      });
    }
  }

  if (err.metadata && typeof err.metadata.getMap === 'function') {
    const meta = err.metadata.getMap();
    for (const [k, v] of Object.entries(meta)) {
      maybePushKV(lines, seenLines, `${branch}.metadata.${k}: `, v);
    }
  }

  if (err.cause) {
    collectErrorDiagnostics(err.cause, lines, seenLines, seenObjects, depth + 1, `${branch}.cause`);
  }
}

function formatCliError(err) {
  const lines = [];
  const seenLines = new Set();

  if (err?.txContext) {
    pushUniqueLine(
      lines,
      seenLines,
      `ERROR: ${err.txContext.kind.toUpperCase()} ${err.txContext.fnName} failed for identity ${err.txContext.identityKey}`
    );
    pushUniqueLine(
      lines,
      seenLines,
      `context: channel=${err.txContext.channelName}, chaincode=${err.txContext.chaincodeName}`
    );
  } else {
    pushUniqueLine(lines, seenLines, 'ERROR: command failed');
  }

  collectErrorDiagnostics(err, lines, seenLines);

  if (lines.length <= 2) {
    pushUniqueLine(
      lines,
      seenLines,
      'hint: the client only received a generic endorsement failure; inspect peer container logs if no specific chaincode message is shown'
    );
  }

  return lines.join('\n');
}

// ============================================================================
// Business helpers
// ============================================================================

function buildCapabilityPayloadFromInput(input) {
  const now = new Date();
  const issuedAt = input.issuedAt || now.toISOString();

  const ttlHours = input.ttlHours !== undefined ? Number(input.ttlHours) : 24;
  if (!Number.isFinite(ttlHours) || ttlHours <= 0) {
    throw new Error('ttlHours must be a positive number');
  }

  const expiresAt =
    input.expiresAt ||
    new Date(Date.parse(issuedAt) + ttlHours * 3600_000).toISOString();

  const nonce = input.nonce || generateNonceHex(8);
  const capId = input.capId || createCapId({
    evidenceId: input.evidenceId,
    granteeId: input.granteeId,
    nonce
  });

  const hasV3Context = Boolean(
    input.commitmentVersion ||
    input.chunkMerkleRoot ||
    input.lifecycleStateAtIssuance ||
    input.evidenceLifecycleEpoch !== undefined ||
    input.allowedLifecycleStates
  );

  return buildCapabilityPayload({
    capId,
    evidenceId: input.evidenceId,
    issuerId: input.issuerId,
    granteeId: input.granteeId,
    scope: input.scope,
    purpose: input.purpose || '',
    issuedAt,
    expiresAt,
    nonce,
    version: input.version || (hasV3Context ? 'cap-v3' : 'cap-v1'),
    bindingDigest: input.bindingDigest,
    commitmentVersion: input.commitmentVersion,
    chunkMerkleRoot: input.chunkMerkleRoot,
    lifecycleStateAtIssuance: input.lifecycleStateAtIssuance,
    evidenceLifecycleEpoch: input.evidenceLifecycleEpoch,
    allowedLifecycleStates: input.allowedLifecycleStates
  });
}

function computeFileSha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function detectHashOnlyDisclosure(token, requestInfo) {
  return token?.scope?.type === 'HASH_ONLY' || requestInfo?.disclosureType === 'HASH_ONLY';
}

// ============================================================================
// Commands
// ============================================================================

async function cmdPreserveEvidence(args) {
  const identity = requireArg(args, 'identity');
  const inputFile = requireArg(args, 'input');
  const payload = await readJsonFile(inputFile);

  const result = await submitTx(
    identity,
    'preserveEvidence',
    JSON.stringify(payload)
  );

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdCommitPreservedEvidence(args) {
  const identity = requireArg(args, 'identity');
  const evidenceId = requireArg(args, 'evidenceId');
  const commitPayload = args.input ? await readJsonFile(args.input) : {};

  const result = await submitTx(
    identity,
    'commitPreservedEvidence',
    evidenceId,
    JSON.stringify(commitPayload)
  );

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdSubmitEvidence(args) {
  const identity = requireArg(args, 'identity');
  const inputFile = requireArg(args, 'input');
  const payload = await readJsonFile(inputFile);

  const result = await submitTx(identity, 'submitEvidence', JSON.stringify(payload));

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdRegisterPublicKey(args) {
  const identity = requireArg(args, 'identity');
  const userId = requireArg(args, 'userId');
  const publicKeyFile = requireArg(args, 'publicKeyFile');
  const purpose = getArg(args, 'purpose', 'DISCLOSURE_CAPABILITY');
  const keyType = getArg(args, 'keyType', 'Ed25519');
  const publicKeyPem = await readTextFile(publicKeyFile);

  const result = await submitTx(
    identity,
    'registerPublicKey',
    userId,
    keyType,
    publicKeyPem,
    purpose
  );

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdCreateCapabilityToken(args) {
  const inputFile = requireArg(args, 'input');
  const privateKeyFile = requireArg(args, 'privateKeyFile');

  const input = await readJsonFile(inputFile);
  const privateKeyPem = await readTextFile(privateKeyFile);

  const payload = buildCapabilityPayloadFromInput(input);
  const token = signCapability(payload, privateKeyPem);

  if (args.output) await writeJsonFile(args.output, token);
  printResult(token);
}

async function cmdIssueCapability(args) {
  const identity = requireArg(args, 'identity');
  const tokenFile = requireArg(args, 'tokenFile');
  const token = await readJsonFile(tokenFile);

  const result = await submitTx(
    identity,
    'issueDisclosureCapability',
    JSON.stringify(token)
  );

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdGetCommitment(args) {
  const identity = requireArg(args, 'identity');
  const evidenceId = requireArg(args, 'evidenceId');

  const result = await evaluateTx(identity, 'getEvidenceCommitment', evidenceId);

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdRequestDisclosure(args) {
  const identity = requireArg(args, 'identity');
  const evidenceId = requireArg(args, 'evidenceId');
  const tokenFile = requireArg(args, 'tokenFile');
  const indicesRaw = getArg(args, 'indices', '[]');

  const token = await readJsonFile(tokenFile);
  const indices = parseJsonString('indices', indicesRaw);
  if (!Array.isArray(indices)) {
    throw new Error('--indices must be a JSON array');
  }

  const result = await submitTx(
    identity,
    'requestDisclosure',
    evidenceId,
    JSON.stringify(token),
    JSON.stringify(indices)
  );

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdBuildBundle(args) {
  const tokenFile = requireArg(args, 'tokenFile');
  const requestFile = requireArg(args, 'requestFile');
  const issuerPublicKeyFile = requireArg(args, 'issuerPublicKeyFile');
  const evidenceFile = requireArg(args, 'evidenceFile');

  const token = await readJsonFile(tokenFile);
  const requestInfo = await readJsonFile(requestFile);
  const issuerPublicKeyPem = await readTextFile(issuerPublicKeyFile);
  const evidenceBuffer = await readBinaryFile(evidenceFile);

  const evidenceType = getArg(args, 'evidenceType', requestInfo.evidenceType || '');

  const generatedAtRaw = getArg(args, 'generatedAt', new Date().toISOString());
  const generatedAt = parseIsoTime('generatedAt', generatedAtRaw).toISOString();

  const nowRaw = getArg(args, 'now', generatedAt);
  const now = parseIsoTime('now', nowRaw);

  const requesterId =
    requestInfo.granteeId ||
    requestInfo.requesterId ||
    token.granteeId;

  const expectedOnChainRoot =
    requestInfo.chunkMerkleRoot ||
    requestInfo.manifest?.chunkMerkleRoot;

  const chunkSize =
    requestInfo.chunkSize ||
    requestInfo.manifest?.chunkSize;

  const commitmentVersion =
    requestInfo.commitmentVersion ||
    requestInfo.manifest?.commitmentVersion ||
    null;

  const requestedChunkIndices =
    requestInfo.requestedChunkIndices ||
    requestInfo.manifest?.requestedChunkIndices ||
    [];

  const localFileSha256 = computeFileSha256Hex(evidenceBuffer);
  const expectedFileHash =
    requestInfo.integrityHash ||
    requestInfo.fileHash ||
    requestInfo.manifest?.fileHash ||
    null;

  if (
    expectedFileHash &&
    String(expectedFileHash).toLowerCase() !== String(localFileSha256).toLowerCase()
  ) {
    throw new Error(
      `Local evidence file hash mismatch: local=${localFileSha256} expected=${expectedFileHash}`
    );
  }

  let bundle;
  if (detectHashOnlyDisclosure(token, requestInfo)) {
    bundle = executeHashOnlyDisclosure({
      evidenceId: token.evidenceId,
      evidenceType,
      evidenceBuffer,
      capabilityToken: token,
      issuerPublicKey: issuerPublicKeyPem,
      requesterId,
      chunkSize,
      expectedOnChainRoot,
      commitmentVersion,
      evidenceMasterKey: getArg(args, 'evidenceMasterKey', getArg(args, 'emk')),
      emk: getArg(args, 'emk'),
      kSalt: getArg(args, 'kSalt'),
      saltKey: getArg(args, 'saltKey'),
      disclosedAt: getArg(args, 'disclosedAt'),
      disclosureTxId: getArg(args, 'disclosureTxId', requestInfo.txId || requestInfo.disclosureTxId),
      disclosureEventHash: getArg(args, 'disclosureEventHash'),
      blockNumber: getArg(args, 'blockNumber'),
      generatedAt,
      now
    });
  } else {
    bundle = buildDisclosureBundle({
      evidenceId: token.evidenceId,
      evidenceType,
      evidenceBuffer,
      capabilityToken: token,
      issuerPublicKey: issuerPublicKeyPem,
      requesterId,
      requestedChunkIndices,
      chunkSize,
      expectedOnChainRoot,
      commitmentVersion,
      evidenceMasterKey: getArg(args, 'evidenceMasterKey', getArg(args, 'emk')),
      emk: getArg(args, 'emk'),
      kSalt: getArg(args, 'kSalt'),
      saltKey: getArg(args, 'saltKey'),
      disclosedAt: getArg(args, 'disclosedAt'),
      disclosureTxId: getArg(args, 'disclosureTxId', requestInfo.txId || requestInfo.disclosureTxId),
      disclosureEventHash: getArg(args, 'disclosureEventHash'),
      blockNumber: getArg(args, 'blockNumber'),
      generatedAt,
      now
    });
  }

  if (commitmentVersion) {
    bundle.manifest = bundle.manifest || {};
    bundle.manifest.commitmentVersion = String(commitmentVersion).trim();
  }

  const sanitizedBundle = sanitizeBundleForLedgerVerification(bundle);

  const debugInfoOutput = getArg(args, 'debugInfoOutput');
  if (debugInfoOutput) {
    await writeJsonFile(debugInfoOutput, {
      evidenceFile: path.resolve(evidenceFile),
      fileSha256: localFileSha256,
      commitmentVersion,
      builtAt: generatedAt
    });
  }

  if (args.output) await writeJsonFile(args.output, sanitizedBundle);
  printResult(sanitizedBundle);
}

async function cmdVerifyDisclosure(args) {
  const identity = requireArg(args, 'identity');
  const evidenceId = requireArg(args, 'evidenceId');
  const bundleFile = requireArg(args, 'bundleFile');
  const bundle = await readJsonFile(bundleFile);

  const result = await submitTx(
    identity,
    'verifyDisclosure',
    evidenceId,
    JSON.stringify(bundle)
  );

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdVerifyHistoricalDisclosure(args) {
  const identity = requireArg(args, 'identity');
  const evidenceId = requireArg(args, 'evidenceId');
  const bundleFile = requireArg(args, 'bundleFile');
  const bundle = await readJsonFile(bundleFile);

  const result = await evaluateTx(
    identity,
    'verifyHistoricalDisclosure',
    evidenceId,
    JSON.stringify(bundle)
  );

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdRevokeCapability(args) {
  const identity = requireArg(args, 'identity');
  const capId = requireArg(args, 'capId');
  const reason = {
    reasonCode: getArg(args, 'reason', 'ADMINISTRATIVE'),
    note: getArg(args, 'note', '')
  };

  const result = await submitTx(identity, 'revokeCapability', capId, JSON.stringify(reason));

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdExpireCapability(args) {
  const identity = requireArg(args, 'identity');
  const capId = requireArg(args, 'capId');

  const result = await submitTx(identity, 'expireCapability', capId);

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdRestrictEvidence(args) {
  const identity = requireArg(args, 'identity');
  const evidenceId = requireArg(args, 'evidenceId');
  const reason = {
    reasonCode: getArg(args, 'reason', 'ADMINISTRATIVE'),
    note: getArg(args, 'note', '')
  };

  const result = await submitTx(identity, 'restrictEvidence', evidenceId, JSON.stringify(reason));

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdWithdrawConfidentiality(args) {
  const identity = requireArg(args, 'identity');
  const evidenceId = requireArg(args, 'evidenceId');
  const reason = {
    reasonCode: getArg(args, 'reason', 'PRIVACY_REQUEST'),
    requestRef: getArg(args, 'requestRef', ''),
    justification: getArg(
      args,
      'justification',
      getArg(args, 'note', 'confidentiality withdrawal requested')
    )
  };

  const result = await submitTx(
    identity,
    'withdrawConfidentiality',
    evidenceId,
    JSON.stringify(reason)
  );

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdDestroyEvidence(args) {
  const identity = requireArg(args, 'identity');
  const evidenceId = requireArg(args, 'evidenceId');

  const reason = {
    reasonCode: getArg(args, 'reason', 'PRIVACY_REQUEST'),
    requestRef: getArg(args, 'requestRef', ''),
    justification: getArg(
      args,
      'justification',
      getArg(args, 'note', 'evidence destruction requested')
    ),
    terminology: 'EVIDENCE_DESTRUCTION',
    mechanism: 'CRYPTOGRAPHIC_KEY_DESTRUCTION_WITH_AUDIT_PRESERVATION'
  };

  const result = await submitTx(
    identity,
    'withdrawConfidentiality',
    evidenceId,
    JSON.stringify(reason)
  );

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdReportKeyDestruction(args) {
  const identity = requireArg(args, 'identity');
  const evidenceId = requireArg(args, 'evidenceId');

  const receipt = args.receiptFile
    ? await readJsonFile(args.receiptFile)
    : {
        erased: true,
        method: getArg(args, 'method', 'CRYPTOGRAPHIC_KEY_DESTRUCTION'),
        completedAt: new Date().toISOString(),
        note: getArg(args, 'note', '')
      };

  const result = await submitTx(
    identity,
    'reportKeyDestructionCompleted',
    evidenceId,
    JSON.stringify(receipt)
  );

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdQueryEvidenceLifecycle(args) {
  const identity = requireArg(args, 'identity');
  const evidenceId = requireArg(args, 'evidenceId');

  const result = await evaluateTx(identity, 'getEvidenceLifecycleState', evidenceId);

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdQueryCapabilityState(args) {
  const identity = requireArg(args, 'identity');
  const capId = requireArg(args, 'capId');

  const result = await evaluateTx(identity, 'getCapabilityRecord', capId);

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}



async function cmdRequestDestruction(args) {
  const identity = requireArg(args, 'identity');
  const evidenceId = requireArg(args, 'evidenceId');

  const payload = args.input
    ? await readJsonFile(args.input)
    : {
        reasonCode: getArg(args, 'reason', 'RETENTION_POLICY'),
        requestRef: getArg(args, 'requestRef', ''),
        justification: getArg(
          args,
          'justification',
          getArg(args, 'note', 'Lifecycle-aware evidence destruction requested')
        )
      };

  const result = await submitTx(
    identity,
    'requestEvidenceDestruction',
    evidenceId,
    JSON.stringify(payload)
  );

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdApproveDestruction(args) {
  const identity = requireArg(args, 'identity');
  const evidenceId = requireArg(args, 'evidenceId');

  const payload = args.input
    ? await readJsonFile(args.input)
    : {
        approvalRef: getArg(args, 'approvalRef', ''),
        approvalNote: getArg(
          args,
          'note',
          getArg(args, 'justification', 'Destruction request approved by judicial reviewer')
        )
      };

  const result = await submitTx(
    identity,
    'approveEvidenceDestruction',
    evidenceId,
    JSON.stringify(payload)
  );

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdReportDestroyed(args) {
  const identity = requireArg(args, 'identity');
  const evidenceId = requireArg(args, 'evidenceId');

  const payload = args.receiptFile
    ? await readJsonFile(args.receiptFile)
    : {
        destroyed: true,
        destructionMethod: getArg(args, 'method', 'HYBRID_CRYPTO_SHREDDING'),
        receiptRef: getArg(args, 'receiptRef', ''),
        completedAt: new Date().toISOString(),
        destroyedKeyClasses: ['EMK', 'DEK', 'K_SALT', 'K_META'],
        keyMaterialDestroyed: true,
        offChainAccessDestroyed: true,
        rawEvidenceAccessRevoked: true,
        emkDestroyed: true,
        dekDestroyed: true,
        saltKeyDestroyed: true,
        metadataKeyDestroyed: true,
        note: getArg(args, 'note', 'Evidence destruction execution completed')
      };

  const result = await submitTx(
    identity,
    'reportEvidenceDestroyed',
    evidenceId,
    JSON.stringify(payload)
  );

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}

async function cmdQueryDestructionRecord(args) {
  const identity = requireArg(args, 'identity');
  const evidenceId = requireArg(args, 'evidenceId');

  const result = await evaluateTx(
    identity,
    'getEvidenceDestructionRecord',
    evidenceId
  );

  if (args.output) await writeJsonFile(args.output, result);
  printResult(result);
}


// ============================================================================
// Main
// ============================================================================

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0] || 'help';

  switch (command) {
    case 'help':
    case '--help':
    case '-h':
      printHelp();
      return;

    case 'preserve-evidence':
      await cmdPreserveEvidence(args);
      return;

    case 'commit-preserved-evidence':
      await cmdCommitPreservedEvidence(args);
      return;

    case 'submit-evidence':
      await cmdSubmitEvidence(args);
      return;

    case 'register-public-key':
      await cmdRegisterPublicKey(args);
      return;

    case 'create-capability-token':
      await cmdCreateCapabilityToken(args);
      return;

    case 'issue-capability':
      await cmdIssueCapability(args);
      return;

    case 'get-commitment':
      await cmdGetCommitment(args);
      return;

    case 'request-disclosure':
      await cmdRequestDisclosure(args);
      return;

    case 'build-bundle':
      await cmdBuildBundle(args);
      return;

    case 'verify-disclosure':
      await cmdVerifyDisclosure(args);
      return;

    case 'verify-historical-disclosure':
      await cmdVerifyHistoricalDisclosure(args);
      return;

    case 'revoke-capability':
      await cmdRevokeCapability(args);
      return;

    case 'expire-capability':
      await cmdExpireCapability(args);
      return;

    case 'restrict-evidence':
      await cmdRestrictEvidence(args);
      return;

    case 'destroy-evidence':
    case 'evidence-destruction':
      await cmdDestroyEvidence(args);
      return;

    case 'withdraw-confidentiality':
      await cmdWithdrawConfidentiality(args);
      return;

    case 'report-key-destruction':
      await cmdReportKeyDestruction(args);
      return;

    case 'query-evidence-lifecycle':
      await cmdQueryEvidenceLifecycle(args);
      return;

    case 'query-capability-state':
      await cmdQueryCapabilityState(args);
      return;

    case 'request-destruction':
      await cmdRequestDestruction(args);
      return;

    case 'approve-destruction':
      await cmdApproveDestruction(args);
      return;

    case 'report-destroyed':
      await cmdReportDestroyed(args);
      return;

    case 'query-destruction-record':
      await cmdQueryDestructionRecord(args);
      return;

    default:
      throw new Error(`Unknown command: ${command}`);
  }
}

main().catch((err) => {
  console.error(formatCliError(err));
  process.exitCode = 1;
});