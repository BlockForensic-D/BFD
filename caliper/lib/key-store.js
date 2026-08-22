'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function generateEd25519KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' })
  };
}

function loadOrCreateKeyStore(filePath, identities) {
  ensureDir(path.dirname(filePath));
  if (fs.existsSync(filePath)) {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  }

  const store = { createdAt: new Date().toISOString(), keys: {} };
  for (const [logicalName, cfg] of Object.entries(identities)) {
    const kp = generateEd25519KeyPair();
    store.keys[logicalName] = {
      actorId: cfg.actorId,
      role: cfg.role,
      publicKeyPem: kp.publicKeyPem,
      privateKeyPem: kp.privateKeyPem
    };
  }

  fs.writeFileSync(filePath, JSON.stringify(store, null, 2));
  return store;
}

function getKeyPair(store, logicalName) {
  const key = store.keys[logicalName];
  if (!key) throw new Error(`Missing key pair for identity ${logicalName}`);
  return key;
}

module.exports = { generateEd25519KeyPair, loadOrCreateKeyStore, getKeyPair };
