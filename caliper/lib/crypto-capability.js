'use strict';

const crypto = require('node:crypto');
const { canonicalizeWithoutFields, sha256CanonicalHex } = require('./canonical-json');
const { capId } = require('./ids');

function normalizeScope(scope) {
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) throw new Error('scope must be an object');
  const type = String(scope.type || '').trim().toUpperCase();
  if (type === 'HASH_ONLY') return { type: 'HASH_ONLY' };
  if (type === 'FULL_CHUNKS') return { type: 'FULL_CHUNKS' };
  if (type === 'CHUNK_SET') {
    const seen = new Set();
    const indices = (scope.indices || [])
      .map(Number)
      .filter((n) => Number.isInteger(n) && n >= 0)
      .filter((n) => {
        if (seen.has(n)) return false;
        seen.add(n);
        return true;
      })
      .sort((a, b) => a - b);
    if (indices.length === 0) throw new Error('CHUNK_SET requires non-empty indices');
    return { type: 'CHUNK_SET', indices };
  }
  throw new Error(`Unsupported scope type: ${scope.type}`);
}

function computeScopeDigest(scope) {
  return sha256CanonicalHex(normalizeScope(scope));
}

function createCapabilityToken(params, privateKeyPem) {
  const issuedAt = params.issuedAt || new Date().toISOString();
  const expiresAt = params.expiresAt || new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const nonce = params.nonce || crypto.randomBytes(8).toString('hex');
  const scope = normalizeScope(params.scope || { type: 'HASH_ONLY' });
  const token = {
    capId: params.capId || capId(params.evidenceId, params.granteeId, nonce),
    evidenceId: String(params.evidenceId),
    issuerId: String(params.issuerId),
    granteeId: String(params.granteeId),
    scope,
    purpose: String(params.purpose || 'CALIPER_DISCLOSURE_BENCHMARK'),
    issuedAt: new Date(issuedAt).toISOString(),
    expiresAt: new Date(expiresAt).toISOString(),
    nonce,
    version: params.version || 'cap-v1',
    ...(params.bindingDigest ? { bindingDigest: String(params.bindingDigest).toLowerCase() } : {}),
    ...(params.commitmentVersion ? { commitmentVersion: String(params.commitmentVersion) } : {}),
    ...(params.chunkMerkleRoot ? { chunkMerkleRoot: String(params.chunkMerkleRoot).toLowerCase() } : {}),
    ...(params.lifecycleStateAtIssuance ? { lifecycleStateAtIssuance: String(params.lifecycleStateAtIssuance).toUpperCase() } : {}),
    ...(Number.isInteger(params.evidenceLifecycleEpoch) ? { evidenceLifecycleEpoch: params.evidenceLifecycleEpoch } : {}),
    ...(params.allowedLifecycleStates ? { allowedLifecycleStates: [...new Set(params.allowedLifecycleStates.map((s) => String(s).toUpperCase()))].sort() } : {})
  };

  const canonical = canonicalizeWithoutFields(token, ['signature']);
  const signature = crypto.sign(null, Buffer.from(canonical, 'utf8'), crypto.createPrivateKey(privateKeyPem)).toString('hex');
  return { ...token, signature };
}

function requestedIndicesForScope(scope) {
  const normalized = normalizeScope(scope);
  if (normalized.type === 'HASH_ONLY') return [];
  if (normalized.type === 'FULL_CHUNKS') return [];
  return normalized.indices;
}

module.exports = { normalizeScope, computeScopeDigest, createCapabilityToken, requestedIndicesForScope };
