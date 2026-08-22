'use strict';

const crypto = require('node:crypto');

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) && !Buffer.isBuffer(value) && !(value instanceof Date);
}

function normalizeForCanonicalJson(value) {
  if (Array.isArray(value)) return value.map(normalizeForCanonicalJson);
  if (value instanceof Date) return value.toISOString();
  if (isPlainObject(value)) {
    const out = {};
    for (const key of Object.keys(value).sort()) {
      if (typeof value[key] !== 'undefined') out[key] = normalizeForCanonicalJson(value[key]);
    }
    return out;
  }
  return value;
}

function canonicalizeJson(obj) {
  return JSON.stringify(normalizeForCanonicalJson(obj));
}

function omitFields(obj, fields = ['signature']) {
  if (!isPlainObject(obj)) throw new TypeError('omitFields expects a plain object');
  const out = {};
  for (const key of Object.keys(obj)) {
    if (!fields.includes(key)) out[key] = obj[key];
  }
  return out;
}

function canonicalizeWithoutFields(obj, fields = ['signature']) {
  return canonicalizeJson(omitFields(obj, fields));
}

function sha256Hex(input) {
  const data = Buffer.isBuffer(input) ? input : Buffer.from(String(input ?? ''), 'utf8');
  return crypto.createHash('sha256').update(data).digest('hex');
}

function sha256CanonicalHex(obj) {
  return sha256Hex(canonicalizeJson(obj));
}

function sha256CanonicalWithoutFieldsHex(obj, fields = ['signature']) {
  return sha256Hex(canonicalizeWithoutFields(obj, fields));
}

module.exports = {
  isPlainObject,
  normalizeForCanonicalJson,
  canonicalizeJson,
  canonicalizeWithoutFields,
  sha256Hex,
  sha256CanonicalHex,
  sha256CanonicalWithoutFieldsHex
};
