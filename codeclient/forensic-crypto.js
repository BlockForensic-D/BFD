'use strict';

import crypto from 'node:crypto';

/**
 * Returns true if the value is a plain object.
 *
 * @param {*} value
 * @returns {boolean}
 */
function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    !Buffer.isBuffer(value) &&
    !(value instanceof Date)
  );
}

/**
 * Recursively normalizes values for stable JSON canonicalization:
 * - object keys are sorted lexicographically
 * - arrays preserve order
 * - Date objects are converted to ISO strings
 * - undefined object properties are omitted
 *
 * @param {*} value
 * @returns {*}
 */
function normalizeForCanonicalJson(value) {
  if (Array.isArray(value)) {
    return value.map(normalizeForCanonicalJson);
  }

  if (value instanceof Date) {
    return value.toISOString();
  }

  if (isPlainObject(value)) {
    const out = {};
    const keys = Object.keys(value).sort();

    for (const key of keys) {
      const v = value[key];
      if (typeof v !== 'undefined') {
        out[key] = normalizeForCanonicalJson(v);
      }
    }

    return out;
  }

  return value;
}

/**
 * Produces a stable canonical JSON string.
 *
 * @param {*} obj
 * @returns {string}
 */
function canonicalizeJson(obj) {
  return JSON.stringify(normalizeForCanonicalJson(obj));
}

/**
 * Returns a shallow clone of an object without selected top-level fields.
 *
 * @param {Object} obj
 * @param {string[]} fields
 * @returns {Object}
 */
function omitFields(obj, fields) {
  if (!isPlainObject(obj)) {
    throw new TypeError('omitFields expects a plain object');
  }

  if (!Array.isArray(fields)) {
    throw new TypeError('fields must be an array of strings');
  }

  const out = {};
  for (const key of Object.keys(obj)) {
    if (!fields.includes(key)) {
      out[key] = obj[key];
    }
  }
  return out;
}

/**
 * Canonicalizes an object after omitting selected top-level fields.
 *
 * @param {Object} obj
 * @param {string[]} [fields=['signature']]
 * @returns {string}
 */
function canonicalizeWithoutFields(obj, fields = ['signature']) {
  return canonicalizeJson(omitFields(obj, fields));
}

/**
 * Converts input to Buffer.
 *
 * Supported:
 * - Buffer
 * - Uint8Array
 * - ArrayBuffer
 * - typed array / DataView
 * - Buffer JSON object: { type: 'Buffer', data: [...] }
 * - string
 *
 * @param {Buffer|string|Uint8Array|ArrayBuffer|Object} input
 * @param {BufferEncoding} [encoding='utf8']
 * @returns {Buffer}
 */
function toBuffer(input, encoding = 'utf8') {
  if (Buffer.isBuffer(input)) {
    return Buffer.from(input);
  }

  if (input instanceof Uint8Array) {
    return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  }

  if (typeof ArrayBuffer !== 'undefined' && input instanceof ArrayBuffer) {
    return Buffer.from(new Uint8Array(input));
  }

  if (
    typeof ArrayBuffer !== 'undefined' &&
    ArrayBuffer.isView(input) &&
    input?.buffer instanceof ArrayBuffer
  ) {
    return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  }

  if (
    input &&
    typeof input === 'object' &&
    input.type === 'Buffer' &&
    Array.isArray(input.data)
  ) {
    for (const b of input.data) {
      if (!Number.isInteger(b) || b < 0 || b > 255) {
        throw new TypeError('Buffer JSON object contains invalid byte values');
      }
    }
    return Buffer.from(input.data);
  }

  if (typeof input === 'string') {
    return Buffer.from(input, encoding);
  }

  throw new TypeError(
    'Expected Buffer, Uint8Array, ArrayBuffer, typed-array view, Buffer JSON object, or string'
  );
}

/**
 * SHA-256 digest as lowercase hex string.
 *
 * @param {Buffer|string|Uint8Array|ArrayBuffer|Object} input
 * @param {BufferEncoding} [encoding='utf8']
 * @returns {string}
 */
function sha256Hex(input, encoding = 'utf8') {
  return crypto.createHash('sha256').update(toBuffer(input, encoding)).digest('hex');
}

/**
 * SHA-256 digest as raw bytes.
 *
 * @param {Buffer|string|Uint8Array|ArrayBuffer|Object} input
 * @param {BufferEncoding} [encoding='utf8']
 * @returns {Buffer}
 */
function sha256Bytes(input, encoding = 'utf8') {
  return crypto.createHash('sha256').update(toBuffer(input, encoding)).digest();
}

/**
 * Validates a SHA-256 hex string.
 *
 * @param {string} hex
 * @returns {boolean}
 */
function isSha256Hex(hex) {
  return typeof hex === 'string' && /^[a-fA-F0-9]{64}$/.test(hex);
}

/**
 * Converts a hex string to Buffer.
 *
 * @param {string} hex
 * @returns {Buffer}
 */
function hexToBytes(hex) {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToBytes expects a string');
  }

  const normalized = hex.trim();
  if (normalized.length === 0) {
    throw new TypeError('Invalid hex string');
  }
  if (normalized.length % 2 !== 0 || !/^[a-fA-F0-9]+$/.test(normalized)) {
    throw new TypeError('Invalid hex string');
  }

  return Buffer.from(normalized, 'hex');
}

/**
 * Converts bytes to lowercase hex.
 *
 * @param {Buffer|Uint8Array|ArrayBuffer|Object} bytes
 * @returns {string}
 */
function bytesToHex(bytes) {
  return toBuffer(bytes).toString('hex');
}

/**
 * Normalizes a private key.
 *
 * @param {crypto.KeyLike} privateKey
 * @returns {crypto.KeyLike}
 */
function normalizePrivateKey(privateKey) {
  if (!privateKey) {
    throw new TypeError('privateKey is required');
  }
  return privateKey;
}

/**
 * Normalizes a public key.
 *
 * @param {crypto.KeyLike} publicKey
 * @returns {crypto.KeyLike}
 */
function normalizePublicKey(publicKey) {
  if (!publicKey) {
    throw new TypeError('publicKey is required');
  }
  return publicKey;
}

/**
 * Signs message bytes using Ed25519.
 *
 * @param {Buffer|string|Uint8Array|ArrayBuffer|Object} message
 * @param {crypto.KeyLike} privateKey
 * @returns {string}
 */
function signEd25519(message, privateKey) {
  const msg = toBuffer(message);
  const key = normalizePrivateKey(privateKey);
  const signature = crypto.sign(null, msg, key);
  return signature.toString('hex');
}

/**
 * Verifies an Ed25519 signature.
 *
 * @param {Buffer|string|Uint8Array|ArrayBuffer|Object} message
 * @param {string|Buffer|Uint8Array|ArrayBuffer|Object} signature
 * @param {crypto.KeyLike} publicKey
 * @returns {boolean}
 */
function verifyEd25519(message, signature, publicKey) {
  const msg = toBuffer(message);
  const key = normalizePublicKey(publicKey);
  const sig = typeof signature === 'string' ? hexToBytes(signature) : toBuffer(signature);
  return crypto.verify(null, msg, key, sig);
}

/**
 * Computes canonical SHA-256 hash of any JSON-serializable object.
 *
 * @param {*} obj
 * @returns {string}
 */
function canonicalSha256Hex(obj) {
  return sha256Hex(canonicalizeJson(obj));
}

/**
 * Computes canonical SHA-256 hash of an object after omitting selected fields.
 *
 * @param {Object} obj
 * @param {string[]} [fields=['signature']]
 * @returns {string}
 */
function canonicalSha256HexWithoutFields(obj, fields = ['signature']) {
  return sha256Hex(canonicalizeWithoutFields(obj, fields));
}

/**
 * Signs a plain object after canonicalizing it.
 *
 * @param {Object} obj
 * @param {crypto.KeyLike} privateKey
 * @returns {string}
 */
function signCanonicalObject(obj, privateKey) {
  if (!isPlainObject(obj)) {
    throw new TypeError('signCanonicalObject expects a plain object');
  }
  const canonical = canonicalizeJson(obj);
  return signEd25519(canonical, privateKey);
}

/**
 * Verifies a signature over a canonicalized plain object.
 *
 * @param {Object} obj
 * @param {string|Buffer|Uint8Array|ArrayBuffer|Object} signature
 * @param {crypto.KeyLike} publicKey
 * @returns {boolean}
 */
function verifyCanonicalObject(obj, signature, publicKey) {
  if (!isPlainObject(obj)) {
    throw new TypeError('verifyCanonicalObject expects a plain object');
  }
  const canonical = canonicalizeJson(obj);
  return verifyEd25519(canonical, signature, publicKey);
}

/**
 * Signs a plain object after removing selected fields first.
 *
 * @param {Object} obj
 * @param {crypto.KeyLike} privateKey
 * @param {string[]} [fields=['signature']]
 * @returns {string}
 */
function signCanonicalObjectWithoutFields(obj, privateKey, fields = ['signature']) {
  if (!isPlainObject(obj)) {
    throw new TypeError('signCanonicalObjectWithoutFields expects a plain object');
  }
  const canonical = canonicalizeWithoutFields(obj, fields);
  return signEd25519(canonical, privateKey);
}

/**
 * Verifies a signature over a plain object after removing selected fields first.
 *
 * @param {Object} obj
 * @param {string|Buffer|Uint8Array|ArrayBuffer|Object} signature
 * @param {crypto.KeyLike} publicKey
 * @param {string[]} [fields=['signature']]
 * @returns {boolean}
 */
function verifyCanonicalObjectWithoutFields(obj, signature, publicKey, fields = ['signature']) {
  if (!isPlainObject(obj)) {
    throw new TypeError('verifyCanonicalObjectWithoutFields expects a plain object');
  }
  const canonical = canonicalizeWithoutFields(obj, fields);
  return verifyEd25519(canonical, signature, publicKey);
}


/**
 * Encodes an unsigned 32-bit integer in big-endian form.
 *
 * @param {number} value
 * @returns {Buffer}
 */
function uint32be(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError('uint32be value must be an unsigned 32-bit safe integer');
  }
  const out = Buffer.allocUnsafe(4);
  out.writeUInt32BE(value, 0);
  return out;
}

/**
 * Encodes an unsigned 64-bit integer in big-endian form.
 *
 * @param {number|bigint} value
 * @returns {Buffer}
 */
function uint64be(value) {
  const n = typeof value === 'bigint' ? value : BigInt(value);
  if (n < 0n || n > 0xffffffffffffffffn) {
    throw new RangeError('uint64be value must be an unsigned 64-bit integer');
  }
  const out = Buffer.allocUnsafe(8);
  out.writeBigUInt64BE(n, 0);
  return out;
}

/**
 * Canonical UTF-8 field encoding: uint32_be(length) || utf8(value).
 *
 * @param {string} value
 * @returns {Buffer}
 */
function lengthPrefixedUtf8(value) {
  if (typeof value !== 'string') {
    throw new TypeError('lengthPrefixedUtf8 expects a string');
  }
  const bytes = Buffer.from(value, 'utf8');
  return Buffer.concat([uint32be(bytes.length), bytes]);
}

/**
 * Normalizes a secret key as bytes. Hex strings of even length are decoded as hex;
 * all other strings are encoded as UTF-8 for compatibility with existing scripts.
 *
 * @param {Buffer|string|Uint8Array|ArrayBuffer|Object} key
 * @returns {Buffer}
 */
function normalizeSecretKey(key) {
  if (typeof key === 'string') {
    const trimmed = key.trim();
    if (/^[a-fA-F0-9]+$/.test(trimmed) && trimmed.length % 2 === 0) {
      return Buffer.from(trimmed, 'hex');
    }
    return Buffer.from(trimmed, 'utf8');
  }
  return toBuffer(key);
}

/**
 * HMAC-SHA-256 digest bytes.
 *
 * @param {Buffer|string|Uint8Array|ArrayBuffer|Object} key
 * @param {Buffer|string|Uint8Array|ArrayBuffer|Object} message
 * @returns {Buffer}
 */
function hmacSha256Bytes(key, message) {
  return crypto.createHmac('sha256', normalizeSecretKey(key)).update(toBuffer(message)).digest();
}

/**
 * HMAC-SHA-256 digest hex.
 *
 * @param {Buffer|string|Uint8Array|ArrayBuffer|Object} key
 * @param {Buffer|string|Uint8Array|ArrayBuffer|Object} message
 * @returns {string}
 */
function hmacSha256Hex(key, message) {
  return hmacSha256Bytes(key, message).toString('hex');
}

/**
 * HKDF-SHA-256 output bytes.
 *
 * @param {Buffer|string|Uint8Array|ArrayBuffer|Object} ikm
 * @param {Object} [options]
 * @param {Buffer|string|Uint8Array|ArrayBuffer|Object} [options.salt]
 * @param {Buffer|string|Uint8Array|ArrayBuffer|Object} [options.info]
 * @param {number} [options.length=32]
 * @returns {Buffer}
 */
function hkdfSha256Bytes(ikm, options = {}) {
  const salt = options.salt == null ? Buffer.alloc(0) : toBuffer(options.salt);
  const info = options.info == null ? Buffer.alloc(0) : toBuffer(options.info);
  const length = options.length ?? 32;
  if (!Number.isSafeInteger(length) || length <= 0) {
    throw new RangeError('HKDF output length must be a positive safe integer');
  }
  return Buffer.from(crypto.hkdfSync('sha256', normalizeSecretKey(ikm), salt, info, length));
}

/**
 * HKDF-SHA-256 output hex.
 *
 * @param {Buffer|string|Uint8Array|ArrayBuffer|Object} ikm
 * @param {Object} [options]
 * @returns {string}
 */
function hkdfSha256Hex(ikm, options = {}) {
  return hkdfSha256Bytes(ikm, options).toString('hex');
}

/**
 * Constant-time comparison for equal-length hex strings.
 *
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  const aa = a.trim().toLowerCase();
  const bb = b.trim().toLowerCase();

  if (aa.length !== bb.length) {
    return false;
  }

  try {
    const ba = hexToBytes(aa);
    const bbuf = hexToBytes(bb);

    if (ba.length !== bbuf.length) {
      return false;
    }

    return crypto.timingSafeEqual(ba, bbuf);
  } catch {
    return false;
  }
}

export {
  isPlainObject,
  normalizeForCanonicalJson,
  canonicalizeJson,
  omitFields,
  canonicalizeWithoutFields,
  toBuffer,
  sha256Hex,
  sha256Bytes,
  isSha256Hex,
  hexToBytes,
  bytesToHex,
  uint32be,
  uint64be,
  lengthPrefixedUtf8,
  normalizeSecretKey,
  hmacSha256Bytes,
  hmacSha256Hex,
  hkdfSha256Bytes,
  hkdfSha256Hex,
  signEd25519,
  verifyEd25519,
  canonicalSha256Hex,
  canonicalSha256HexWithoutFields,
  signCanonicalObject,
  verifyCanonicalObject,
  signCanonicalObjectWithoutFields,
  verifyCanonicalObjectWithoutFields,
  safeEqualHex
};