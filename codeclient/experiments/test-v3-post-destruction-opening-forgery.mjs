import crypto from 'crypto';

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

function sha256Hex(buf) {
  return sha256(buf).toString('hex');
}

function hmac(key, msg) {
  return crypto.createHmac('sha256', key).update(msg).digest();
}

function u32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

function lenPrefixedUtf8(s) {
  const b = Buffer.from(String(s), 'utf8');
  return Buffer.concat([u32be(b.length), b]);
}

function leafV3({ evidenceId, index, actualLength, salt, chunk }) {
  const chunkDigest = sha256(Buffer.concat([
    Buffer.from('FDEM-CHUNK-v3', 'utf8'),
    u32be(actualLength),
    chunk
  ]));

  return sha256Hex(Buffer.concat([
    Buffer.from('FDEM-LEAF-v3', 'utf8'),
    lenPrefixedUtf8(evidenceId),
    u32be(index),
    u32be(actualLength),
    salt,
    chunkDigest
  ]));
}

function deriveSalt(kSalt, evidenceId, index, actualLength) {
  return hmac(kSalt, Buffer.concat([
    Buffer.from('FDEM-SALT-v3', 'utf8'),
    lenPrefixedUtf8(evidenceId),
    u32be(index),
    u32be(actualLength)
  ]));
}

const attempts = Number(process.argv[2] || 10000);

const evidenceId = 'ev-forgery-test';
const index = 7;
const chunk = Buffer.from('function_code=03\nregister=40001\nvalue=normal\n', 'utf8');
const actualLength = chunk.length;

const kSalt = crypto.randomBytes(32);
const realSalt = deriveSalt(kSalt, evidenceId, index, actualLength);
const committedLeaf = leafV3({ evidenceId, index, actualLength, salt: realSalt, chunk });

let forged = false;

for (let i = 0; i < attempts; i++) {
  const guessedSalt = crypto.randomBytes(32);
  const guessedLeaf = leafV3({ evidenceId, index, actualLength, salt: guessedSalt, chunk });
  if (guessedLeaf === committedLeaf) {
    forged = true;
    break;
  }
}

const positiveControl = leafV3({ evidenceId, index, actualLength, salt: realSalt, chunk }) === committedLeaf;

const result = {
  test: 'post-destruction-adversarial-opening-forgery-without-ksalt',
  attempts,
  forgedOpeningFound: forged,
  positiveControlWithRealOpening: positiveControl,
  expected: {
    forgedOpeningFound: false,
    positiveControlWithRealOpening: true
  },
  pass: forged === false && positiveControl === true
};

console.log(JSON.stringify(result, null, 2));

if (!result.pass) process.exit(1);
