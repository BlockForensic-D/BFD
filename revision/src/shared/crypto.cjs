"use strict";
const crypto = require("node:crypto");
const C = require("./canonical.cjs");
const { POLICY } = require("./policy.cjs");
function publicKey(s) {
  const der = C.base64(s);
  let key;
  try {
    key = crypto.createPublicKey({ key: der, type: "spki", format: "der" });
  } catch {
    C.fail("INVALID_PUBLIC_KEY");
  }
  if (
    key.asymmetricKeyType !== "ed25519" ||
    !key.export({ type: "spki", format: "der" }).equals(der)
  )
    C.fail("INVALID_ED25519_KEY");
  return key;
}
function fingerprint(s) {
  publicKey(s);
  return C.digest(C.base64(s));
}
function sign(kind, core, privateKey) {
  return crypto.sign(null, C.encode(kind, core), privateKey).toString("base64");
}
function verify(kind, core, signature, key) {
  try {
    return crypto.verify(
      null,
      C.encode(kind, core),
      publicKey(key),
      C.base64(signature, 64),
    );
  } catch {
    return false;
  }
}
function u32(n) {
  C.integer(n, 0, 0xffffffff);
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
}
function u64(n) {
  C.integer(n);
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}
function lp(s) {
  C.text(s);
  const b = Buffer.from(s);
  return Buffer.concat([u32(b.length), b]);
}
function evidenceContext(e, i, len) {
  return Buffer.concat([lp(C.id(e)), u64(i), u32(len)]);
}
function derive(emk, e) {
  if (!Buffer.isBuffer(emk) || emk.length !== 32) C.fail("EMK_LENGTH");
  C.id(e);
  const salt = Buffer.concat([Buffer.from("FDEM-HKDF-SALT-v3"), lp(e)]);
  const key = (label) =>
    Buffer.from(
      crypto.hkdfSync(
        "sha256",
        emk,
        salt,
        Buffer.concat([Buffer.from(label), lp(e)]),
        32,
      ),
    );
  return {
    dek: key("FDEM-DEK-v3"),
    kSalt: key("FDEM-KSALT-v3"),
    kMeta: key("FDEM-META-v3"),
  };
}
function opening(kSalt, e, i, len) {
  if (!Buffer.isBuffer(kSalt) || kSalt.length !== 32) C.fail("KSALT_LENGTH");
  return crypto
    .createHmac("sha256", kSalt)
    .update(
      Buffer.concat([Buffer.from("FDEM-SALT-v3"), evidenceContext(e, i, len)]),
    )
    .digest("hex");
}
function leaf(bytes, e, i, rho) {
  if (!Buffer.isBuffer(bytes)) C.fail("CHUNK_BYTES");
  C.hex(rho);
  const chunkDigest = C.digest(
    Buffer.concat([Buffer.from("FDEM-CHUNK-v3"), u32(bytes.length), bytes]),
  );
  return C.digest(
    Buffer.concat([
      Buffer.from("FDEM-LEAF-v3"),
      evidenceContext(e, i, bytes.length),
      Buffer.from(rho, "hex"),
      Buffer.from(chunkDigest, "hex"),
    ]),
  );
}
function parent(a, b) {
  return C.digest(
    Buffer.concat([
      Buffer.from("FDEM-NODE-v3"),
      Buffer.from(C.hex(a), "hex"),
      Buffer.from(C.hex(b), "hex"),
    ]),
  );
}
function tree(leaves) {
  if (!Array.isArray(leaves) || !leaves.length) C.fail("EMPTY_TREE");
  const levels = [leaves.map(C.hex)];
  while (levels.at(-1).length > 1) {
    const old = levels.at(-1),
      next = [];
    for (let i = 0; i < old.length; i += 2)
      next.push(parent(old[i], old[i + 1] || old[i]));
    levels.push(next);
  }
  return { levels, root: levels.at(-1)[0] };
}
function proof(levels, index) {
  C.integer(index, 0, levels[0].length - 1);
  const out = [];
  for (let l = 0; l < levels.length - 1; l++) {
    const row = levels[l],
      other = index % 2 ? index - 1 : index + 1;
    out.push({
      position: index % 2 ? "left" : "right",
      data: row[other] || row[index],
    });
    index = Math.floor(index / 2);
  }
  return out;
}
function verifyProof(hash, index, m, path, root) {
  try {
    C.hex(hash);
    C.hex(root);
    C.integer(m, 1);
    C.integer(index, 0, m - 1);
    if (!Array.isArray(path)) return false;
    let level = 0;
    while (m > 1) {
      const step = path[level++];
      C.fields(step, ["position", "data"]);
      C.hex(step.data);
      if (step.position !== (index % 2 ? "left" : "right")) return false;
      if (index % 2 === 0 && index === m - 1 && step.data !== hash)
        return false;
      hash = index % 2 ? parent(step.data, hash) : parent(hash, step.data);
      index = Math.floor(index / 2);
      m = Math.ceil(m / 2);
    }
    return level === path.length && hash === root;
  } catch {
    return false;
  }
}
class Accumulator {
  constructor() {
    this.stack = [];
    this.count = 0;
  }
  add(h) {
    C.hex(h);
    let level = 0;
    while (this.stack[level]) {
      h = parent(this.stack[level], h);
      this.stack[level] = null;
      level++;
    }
    this.stack[level] = h;
    this.count++;
  }
  root() {
    if (!this.count) C.fail("EMPTY_TREE");
    let h = null,
      height = 0;
    for (let l = 0; l < this.stack.length; l++) {
      if (!this.stack[l]) continue;
      if (h === null) {
        h = this.stack[l];
        height = l;
        continue;
      }
      while (height < l) {
        h = parent(h, h);
        height++;
      }
      h = parent(this.stack[l], h);
      height = l + 1;
    }
    return h;
  }
}
function params(p) {
  C.fields(p, [
    "h_E",
    "R",
    "totalBytes",
    "z",
    "m",
    "commitmentVersion",
    "oddNodeRule",
  ]);
  C.hex(p.h_E);
  C.hex(p.R);
  C.integer(p.totalBytes, 1);
  C.integer(p.z, 1, POLICY.maxChunkSize);
  C.integer(p.m, 1);
  if (
    p.m !== Math.ceil(p.totalBytes / p.z) ||
    p.commitmentVersion !== POLICY.commitmentVersion ||
    p.oddNodeRule !== POLICY.oddNodeRule
  )
    C.fail("COMMITMENT_PARAMS");
  return p;
}
module.exports = {
  publicKey,
  fingerprint,
  sign,
  verify,
  derive,
  opening,
  leaf,
  parent,
  tree,
  proof,
  verifyProof,
  Accumulator,
  params,
};
