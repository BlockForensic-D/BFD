"use strict";
const fs = require("node:fs"),
  fsp = fs.promises,
  crypto = require("node:crypto");
const C = require("../shared/canonical.cjs"),
  K = require("../shared/crypto.cjs"),
  { POLICY: P } = require("../shared/policy.cjs");
const { immutableJson } = require("./files.cjs");
function metadata(session, anchor) {
  K.params(anchor.params);
  C.scope(session.requestedScope, anchor.params.m);
  if (
    session.evidenceId !== anchor.preserve.evidenceId ||
    session.commitRef !== anchor.commitRef ||
    session.acquisitionReceiptDigest !== anchor.acquisitionReceiptDigest
  )
    C.fail("BUNDLE_ANCHOR");
  const p = anchor.params;
  return {
    schemaVersion: 1,
    context: anchor.preserve.context,
    sessionId: session.sessionId,
    capHash: session.capHash,
    evidenceId: session.evidenceId,
    commitRef: session.commitRef,
    acquisitionReceiptDigest: session.acquisitionReceiptDigest,
    granteePrincipal: session.granteePrincipal,
    scopeDigest: session.scopeDigest,
    mode: session.requestedScope.mode,
    h_E: p.h_E,
    R: p.R,
    totalBytes: p.totalBytes,
    z: p.z,
    m: p.m,
    commitmentVersion: p.commitmentVersion,
  };
}
function* indices(scope, m) {
  if (scope.mode === "FULL") {
    for (let i = 0; i < m; i++) yield i;
  } else if (scope.mode === "CHUNK_SET") yield* scope.indices;
}
function checkChunk(c, index, meta) {
  C.fields(c, ["index", "actualLength", "dataB64", "saltHex", "proof"]);
  C.integer(c.index);
  C.integer(c.actualLength, 1, meta.z);
  C.hex(c.saltHex);
  const bytes = C.base64(c.dataB64),
    len =
      index === meta.m - 1 ? meta.totalBytes - meta.z * (meta.m - 1) : meta.z;
  if (c.index !== index || c.actualLength !== len || bytes.length !== len)
    C.fail("BUNDLE_CHUNK_BINDING");
  const h = K.leaf(bytes, meta.evidenceId, index, c.saltHex);
  if (!K.verifyProof(h, index, meta.m, c.proof, meta.R))
    C.fail("BUNDLE_POSITIONAL_PROOF");
  return bytes;
}
async function* generatedChunks(file, session, anchor, index, kSalt, gate) {
  const meta = metadata(session, anchor);
  if (meta.mode === "HASH_ONLY") return;
  if (
    !index ||
    !C.equal(index.params, anchor.params) ||
    index.evidenceId !== meta.evidenceId ||
    index.levels[0].length !== meta.m
  )
    C.fail("CACHE_ANCHOR");
  const fd =
      typeof file?.openRead === "function"
        ? await file.openRead()
        : await fsp.open(file, "r"),
    fullHash = meta.mode === "FULL" ? crypto.createHash("sha256") : null;
  try {
    const before = await fd.stat();
    if (!before.isFile() || before.size !== meta.totalBytes)
      C.fail("SNAPSHOT_SIZE");
    for (const i of indices(session.requestedScope, meta.m)) {
      if (gate) await gate();
      const len = Math.min(meta.z, meta.totalBytes - i * meta.z),
        data = Buffer.alloc(len);
      let n = 0;
      while (n < len) {
        const r = await fd.read(data, n, len - n, i * meta.z + n);
        if (!r.bytesRead) C.fail("SNAPSHOT_TRUNCATED");
        n += r.bytesRead;
      }
      const item = {
        index: i,
        actualLength: len,
        dataB64: data.toString("base64"),
        saltHex: K.opening(kSalt, meta.evidenceId, i, len),
        proof: K.proof(index.levels, i),
      };
      checkChunk(item, i, meta);
      if (fullHash) fullHash.update(data);
      // A file read or proof calculation may cross expiry after the first gate.
      if (gate) await gate();
      yield item;
    }
    const after = await fd.stat();
    if (
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ino !== after.ino
    )
      C.fail("SNAPSHOT_CHANGED");
    if (fullHash && fullHash.digest("hex") !== meta.h_E)
      C.fail("FULL_FILE_HASH");
  } finally {
    await fd.close();
  }
}
async function* corePieces(meta, chunks) {
  const keys = [...Object.keys(meta), "chunks"].sort();
  yield Buffer.from("{");
  for (let k = 0; k < keys.length; k++) {
    const key = keys[k];
    yield Buffer.from((k ? "," : "") + JSON.stringify(key) + ":");
    if (key === "chunks") {
      yield Buffer.from("[");
      let first = true;
      for await (const c of chunks) {
        yield Buffer.from((first ? "" : ",") + C.canonical(c));
        first = false;
      }
      yield Buffer.from("]");
    } else yield Buffer.from(C.canonical(meta[key]));
  }
  yield Buffer.from("}");
}
async function hashPieces(pieces) {
  const h = crypto.createHash("sha256").update(C.domain("BundleCoreV1"));
  let bytes = 0;
  for await (const b of pieces) {
    h.update(b);
    bytes += b.length;
  }
  return { bundleHash: h.digest("hex"), serializedBytes: bytes };
}
function bundleStream(file, session, anchor, index, kSalt, gate) {
  return corePieces(
    metadata(session, anchor),
    generatedChunks(file, session, anchor, index, kSalt, gate),
  );
}
async function prepareBundle({
  file,
  session,
  anchor,
  index,
  kSalt,
  manifestPath,
}) {
  if (session.status !== "OPEN" && session.status !== "FINALIZED")
    C.fail("SESSION_STATE");
  const result = await hashPieces(
    bundleStream(file, session, anchor, index, kSalt),
  );
  if (
    session.status === "FINALIZED" &&
    result.bundleHash !== session.bundleHash
  )
    C.fail("FINALIZED_DIGEST_MISMATCH");
  const manifest = {
    schemaVersion: 1,
    sessionId: session.sessionId,
    commitRef: session.commitRef,
    scopeDigest: session.scopeDigest,
    snapshotDigest: anchor.params.h_E,
    generatorVersion: "BFD_CORE_STREAM_1",
    keyDerivationVersion: P.commitmentVersion,
    ...result,
  };
  if (manifestPath) await immutableJson(manifestPath, manifest);
  return manifest;
}
function verifyAuthority({
  session,
  anchor,
  receipt,
  capability,
  issuerKey,
  granteePrincipal,
}) {
  const meta = metadata(session, anchor),
    cap = capability.core;
  if (
    !K.verify(
      "CapabilityCoreV1",
      cap,
      capability.signature,
      issuerKey.publicKey,
    ) ||
    !C.equal(capability.signerKeyRef, cap.issuerKeyRef) ||
    !C.equal(issuerKey.keyRef, cap.issuerKeyRef)
  )
    C.fail("CAPABILITY_SIGNATURE");
  if (
    C.hash("CapabilityCoreV1", cap) !== session.capHash ||
    !C.equal(cap.granteePrincipal, granteePrincipal) ||
    !C.equal(session.granteePrincipal, granteePrincipal) ||
    cap.evidenceId !== session.evidenceId ||
    cap.commitRef !== session.commitRef ||
    cap.acquisitionReceiptDigest !== session.acquisitionReceiptDigest ||
    cap.epoch !== session.epoch ||
    cap.policyVersion !== session.policyVersion ||
    cap.usageMode !== "SINGLE_USE" ||
    !C.equal(cap.context, meta.context)
  )
    C.fail("CAPABILITY_SESSION_BINDING");
  if (
    !C.subset(session.requestedScope, cap.capabilityScope, meta.m) ||
    C.hash("ScopeV1", session.requestedScope) !== session.scopeDigest
  )
    C.fail("RECIPIENT_SCOPE");
  if (
    session.status !== "FINALIZED" ||
    receipt.sessionId !== session.sessionId ||
    receipt.bundleHash !== session.bundleHash ||
    receipt.scopeDigest !== session.scopeDigest ||
    receipt.commitRef !== session.commitRef ||
    receipt.acquisitionReceiptDigest !== session.acquisitionReceiptDigest ||
    receipt.finalizedTxRef !== session.finalizedTxRef ||
    receipt.epoch !== session.epoch ||
    receipt.policyVersion !== session.policyVersion ||
    !C.equal(receipt.finalizerPrincipal, session.finalizerPrincipal) ||
    !C.equal(receipt.context, meta.context) ||
    receipt.assurance !== "FINALIZE_AUTHORIZATION_ONLY"
  )
    C.fail("FINAL_RECEIPT_BINDING");
  return meta;
}
function verifyObject(core, args) {
  const meta = verifyAuthority(args);
  C.fields(core, [...Object.keys(meta), "chunks"]);
  for (const [k, v] of Object.entries(meta))
    if (!C.equal(core[k], v)) C.fail("BUNDLE_METADATA:" + k);
  if (!Array.isArray(core.chunks)) C.fail("BUNDLE_CHUNKS");
  const wanted = [...indices(args.session.requestedScope, meta.m)];
  if (core.chunks.length !== wanted.length) C.fail("BUNDLE_SCOPE_COUNT");
  const full = meta.mode === "FULL" ? crypto.createHash("sha256") : null;
  for (let n = 0; n < wanted.length; n++) {
    const b = checkChunk(core.chunks[n], wanted[n], meta);
    if (full) full.update(b);
  }
  if (full && full.digest("hex") !== meta.h_E) C.fail("FULL_FILE_HASH");
  if (C.hash("BundleCoreV1", core) !== args.receipt.bundleHash)
    C.fail("BUNDLE_DIGEST");
  return {
    contentIntegrity: meta.mode === "HASH_ONLY" ? "NOT_CHECKED" : "PASS",
    historicallyAuthorized: true,
    currentlyEligible: "SEPARATE_CHECK_REQUIRED",
    deliveryAcknowledged: false,
  };
}
class CoreReader {
  constructor(file) {
    this.stream = fs.createReadStream(file, { highWaterMark: 65536 });
    this.iterator = this.stream[Symbol.asyncIterator]();
    this.buffer = Buffer.alloc(0);
    this.offset = 0;
    this.done = false;
    this.hash = crypto.createHash("sha256").update(C.domain("BundleCoreV1"));
  }
  async ensure() {
    if (this.offset < this.buffer.length) return true;
    if (this.done) return false;
    const r = await this.iterator.next();
    if (r.done) {
      this.done = true;
      return false;
    }
    this.buffer = r.value;
    this.offset = 0;
    this.hash.update(r.value);
    return true;
  }
  async expect(value) {
    const want = Buffer.from(value);
    let n = 0;
    while (n < want.length) {
      if (!(await this.ensure())) C.fail("BUNDLE_TRUNCATED");
      const k = Math.min(want.length - n, this.buffer.length - this.offset);
      if (
        !this.buffer
          .subarray(this.offset, this.offset + k)
          .equals(want.subarray(n, n + k))
      )
        C.fail("NONCANONICAL_CORE_OR_METADATA");
      this.offset += k;
      n += k;
    }
  }
  async object(maxBytes) {
    let depth = 0,
      string = false,
      escape = false,
      total = 0;
    const parts = [];
    let first = true;
    while (await this.ensure()) {
      const start = this.offset;
      while (this.offset < this.buffer.length) {
        const b = this.buffer[this.offset++];
        total++;
        if (total > maxBytes) C.fail("CHUNK_RECORD_SIZE");
        if (first) {
          first = false;
          if (b !== 123) C.fail("CHUNK_OBJECT_REQUIRED");
        }
        if (string) {
          if (escape) escape = false;
          else if (b === 92) escape = true;
          else if (b === 34) string = false;
        } else if (b === 34) string = true;
        else if (b === 123 || b === 91) depth++;
        else if (b === 125 || b === 93) depth--;
        if (depth === 0 && !string) {
          parts.push(this.buffer.subarray(start, this.offset));
          const bytes = Buffer.concat(parts),
            raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes),
            obj = C.parseStrict(raw, maxBytes);
          if (C.canonical(obj) !== raw) C.fail("NONCANONICAL_CHUNK");
          return obj;
        }
        if (depth < 0) C.fail("CHUNK_JSON");
      }
      parts.push(this.buffer.subarray(start, this.offset));
    }
    C.fail("BUNDLE_TRUNCATED");
  }
  async finish() {
    if (await this.ensure()) C.fail("TRAILING_BUNDLE_DATA");
    return this.hash.digest("hex");
  }
  close() {
    this.stream.destroy();
  }
}
async function verifyFile(file, args) {
  const meta = verifyAuthority(args),
    r = new CoreReader(file),
    keys = [...Object.keys(meta), "chunks"].sort(),
    full = meta.mode === "FULL" ? crypto.createHash("sha256") : null;
  try {
    await r.expect("{");
    for (let k = 0; k < keys.length; k++) {
      const key = keys[k];
      await r.expect((k ? "," : "") + JSON.stringify(key) + ":");
      if (key === "chunks") {
        await r.expect("[");
        let first = true;
        for (const i of indices(args.session.requestedScope, meta.m)) {
          if (!first) await r.expect(",");
          const c = await r.object(Math.ceil((meta.z * 4) / 3) + 32768),
            b = checkChunk(c, i, meta);
          if (full) full.update(b);
          first = false;
        }
        await r.expect("]");
      } else await r.expect(C.canonical(meta[key]));
    }
    await r.expect("}");
    const hash = await r.finish();
    if (hash !== args.receipt.bundleHash) C.fail("BUNDLE_DIGEST");
    if (full && full.digest("hex") !== meta.h_E) C.fail("FULL_FILE_HASH");
    return {
      contentIntegrity: meta.mode === "HASH_ONLY" ? "NOT_CHECKED" : "PASS",
      historicallyAuthorized: true,
      currentlyEligible: "SEPARATE_CHECK_REQUIRED",
      deliveryAcknowledged: false,
    };
  } finally {
    r.close();
  }
}
module.exports = {
  metadata,
  indices,
  checkChunk,
  generatedChunks,
  corePieces,
  hashPieces,
  bundleStream,
  prepareBundle,
  verifyAuthority,
  verifyObject,
  verifyFile,
};
