"use strict";
const fs = require("node:fs"),
  fsp = fs.promises,
  path = require("node:path"),
  crypto = require("node:crypto");
const C = require("../shared/canonical.cjs"),
  K = require("../shared/crypto.cjs"),
  { POLICY: P } = require("../shared/policy.cjs");
async function* chunks(file, z) {
  C.integer(z, 1, P.maxChunkSize);
  const fd =
    typeof file?.openRead === "function"
      ? await file.openRead()
      : await fsp.open(file, "r");
  try {
    const before = await fd.stat();
    if (!before.isFile()) C.fail("SNAPSHOT_NOT_FILE");
    let offset = 0,
      index = 0;
    while (offset < before.size) {
      const size = Math.min(z, before.size - offset),
        data = Buffer.alloc(size);
      let n = 0;
      while (n < size) {
        const r = await fd.read(data, n, size - n, offset + n);
        if (!r.bytesRead) C.fail("SNAPSHOT_TRUNCATED");
        n += r.bytesRead;
      }
      yield { index: index++, actualLength: data.length, data };
      offset += size;
    }
    const after = await fd.stat();
    if (
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ino !== after.ino
    )
      C.fail("SNAPSHOT_CHANGED");
  } finally {
    await fd.close();
  }
}
async function syncDirectory(dir) {
  const d = await fsp.open(dir, "r");
  try {
    await d.sync();
  } finally {
    await d.close();
  }
}
async function immutableJson(file, obj) {
  const bytes = C.canonical(obj);
  await fsp.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  try {
    const previous = await fsp.readFile(file, "utf8");
    if (previous !== bytes) C.fail("DURABLE_RECORD_CONFLICT");
    return obj;
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  const temp = file + ".tmp-" + crypto.randomBytes(8).toString("hex");
  const fd = await fsp.open(temp, "wx", 0o600);
  try {
    await fd.writeFile(bytes);
    await fd.sync();
  } finally {
    await fd.close();
  }
  try {
    await fsp.link(temp, file);
  } catch (e) {
    if (e.code !== "EEXIST") throw e;
    if ((await fsp.readFile(file, "utf8")) !== bytes)
      C.fail("DURABLE_RECORD_CONFLICT");
  } finally {
    await fsp.unlink(temp);
  }
  await syncDirectory(path.dirname(file));
  return obj;
}
async function snapshot(source, destination) {
  await fsp.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  const out = await fsp.open(destination, "wx", 0o600),
    hash = crypto.createHash("sha256");
  let totalBytes = 0,
    success = false;
  try {
    for await (const chunk of chunks(source, 65536)) {
      hash.update(chunk.data);
      await out.writeFile(chunk.data);
      totalBytes += chunk.actualLength;
    }
    await out.sync();
    success = true;
  } finally {
    await out.close();
    if (!success) await fsp.unlink(destination);
  }
  await fsp.chmod(destination, 0o400);
  await syncDirectory(path.dirname(destination));
  return { h_E: hash.digest("hex"), totalBytes };
}
async function buildCommitment(file, evidenceId, z, emk) {
  C.id(evidenceId);
  C.integer(z, 1, P.maxChunkSize);
  const keys = K.derive(emk, evidenceId),
    leaves = [],
    hash = crypto.createHash("sha256");
  let totalBytes = 0;
  try {
    for await (const c of chunks(file, z)) {
      hash.update(c.data);
      totalBytes += c.actualLength;
      leaves.push(
        K.leaf(
          c.data,
          evidenceId,
          c.index,
          K.opening(keys.kSalt, evidenceId, c.index, c.actualLength),
        ),
      );
    }
    if (!totalBytes) C.fail("EMPTY_COMMITMENT");
    const tree = K.tree(leaves);
    return {
      schemaVersion: 1,
      evidenceId,
      params: {
        h_E: hash.digest("hex"),
        R: tree.root,
        totalBytes,
        z,
        m: leaves.length,
        commitmentVersion: P.commitmentVersion,
        oddNodeRule: P.oddNodeRule,
      },
      levels: tree.levels,
    };
  } finally {
    keys.dek.fill(0);
    keys.kSalt.fill(0);
    keys.kMeta.fill(0);
  }
}
async function* acquisitionOpenings(file, evidenceId, z, kSalt) {
  for await (const c of chunks(file, z))
    yield {
      ...c,
      saltHex: K.opening(kSalt, evidenceId, c.index, c.actualLength),
    };
}
async function auditAcquisition(
  anchor,
  params,
  stream,
  assignment,
  auditorKey,
  auditJobId,
) {
  K.params(params);
  const p = anchor.preserve;
  if (
    anchor.preserveDigest !== C.hash("PreserveCoreV1", p) ||
    params.h_E !== p.h_E ||
    params.totalBytes !== p.totalBytes
  )
    C.fail("AUDIT_PRESERVE_BINDING");
  if (
    assignment.evidenceId !== p.evidenceId ||
    assignment.preserveDigest !== anchor.preserveDigest ||
    !C.equal(assignment.auditorKeyRef, auditorKey.keyRef)
  )
    C.fail("AUDIT_ASSIGNMENT_BINDING");
  const hash = crypto.createHash("sha256"),
    acc = new K.Accumulator();
  let count = 0,
    totalBytes = 0;
  for await (const c of stream) {
    C.fields(c, ["index", "actualLength", "data", "saltHex"]);
    C.integer(c.index);
    C.integer(c.actualLength, 1, params.z);
    C.hex(c.saltHex);
    const expectedLength =
      count === params.m - 1
        ? params.totalBytes - params.z * (params.m - 1)
        : params.z;
    if (
      count >= params.m ||
      c.index !== count ||
      !Buffer.isBuffer(c.data) ||
      c.data.length !== c.actualLength ||
      c.actualLength !== expectedLength
    )
      C.fail("AUDIT_CHUNK_SEQUENCE");
    hash.update(c.data);
    totalBytes += c.actualLength;
    acc.add(K.leaf(c.data, p.evidenceId, count, c.saltHex));
    count++;
  }
  if (
    count !== params.m ||
    totalBytes !== params.totalBytes ||
    hash.digest("hex") !== params.h_E ||
    acc.root() !== params.R
  )
    C.fail("AUDIT_CONTENT_MISMATCH");
  const core = {
    schemaVersion: 1,
    context: p.context,
    evidenceId: p.evidenceId,
    preserveDigest: anchor.preserveDigest,
    assignmentId: assignment.assignmentId,
    auditJobId,
    auditorPrincipal: assignment.auditorPrincipal,
    auditorKeyRef: assignment.auditorKeyRef,
    ...params,
    validationMethodVersion: P.validationMethodVersion,
    outcome: "PASS",
  };
  return {
    core,
    signerKeyRef: auditorKey.keyRef,
    signature: K.sign("AcquisitionReceiptV1", core, auditorKey.privateKey),
  };
}
module.exports = {
  chunks,
  immutableJson,
  snapshot,
  buildCommitment,
  acquisitionOpenings,
  auditAcquisition,
  syncDirectory,
};
