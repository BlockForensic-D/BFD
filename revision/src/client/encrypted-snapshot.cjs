"use strict";
// Optional local encrypted research snapshot. Each chunk has independent AES-256-GCM.
// This does not replace an organization's key manager or sanitize the source file.
const fs = require("node:fs"),
  fsp = fs.promises,
  crypto = require("node:crypto");
const C = require("../shared/canonical.cjs"),
  K = require("../shared/crypto.cjs"),
  { POLICY: P } = require("../shared/policy.cjs");
const HEADER = 64,
  MAGIC = Buffer.from("BFDSNAP1");
function nonce(prefix, i) {
  const n = Buffer.alloc(12);
  prefix.copy(n);
  n.writeUInt32BE(i, 8);
  return n;
}
function aad(evidenceId, header, i, len) {
  return Buffer.concat([
    C.encode("EncryptedChunkV1", { evidenceId, index: i, actualLength: len }),
    header,
  ]);
}
async function exact(fd, n, pos) {
  const b = Buffer.alloc(n);
  let read = 0;
  while (read < n) {
    const r = await fd.read(b, read, n - read, pos + read);
    if (!r.bytesRead) C.fail("ENCRYPTED_SNAPSHOT_TRUNCATED");
    read += r.bytesRead;
  }
  return b;
}
async function encryptSnapshot(
  source,
  destination,
  { evidenceId, params, dek },
) {
  K.params(params);
  C.id(evidenceId);
  if (!Buffer.isBuffer(dek) || dek.length !== 32) C.fail("DEK_LENGTH");
  if (params.m > 0xffffffff) C.fail("ENCRYPTED_CHUNK_NONCE_LIMIT");
  const header = Buffer.alloc(HEADER);
  MAGIC.copy(header);
  crypto.randomBytes(8).copy(header, 8);
  header.writeUInt32BE(params.z, 16);
  header.writeBigUInt64BE(BigInt(params.totalBytes), 20);
  Buffer.from(params.h_E, "hex").copy(header, 28);
  const input = await fsp.open(source, "r"),
    out = await fsp.open(destination, "wx", 0o600).catch(async (error) => {
      await input.close();
      throw error;
    }),
    hash = crypto.createHash("sha256");
  let success = false;
  try {
    const before = await input.stat();
    if (before.size !== params.totalBytes) C.fail("SNAPSHOT_SIZE");
    await out.writeFile(header);
    for (let i = 0; i < params.m; i++) {
      const len = Math.min(params.z, params.totalBytes - i * params.z),
        plain = await exact(input, len, i * params.z),
        cipher = crypto.createCipheriv(
          "aes-256-gcm",
          dek,
          nonce(header.subarray(8, 16), i),
        );
      hash.update(plain);
      cipher.setAAD(aad(evidenceId, header, i, len));
      const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
      plain.fill(0);
      await out.writeFile(encrypted);
      await out.writeFile(cipher.getAuthTag());
    }
    const after = await input.stat();
    if (
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      hash.digest("hex") !== params.h_E
    )
      C.fail("ENCRYPTED_SOURCE_CHANGED");
    await out.sync();
    success = true;
  } finally {
    await input.close();
    await out.close();
    if (!success) await fsp.unlink(destination);
  }
  return {
    format: "BFD_ENCRYPTED_SNAPSHOT_V1",
    evidenceId,
    params,
    sourceDeleted: false,
  };
}
function encryptedSource(file, { evidenceId, params, dek }) {
  K.params(params);
  C.id(evidenceId);
  if (!Buffer.isBuffer(dek) || dek.length !== 32) C.fail("DEK_LENGTH");
  return {
    async openRead() {
      const fd = await fsp.open(file, "r");
      let header;
      try {
        header = await exact(fd, HEADER, 0);
        if (
          !header.subarray(0, 8).equals(MAGIC) ||
          header.readUInt32BE(16) !== params.z ||
          header.readBigUInt64BE(20) !== BigInt(params.totalBytes) ||
          header.subarray(28, 60).toString("hex") !== params.h_E ||
          !header.subarray(60).equals(Buffer.alloc(4))
        )
          C.fail("ENCRYPTED_HEADER_BINDING");
        const st = await fd.stat();
        if (st.size !== HEADER + params.totalBytes + 16 * params.m)
          C.fail("ENCRYPTED_STORAGE_SIZE");
      } catch (e) {
        await fd.close();
        throw e;
      }
      return {
        async stat() {
          const st = await fd.stat();
          return {
            size: params.totalBytes,
            mtimeMs: st.mtimeMs,
            ino: st.ino,
            isFile: () => st.isFile(),
          };
        },
        async read(target, offset, length, position) {
          C.integer(position, 0, params.totalBytes);
          C.integer(length, 0, target.length - offset);
          let copied = 0;
          while (copied < length && position + copied < params.totalBytes) {
            const absolute = position + copied,
              i = Math.floor(absolute / params.z),
              within = absolute % params.z,
              len = Math.min(params.z, params.totalBytes - i * params.z),
              record = await exact(fd, len + 16, HEADER + i * (params.z + 16));
            const d = crypto.createDecipheriv(
              "aes-256-gcm",
              dek,
              nonce(header.subarray(8, 16), i),
            );
            d.setAAD(aad(evidenceId, header, i, len));
            d.setAuthTag(record.subarray(len));
            let plain;
            try {
              plain = Buffer.concat([
                d.update(record.subarray(0, len)),
                d.final(),
              ]);
            } catch {
              C.fail("ENCRYPTED_CHUNK_AUTHENTICATION");
            }
            const n = Math.min(length - copied, len - within);
            plain.copy(target, offset + copied, within, within + n);
            plain.fill(0);
            copied += n;
          }
          return { bytesRead: copied, buffer: target };
        },
        close: () => fd.close(),
      };
    },
  };
}
module.exports = { encryptSnapshot, encryptedSource };
