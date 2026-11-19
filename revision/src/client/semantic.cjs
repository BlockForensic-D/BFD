"use strict";
const fs = require("node:fs"),
  fsp = fs.promises,
  crypto = require("node:crypto");
const C = require("../shared/canonical.cjs"),
  { POLICY: P } = require("../shared/policy.cjs");
function flow4(packet, linkType) {
  if (linkType !== 1 || packet.length < 14) return null;
  let offset = 14,
    type = packet.readUInt16BE(12),
    tags = 0;
  while ([0x8100, 0x88a8].includes(type) && tags++ < 2) {
    if (packet.length < offset + 4) return null;
    type = packet.readUInt16BE(offset + 2);
    offset += 4;
  }
  if (
    type !== 0x0800 ||
    packet.length < offset + 20 ||
    packet[offset] >> 4 !== 4
  )
    return null;
  const ihl = (packet[offset] & 15) * 4;
  if (ihl < 20 || packet.length < offset + ihl + 4) return null;
  if ((packet.readUInt16BE(offset + 6) & 0x1fff) !== 0) return null;
  const protocol = packet[offset + 9];
  if (![6, 17].includes(protocol)) return null;
  return {
    src: [...packet.subarray(offset + 12, offset + 16)].join("."),
    dst: [...packet.subarray(offset + 16, offset + 20)].join("."),
    srcPort: packet.readUInt16BE(offset + ihl),
    dstPort: packet.readUInt16BE(offset + ihl + 2),
    protocol: protocol === 6 ? "TCP" : "UDP",
  };
}
async function indexPcap(file) {
  const fd = await fsp.open(file, "r"),
    hash = crypto.createHash("sha256"),
    records = [];
  // Sequential page buffering avoids two asynchronous filesystem reads per packet.
  let page = Buffer.alloc(0),
    cursor = 0,
    diskOffset = 0;
  async function next(n) {
    const out = Buffer.alloc(n);
    let copied = 0;
    while (copied < n) {
      if (cursor === page.length) {
        const buffer = Buffer.allocUnsafe(65536),
          r = await fd.read(buffer, 0, buffer.length, diskOffset);
        if (!r.bytesRead) C.fail("TRUNCATED_ARTIFACT");
        diskOffset += r.bytesRead;
        page = buffer.subarray(0, r.bytesRead);
        cursor = 0;
      }
      const size = Math.min(n - copied, page.length - cursor);
      page.copy(out, copied, cursor, cursor + size);
      cursor += size;
      copied += size;
    }
    return out;
  }
  try {
    const before = await fd.stat();
    if (before.size < 24) C.fail("PCAP_HEADER");
    const header = await next(24),
      magic = header.subarray(0, 4).toString("hex");
    const formats = {
      d4c3b2a1: { little: true, nano: false },
      a1b2c3d4: { little: false, nano: false },
      "4d3cb2a1": { little: true, nano: true },
      a1b23c4d: { little: false, nano: true },
    };
    const format = formats[magic];
    if (!format)
      C.fail(magic === "0a0d0d0a" ? "PCAPNG_NOT_SUPPORTED" : "PCAP_MAGIC");
    const u16 = (b, n) =>
        format.little ? b.readUInt16LE(n) : b.readUInt16BE(n),
      u32 = (b, n) => (format.little ? b.readUInt32LE(n) : b.readUInt32BE(n));
    if (u16(header, 4) !== 2 || u16(header, 6) !== 4) C.fail("PCAP_VERSION");
    const snaplen = u32(header, 16),
      linkType = u32(header, 20) & 0xffff;
    if (!snaplen) C.fail("PCAP_SNAPLEN");
    hash.update(header);
    let offset = 24;
    while (offset < before.size) {
      if (before.size - offset < 16) C.fail("TRUNCATED_PACKET_HEADER");
      const h = await next(16),
        seconds = u32(h, 0),
        fraction = u32(h, 4),
        captured = u32(h, 8),
        original = u32(h, 12);
      if (
        captured > original ||
        captured > snaplen ||
        captured > 16 * 1024 * 1024 ||
        offset + 16 + captured > before.size ||
        fraction >= (format.nano ? 1e9 : 1e6)
      )
        C.fail("PCAP_PACKET_LENGTH_OR_TIME");
      const data = await next(captured);
      hash.update(h).update(data);
      records.push({
        record: records.length,
        start: offset,
        end: offset + 16 + captured,
        timestampMs:
          seconds * 1000 + Math.floor(fraction / (format.nano ? 1e6 : 1e3)),
        capturedBytes: captured,
        originalBytes: original,
        flow: flow4(data, linkType),
      });
      offset += 16 + captured;
    }
    const after = await fd.stat();
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs)
      C.fail("ARTIFACT_CHANGED");
    return {
      schemaVersion: 1,
      format: "PCAP_CLASSIC",
      parserVersion: "BFD_PCAP_1",
      h_E: hash.digest("hex"),
      totalBytes: before.size,
      globalHeader: { start: 0, end: 24 },
      linkType,
      records,
    };
  } finally {
    await fd.close();
  }
}
async function indexLines(
  file,
  {
    jsonl = false,
    timestampField = "timestamp",
    numericTimestampUnit = null,
    maxLineBytes = 1048576,
  } = {},
) {
  const before = await fsp.stat(file),
    hash = crypto.createHash("sha256"),
    records = [];
  let pending = Buffer.alloc(0),
    offset = 0,
    number = 0;
  function add(b) {
    if (b.length > maxLineBytes) C.fail("LOG_LINE_LIMIT");
    let timestampMs = null;
    if (jsonl) {
      let text = new TextDecoder("utf-8", { fatal: true }).decode(b);
      if (number === 0) text = text.replace(/^\uFEFF/, "");
      if (!text.trim()) C.fail("EMPTY_JSONL_RECORD");
      const obj = C.parseStrict(text, maxLineBytes, true),
        v = obj[timestampField];
      if (typeof v === "string") {
        if (!/^\d{4}-\d\d-\d\dT.*(?:Z|[+-]\d\d:\d\d)$/.test(v))
          C.fail("TIMESTAMP_FORMAT");
        timestampMs = Date.parse(v);
        if (!Number.isFinite(timestampMs)) C.fail("TIMESTAMP_FORMAT");
      } else if (typeof v === "number") {
        if (!["ms", "s"].includes(numericTimestampUnit))
          C.fail("NUMERIC_TIMESTAMP_UNIT_REQUIRED");
        timestampMs = v * (numericTimestampUnit === "s" ? 1000 : 1);
        if (!Number.isSafeInteger(timestampMs) || timestampMs < 0)
          C.fail("TIMESTAMP_RANGE");
      } else if (v !== undefined) C.fail("TIMESTAMP_TYPE");
    } else new TextDecoder("utf-8", { fatal: true }).decode(b);
    records.push({
      record: number++,
      start: offset,
      end: offset + b.length,
      timestampMs,
    });
    offset += b.length;
  }
  for await (const block of fs.createReadStream(file, {
    highWaterMark: 65536,
  })) {
    hash.update(block);
    const all = pending.length ? Buffer.concat([pending, block]) : block;
    let start = 0;
    for (let n = 0; n < all.length; n++)
      if (all[n] === 10) {
        add(all.subarray(start, n + 1));
        start = n + 1;
      }
    pending = Buffer.from(all.subarray(start));
    if (pending.length > maxLineBytes) C.fail("LOG_LINE_LIMIT");
  }
  if (pending.length) add(pending);
  const after = await fsp.stat(file);
  if (
    before.size !== after.size ||
    before.mtimeMs !== after.mtimeMs ||
    offset !== before.size
  )
    C.fail("ARTIFACT_CHANGED");
  return {
    schemaVersion: 1,
    format: jsonl ? "JSONL" : "UTF8_LINES",
    parserVersion: "BFD_LINES_1",
    h_E: hash.digest("hex"),
    totalBytes: before.size,
    records,
  };
}
function query(index, q) {
  C.fields(
    q,
    [],
    ["recordStart", "recordEnd", "timeStartMs", "timeEndMs", "flow"],
  );
  if (!Object.keys(q).length) C.fail("EMPTY_QUERY");
  if (q.recordStart !== undefined) C.integer(q.recordStart);
  if (q.recordEnd !== undefined) C.integer(q.recordEnd);
  if (
    q.recordStart !== undefined &&
    q.recordEnd !== undefined &&
    q.recordStart >= q.recordEnd
  )
    C.fail("QUERY_RANGE");
  for (const k of ["timeStartMs", "timeEndMs"])
    if (q[k] !== undefined) C.integer(q[k]);
  if (
    q.timeStartMs !== undefined &&
    q.timeEndMs !== undefined &&
    q.timeStartMs >= q.timeEndMs
  )
    C.fail("QUERY_RANGE");
  if (q.flow) {
    C.fields(q.flow, [], ["src", "dst", "srcPort", "dstPort", "protocol"]);
    if (index.format !== "PCAP_CLASSIC" || index.linkType !== 1)
      C.fail("FLOW_FORMAT_UNSUPPORTED");
    if (!Object.keys(q.flow).length) C.fail("EMPTY_FLOW_QUERY");
    for (const key of ["src", "dst"])
      if (
        q.flow[key] !== undefined &&
        (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(q.flow[key]) ||
          q.flow[key].split(".").some((x) => Number(x) > 255))
      )
        C.fail("FLOW_IPV4_REQUIRED");
    for (const key of ["srcPort", "dstPort"])
      if (q.flow[key] !== undefined) C.integer(q.flow[key], 0, 65535);
    if (
      q.flow.protocol !== undefined &&
      !["TCP", "UDP"].includes(q.flow.protocol)
    )
      C.fail("FLOW_PROTOCOL_UNSUPPORTED");
  }
  return index.records.filter((r) => {
    if (
      (q.recordStart !== undefined && r.record < q.recordStart) ||
      (q.recordEnd !== undefined && r.record >= q.recordEnd)
    )
      return false;
    if (
      (q.timeStartMs !== undefined || q.timeEndMs !== undefined) &&
      r.timestampMs === null
    )
      C.fail("TIMESTAMP_NOT_INDEXED");
    if (
      (q.timeStartMs !== undefined && r.timestampMs < q.timeStartMs) ||
      (q.timeEndMs !== undefined && r.timestampMs >= q.timeEndMs)
    )
      return false;
    if (
      q.flow &&
      (!r.flow || Object.entries(q.flow).some(([k, v]) => r.flow[k] !== v))
    )
      return false;
    return true;
  });
}
function mapRanges(index, records, z, { includePcapHeader = true } = {}) {
  C.integer(z, 1, P.maxChunkSize);
  C.hex(index.h_E);
  C.integer(index.totalBytes);
  if (!records.length)
    return {
      scope: null,
      selectedBytes: 0,
      disclosedBytes: 0,
      excessBytes: 0,
      recordCount: 0,
      reason: "NO_MATCH",
    };
  const ranges = records.map((r) => ({ start: r.start, end: r.end }));
  if (index.format === "PCAP_CLASSIC" && includePcapHeader)
    ranges.push(index.globalHeader);
  ranges.sort((a, b) => a.start - b.start);
  const merged = [];
  for (const r of ranges) {
    C.integer(r.start, 0, index.totalBytes);
    C.integer(r.end, r.start + 1, index.totalBytes);
    const last = merged.at(-1);
    if (last && r.start <= last.end) last.end = Math.max(last.end, r.end);
    else merged.push({ ...r });
  }
  const wanted = new Set();
  let selectedBytes = 0;
  for (const r of merged) {
    selectedBytes += r.end - r.start;
    for (
      let i = Math.floor(r.start / z);
      i <= Math.floor((r.end - 1) / z);
      i++
    ) {
      wanted.add(i);
      if (wanted.size > P.maxScopeIndices) C.fail("SCOPE_LIMIT");
    }
  }
  const indices = [...wanted].sort((a, b) => a - b),
    disclosedBytes = indices.reduce(
      (n, i) => n + Math.min(z, index.totalBytes - i * z),
      0,
    );
  return {
    scope: { mode: "CHUNK_SET", indices },
    selectedBytes,
    disclosedBytes,
    excessBytes: disclosedBytes - selectedBytes,
    recordCount: records.length,
    ranges: merged,
    sourceDigest: index.h_E,
    parserVersion: index.parserVersion,
  };
}
function validateIndex(index, anchor) {
  if (
    index.h_E !== anchor.h_E ||
    index.totalBytes !== anchor.totalBytes ||
    index.schemaVersion !== 1
  )
    C.fail("STALE_SEMANTIC_INDEX");
}
module.exports = { indexPcap, indexLines, query, mapRanges, validateIndex };
