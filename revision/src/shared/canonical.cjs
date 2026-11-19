"use strict";
const crypto = require("node:crypto");
const { POLICY } = require("./policy.cjs");
function fail(code) {
  throw new Error(code);
}
function unicode(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(++i);
      if (!(d >= 0xdc00 && d <= 0xdfff)) fail("INVALID_UNICODE");
    } else if (c >= 0xdc00 && c <= 0xdfff) fail("INVALID_UNICODE");
  }
  return s;
}
function safeKey(k) {
  unicode(k);
  if (["__proto__", "prototype", "constructor"].includes(k)) fail("UNSAFE_KEY");
}
function parseStrict(
  raw,
  maxBytes = POLICY.maxLedgerBytes,
  evidenceNumbers = false,
) {
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > maxBytes)
    fail("INPUT_SIZE");
  let i = 0;
  const ws = () => {
    while (/[\x20\t\r\n]/.test(raw[i] || "\0")) i++;
  };
  function str() {
    const start = i++;
    let escape = false;
    while (i < raw.length) {
      const c = raw[i++];
      if (!escape && c === '"') {
        let v;
        try {
          v = JSON.parse(raw.slice(start, i));
        } catch {
          fail("INVALID_JSON_STRING");
        }
        return unicode(v);
      }
      if (!escape && c === "\\") escape = true;
      else escape = false;
    }
    fail("UNTERMINATED_STRING");
  }
  function value(depth) {
    if (depth > 64) fail("MAX_DEPTH");
    ws();
    const c = raw[i];
    if (c === '"') return str();
    if (c === "{") {
      i++;
      ws();
      const out = Object.create(null),
        seen = new Set();
      if (raw[i] === "}") {
        i++;
        return out;
      }
      while (true) {
        ws();
        if (raw[i] !== '"') fail("EXPECTED_KEY");
        const k = str();
        safeKey(k);
        if (seen.has(k)) fail("DUPLICATE_KEY");
        seen.add(k);
        ws();
        if (raw[i++] !== ":") fail("EXPECTED_COLON");
        out[k] = value(depth + 1);
        ws();
        const d = raw[i++];
        if (d === "}") return out;
        if (d !== ",") fail("EXPECTED_OBJECT_DELIMITER");
      }
    }
    if (c === "[") {
      i++;
      ws();
      const out = [];
      if (raw[i] === "]") {
        i++;
        return out;
      }
      while (true) {
        out.push(value(depth + 1));
        ws();
        const d = raw[i++];
        if (d === "]") return out;
        if (d !== ",") fail("EXPECTED_ARRAY_DELIMITER");
      }
    }
    if (raw.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (raw.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (raw.startsWith("null", i)) {
      i += 4;
      return null;
    }
    if (evidenceNumbers) {
      // External evidence JSON only. Protocol entry points use integer-only defaults.
      const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(
        raw.slice(i),
      );
      if (!m) fail("INVALID_JSON_VALUE");
      i += m[0].length;
      const n = Number(m[0]);
      if (!Number.isFinite(n)) fail("NONFINITE_EVIDENCE_NUMBER");
      return n;
    }
    const m = /^(0|[1-9][0-9]*)/.exec(raw.slice(i));
    if (!m) fail("INVALID_JSON_VALUE");
    i += m[0].length;
    const n = Number(m[0]);
    if (!Number.isSafeInteger(n)) fail("UNSAFE_INTEGER");
    return n;
  }
  const result = value(0);
  ws();
  if (i !== raw.length) fail("TRAILING_OR_NONINTEGER_JSON");
  return result;
}
function canonical(value, depth = 0) {
  if (depth > 64) fail("MAX_DEPTH");
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(unicode(value));
  if (typeof value === "boolean") return String(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0))
      fail("UNSAFE_INTEGER");
    return String(value);
  }
  if (Array.isArray(value))
    return "[" + value.map((v) => canonical(v, depth + 1)).join(",") + "]";
  if (
    value &&
    typeof value === "object" &&
    [null, Object.prototype].includes(Object.getPrototypeOf(value))
  ) {
    return (
      "{" +
      Object.keys(value)
        .sort()
        .map((k) => {
          safeKey(k);
          return JSON.stringify(k) + ":" + canonical(value[k], depth + 1);
        })
        .join(",") +
      "}"
    );
  }
  fail("NON_JSON_VALUE");
}
const digest = (b) => crypto.createHash("sha256").update(b).digest("hex");
const domain = (k) => Buffer.from("BFD/" + k + "/1\0", "utf8");
const encode = (k, core) =>
  Buffer.concat([domain(k), Buffer.from(canonical(core))]);
const hash = (k, core) => digest(encode(k, core));
function fields(o, required, optional = []) {
  if (!o || typeof o !== "object" || Array.isArray(o)) fail("OBJECT_REQUIRED");
  const all = new Set([...required, ...optional]);
  for (const k of Object.keys(o)) {
    safeKey(k);
    if (!all.has(k)) fail("UNKNOWN_FIELD:" + k);
  }
  for (const k of required)
    if (!Object.hasOwn(o, k) || o[k] === null || o[k] === undefined)
      fail("MISSING_FIELD:" + k);
  return o;
}
function text(v, max = 8192) {
  if (
    typeof v !== "string" ||
    !v.length ||
    Buffer.byteLength(v) > max ||
    v.includes("\0")
  )
    fail("INVALID_TEXT");
  unicode(v);
  return v;
}
function id(v) {
  if (typeof v !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(v))
    fail("INVALID_ID");
  return v;
}
function hex(v) {
  if (typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v))
    fail("INVALID_DIGEST");
  return v;
}
function integer(v, min = 0, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(v) || Object.is(v, -0) || v < min || v > max)
    fail("INVALID_INTEGER");
  return v;
}
function base64(v, length) {
  if (
    typeof v !== "string" ||
    !v.length ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(v)
  )
    fail("INVALID_BASE64");
  const b = Buffer.from(v, "base64");
  if (
    b.toString("base64") !== v ||
    (length !== undefined && b.length !== length)
  )
    fail("INVALID_BASE64");
  return b;
}
function principal(p) {
  fields(p, ["mspId", "clientIdentityId"]);
  text(p.mspId);
  text(p.clientIdentityId);
  return p;
}
const equal = (a, b) => canonical(a) === canonical(b);
function context(c, expected) {
  fields(c, ["profile", "channelId", "chaincodeName"]);
  if (c.profile !== POLICY.profile || !equal(c, expected))
    fail("WRONG_CONTEXT");
}
function header(o, required, expected, optional = []) {
  fields(o, ["schemaVersion", "context", ...required], optional);
  if (o.schemaVersion !== 1) fail("SCHEMA_VERSION");
  context(o.context, expected);
  return o;
}
function keyRef(r) {
  fields(r, ["ownerPrincipal", "purpose", "version"]);
  principal(r.ownerPrincipal);
  if (!Object.hasOwn(POLICY.purposes, r.purpose)) fail("KEY_PURPOSE");
  integer(r.version, 1);
  return r;
}
function scope(s, m) {
  fields(s, ["mode", "indices"]);
  if (!Array.isArray(s.indices) || s.indices.length > POLICY.maxScopeIndices)
    fail("SCOPE_LIMIT");
  if (!["HASH_ONLY", "FULL", "CHUNK_SET"].includes(s.mode)) fail("SCOPE_MODE");
  if (s.mode !== "CHUNK_SET") {
    if (s.indices.length) fail("SCOPE_INDICES");
  } else {
    if (!s.indices.length) fail("EMPTY_SCOPE");
    let last = -1;
    for (const n of s.indices) {
      integer(n, 0, m - 1);
      if (n <= last) fail("SCOPE_ORDER");
      last = n;
    }
  }
  return s;
}
function subset(wanted, allowed, m) {
  scope(wanted, m);
  scope(allowed, m);
  if (wanted.mode === "HASH_ONLY") return true;
  if (allowed.mode === "FULL") return true;
  if (allowed.mode !== "CHUNK_SET" || wanted.mode !== "CHUNK_SET") return false;
  const a = new Set(allowed.indices);
  return wanted.indices.every((i) => a.has(i));
}
module.exports = {
  fail,
  parseStrict,
  canonical,
  digest,
  domain,
  encode,
  hash,
  fields,
  text,
  id,
  hex,
  integer,
  base64,
  principal,
  equal,
  context,
  header,
  keyRef,
  scope,
  subset,
};
