"use strict";
const https = require("node:https"),
  { Readable } = require("node:stream"),
  { pipeline } = require("node:stream/promises");
const C = require("../shared/canonical.cjs"),
  { POLICY: P } = require("../shared/policy.cjs");
async function body(request) {
  let length = 0;
  const parts = [];
  for await (const b of request) {
    length += b.length;
    if (length > P.maxLedgerBytes) C.fail("REQUEST_BODY_SIZE");
    parts.push(b);
  }
  return C.parseStrict(
    new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(parts)),
  );
}
function createReleaseServer(
  controller,
  { key, cert, host = "127.0.0.1", port = 8443 },
) {
  const server = https.createServer(
    { key, cert, minVersion: "TLSv1.2" },
    async (req, res) => {
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("X-Content-Type-Options", "nosniff");
      try {
        if (req.method !== "POST") C.fail("POST_REQUIRED");
        const input = await body(req);
        if (req.url === "/challenge") {
          C.fields(input, ["sessionId"]);
          const challenge = await controller.challenge(input.sessionId);
          res.setHeader("Content-Type", "application/json");
          res.end(C.canonical(challenge));
          return;
        }
        if (req.url === "/release") {
          // Delay status/body until authentication and preflight have completed.
          const stream = controller.release(input),
            first = await stream.next();
          res.setHeader("Content-Type", "application/vnd.bfd.bundle-core+json");
          try {
            async function* source() {
              if (!first.done) yield first.value;
              yield* stream;
            }
            await pipeline(Readable.from(source()), res);
          } finally {
            await stream.return();
          }
          return;
        }
        C.fail("UNKNOWN_ENDPOINT");
      } catch (e) {
        if (res.headersSent) {
          res.destroy();
          return;
        }
        res.statusCode = 400;
        res.setHeader("Content-Type", "application/json");
        // Never expose SDK errors, certificate content, evidence paths or bundle bytes.
        res.end(JSON.stringify({ error: "RELEASE_REJECTED" }));
      }
    },
  );
  server.requestTimeout = 30000;
  server.headersTimeout = 10000;
  return {
    server,
    listen: () =>
      new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          server.off("error", reject);
          resolve(server.address());
        });
      }),
  };
}
module.exports = { createReleaseServer };
