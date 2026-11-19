"use strict";
const fs = require("node:fs").promises,
  crypto = require("node:crypto");
const C = require("../shared/canonical.cjs"),
  { immutableJson } = require("./files.cjs");
async function requestWithRecovery({
  ledger,
  capability,
  requestedScope,
  requestPath,
  principal,
}) {
  const core = capability.core;
  if (!C.equal(core.granteePrincipal, principal))
    C.fail("BOUND_GRANTEE_REQUIRED");
  const stable = {
    schemaVersion: 1,
    context: core.context,
    capId: core.capId,
    capHash: C.hash("CapabilityCoreV1", core),
    granteePrincipal: principal,
    requestedScope,
  };
  let input;
  try {
    input = C.parseStrict(await fs.readFile(requestPath, "utf8"));
    C.fields(input, [...Object.keys(stable), "requestId"]);
    C.hex(input.requestId);
    const { requestId, ...rest } = input;
    if (!C.equal(stable, rest)) C.fail("DURABLE_REQUEST_CONFLICT");
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
    input = { ...stable, requestId: crypto.randomBytes(32).toString("hex") };
    await immutableJson(requestPath, input);
  }
  // An unknown commit outcome must propagate; the persisted request remains unchanged.
  const result = await ledger.submit("requestDisclosure", input);
  if (result.commit?.successful !== true)
    C.fail("COMMIT_CONFIRMATION_REQUIRED");
  return result;
}
module.exports = { requestWithRecovery };
