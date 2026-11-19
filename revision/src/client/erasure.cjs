"use strict";
const fs = require("node:fs"),
  fsp = fs.promises,
  path = require("node:path");
const C = require("../shared/canonical.cjs"),
  { POLICY: P } = require("../shared/policy.cjs");
const { immutableJson, syncDirectory } = require("./files.cjs");
// A provider must invalidate every inventoried copy for the named class.
// The local-file provider is intentionally limited to disposable research fixtures.
class FixtureFileProvider {
  constructor(root, manifest) {
    this.root = path.resolve(root);
    this.manifest = manifest;
  }
  async initialize() {
    const root = await fsp.realpath(this.root);
    if (root !== this.root) C.fail("ERASURE_ROOT_SYMLINK");
    const mark = await fsp.readFile(
      path.join(root, ".bfd-disposable-fixture"),
      "utf8",
    );
    if (mark !== "BFD_SYNTHETIC_KEYS_ONLY_V1\n")
      C.fail("DISPOSABLE_FIXTURE_MARKER");
    C.fields(this.manifest, ["evidenceId", "classes"]);
    C.id(this.manifest.evidenceId);
    C.fields(this.manifest.classes, P.requiredKeyClasses);
    for (const k of P.requiredKeyClasses) {
      const names = this.manifest.classes[k];
      if (!Array.isArray(names) || !names.length) C.fail("EMPTY_KEY_INVENTORY");
      for (const name of names)
        if (typeof name !== "string" || !/^key-[A-Za-z0-9._-]+$/.test(name))
          C.fail("ERASURE_FILE_NAME");
    }
    const all = P.requiredKeyClasses.flatMap((k) => this.manifest.classes[k]);
    if (new Set(all).size !== all.length) C.fail("DUPLICATE_KEY_PATH");
    return this;
  }
  async erase(keyClass) {
    for (const name of this.manifest.classes[keyClass]) {
      const file = path.join(this.root, name);
      try {
        const st = await fsp.lstat(file);
        if (!st.isFile() || st.isSymbolicLink() || st.nlink !== 1)
          C.fail("UNSAFE_KEY_FILE");
        // unlink is NOT claimed as secure physical media sanitization.
        await fsp.unlink(file);
      } catch (e) {
        if (e.code !== "ENOENT") throw e;
      }
    }
    await syncDirectory(this.root);
    return {
      keyClass,
      scope: "INVENTORIED_DISPOSABLE_FILES",
      method: "UNLINK_ONLY",
      physicalSanitizationProven: false,
    };
  }
}
async function executeErasure({
  ledger,
  operationId,
  provider,
  journalDir,
  clockHealthy,
  now = () => Math.floor(Date.now() / 1000),
  afterClass,
}) {
  if (typeof clockHealthy !== "function" || !(await clockHealthy()))
    C.fail("CLOCK_UNHEALTHY");
  C.id(operationId);
  await fsp.mkdir(journalDir, { recursive: true, mode: 0o700 });
  const initial = await ledger.query("getErasureOperation", { operationId }),
    op = initial.operation;
  if (op.status !== "ERASURE_AUTHORIZED") C.fail("ERASURE_NOT_AUTHORIZED");
  if (provider.manifest?.evidenceId !== op.evidenceId)
    C.fail("PROVIDER_EVIDENCE_BINDING");
  const destroyed = [],
    observations = [];
  let stopped = null;
  for (const keyClass of P.requiredKeyClasses) {
    const recordPath = path.join(journalDir, keyClass + ".json");
    try {
      const prior = C.parseStrict(await fsp.readFile(recordPath, "utf8"));
      if (
        prior.operationId !== operationId ||
        prior.keyClass !== keyClass ||
        prior.evidenceId !== op.evidenceId
      )
        C.fail("ERASURE_JOURNAL_BINDING");
      destroyed.push(keyClass);
      observations.push(prior);
      continue;
    } catch (e) {
      if (e.code !== "ENOENT") throw e;
    }
    const current = await ledger.query("getErasureOperation", { operationId });
    if (!(await clockHealthy())) {
      stopped = "CLOCK_UNHEALTHY";
      break;
    }
    if (current.hold?.active) {
      stopped = "LEGAL_HOLD";
      break;
    }
    if (
      current.operation.status !== "ERASURE_AUTHORIZED" ||
      current.operation.authorizedTxRef !== op.authorizedTxRef ||
      current.evidence.epoch !== op.epoch ||
      current.evidence.lifecycle !== "DESTRUCTION_APPROVED"
    ) {
      stopped = "ERASURE_AUTHORIZATION_CHANGED";
      break;
    }
    try {
      const outcome = await provider.erase(keyClass);
      const row = {
        operationId,
        evidenceId: op.evidenceId,
        keyClass,
        ...outcome,
      };
      await immutableJson(recordPath, row);
      destroyed.push(keyClass);
      observations.push(row);
      if (afterClass) await afterClass(keyClass);
    } catch (e) {
      stopped = "PROVIDER_OR_JOURNAL_FAILURE";
      break;
    }
  }
  const current = await ledger.query("getErasureOperation", { operationId });
  const outcome =
    destroyed.length === P.requiredKeyClasses.length
      ? "COMPLETED"
      : destroyed.length
        ? "PARTIAL"
        : stopped === "LEGAL_HOLD"
          ? "ABORTED_BEFORE_ERASURE"
          : "FAILED";
  return {
    operationId,
    evidenceId: op.evidenceId,
    outcome,
    destroyedKeyClasses: destroyed.sort(),
    completedAtClaim: now(),
    stopped,
    lateHoldActive: !!current.hold?.active,
    observations,
    physicalSanitizationProven: false,
    limitations:
      "Only inventoried provider locations were examined. Backups, snapshots, untracked processes, retained openings and plaintext are not eliminated by this report. A hold may race with an irreversible provider action.",
  };
}
module.exports = { FixtureFileProvider, executeErasure };
