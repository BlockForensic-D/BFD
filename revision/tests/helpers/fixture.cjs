"use strict";
const crypto = require("node:crypto");
const C = require("../../src/shared/canonical.cjs"),
  K = require("../../src/shared/crypto.cjs"),
  { POLICY: P } = require("../../src/shared/policy.cjs");
const { MemoryLedger } = require("./memory.cjs");
const context = {
  profile: P.profile,
  channelId: "bfd-test",
  chaincodeName: P.chaincodeName,
};
const core = (x) => ({ schemaVersion: 1, context, ...x });
function actor(name, msp, role) {
  return {
    principal: { mspId: msp, clientIdentityId: "x509::CN=" + name + "::CN=ca" },
    role,
    clearance: "High",
  };
}
const actors = () => ({
  collector: actor("collector", "Org1MSP", "GatewayCollector"),
  ec: actor("ec", "Org1MSP", "EvidenceCustodian"),
  av: actor("av", "Org3MSP", "AcquisitionAuditor"),
  jr: actor("jr", "Org2MSP", "JudicialReviewer"),
  dpo: actor("dpo", "Org2MSP", "DataProtectionOfficer"),
  grantee: actor("insurer", "Org3MSP", "ExternalAuditor"),
  other: actor("other", "Org3MSP", "ExternalAuditor"),
});
async function register(ledger, owner, purpose, version = 1, previousKeyRef) {
  const kp = crypto.generateKeyPairSync("ed25519"),
    publicKey = kp.publicKey
      .export({ type: "spki", format: "der" })
      .toString("base64");
  const intent = core({
    ownerPrincipal: owner.principal,
    purpose,
    algorithm: "Ed25519",
    publicKey,
    fingerprint: K.fingerprint(publicKey),
    keyVersion: version,
    intentNonce: crypto.randomBytes(32).toString("hex"),
  });
  const input = {
    intent,
    signature: K.sign("RegistrationIntentV1", intent, kp.privateKey),
  };
  if (previousKeyRef) input.previousKeyRef = previousKeyRef;
  const record = await ledger.invoke(
    previousKeyRef ? "rotatePublicKey" : "registerPublicKey",
    owner,
    input,
  );
  return {
    ...kp,
    keyRef: record.keyRef,
    publicKeyText: publicKey,
    record,
    input,
  };
}
async function fixture({ commit = true, issue = true, mode = "FULL" } = {}) {
  const ledger = new MemoryLedger(),
    a = actors();
  const issuer = await register(ledger, a.ec, "CAPABILITY_ISSUER");
  const avKey = await register(ledger, a.av, "ACQUISITION_VALIDATION");
  const bytes = Buffer.from(
    "Synthetic forensic fixture: one/two/three/four/five; no operational evidence.",
  );
  const evidenceId = "evidence-01",
    z = 13,
    emk = crypto.randomBytes(32),
    keys = K.derive(emk, evidenceId),
    chunks = [],
    leaves = [];
  for (let start = 0, i = 0; start < bytes.length; start += z, i++) {
    const b = bytes.subarray(start, start + z),
      salt = K.opening(keys.kSalt, evidenceId, i, b.length),
      h = K.leaf(b, evidenceId, i, salt);
    chunks.push({
      index: i,
      actualLength: b.length,
      dataB64: b.toString("base64"),
      saltHex: salt,
    });
    leaves.push(h);
  }
  const tree = K.tree(leaves);
  chunks.forEach((c) => (c.proof = K.proof(tree.levels, c.index)));
  const params = {
    h_E: C.digest(bytes),
    R: tree.root,
    totalBytes: bytes.length,
    z,
    m: chunks.length,
    commitmentVersion: P.commitmentVersion,
    oddNodeRule: P.oddNodeRule,
  };
  const preserve = core({
    evidenceId,
    collectorPrincipal: a.collector.principal,
    custodianPrincipal: a.ec.principal,
    h_E: params.h_E,
    totalBytes: params.totalBytes,
    sourceMetadataDigest: C.digest("fixture source"),
  });
  const evidence = await ledger.invoke(
    "preserveEvidence",
    a.collector,
    preserve,
  );
  const assignmentInput = {
    assignmentId: "audit-01",
    evidenceId,
    preserveDigest: evidence.preserveDigest,
    auditorPrincipal: a.av.principal,
    auditorKeyRef: avKey.keyRef,
    expiresAt: 6000,
  };
  const assignment = await ledger.invoke(
    "assignAcquisitionAuditor",
    a.jr,
    assignmentInput,
  );
  const receiptCore = core({
    evidenceId,
    preserveDigest: evidence.preserveDigest,
    assignmentId: assignment.assignmentId,
    auditJobId: "job-01",
    auditorPrincipal: a.av.principal,
    auditorKeyRef: avKey.keyRef,
    ...params,
    validationMethodVersion: P.validationMethodVersion,
    outcome: "PASS",
  });
  const receipt = {
    core: receiptCore,
    signerKeyRef: avKey.keyRef,
    signature: K.sign("AcquisitionReceiptV1", receiptCore, avKey.privateKey),
  };
  const commitInput = { evidenceId, params, receipt };
  let anchor = evidence,
    token,
    cap;
  if (commit)
    anchor = await ledger.invoke("commitPreservedEvidence", a.ec, commitInput);
  if (issue && commit) {
    const capCore = core({
      capId: "cap-01",
      evidenceId,
      commitRef: anchor.commitRef,
      acquisitionReceiptDigest: anchor.acquisitionReceiptDigest,
      issuerPrincipal: a.ec.principal,
      issuerKeyRef: issuer.keyRef,
      granteePrincipal: a.grantee.principal,
      usageMode: "SINGLE_USE",
      capabilityScope: { mode, indices: mode === "CHUNK_SET" ? [0, 2] : [] },
      epoch: 0,
      policyVersion: 1,
      issuedAt: 1000,
      notBefore: 1000,
      expiresAt: 5000,
      allowedLifecycle: ["COMMITTED"],
    });
    token = {
      core: capCore,
      signerKeyRef: issuer.keyRef,
      signature: K.sign("CapabilityCoreV1", capCore, issuer.privateKey),
    };
    cap = await ledger.invoke("issueDisclosureCapability", a.ec, token);
  }
  const request = (scope) =>
    core({
      requestId: crypto.randomBytes(32).toString("hex"),
      capId: cap.token.core.capId,
      capHash: cap.capHash,
      granteePrincipal: a.grantee.principal,
      requestedScope: scope || {
        mode,
        indices: mode === "CHUNK_SET" ? [0, 2] : [],
      },
    });
  return {
    ledger,
    a,
    issuer,
    avKey,
    bytes,
    evidenceId,
    z,
    emk,
    keys,
    chunks,
    tree,
    params,
    preserve,
    assignmentInput,
    assignment,
    receipt,
    commitInput,
    anchor,
    token,
    cap,
    request,
  };
}
module.exports = { MemoryLedger, fixture, register, core, context, actors };
