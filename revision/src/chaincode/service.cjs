"use strict";
const C = require("../shared/canonical.cjs");
const K = require("../shared/crypto.cjs");
const { POLICY: P } = require("../shared/policy.cjs");
const EVIDENCE_STATES = new Set([
  "PRESERVED",
  "COMMITTED",
  "RESTRICTED",
  "WITHDRAWN",
  "DESTRUCTION_REQUESTED",
  "DESTRUCTION_APPROVED",
  "DESTROYED",
]);
class RevisionService {
  context(ctx) {
    return {
      profile: P.profile,
      channelId: ctx.stub.getChannelID(),
      chaincodeName: P.chaincodeName,
    };
  }
  actor(ctx) {
    return C.principal({
      mspId: ctx.clientIdentity.getMSPID(),
      clientIdentityId: ctx.clientIdentity.getID(),
    });
  }
  role(ctx, roles, clearance = "High") {
    const role = ctx.clientIdentity.getAttributeValue("role"),
      level = ctx.clientIdentity.getAttributeValue("clearance");
    if (
      !roles.includes(role) ||
      !(clearance === "Medium" ? ["Medium", "High"] : ["High"]).includes(level)
    )
      C.fail("ROLE_OR_CLEARANCE");
    return role;
  }
  time(ctx) {
    const t = ctx.stub.getTxTimestamp();
    const seconds = String(t.seconds);
    if (!/^[0-9]+$/.test(seconds)) C.fail("TIMESTAMP");
    return C.integer(Number(seconds));
  }
  key(ctx, type, id) {
    return ctx.stub.createCompositeKey("bfd.rev1." + type, [
      typeof id === "string" ? id : C.hash("LedgerKey", id),
    ]);
  }
  async get(ctx, type, id) {
    const raw = await ctx.stub.getState(this.key(ctx, type, id));
    if (!raw || raw.length === 0) return null;
    const r = C.parseStrict(raw.toString(), 4 * P.maxLedgerBytes);
    if (
      r.recordType !== type ||
      r.schemaVersion !== 1 ||
      r.profile !== P.profile
    )
      C.fail("RECORD_TYPE_OR_PROFILE");
    return r;
  }
  async put(ctx, type, id, data) {
    if (
      Object.hasOwn(data, "recordType") ||
      Object.hasOwn(data, "schemaVersion") ||
      Object.hasOwn(data, "profile")
    )
      C.fail("RESERVED_RECORD_FIELD");
    const r = {
      ...data,
      recordType: type,
      schemaVersion: 1,
      profile: P.profile,
    };
    await ctx.stub.putState(
      this.key(ctx, type, id),
      Buffer.from(C.canonical(r)),
    );
    return r;
  }
  data(r) {
    const { recordType, schemaVersion, profile, ...rest } = r;
    return rest;
  }
  async fresh(ctx, type, id) {
    if (await this.get(ctx, type, id)) C.fail("ALREADY_EXISTS");
  }
  async notSuspended(ctx, actor) {
    const r = await this.get(ctx, "principal", actor);
    if (r && r.suspended !== false) C.fail("PRINCIPAL_SUSPENDED");
  }
  async event(ctx, operation, ids) {
    const txId = ctx.stub.getTxID();
    await this.fresh(ctx, "audit", txId);
    const entry = {
      operation,
      ids,
      actor: this.actor(ctx),
      txId,
      proposalTime: this.time(ctx),
    };
    await this.put(ctx, "audit", txId, entry);
    ctx.stub.setEvent("BFDRevisionEvent", Buffer.from(C.canonical(entry)));
  }
  async keyRecord(ctx, ref, active = true) {
    C.keyRef(ref);
    const k = await this.get(ctx, "key", ref);
    if (!k) C.fail("KEY_NOT_FOUND");
    if (!["ACTIVE", "RETIRED", "REVOKED"].includes(k.status))
      C.fail("KEY_STATE");
    if (active) {
      if (k.status !== "ACTIVE") C.fail("KEY_NOT_ACTIVE");
      await this.notSuspended(ctx, ref.ownerPrincipal);
      const a = await this.get(ctx, "activeKey", {
        ownerPrincipal: ref.ownerPrincipal,
        purpose: ref.purpose,
      });
      if (!a || !C.equal(a.keyRef, ref)) C.fail("ACTIVE_KEY_BINDING");
    }
    return k;
  }
  envelope(e) {
    C.fields(e, ["core", "signerKeyRef", "signature"]);
    C.keyRef(e.signerKeyRef);
    C.base64(e.signature, 64);
    return e;
  }
  async signed(ctx, kind, envelope, purpose, active = true) {
    this.envelope(envelope);
    if (envelope.signerKeyRef.purpose !== purpose)
      C.fail("WRONG_SIGNER_PURPOSE");
    const key = await this.keyRecord(ctx, envelope.signerKeyRef, active);
    if (!K.verify(kind, envelope.core, envelope.signature, key.publicKey))
      C.fail("BAD_SIGNATURE");
    return key;
  }
  async evidence(ctx, id) {
    C.id(id);
    const e = await this.get(ctx, "evidence", id);
    if (!e) C.fail("EVIDENCE_NOT_FOUND");
    if (!EVIDENCE_STATES.has(e.lifecycle)) C.fail("UNKNOWN_LIFECYCLE");
    C.integer(e.epoch);
    return e;
  }
  async availableEvidence(ctx, id) {
    const e = await this.evidence(ctx, id);
    if (
      e.lifecycle !== "COMMITTED" ||
      !e.acquisitionReceiptDigest ||
      !e.commitRef
    )
      C.fail("EVIDENCE_NOT_DISCLOSABLE");
    await this.notSuspended(ctx, e.preserve.custodianPrincipal);
    return e;
  }
  owner(ctx, e) {
    if (!C.equal(this.actor(ctx), e.preserve.custodianPrincipal))
      C.fail("NOT_DESIGNATED_CUSTODIAN");
    this.role(ctx, ["EvidenceCustodian"]);
  }
  async hold(ctx, eid) {
    const h = await this.get(ctx, "hold", eid);
    if (h && typeof h.active !== "boolean") C.fail("HOLD_STATE");
    return h;
  }
  async noHold(ctx, eid) {
    const h = await this.hold(ctx, eid);
    if (h?.active) C.fail("LEGAL_HOLD");
  }
  async registerPublicKey(ctx, input) {
    return this._register(ctx, input, false);
  }
  async rotatePublicKey(ctx, input) {
    return this._register(ctx, input, true);
  }
  async _register(ctx, input, rotate) {
    C.fields(
      input,
      rotate
        ? ["intent", "signature", "previousKeyRef"]
        : ["intent", "signature"],
    );
    const i = input.intent;
    C.header(
      i,
      [
        "ownerPrincipal",
        "purpose",
        "algorithm",
        "publicKey",
        "fingerprint",
        "keyVersion",
        "intentNonce",
      ],
      this.context(ctx),
    );
    C.principal(i.ownerPrincipal);
    C.integer(i.keyVersion, 1);
    C.hex(i.intentNonce);
    C.hex(i.fingerprint);
    const actor = this.actor(ctx);
    if (!C.equal(actor, i.ownerPrincipal)) C.fail("SELF_REGISTRATION_ONLY");
    if (!Object.hasOwn(P.purposes, i.purpose) || i.algorithm !== "Ed25519")
      C.fail("PURPOSE_OR_ALGORITHM");
    const role = this.role(ctx, P.purposes[i.purpose]);
    await this.notSuspended(ctx, actor);
    if (
      K.fingerprint(i.publicKey) !== i.fingerprint ||
      !K.verify("RegistrationIntentV1", i, input.signature, i.publicKey)
    )
      C.fail("PROOF_OF_POSSESSION");
    const ref = {
      ownerPrincipal: actor,
      purpose: i.purpose,
      version: i.keyVersion,
    };
    const activeId = { ownerPrincipal: actor, purpose: i.purpose },
      old = await this.get(ctx, "activeKey", activeId);
    await this.fresh(ctx, "key", ref);
    await this.fresh(ctx, "registrationNonce", {
      ownerPrincipal: actor,
      nonce: i.intentNonce,
    });
    await this.fresh(ctx, "keyFingerprint", i.fingerprint);
    if (rotate) {
      C.keyRef(input.previousKeyRef);
      if (
        !old ||
        !C.equal(old.keyRef, input.previousKeyRef) ||
        !C.equal(actor, input.previousKeyRef.ownerPrincipal) ||
        input.previousKeyRef.purpose !== i.purpose ||
        i.keyVersion !== input.previousKeyRef.version + 1
      )
        C.fail("ROTATION_BINDING");
      const previous = await this.keyRecord(ctx, input.previousKeyRef, true);
      await this.put(ctx, "key", input.previousKeyRef, {
        ...this.data(previous),
        status: "RETIRED",
        retirementTxRef: ctx.stub.getTxID(),
      });
    } else if (old) {
      const previous = await this.keyRecord(ctx, old.keyRef, false);
      if (
        previous.status !== "REVOKED" ||
        i.keyVersion !== old.keyRef.version + 1
      )
        C.fail("EXPLICIT_ROTATION_REQUIRED");
    } else if (i.keyVersion !== 1) C.fail("FIRST_KEY_VERSION");
    const record = await this.put(ctx, "key", ref, {
      keyRef: ref,
      publicKey: i.publicKey,
      fingerprint: i.fingerprint,
      role,
      status: "ACTIVE",
      registrationTxRef: ctx.stub.getTxID(),
    });
    await this.put(ctx, "activeKey", activeId, { keyRef: ref });
    await this.put(ctx, "keyFingerprint", i.fingerprint, { keyRef: ref });
    await this.put(
      ctx,
      "registrationNonce",
      { ownerPrincipal: actor, nonce: i.intentNonce },
      { keyRef: ref },
    );
    await this.event(ctx, rotate ? "rotatePublicKey" : "registerPublicKey", {
      keyRef: ref,
    });
    return record;
  }
  async revokePublicKey(ctx, i) {
    C.fields(i, ["keyRef", "reasonDigest"]);
    C.hex(i.reasonDigest);
    C.keyRef(i.keyRef);
    // Self-revocation remains available for containment, including while suspended.
    // Administrative revocation of another principal requires active authority.
    if (!C.equal(this.actor(ctx), i.keyRef.ownerPrincipal)) {
      this.role(ctx, ["JudicialReviewer"]);
      await this.notSuspended(ctx, this.actor(ctx));
    }
    const k = await this.keyRecord(ctx, i.keyRef, false);
    if (k.status === "REVOKED") return k;
    const r = await this.put(ctx, "key", i.keyRef, {
      ...this.data(k),
      status: "REVOKED",
      revocationTxRef: ctx.stub.getTxID(),
      reasonDigest: i.reasonDigest,
    });
    await this.event(ctx, "revokePublicKey", { keyRef: i.keyRef });
    return r;
  }
  async setPrincipalSuspension(ctx, i) {
    this.role(ctx, ["JudicialReviewer"]);
    await this.notSuspended(ctx, this.actor(ctx));
    C.fields(i, ["principal", "suspended", "reasonDigest"]);
    C.principal(i.principal);
    C.hex(i.reasonDigest);
    if (typeof i.suspended !== "boolean") C.fail("BOOLEAN_REQUIRED");
    await this.get(ctx, "principal", i.principal);
    const r = await this.put(ctx, "principal", i.principal, {
      principal: i.principal,
      suspended: i.suspended,
      reasonDigest: i.reasonDigest,
      changedTxRef: ctx.stub.getTxID(),
    });
    await this.event(ctx, "setPrincipalSuspension", {
      principal: i.principal,
      suspended: i.suspended,
    });
    return r;
  }
  async preserveEvidence(ctx, i) {
    this.role(ctx, ["GatewayCollector", "ManualCollector"], "Medium");
    await this.notSuspended(ctx, this.actor(ctx));
    C.header(
      i,
      [
        "evidenceId",
        "collectorPrincipal",
        "custodianPrincipal",
        "h_E",
        "totalBytes",
        "sourceMetadataDigest",
      ],
      this.context(ctx),
    );
    C.id(i.evidenceId);
    C.principal(i.collectorPrincipal);
    C.principal(i.custodianPrincipal);
    C.hex(i.h_E);
    C.hex(i.sourceMetadataDigest);
    C.integer(i.totalBytes);
    if (
      !C.equal(i.collectorPrincipal, this.actor(ctx)) ||
      C.equal(i.collectorPrincipal, i.custodianPrincipal)
    )
      C.fail("COLLECTOR_BINDING");
    await this.notSuspended(ctx, i.custodianPrincipal);
    const digest = C.hash("PreserveCoreV1", i),
      old = await this.get(ctx, "evidence", i.evidenceId);
    if (old) {
      await this.evidence(ctx, i.evidenceId);
      if (old.preserveDigest === digest) return old;
      C.fail("EVIDENCE_ID_IMMUTABLE");
    }
    const r = await this.put(ctx, "evidence", i.evidenceId, {
      preserve: i,
      preserveDigest: digest,
      lifecycle: "PRESERVED",
      epoch: 0,
      preserveTxRef: ctx.stub.getTxID(),
    });
    await this.event(ctx, "preserveEvidence", { evidenceId: i.evidenceId });
    return r;
  }
  async assignAcquisitionAuditor(ctx, i) {
    this.role(ctx, ["JudicialReviewer"]);
    await this.notSuspended(ctx, this.actor(ctx));
    C.fields(i, [
      "assignmentId",
      "evidenceId",
      "preserveDigest",
      "auditorPrincipal",
      "auditorKeyRef",
      "expiresAt",
    ]);
    C.id(i.assignmentId);
    C.principal(i.auditorPrincipal);
    C.hex(i.preserveDigest);
    C.integer(i.expiresAt);
    const e = await this.evidence(ctx, i.evidenceId),
      t = this.time(ctx);
    if (
      e.lifecycle !== "PRESERVED" ||
      e.preserveDigest !== i.preserveDigest ||
      i.expiresAt <= t ||
      i.expiresAt - t > P.maxAssignmentTTL
    )
      C.fail("ASSIGNMENT_STATE_OR_TIME");
    if (
      !C.equal(i.auditorKeyRef.ownerPrincipal, i.auditorPrincipal) ||
      i.auditorKeyRef.purpose !== "ACQUISITION_VALIDATION"
    )
      C.fail("AUDITOR_KEY_BINDING");
    await this.keyRecord(ctx, i.auditorKeyRef, true);
    const actor = this.actor(ctx),
      ec = e.preserve.custodianPrincipal;
    if (
      C.equal(ec, i.auditorPrincipal) ||
      ec.mspId === i.auditorPrincipal.mspId ||
      C.equal(actor, ec) ||
      C.equal(actor, i.auditorPrincipal)
    )
      C.fail("AUDITOR_INDEPENDENCE");
    await this.fresh(ctx, "assignment", i.assignmentId);
    await this.get(ctx, "assignmentCurrent", i.evidenceId);
    const r = await this.put(ctx, "assignment", i.assignmentId, {
      ...i,
      assignedByJR: actor,
      status: "ACTIVE",
      assignmentTxRef: ctx.stub.getTxID(),
    });
    await this.put(ctx, "assignmentCurrent", i.evidenceId, {
      assignmentId: i.assignmentId,
    });
    await this.event(ctx, "assignAcquisitionAuditor", {
      evidenceId: i.evidenceId,
      assignmentId: i.assignmentId,
    });
    return r;
  }
  async revokeAcquisitionAssignment(ctx, i) {
    this.role(ctx, ["JudicialReviewer"]);
    await this.notSuspended(ctx, this.actor(ctx));
    C.fields(i, ["assignmentId", "reasonDigest"]);
    C.id(i.assignmentId);
    C.hex(i.reasonDigest);
    const a = await this.get(ctx, "assignment", i.assignmentId);
    if (!a) C.fail("ASSIGNMENT_NOT_FOUND");
    const r = await this.put(ctx, "assignment", i.assignmentId, {
      ...this.data(a),
      status: "REVOKED",
      reasonDigest: i.reasonDigest,
      revocationTxRef: ctx.stub.getTxID(),
    });
    await this.event(ctx, "revokeAcquisitionAssignment", {
      assignmentId: i.assignmentId,
    });
    return r;
  }
  async commitPreservedEvidence(ctx, i) {
    C.fields(i, ["evidenceId", "params", "receipt"]);
    C.id(i.evidenceId);
    K.params(i.params);
    this.envelope(i.receipt);
    const e = await this.evidence(ctx, i.evidenceId);
    this.owner(ctx, e);
    await this.notSuspended(ctx, this.actor(ctx));
    const c = i.receipt.core;
    C.header(
      c,
      [
        "evidenceId",
        "preserveDigest",
        "assignmentId",
        "auditJobId",
        "auditorPrincipal",
        "auditorKeyRef",
        "h_E",
        "R",
        "totalBytes",
        "z",
        "m",
        "commitmentVersion",
        "oddNodeRule",
        "validationMethodVersion",
        "outcome",
      ],
      this.context(ctx),
    );
    C.id(c.auditJobId);
    C.id(c.assignmentId);
    C.principal(c.auditorPrincipal);
    C.keyRef(c.auditorKeyRef);
    const receiptDigest = C.hash("AcquisitionReceiptV1", c);
    if (e.lifecycle === "COMMITTED") {
      if (
        e.acquisitionReceiptDigest === receiptDigest &&
        C.equal(e.params, i.params)
      )
        return e;
      C.fail("COMMITMENT_IMMUTABLE");
    }
    if (e.lifecycle !== "PRESERVED") C.fail("NOT_PRESERVED");
    if (
      c.evidenceId !== i.evidenceId ||
      c.preserveDigest !== e.preserveDigest ||
      c.h_E !== e.preserve.h_E ||
      c.totalBytes !== e.preserve.totalBytes ||
      c.outcome !== "PASS" ||
      c.validationMethodVersion !== P.validationMethodVersion
    )
      C.fail("AUDIT_ANCHOR_MISMATCH");
    for (const [k, v] of Object.entries(i.params))
      if (c[k] !== v) C.fail("AUDIT_PARAM_MISMATCH:" + k);
    if (
      !C.equal(c.auditorKeyRef, i.receipt.signerKeyRef) ||
      !C.equal(c.auditorPrincipal, c.auditorKeyRef.ownerPrincipal)
    )
      C.fail("AUDITOR_BINDING");
    const current = await this.get(ctx, "assignmentCurrent", i.evidenceId),
      a = await this.get(ctx, "assignment", c.assignmentId);
    if (
      !a ||
      a.status !== "ACTIVE" ||
      a.expiresAt <= this.time(ctx) ||
      current?.assignmentId !== a.assignmentId ||
      a.evidenceId !== i.evidenceId ||
      a.preserveDigest !== e.preserveDigest ||
      !C.equal(a.auditorKeyRef, c.auditorKeyRef) ||
      !C.equal(a.auditorPrincipal, c.auditorPrincipal)
    )
      C.fail("AUDIT_ASSIGNMENT");
    await this.notSuspended(ctx, a.assignedByJR);
    if (
      C.equal(e.preserve.custodianPrincipal, c.auditorPrincipal) ||
      e.preserve.custodianPrincipal.mspId === c.auditorPrincipal.mspId
    )
      C.fail("AUDITOR_INDEPENDENCE");
    await this.signed(
      ctx,
      "AcquisitionReceiptV1",
      i.receipt,
      "ACQUISITION_VALIDATION",
    );
    const r = await this.put(ctx, "evidence", i.evidenceId, {
      ...this.data(e),
      lifecycle: "COMMITTED",
      params: i.params,
      acquisitionReceipt: i.receipt,
      acquisitionReceiptDigest: receiptDigest,
      commitRef: ctx.stub.getTxID(),
    });
    await this.event(ctx, "commitPreservedEvidence", {
      evidenceId: i.evidenceId,
      acquisitionReceiptDigest: receiptDigest,
    });
    return r;
  }
  validateCapability(c, ctx, e) {
    C.header(
      c,
      [
        "capId",
        "evidenceId",
        "commitRef",
        "acquisitionReceiptDigest",
        "issuerPrincipal",
        "issuerKeyRef",
        "granteePrincipal",
        "usageMode",
        "capabilityScope",
        "epoch",
        "policyVersion",
        "issuedAt",
        "notBefore",
        "expiresAt",
        "allowedLifecycle",
      ],
      this.context(ctx),
    );
    C.id(c.capId);
    C.principal(c.issuerPrincipal);
    C.principal(c.granteePrincipal);
    C.keyRef(c.issuerKeyRef);
    C.hex(c.acquisitionReceiptDigest);
    for (const k of [
      "epoch",
      "policyVersion",
      "issuedAt",
      "notBefore",
      "expiresAt",
    ])
      C.integer(c[k]);
    C.scope(c.capabilityScope, e.params.m);
    if (
      c.usageMode !== "SINGLE_USE" ||
      c.policyVersion !== P.policyVersion ||
      !C.equal(c.allowedLifecycle, ["COMMITTED"]) ||
      c.epoch !== e.epoch ||
      c.commitRef !== e.commitRef ||
      c.acquisitionReceiptDigest !== e.acquisitionReceiptDigest ||
      c.evidenceId !== e.preserve.evidenceId
    )
      C.fail("CAPABILITY_BINDING");
    if (
      !C.equal(c.issuerPrincipal, e.preserve.custodianPrincipal) ||
      !C.equal(c.issuerKeyRef.ownerPrincipal, c.issuerPrincipal) ||
      c.issuerKeyRef.purpose !== "CAPABILITY_ISSUER"
    )
      C.fail("CAPABILITY_ISSUER");
    if (
      c.expiresAt <= c.issuedAt ||
      c.expiresAt - c.issuedAt > P.maxCapTTL ||
      c.notBefore < c.issuedAt ||
      c.notBefore >= c.expiresAt
    )
      C.fail("CAPABILITY_VALIDITY");
  }
  async issueDisclosureCapability(ctx, i) {
    this.envelope(i);
    const c = i.core,
      e = await this.availableEvidence(ctx, c.evidenceId);
    this.owner(ctx, e);
    this.validateCapability(c, ctx, e);
    if (!C.equal(i.signerKeyRef, c.issuerKeyRef)) C.fail("CAPABILITY_KEY");
    const t = this.time(ctx);
    if (Math.abs(c.issuedAt - t) > P.issuanceSkew || t >= c.expiresAt)
      C.fail("CAPABILITY_ISSUANCE_TIME");
    await this.notSuspended(ctx, c.granteePrincipal);
    await this.signed(ctx, "CapabilityCoreV1", i, "CAPABILITY_ISSUER");
    await this.fresh(ctx, "capability", c.capId);
    const r = await this.put(ctx, "capability", c.capId, {
      token: i,
      capHash: C.hash("CapabilityCoreV1", c),
      useState: "AVAILABLE",
      revoked: false,
      issueTxRef: ctx.stub.getTxID(),
    });
    await this.event(ctx, "issueDisclosureCapability", {
      capId: c.capId,
      evidenceId: c.evidenceId,
    });
    return r;
  }
  async capability(ctx, id) {
    C.id(id);
    const r = await this.get(ctx, "capability", id);
    if (!r) C.fail("CAPABILITY_NOT_FOUND");
    if (
      !["AVAILABLE", "CONSUMED"].includes(r.useState) ||
      typeof r.revoked !== "boolean"
    )
      C.fail("CAPABILITY_STATE");
    return r;
  }
  async eligible(ctx, cap, session) {
    const c = cap.token.core,
      e = await this.availableEvidence(ctx, c.evidenceId);
    this.validateCapability(c, ctx, e);
    if (cap.revoked) C.fail("CAPABILITY_REVOKED");
    await this.notSuspended(ctx, c.granteePrincipal);
    await this.keyRecord(ctx, c.issuerKeyRef, true);
    const t = this.time(ctx);
    if (t < c.notBefore || t >= c.expiresAt)
      C.fail("CAPABILITY_EXPIRED_OR_EARLY");
    if (session) {
      if (
        session.epoch !== e.epoch ||
        session.policyVersion !== P.policyVersion ||
        session.commitRef !== e.commitRef ||
        session.capHash !== cap.capHash ||
        session.acquisitionReceiptDigest !== e.acquisitionReceiptDigest ||
        session.sessionExpiresAt <= t
      )
        C.fail("SESSION_INELIGIBLE");
      if (
        cap.useState !== "CONSUMED" ||
        cap.consumedBySessionId !== session.sessionId
      )
        C.fail("SESSION_CONSUMPTION_BINDING");
    }
    return e;
  }
  async requestDisclosure(ctx, i) {
    C.header(
      i,
      ["requestId", "capId", "capHash", "granteePrincipal", "requestedScope"],
      this.context(ctx),
    );
    C.hex(i.requestId);
    C.hex(i.capHash);
    C.principal(i.granteePrincipal);
    if (!C.equal(i.granteePrincipal, this.actor(ctx)))
      C.fail("BOUND_GRANTEE_REQUIRED");
    const cap = await this.capability(ctx, i.capId),
      c = cap.token.core;
    if (
      (c.granteePrincipal &&
        !C.equal(c.granteePrincipal, i.granteePrincipal)) ||
      cap.capHash !== i.capHash
    )
      C.fail("REQUEST_BINDING");
    const fingerprint = C.hash("RequestCoreV1", i),
      replayId = { principal: i.granteePrincipal, requestId: i.requestId };
    const old = await this.get(ctx, "requestReplay", replayId);
    if (old) {
      if (old.requestFingerprint !== fingerprint) C.fail("REQUEST_ID_CONFLICT");
      return {
        session: await this.session(ctx, old.sessionId),
        alreadyRecorded: true,
      };
    }
    const e = await this.eligible(ctx, cap);
    if (cap.useState !== "AVAILABLE") C.fail("CAPABILITY_CONSUMED");
    if (!C.subset(i.requestedScope, c.capabilityScope, e.params.m))
      C.fail("SCOPE_NOT_AUTHORIZED");
    const sessionId = C.hash("SessionIdV1", {
      context: this.context(ctx),
      capId: i.capId,
      granteePrincipal: i.granteePrincipal,
      requestId: i.requestId,
    });
    await this.fresh(ctx, "session", sessionId);
    const t = this.time(ctx);
    const session = {
      sessionId,
      requestFingerprint: fingerprint,
      requestId: i.requestId,
      capId: i.capId,
      capHash: i.capHash,
      evidenceId: c.evidenceId,
      commitRef: e.commitRef,
      acquisitionReceiptDigest: e.acquisitionReceiptDigest,
      granteePrincipal: i.granteePrincipal,
      finalizerPrincipal: e.preserve.custodianPrincipal,
      requestedScope: i.requestedScope,
      scopeDigest: C.hash("ScopeV1", i.requestedScope),
      epoch: e.epoch,
      policyVersion: P.policyVersion,
      requestTxRef: ctx.stub.getTxID(),
      requestTime: t,
      sessionExpiresAt: Math.min(t + P.maxSessionTTL, c.expiresAt),
      status: "OPEN",
    };
    const r = await this.put(ctx, "session", sessionId, session);
    await this.put(ctx, "capability", i.capId, {
      ...this.data(cap),
      useState: "CONSUMED",
      consumedBySessionId: sessionId,
    });
    await this.put(ctx, "requestReplay", replayId, {
      sessionId,
      requestFingerprint: fingerprint,
    });
    await this.event(ctx, "requestDisclosure", { sessionId, capId: i.capId });
    return { session: r, alreadyRecorded: false };
  }
  async session(ctx, id) {
    C.hex(id);
    const r = await this.get(ctx, "session", id);
    if (!r || !["OPEN", "FINALIZED"].includes(r.status))
      C.fail("SESSION_NOT_FOUND_OR_STATE");
    return r;
  }
  async finalizeDisclosure(ctx, i) {
    C.fields(i, ["sessionId", "bundleHash", "scopeDigest", "commitRef"]);
    C.hex(i.bundleHash);
    C.hex(i.scopeDigest);
    const s = await this.session(ctx, i.sessionId);
    if (!C.equal(this.actor(ctx), s.finalizerPrincipal))
      C.fail("FINALIZER_BINDING");
    this.role(ctx, ["EvidenceCustodian"]);
    if (s.scopeDigest !== i.scopeDigest || s.commitRef !== i.commitRef)
      C.fail("FINALIZE_METADATA_BINDING");
    if (s.status === "FINALIZED") {
      if (s.bundleHash !== i.bundleHash) C.fail("FINALIZED_HASH_IMMUTABLE");
      return {
        receipt: await this.get(ctx, "receipt", s.sessionId),
        alreadyRecorded: true,
      };
    }
    const cap = await this.capability(ctx, s.capId);
    await this.eligible(ctx, cap, s);
    await this.fresh(ctx, "receipt", s.sessionId);
    const r = await this.put(ctx, "receipt", s.sessionId, {
      context: this.context(ctx),
      sessionId: s.sessionId,
      bundleHash: i.bundleHash,
      scopeDigest: s.scopeDigest,
      commitRef: s.commitRef,
      acquisitionReceiptDigest: s.acquisitionReceiptDigest,
      finalizerPrincipal: s.finalizerPrincipal,
      epoch: s.epoch,
      policyVersion: s.policyVersion,
      finalizedTxRef: ctx.stub.getTxID(),
      assurance: "FINALIZE_AUTHORIZATION_ONLY",
    });
    await this.put(ctx, "session", s.sessionId, {
      ...this.data(s),
      status: "FINALIZED",
      bundleHash: i.bundleHash,
      finalizedTxRef: ctx.stub.getTxID(),
    });
    await this.event(ctx, "finalizeDisclosure", {
      sessionId: s.sessionId,
      bundleHash: i.bundleHash,
    });
    return { receipt: r, alreadyRecorded: false };
  }
  async revokeDisclosureCapability(ctx, i) {
    C.fields(i, ["capId", "reasonDigest"]);
    C.hex(i.reasonDigest);
    const cap = await this.capability(ctx, i.capId);
    if (!C.equal(this.actor(ctx), cap.token.core.issuerPrincipal))
      this.role(ctx, ["JudicialReviewer"]);
    await this.notSuspended(ctx, this.actor(ctx));
    if (cap.revoked) return cap;
    const r = await this.put(ctx, "capability", i.capId, {
      ...this.data(cap),
      revoked: true,
      revocationTxRef: ctx.stub.getTxID(),
      reasonDigest: i.reasonDigest,
    });
    await this.event(ctx, "revokeDisclosureCapability", { capId: i.capId });
    return r;
  }
  async placeLegalHold(ctx, i) {
    return this._hold(ctx, i, true);
  }
  async releaseLegalHold(ctx, i) {
    return this._hold(ctx, i, false);
  }
  async _hold(ctx, i, active) {
    this.role(ctx, ["JudicialReviewer"]);
    await this.notSuspended(ctx, this.actor(ctx));
    C.fields(i, ["evidenceId", "holdId", "reasonDigest"]);
    C.id(i.holdId);
    C.hex(i.reasonDigest);
    await this.evidence(ctx, i.evidenceId);
    const old = await this.hold(ctx, i.evidenceId);
    if (active) {
      if (old?.active) C.fail("HOLD_ALREADY_ACTIVE");
      await this.fresh(ctx, "holdHistory", i.holdId);
    } else if (!old?.active || old.holdId !== i.holdId) C.fail("HOLD_BINDING");
    const r = await this.put(ctx, "hold", i.evidenceId, {
      ...i,
      active,
      changedTxRef: ctx.stub.getTxID(),
    });
    if (active)
      await this.put(ctx, "holdHistory", i.holdId, {
        ...i,
        createdTxRef: ctx.stub.getTxID(),
      });
    await this.fresh(ctx, "holdEvent", ctx.stub.getTxID());
    await this.put(ctx, "holdEvent", ctx.stub.getTxID(), {
      ...i,
      active,
      changedTxRef: ctx.stub.getTxID(),
    });
    await this.event(ctx, active ? "placeLegalHold" : "releaseLegalHold", {
      evidenceId: i.evidenceId,
      holdId: i.holdId,
    });
    return r;
  }
  async restrictEvidence(ctx, i) {
    return this._restrict(ctx, i, "RESTRICTED");
  }
  async withdrawEvidence(ctx, i) {
    return this._restrict(ctx, i, "WITHDRAWN");
  }
  async _restrict(ctx, i, state) {
    this.role(ctx, ["JudicialReviewer", "DataProtectionOfficer"]);
    await this.notSuspended(ctx, this.actor(ctx));
    C.fields(i, ["evidenceId", "reasonDigest"]);
    C.hex(i.reasonDigest);
    const e = await this.evidence(ctx, i.evidenceId);
    if (!["PRESERVED", "COMMITTED", "RESTRICTED"].includes(e.lifecycle))
      C.fail("TERMINAL_OR_DESTRUCTION_STATE");
    const r = await this.put(ctx, "evidence", i.evidenceId, {
      ...this.data(e),
      lifecycle: state,
      epoch: e.epoch + 1,
      restrictionTxRef: ctx.stub.getTxID(),
      reasonDigest: i.reasonDigest,
    });
    await this.event(
      ctx,
      state === "RESTRICTED" ? "restrictEvidence" : "withdrawEvidence",
      { evidenceId: i.evidenceId },
    );
    return r;
  }
  async requestEvidenceDestruction(ctx, i) {
    this.role(ctx, ["DataProtectionOfficer"]);
    await this.notSuspended(ctx, this.actor(ctx));
    C.fields(i, ["evidenceId", "reasonDigest"]);
    C.hex(i.reasonDigest);
    const e = await this.evidence(ctx, i.evidenceId);
    await this.noHold(ctx, i.evidenceId);
    if (C.equal(this.actor(ctx), e.preserve.custodianPrincipal))
      C.fail("DESTRUCTION_SEPARATION");
    if (!["COMMITTED", "RESTRICTED", "WITHDRAWN"].includes(e.lifecycle))
      C.fail("DESTRUCTION_STATE");
    await this.fresh(ctx, "destruction", i.evidenceId);
    const r = await this.put(ctx, "destruction", i.evidenceId, {
      evidenceId: i.evidenceId,
      status: "REQUESTED",
      requestRef: ctx.stub.getTxID(),
      requestedBy: this.actor(ctx),
      reasonDigest: i.reasonDigest,
      epoch: e.epoch + 1,
      requiredKeyClasses: P.requiredKeyClasses,
    });
    await this.put(ctx, "evidence", i.evidenceId, {
      ...this.data(e),
      lifecycle: "DESTRUCTION_REQUESTED",
      epoch: e.epoch + 1,
    });
    await this.event(ctx, "requestEvidenceDestruction", {
      evidenceId: i.evidenceId,
    });
    return r;
  }
  async approveEvidenceDestruction(ctx, i) {
    this.role(ctx, ["JudicialReviewer"]);
    await this.notSuspended(ctx, this.actor(ctx));
    C.fields(i, ["evidenceId", "requestRef"]);
    const e = await this.evidence(ctx, i.evidenceId),
      d = await this.get(ctx, "destruction", i.evidenceId);
    await this.noHold(ctx, i.evidenceId);
    if (
      e.lifecycle !== "DESTRUCTION_REQUESTED" ||
      d?.status !== "REQUESTED" ||
      d.requestRef !== i.requestRef
    )
      C.fail("DESTRUCTION_REQUEST_BINDING");
    if (
      C.equal(this.actor(ctx), d.requestedBy) ||
      C.equal(this.actor(ctx), e.preserve.custodianPrincipal)
    )
      C.fail("DESTRUCTION_SEPARATION");
    const r = await this.put(ctx, "destruction", i.evidenceId, {
      ...this.data(d),
      status: "APPROVED",
      approvalRef: ctx.stub.getTxID(),
      approvedBy: this.actor(ctx),
    });
    await this.put(ctx, "evidence", i.evidenceId, {
      ...this.data(e),
      lifecycle: "DESTRUCTION_APPROVED",
    });
    await this.event(ctx, "approveEvidenceDestruction", {
      evidenceId: i.evidenceId,
    });
    return r;
  }
  async beginKeyErasure(ctx, i) {
    C.fields(i, ["evidenceId", "operationId", "approvalRef"]);
    C.id(i.operationId);
    const e = await this.evidence(ctx, i.evidenceId);
    this.owner(ctx, e);
    await this.notSuspended(ctx, this.actor(ctx));
    const old = await this.get(ctx, "erasure", i.operationId);
    if (old) {
      if (old.evidenceId === i.evidenceId && old.approvalRef === i.approvalRef)
        return { operation: old, alreadyRecorded: true };
      C.fail("OPERATION_ID_CONFLICT");
    }
    const d = await this.get(ctx, "destruction", i.evidenceId);
    await this.noHold(ctx, i.evidenceId);
    if (
      e.lifecycle !== "DESTRUCTION_APPROVED" ||
      d?.status !== "APPROVED" ||
      d.approvalRef !== i.approvalRef
    )
      C.fail("DESTRUCTION_APPROVAL_BINDING");
    const r = await this.put(ctx, "erasure", i.operationId, {
      operationId: i.operationId,
      evidenceId: i.evidenceId,
      approvalRef: i.approvalRef,
      requestRef: d.requestRef,
      epoch: e.epoch,
      status: "ERASURE_AUTHORIZED",
      authorizedTxRef: ctx.stub.getTxID(),
      authorizedBy: this.actor(ctx),
    });
    await this.put(ctx, "destruction", i.evidenceId, {
      ...this.data(d),
      status: "ERASURE_AUTHORIZED",
      operationId: i.operationId,
    });
    await this.event(ctx, "beginKeyErasure", {
      evidenceId: i.evidenceId,
      operationId: i.operationId,
    });
    return { operation: r, alreadyRecorded: false };
  }
  async reportEvidenceDestroyed(ctx, i) {
    C.fields(i, ["statement", "attestations"]);
    const s = i.statement;
    C.header(
      s,
      [
        "evidenceId",
        "destructionRequestRef",
        "approvalRef",
        "erasureOperationRef",
        "priorOperationRefs",
        "epoch",
        "policyVersion",
        "completedAtClaim",
        "outcome",
        "destroyedKeyClasses",
        "retainedCopyLimitationsDigest",
      ],
      this.context(ctx),
    );
    C.integer(s.epoch);
    C.integer(s.completedAtClaim);
    C.hex(s.retainedCopyLimitationsDigest);
    if (
      !["COMPLETED", "PARTIAL", "FAILED", "ABORTED_BEFORE_ERASURE"].includes(
        s.outcome,
      ) ||
      !Array.isArray(s.priorOperationRefs) ||
      !Array.isArray(s.destroyedKeyClasses) ||
      !Array.isArray(i.attestations) ||
      i.attestations.length > 3
    )
      C.fail("DESTRUCTION_STATEMENT");
    const classes = s.destroyedKeyClasses;
    if (
      !C.equal(classes, [...new Set(classes)].sort()) ||
      classes.some((x) => !P.requiredKeyClasses.includes(x))
    )
      C.fail("SIGNED_KEY_CLASSES");
    const e = await this.evidence(ctx, s.evidenceId);
    this.owner(ctx, e);
    await this.notSuspended(ctx, this.actor(ctx));
    const op = await this.get(ctx, "erasure", s.erasureOperationRef),
      d = await this.get(ctx, "destruction", s.evidenceId),
      statementDigest = C.hash("DestructionStatementV1", s);
    if (op?.status === "REPORTED") {
      if (op.statementDigest === statementDigest) return op;
      C.fail("ERASURE_REPORT_IMMUTABLE");
    }
    if (
      !op ||
      op.evidenceId !== s.evidenceId ||
      op.status !== "ERASURE_AUTHORIZED" ||
      d?.status !== "ERASURE_AUTHORIZED" ||
      d.operationId !== s.erasureOperationRef ||
      e.lifecycle !== "DESTRUCTION_APPROVED" ||
      op.approvalRef !== s.approvalRef ||
      op.requestRef !== s.destructionRequestRef ||
      s.epoch !== e.epoch ||
      s.policyVersion !== P.policyVersion
    )
      C.fail("ERASURE_OPERATION_BINDING");
    const prior = new Set();
    for (const id of s.priorOperationRefs) {
      C.id(id);
      if (prior.has(id) || id === s.erasureOperationRef)
        C.fail("PRIOR_OPERATION_DUPLICATE");
      prior.add(id);
      const p = await this.get(ctx, "erasure", id);
      if (p?.status !== "REPORTED" || p.evidenceId !== s.evidenceId)
        C.fail("PRIOR_OPERATION_BINDING");
    }
    const actors = new Set(),
      roles = new Set(),
      fingerprints = new Set();
    for (const a of i.attestations) {
      C.fields(a, ["signerKeyRef", "signature"]);
      const k = await this.signed(
        ctx,
        "DestructionStatementV1",
        { core: s, ...a },
        "DESTRUCTION_ATTESTATION",
      );
      const owner = a.signerKeyRef.ownerPrincipal;
      if (
        (k.role === "EvidenceCustodian" &&
          !C.equal(owner, e.preserve.custodianPrincipal)) ||
        (k.role === "DataProtectionOfficer" &&
          !C.equal(owner, d.requestedBy)) ||
        (k.role === "JudicialReviewer" && !C.equal(owner, d.approvedBy))
      )
        C.fail("ATTESTOR_ASSIGNMENT");
      const actor = C.hash("PrincipalV1", owner);
      if (
        actors.has(actor) ||
        roles.has(k.role) ||
        fingerprints.has(k.fingerprint)
      )
        C.fail("DISTINCT_ATTESTORS");
      actors.add(actor);
      roles.add(k.role);
      fingerprints.add(k.fingerprint);
    }
    if (s.outcome === "COMPLETED") {
      if (actors.size < 2 || !C.equal(classes, P.requiredKeyClasses))
        C.fail("DESTRUCTION_THRESHOLD_OR_CLASSES");
    } else if (!actors.has(C.hash("PrincipalV1", this.actor(ctx))))
      C.fail("EC_FAILURE_ATTESTATION_REQUIRED");
    const hold = await this.hold(ctx, s.evidenceId);
    const record = await this.put(ctx, "erasure", s.erasureOperationRef, {
      ...this.data(op),
      status: "REPORTED",
      statement: s,
      attestations: i.attestations,
      statementDigest,
      reportTxRef: ctx.stub.getTxID(),
      lateHoldActive: !!hold?.active,
    });
    const completed = s.outcome === "COMPLETED";
    await this.put(ctx, "destruction", s.evidenceId, {
      ...this.data(d),
      status: completed ? "DESTROYED" : "REQUESTED",
      latestOperationId: s.erasureOperationRef,
      outcome: s.outcome,
    });
    await this.put(ctx, "evidence", s.evidenceId, {
      ...this.data(e),
      lifecycle: completed ? "DESTROYED" : "DESTRUCTION_REQUESTED",
      destructionReportRef: ctx.stub.getTxID(),
    });
    await this.event(ctx, "reportEvidenceDestroyed", {
      evidenceId: s.evidenceId,
      operationId: s.erasureOperationRef,
      outcome: s.outcome,
      lateHoldActive: !!hold?.active,
    });
    return record;
  }
  async getEvidenceAnchor(ctx, i) {
    C.fields(i, ["evidenceId"]);
    return this.evidence(ctx, i.evidenceId);
  }
  async getDisclosureSession(ctx, i) {
    C.fields(i, ["sessionId"]);
    return this.session(ctx, i.sessionId);
  }
  async getFinalizationReceipt(ctx, i) {
    C.fields(i, ["sessionId"]);
    C.hex(i.sessionId);
    const r = await this.get(ctx, "receipt", i.sessionId);
    if (!r) C.fail("RECEIPT_NOT_FOUND");
    return r;
  }
  async getKeyVersion(ctx, i) {
    C.fields(i, ["keyRef"]);
    return this.keyRecord(ctx, i.keyRef, false);
  }
  async getEligibility(ctx, i) {
    C.fields(i, ["sessionId"]);
    const s = await this.session(ctx, i.sessionId),
      cap = await this.capability(ctx, s.capId);
    try {
      await this.eligible(ctx, cap, s);
      return {
        eligible: s.status === "FINALIZED",
        buildEligible: true,
        proposalTime: this.time(ctx),
        sessionExpiresAt: s.sessionExpiresAt,
        capExpiresAt: cap.token.core.expiresAt,
        status: s.status,
        sessionId: s.sessionId,
        bundleHash: s.bundleHash || null,
        assurance: "LEDGER_VIEW_NOT_WALL_CLOCK",
      };
    } catch (err) {
      return {
        eligible: false,
        reason: err.message,
        proposalTime: this.time(ctx),
        sessionId: s.sessionId,
        assurance: "LEDGER_VIEW_NOT_WALL_CLOCK",
      };
    }
  }
  async getErasureOperation(ctx, i) {
    C.fields(i, ["operationId"]);
    C.id(i.operationId);
    const op = await this.get(ctx, "erasure", i.operationId);
    if (!op) C.fail("OPERATION_NOT_FOUND");
    return {
      operation: op,
      hold: await this.hold(ctx, op.evidenceId),
      evidence: await this.evidence(ctx, op.evidenceId),
    };
  }
  async getReleaseAuthorization(ctx, i) {
    C.header(
      i,
      ["sessionId", "bundleHash", "nonce", "expiresAt", "granteePrincipal"],
      this.context(ctx),
    );
    C.hex(i.sessionId);
    C.hex(i.bundleHash);
    C.hex(i.nonce);
    C.integer(i.expiresAt);
    C.principal(i.granteePrincipal);
    const s = await this.session(ctx, i.sessionId),
      t = this.time(ctx);
    if (
      !C.equal(this.actor(ctx), s.granteePrincipal) ||
      !C.equal(i.granteePrincipal, s.granteePrincipal) ||
      s.status !== "FINALIZED" ||
      s.bundleHash !== i.bundleHash ||
      i.expiresAt <= t ||
      i.expiresAt - t > 60
    )
      C.fail("RELEASE_CHALLENGE_BINDING");
    await this.eligible(ctx, await this.capability(ctx, s.capId), s);
    return {
      challenge: i,
      principal: this.actor(ctx),
      assurance: "AUTHENTICATED_RELEASE_QUERY",
    };
  }
}
const METHODS = Object.getOwnPropertyNames(RevisionService.prototype).filter(
  (n) =>
    [
      "registerPublicKey",
      "rotatePublicKey",
      "revokePublicKey",
      "setPrincipalSuspension",
      "preserveEvidence",
      "assignAcquisitionAuditor",
      "revokeAcquisitionAssignment",
      "commitPreservedEvidence",
      "issueDisclosureCapability",
      "requestDisclosure",
      "finalizeDisclosure",
      "revokeDisclosureCapability",
      "placeLegalHold",
      "releaseLegalHold",
      "restrictEvidence",
      "withdrawEvidence",
      "requestEvidenceDestruction",
      "approveEvidenceDestruction",
      "beginKeyErasure",
      "reportEvidenceDestroyed",
      "getEvidenceAnchor",
      "getDisclosureSession",
      "getFinalizationReceipt",
      "getKeyVersion",
      "getEligibility",
      "getErasureOperation",
      "getReleaseAuthorization",
    ].includes(n),
);
module.exports = { RevisionService, METHODS };
