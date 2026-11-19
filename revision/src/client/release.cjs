"use strict";
const crypto = require("node:crypto");
const { performance } = require("node:perf_hooks");
const C = require("../shared/canonical.cjs");
const B = require("./bundle.cjs");
class ReleaseController {
  constructor({
    ledger,
    resolveEvidence,
    clockHealthy,
    now = () => Math.floor(Date.now() / 1000),
    monotonic = () => performance.now(),
    refreshMs = 5000,
    maxEligibilityQueryMs = 5000,
  }) {
    if (
      typeof ledger?.authenticateRelease !== "function" ||
      typeof resolveEvidence !== "function" ||
      typeof clockHealthy !== "function"
    )
      C.fail("RELEASE_TRUST_PROVIDERS_REQUIRED");
    if (!Number.isFinite(refreshMs) || refreshMs < 0 || refreshMs > 5000)
      C.fail("ELIGIBILITY_REFRESH_BOUND");
    if (
      !Number.isFinite(maxEligibilityQueryMs) ||
      maxEligibilityQueryMs <= 0 ||
      maxEligibilityQueryMs > 5000
    )
      C.fail("ELIGIBILITY_QUERY_BOUND");
    Object.assign(this, {
      ledger,
      resolveEvidence,
      clockHealthy,
      now,
      monotonic,
      refreshMs,
      maxEligibilityQueryMs,
    });
    this.challenges = new Map();
    this.lastTime = 0;
  }
  async time() {
    if (!(await this.clockHealthy())) C.fail("CLOCK_UNHEALTHY");
    const t = C.integer(this.now());
    if (t < this.lastTime) C.fail("CLOCK_MOVED_BACKWARDS");
    this.lastTime = t;
    return t;
  }
  async challenge(sessionId) {
    C.hex(sessionId);
    let t = await this.time();
    for (const [nonce, c] of this.challenges)
      if (c.expiresAt <= t) this.challenges.delete(nonce);
    if (this.challenges.size >= 1000) C.fail("CHALLENGE_LIMIT");
    const session = await this.ledger.query("getDisclosureSession", {
        sessionId,
      }),
      eligibility = await this.ledger.query("getEligibility", { sessionId });
    t = await this.time();
    if (
      session.status !== "FINALIZED" ||
      !eligibility.eligible ||
      eligibility.sessionId !== sessionId ||
      eligibility.bundleHash !== session.bundleHash ||
      t >= eligibility.sessionExpiresAt ||
      t >= eligibility.capExpiresAt
    )
      C.fail("RELEASE_INELIGIBLE");
    const anchor = await this.ledger.query("getEvidenceAnchor", {
      evidenceId: session.evidenceId,
    });
    t = await this.time();
    if (t >= eligibility.sessionExpiresAt || t >= eligibility.capExpiresAt)
      C.fail("RELEASE_INELIGIBLE");
    const c = {
      schemaVersion: 1,
      context: anchor.preserve.context,
      sessionId,
      bundleHash: session.bundleHash,
      nonce: crypto.randomBytes(32).toString("hex"),
      expiresAt: Math.min(
        t + 60,
        eligibility.sessionExpiresAt,
        eligibility.capExpiresAt,
      ),
      granteePrincipal: session.granteePrincipal,
    };
    // Concurrent asynchronous challenges must also obey the capacity bound.
    if (this.challenges.size >= 1000) C.fail("CHALLENGE_LIMIT");
    this.challenges.set(c.nonce, c);
    return c;
  }
  async *release(proof) {
    C.fields(proof, ["challenge", "proposalBytes", "signature"]);
    const supplied = proof.challenge;
    C.hex(supplied.nonce);
    const challenge = this.challenges.get(supplied.nonce);
    if (!challenge || !C.equal(challenge, supplied))
      C.fail("UNKNOWN_RELEASE_CHALLENGE");
    // Consume before any await to prevent concurrent replay within this process.
    this.challenges.delete(supplied.nonce);
    if ((await this.time()) >= challenge.expiresAt)
      C.fail("RELEASE_CHALLENGE_EXPIRED");
    const principal = await this.ledger.authenticateRelease(proof, challenge);
    if ((await this.time()) >= challenge.expiresAt)
      C.fail("RELEASE_CHALLENGE_EXPIRED");
    if (!C.equal(principal, challenge.granteePrincipal))
      C.fail("BOUND_GRANTEE_REQUIRED");
    const session = await this.ledger.query("getDisclosureSession", {
        sessionId: challenge.sessionId,
      }),
      anchor = await this.ledger.query("getEvidenceAnchor", {
        evidenceId: session.evidenceId,
      }),
      receipt = await this.ledger.query("getFinalizationReceipt", {
        sessionId: session.sessionId,
      });
    if (
      session.status !== "FINALIZED" ||
      session.bundleHash !== challenge.bundleHash ||
      receipt.bundleHash !== session.bundleHash ||
      receipt.finalizedTxRef !== session.finalizedTxRef
    )
      C.fail("RELEASE_RECEIPT");
    let lastCheck = -Infinity,
      lastEligibility = null;
    const gate = async () => {
      const tick = this.monotonic();
      if (tick - lastCheck >= this.refreshMs || !lastEligibility) {
        lastEligibility = await this.ledger.query("getEligibility", {
          sessionId: session.sessionId,
        });
        if (this.monotonic() - tick > this.maxEligibilityQueryMs)
          C.fail("ELIGIBILITY_QUERY_TOO_OLD");
        // Cache age starts before RPC, not when its possibly stale answer arrives.
        lastCheck = tick;
      }
      const t = await this.time();
      if (
        !lastEligibility.eligible ||
        lastEligibility.sessionId !== session.sessionId ||
        lastEligibility.bundleHash !== session.bundleHash ||
        t >= lastEligibility.sessionExpiresAt ||
        t >= lastEligibility.capExpiresAt
      )
        C.fail("RELEASE_INELIGIBLE");
    };
    await gate();
    const material = await this.resolveEvidence(
      session.evidenceId,
      session.requestedScope.mode,
    );
    const secret = material.kSalt ? Buffer.from(material.kSalt) : null;
    try {
      const candidate = await B.prepareBundle({
        file: material.file,
        index: material.index,
        kSalt: secret,
        session,
        anchor,
        manifestPath: material.manifestPath?.(session.sessionId),
      });
      if (candidate.bundleHash !== receipt.bundleHash)
        C.fail("RELEASE_REBUILD_DIGEST");
      // Fresh query after potentially expensive rebuild, immediately before transfer.
      lastCheck = -Infinity;
      await gate();
      const hash = crypto.createHash("sha256").update(C.domain("BundleCoreV1"));
      for await (const bytes of B.bundleStream(
        material.file,
        session,
        anchor,
        material.index,
        secret,
        gate,
      )) {
        // Recheck when a backpressured consumer resumes, including HASH_ONLY.
        await gate();
        hash.update(bytes);
        yield bytes;
      }
      if (hash.digest("hex") !== receipt.bundleHash)
        C.fail("RELEASE_STREAM_DIGEST");
    } finally {
      if (secret) secret.fill(0);
      if (material.dispose) await material.dispose();
    }
  }
}
module.exports = { ReleaseController };
