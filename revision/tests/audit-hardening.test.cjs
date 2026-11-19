"use strict";
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs/promises"),
  os = require("node:os"),
  path = require("node:path");
const { fixture } = require("./helpers/fixture.cjs");
const C = require("../src/shared/canonical.cjs"),
  B = require("../src/client/bundle.cjs");
const { ReleaseController } = require("../src/client/release.cjs");
const reasonDigest = C.digest("isolated regression");
for (const suspended of [false, true])
  for (const actor of ["ec", "jr", "other"]) {
    test(`key revocation actor=${actor} suspended=${suspended}`, async () => {
      const f = await fixture();
      if (suspended)
        await f.ledger.invoke("setPrincipalSuspension", f.a.jr, {
          principal: f.a[actor].principal,
          suspended: true,
          reasonDigest,
        });
      const input = { keyRef: f.issuer.keyRef, reasonDigest };
      const invoke = () =>
        f.ledger.invoke("revokePublicKey", f.a[actor], input);
      if (actor === "other" || (actor === "jr" && suspended)) {
        await assert.rejects(invoke());
        assert.equal(
          (
            await f.ledger.query("getKeyVersion", f.a.ec, {
              keyRef: input.keyRef,
            })
          ).status,
          "ACTIVE",
        );
      } else {
        assert.equal((await invoke()).status, "REVOKED");
        assert.equal((await invoke()).status, "REVOKED");
      }
    });
  }
async function setup(t, mode = "FULL") {
  const f = await fixture({ mode }),
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bfd-hardening-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "data");
  await fs.writeFile(file, f.bytes);
  const session = (
    await f.ledger.invoke("requestDisclosure", f.a.grantee, f.request())
  ).session;
  const index = {
    evidenceId: f.evidenceId,
    params: f.params,
    levels: f.tree.levels,
  };
  const prepared = await B.prepareBundle({
    file,
    session,
    anchor: f.anchor,
    index,
    kSalt: f.keys.kSalt,
  });
  await f.ledger.invoke("finalizeDisclosure", f.a.ec, {
    sessionId: session.sessionId,
    bundleHash: prepared.bundleHash,
    scopeDigest: session.scopeDigest,
    commitRef: session.commitRef,
  });
  const s = {
    now: 4999,
    tick: 0,
    healthy: true,
    armed: false,
    queries: 0,
    dispose: 0,
  };
  const ledger = {
    query: async (n, i) => {
      const v = await f.ledger.query(n, f.a.ec, i, s.now);
      if (n === "getEligibility") {
        s.queries++;
        if (s.onQuery) await s.onQuery();
      }
      return v;
    },
    authenticateRelease: async () => {
      if (s.onAuth) await s.onAuth();
      return f.a.grantee.principal;
    },
  };
  const controller = new ReleaseController({
    ledger,
    now: () => s.now,
    monotonic: () => s.tick,
    clockHealthy: async () => s.healthy,
    refreshMs: 0,
    resolveEvidence: async () => ({
      file: s.file || file,
      index,
      kSalt: f.keys.kSalt,
      dispose: async () => {
        s.dispose++;
      },
    }),
  });
  const challenge = await controller.challenge(session.sessionId);
  return {
    ...f,
    file,
    index,
    session,
    s,
    controller,
    proof: { challenge, proposalBytes: "dGVzdA==", signature: "dGVzdA==" },
  };
}
async function collect(stream, parts = []) {
  for await (const b of stream) parts.push(b);
  return Buffer.concat(parts);
}
test("delayed eligibility crossing expiry emits no content chunk", async (t) => {
  const f = await setup(t);
  const parts = [];
  f.s.onQuery = () => {
    f.s.now = 5001;
    f.s.tick += 2000;
  };
  await assert.rejects(
    collect(f.controller.release(f.proof), parts),
    /RELEASE_INELIGIBLE/,
  );
  assert(!Buffer.concat(parts).toString().includes("dataB64"));
});
test("late file read rejected and material disposed", async (t) => {
  const f = await setup(t);
  let opens = 0;
  f.s.file = {
    openRead: async () => {
      const fd = await fs.open(f.file, "r");
      opens++;
      return {
        stat: () => fd.stat(),
        close: () => fd.close(),
        read: async (...a) => {
          const r = await fd.read(...a);
          if (opens >= 2) f.s.now = 5001;
          return r;
        },
      };
    },
  };
  const parts = [];
  await assert.rejects(
    collect(f.controller.release(f.proof), parts),
    /RELEASE_INELIGIBLE/,
  );
  assert(!Buffer.concat(parts).toString().includes("dataB64"));
  assert.equal(f.s.dispose, 1);
});
test("slow eligibility response is rejected even before expiry", async (t) => {
  const f = await setup(t);
  f.s.onQuery = () => {
    f.s.tick += 5001;
  };
  await assert.rejects(
    collect(f.controller.release(f.proof)),
    /ELIGIBILITY_QUERY_TOO_OLD/,
  );
});
test("authentication crossing challenge expiry rejected", async (t) => {
  const f = await setup(t);
  f.s.onAuth = () => {
    f.s.now = 5000;
  };
  await assert.rejects(
    collect(f.controller.release(f.proof)),
    /RELEASE_CHALLENGE_EXPIRED/,
  );
});
for (const mode of ["FULL", "HASH_ONLY"])
  test(`backpressure expiry stops subsequent output ${mode}`, async (t) => {
    const f = await setup(t, mode),
      stream = f.controller.release(f.proof);
    assert.equal((await stream.next()).done, false);
    f.s.now = 5000;
    await assert.rejects(stream.next(), /RELEASE_INELIGIBLE/);
    assert.equal(f.s.dispose, 1);
  });
test("healthy preflight followed by unhealthy clock fails closed", async (t) => {
  const f = await setup(t),
    stream = f.controller.release(f.proof);
  await stream.next();
  f.s.healthy = false;
  await assert.rejects(stream.next(), /CLOCK_UNHEALTHY/);
});
test("backwards clock during stream fails closed", async (t) => {
  const f = await setup(t),
    stream = f.controller.release(f.proof);
  await stream.next();
  f.s.now--;
  await assert.rejects(stream.next(), /CLOCK_MOVED_BACKWARDS/);
});
test("invalid freshness bounds rejected", () => {
  const opts = {
    ledger: { authenticateRelease: async () => {} },
    resolveEvidence: async () => {},
    clockHealthy: async () => true,
  };
  for (const refreshMs of [NaN, Infinity, -1, 5001])
    assert.throws(() => new ReleaseController({ ...opts, refreshMs }));
  for (const maxEligibilityQueryMs of [NaN, Infinity, 0, -1, 5001])
    assert.throws(
      () => new ReleaseController({ ...opts, maxEligibilityQueryMs }),
    );
});
