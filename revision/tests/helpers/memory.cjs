"use strict";
// Unit-test transaction model ONLY. This is not a Fabric network or endorsement test.
const C = require("../../src/shared/canonical.cjs");
const { RevisionService } = require("../../src/chaincode/service.cjs");
class MemoryLedger {
  constructor() {
    this.state = new Map();
    this.version = 0;
    this.counter = 0;
    this.service = new RevisionService();
    this.events = [];
  }
  async simulate(method, actor, input, time = 1000) {
    const snapshot = new Map(this.state),
      reads = new Map(),
      writes = new Map(),
      events = [];
    const txId = "unit-tx-" + ++this.counter;
    const ctx = {
      clientIdentity: {
        getMSPID: () => actor.principal.mspId,
        getID: () => actor.principal.clientIdentityId,
        getAttributeValue: (name) => actor[name],
      },
      stub: {
        getChannelID: () => "bfd-test",
        getTxID: () => txId,
        getTxTimestamp: () => ({
          seconds: { toString: () => String(time) },
          nanos: 0,
        }),
        createCompositeKey: (type, attrs) =>
          "\0" + type + "\0" + attrs.join("\0") + "\0",
        getState: async (key) => {
          const v = snapshot.get(key);
          reads.set(key, v?.version || 0);
          return v ? Buffer.from(v.bytes) : Buffer.alloc(0);
        },
        putState: async (key, bytes) => {
          writes.set(key, Buffer.from(bytes));
        },
        setEvent: (name, bytes) => {
          events.splice(0, events.length, { name, bytes: Buffer.from(bytes) });
        },
      },
    };
    const result = await this.service[method](ctx, input);
    return { txId, reads, writes, events, result };
  }
  commit(tx) {
    for (const [k, v] of tx.reads)
      if ((this.state.get(k)?.version || 0) !== v)
        throw Error("MVCC_READ_CONFLICT_MODEL");
    for (const [k, bytes] of tx.writes)
      this.state.set(k, { bytes, version: ++this.version });
    this.events.push(...tx.events);
    return tx.result;
  }
  async invoke(method, actor, input, time = 1000) {
    return this.commit(await this.simulate(method, actor, input, time));
  }
  async query(method, actor, input, time = 1000) {
    const tx = await this.simulate(method, actor, input, time);
    if (tx.writes.size) throw Error("QUERY_WROTE_STATE");
    return tx.result;
  }
}
module.exports = { MemoryLedger };
