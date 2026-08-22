'use strict';

const { BlockForensicWorkloadBase } = require('./_base');
const { buildItem, registerCorePublicKeys } = require('../lib/seed-flow');
const { jsonArg } = require('../lib/caliper-utils');

function n(v, d) {
  const x = Number(v);
  return Number.isFinite(x) ? x : d;
}

class PreseedPreservedPoolWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);

    this.poolPrefix = this.roundArguments.poolPrefix || this.roundArguments.poolId || 'commitpool';
    this.poolWorkerIndex = n(this.roundArguments.poolWorkerIndex, 0);
    this.sliceOffset = n(this.roundArguments.sliceOffset, 0);
    this.itemCount = n(this.roundArguments.itemCount || this.roundArguments.seedCount, this.txCount());
    this.scopeProfile = this.roundArguments.scopeProfile || 'HASH_ONLY';

    await registerCorePublicKeys(this.sutAdapter, this.contractId);

    this.items = [];
    const start = this.sliceOffset + (this.workerIndex * this.itemCount);

    for (let i = 0; i < this.itemCount; i++) {
      this.items.push(buildItem({
        prefix: this.poolPrefix,
        workerIndex: this.poolWorkerIndex,
        index: start + i,
        scopeProfile: this.scopeProfile
      }));
    }

    console.log(`[preseed-pool] poolPrefix=${this.poolPrefix} worker=${this.workerIndex}/${this.totalWorkers} start=${start} count=${this.itemCount}`);
  }

  nextItemOnce() {
    if (this.next >= this.items.length) {
      throw new Error(`[preseed-pool] item pool exhausted: next=${this.next}, count=${this.items.length}`);
    }
    return this.items[this.next++];
  }

  async submitTransaction() {
    const item = this.nextItemOnce();
    return this.invoke(
      'preserveEvidence',
      [jsonArg(item.evidence)],
      'GatewayCollector',
      false
    );
  }
}

module.exports.createWorkloadModule = () => new PreseedPreservedPoolWorkload();
