'use strict';

const { BlockForensicWorkloadBase } = require('./_base');
const { jsonArg } = require('../lib/caliper-utils');
const {
  buildItem,
  registerCorePublicKeys
} = require('../lib/seed-flow');

class IssueFromCommittedPoolWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);

    this.poolPrefix = this.roundArguments.poolPrefix || 'issuepool';
    this.poolWorkerIndex = Number(this.roundArguments.poolWorkerIndex || 0);
    this.sliceOffset = Number(this.roundArguments.sliceOffset || 0);
    this.itemCount = Number(this.roundArguments.itemCount || this.txCount());
    this.scopeProfile = this.roundArguments.scopeProfile || 'HASH_ONLY';

    console.log(
      `[issue-from-committed-pool] poolPrefix=${this.poolPrefix} ` +
      `worker=${this.workerIndex}/${this.totalWorkers} ` +
      `sliceOffset=${this.sliceOffset} itemCount=${this.itemCount}`
    );

    await registerCorePublicKeys(this.sutAdapter, this.contractId);
  }

  itemFor(localIndex) {
    const globalIndex = this.sliceOffset + this.workerIndex + (localIndex * this.totalWorkers);

    return buildItem({
      prefix: this.poolPrefix,
      workerIndex: this.poolWorkerIndex,
      index: globalIndex,
      scopeProfile: this.scopeProfile
    });
  }

  async submitTransaction() {
    const localIndex = this.next;
    this.next += 1;

    if (localIndex >= this.itemCount) {
      throw new Error(`issue itemCount exhausted: localIndex=${localIndex}, itemCount=${this.itemCount}`);
    }

    const item = this.itemFor(localIndex);

    return this.invoke(
      'issueDisclosureCapability',
      [jsonArg(item.capabilityToken)],
      'EvidenceCustodian',
      false
    );
  }
}

module.exports.createWorkloadModule = () => new IssueFromCommittedPoolWorkload();
