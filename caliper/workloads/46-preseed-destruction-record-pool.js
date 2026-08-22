'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const { getDefaults } = require('../lib/caliper-utils');
const { appendManifest, seedDestroyedItem, recordFromItem } = require('./_bfdd-extra-utils');

class PreseedDestructionRecordPool extends WorkloadModuleBase {
  async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
    await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
    this.workerIndex = workerIndex;
    this.roundArguments = roundArguments || {};
    this.defaults = getDefaults();
    this.contractId = this.roundArguments.contractId || this.defaults.contractId;
    this.poolPrefix = this.roundArguments.poolPrefix || 'gdr';
    this.itemCount = Number(this.roundArguments.itemCount || this.roundArguments.txNumber || 100);
    this.manifest = this.roundArguments.poolManifest || `results/pool-destruction-record-${Date.now()}.jsonl`;
    this.next = 0;
  }

  async submitTransaction() {
    const index = this.next++;
    if (index >= this.itemCount) {
      throw new Error(`preseed getEvidenceDestructionRecord pool exhausted: index=${index}, itemCount=${this.itemCount}`);
    }

    const { item } = await seedDestroyedItem(
      this.sutAdapter,
      this.contractId,
      this.workerIndex,
      index,
      this.poolPrefix
    );

    appendManifest(this.manifest, this.workerIndex, recordFromItem(this.workerIndex, index, item, {
      lifecycleState: 'DESTROYED'
    }));
  }
}

module.exports.createWorkloadModule = () => new PreseedDestructionRecordPool();
