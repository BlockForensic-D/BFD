'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const { getDefaults } = require('../lib/caliper-utils');
const {
  appendManifest,
  recordFromItem,
  seedForVerifyHistoricalDisclosure
} = require('./_bfdd-extra-utils');

class PreseedHistoricalDisclosurePool extends WorkloadModuleBase {
  async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
    await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
    this.workerIndex = workerIndex;
    this.args = roundArguments || {};
    this.defaults = getDefaults();
    this.contractId = this.args.contractId || this.defaults.contractId;
    this.poolPrefix = this.args.poolPrefix || 'vhist';
    this.itemCount = Number(this.args.itemCount || this.args.txNumber || 100);
    this.measureWorkers = Number(this.args.measureWorkers || totalWorkers || 1);
    this.poolManifest = this.args.poolManifest;
    this.next = 0;
  }

  async submitTransaction() {
    const index = this.next++;
    if (index >= this.itemCount) {
      throw new Error(`verifyHistoricalDisclosure preseed exhausted: index=${index}, itemCount=${this.itemCount}`);
    }

    const { item, bundle } = await seedForVerifyHistoricalDisclosure(
      this.sutAdapter,
      this.contractId,
      this.workerIndex,
      index,
      this.poolPrefix
    );

    appendManifest(this.poolManifest, this.workerIndex, recordFromItem(this.workerIndex, index, item, {
      measureWorkerIndex: index % this.measureWorkers,
      bundle,
      lifecycleState: 'DESTROYED'
    }));
  }
}

module.exports.createWorkloadModule = () => new PreseedHistoricalDisclosurePool();
