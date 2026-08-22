'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const { getDefaults } = require('../lib/caliper-utils');
const {
  appendManifest,
  manifestRecord,
  registerKeysOnce,
  seedEvidenceCommitmentItem
} = require('./_bfdd-extra-final-utils');

class PreseedEvidenceCommitmentPool extends WorkloadModuleBase {
  async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
    await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);

    this.workerIndex = workerIndex;
    this.args = roundArguments || {};
    this.defaults = getDefaults();
    this.contractId = this.args.contractId || this.defaults.contractId;
    this.poolPrefix = this.args.poolPrefix || 'gcom';
    this.poolManifest = this.args.poolManifest;
    this.measureWorkers = Number(this.args.measureWorkers || 4);
    this.next = 0;

    await registerKeysOnce(this.sutAdapter, this.contractId);
  }

  async submitTransaction() {
    const index = this.next++;

    const { item } = await seedEvidenceCommitmentItem(
      this.sutAdapter,
      this.contractId,
      this.workerIndex,
      index,
      this.poolPrefix
    );

    appendManifest(this.poolManifest, this.workerIndex, manifestRecord(
      this.workerIndex,
      index,
      this.measureWorkers,
      item,
      {
        lifecycleState: 'COMMITTED'
      }
    ));
  }
}

module.exports.createWorkloadModule = () => new PreseedEvidenceCommitmentPool();
