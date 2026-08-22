'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const { getDefaults, getIdentityConfig, send } = require('../lib/caliper-utils');
const { loadManifest } = require('./_bfdd-extra-final-utils');

class GetEvidenceDestructionRecordFromPool extends WorkloadModuleBase {
  async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
    await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);

    this.workerIndex = workerIndex;
    this.totalWorkers = totalWorkers;
    this.args = roundArguments || {};
    this.defaults = getDefaults();
    this.contractId = this.args.contractId || this.defaults.contractId;
    this.readOnly = String(this.args.readOnly || 'true').toLowerCase() === 'true';
    this.items = loadManifest(this.args.poolManifest, workerIndex, totalWorkers);
    this.next = 0;
  }

  async submitTransaction() {
    const record = this.items[this.next++];

    if (!record) {
      throw new Error(`getEvidenceDestructionRecord pool exhausted: worker=${this.workerIndex}, loaded=${this.items.length}`);
    }

    return send(this.sutAdapter, {
      contractId: this.contractId,
      identity: getIdentityConfig('DataProtectionOfficer').caliperIdentity,
      fcn: 'getEvidenceDestructionRecord',
      args: [record.evidenceId],
      readOnly: this.readOnly
    });
  }
}

module.exports.createWorkloadModule = () => new GetEvidenceDestructionRecordFromPool();
