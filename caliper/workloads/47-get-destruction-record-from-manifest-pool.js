'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const { getDefaults, getIdentityConfig, send } = require('../lib/caliper-utils');
const { loadManifest } = require('./_bfdd-extra-utils');

class GetEvidenceDestructionRecordFromManifestPool extends WorkloadModuleBase {
  async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
    await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);
    this.workerIndex = workerIndex;
    this.totalWorkers = totalWorkers;
    this.roundArguments = roundArguments || {};
    this.defaults = getDefaults();
    this.contractId = this.roundArguments.contractId || this.defaults.contractId;
    this.readOnly = String(this.roundArguments.readOnly || 'true').toLowerCase() === 'true';
    this.items = loadManifest(this.roundArguments.poolManifest, workerIndex, totalWorkers);
    this.next = 0;
  }

  async submitTransaction() {
    const record = this.items[this.next++];
    if (!record) {
      throw new Error(`getEvidenceDestructionRecord manifest pool exhausted: loaded=${this.items.length}`);
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

module.exports.createWorkloadModule = () => new GetEvidenceDestructionRecordFromManifestPool();
