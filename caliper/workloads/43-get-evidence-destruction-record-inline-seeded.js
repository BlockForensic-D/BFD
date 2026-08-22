'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const { getDefaults, getIdentityConfig, send } = require('../lib/caliper-utils');
const {
  buildItemFor,
  prepareKeys,
  seedDestroyedItem,
  nextItem
} = require('./_bfdd-inline-seed-utils');

class GetEvidenceDestructionRecordInlineSeeded extends WorkloadModuleBase {
  async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
    await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);

    this.workerIndex = workerIndex;
    this.args = roundArguments || {};
    this.defaults = getDefaults();
    this.contractId = this.args.contractId || this.defaults.contractId;
    this.seedCount = Number(this.args.seedCount || 100);
    this.poolPrefix = this.args.poolPrefix || 'gdr';
    this.readOnly = String(this.args.readOnly || 'true').toLowerCase() === 'true';
    this.circular = String(this.args.circularPool || 'false').toLowerCase() === 'true';
    this.items = [];
    this.next = 0;
    this.operation = 'getEvidenceDestructionRecord';

    await prepareKeys(this.sutAdapter, this.contractId);

    for (let i = 0; i < this.seedCount; i++) {
      const item = buildItemFor(this.workerIndex, i, this.poolPrefix, 'HASH_ONLY');
      await seedDestroyedItem(this.sutAdapter, this.contractId, item, i);
      this.items.push({ evidenceId: item.evidence.evidenceId });
    }
  }

  async submitTransaction() {
    const record = nextItem(this);

    return send(this.sutAdapter, {
      contractId: this.contractId,
      identity: getIdentityConfig('DataProtectionOfficer').caliperIdentity,
      fcn: 'getEvidenceDestructionRecord',
      args: [record.evidenceId],
      readOnly: this.readOnly
    });
  }
}

module.exports.createWorkloadModule = () => new GetEvidenceDestructionRecordInlineSeeded();
