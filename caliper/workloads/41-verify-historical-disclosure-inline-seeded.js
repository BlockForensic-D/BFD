'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const { getDefaults, getIdentityConfig, jsonArg, send } = require('../lib/caliper-utils');
const {
  buildItemFor,
  prepareKeys,
  seedHistoricalDisclosureItem,
  nextItem
} = require('./_bfdd-inline-seed-utils');

class VerifyHistoricalDisclosureInlineSeeded extends WorkloadModuleBase {
  async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
    await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);

    this.workerIndex = workerIndex;
    this.args = roundArguments || {};
    this.defaults = getDefaults();
    this.contractId = this.args.contractId || this.defaults.contractId;
    this.seedCount = Number(this.args.seedCount || 10);
    this.poolPrefix = this.args.poolPrefix || 'vhist';
    this.readOnly = String(this.args.readOnly || 'true').toLowerCase() === 'true';
    this.circular = String(this.args.circularPool || 'false').toLowerCase() === 'true';
    this.items = [];
    this.next = 0;
    this.operation = 'verifyHistoricalDisclosure';

    await prepareKeys(this.sutAdapter, this.contractId);

    for (let i = 0; i < this.seedCount; i++) {
      const item = buildItemFor(this.workerIndex, i, this.poolPrefix, 'HASH_ONLY');
      const bundle = await seedHistoricalDisclosureItem(this.sutAdapter, this.contractId, item, i);
      this.items.push({ evidenceId: item.evidence.evidenceId, bundle });
    }
  }

  async submitTransaction() {
    const record = nextItem(this);

    return send(this.sutAdapter, {
      contractId: this.contractId,
      identity: getIdentityConfig('ExternalAuditor').caliperIdentity,
      fcn: 'verifyHistoricalDisclosure',
      args: [record.evidenceId, jsonArg(record.bundle)],
      readOnly: this.readOnly
    });
  }
}

module.exports.createWorkloadModule = () => new VerifyHistoricalDisclosureInlineSeeded();
