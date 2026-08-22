'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const { getDefaults, getIdentityConfig, jsonArg, send } = require('../lib/caliper-utils');
const {
  buildItemFor,
  prepareKeys,
  seedDisclosureRequestedItem,
  nextItem
} = require('./_bfdd-inline-seed-utils');

class VerifyDisclosureInlineSeeded extends WorkloadModuleBase {
  async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
    await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);

    this.workerIndex = workerIndex;
    this.args = roundArguments || {};
    this.defaults = getDefaults();
    this.contractId = this.args.contractId || this.defaults.contractId;
    this.seedCount = Number(this.args.seedCount || 20);
    this.poolPrefix = this.args.poolPrefix || 'vdis';
    this.items = [];
    this.next = 0;
    this.operation = 'verifyDisclosure';

    await prepareKeys(this.sutAdapter, this.contractId);

    for (let i = 0; i < this.seedCount; i++) {
      const item = buildItemFor(this.workerIndex, i, this.poolPrefix, 'HASH_ONLY');
      const bundle = await seedDisclosureRequestedItem(this.sutAdapter, this.contractId, item);
      this.items.push({ evidenceId: item.evidence.evidenceId, bundle });
    }
  }

  async submitTransaction() {
    const record = nextItem(this);

    return send(this.sutAdapter, {
      contractId: this.contractId,
      identity: getIdentityConfig('ExternalVendor').caliperIdentity,
      fcn: 'verifyDisclosure',
      args: [record.evidenceId, jsonArg(record.bundle)],
      readOnly: false
    });
  }
}

module.exports.createWorkloadModule = () => new VerifyDisclosureInlineSeeded();
