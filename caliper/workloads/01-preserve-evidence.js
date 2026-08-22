'use strict';
const { BlockForensicWorkloadBase } = require('./_base');
const { buildItem, registerCorePublicKeys } = require('../lib/seed-flow');
const { jsonArg } = require('../lib/caliper-utils');

class PreserveEvidenceWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);
    await registerCorePublicKeys(this.sutAdapter, this.contractId);
    this.items = this.buildItems(this.txCount(), 'preserve');
  }
  async submitTransaction() {
    const item = this.currentItem();
    return this.invoke('preserveEvidence', [jsonArg(item.evidence)], 'GatewayCollector', false);
  }
}
module.exports.createWorkloadModule = () => new PreserveEvidenceWorkload();
