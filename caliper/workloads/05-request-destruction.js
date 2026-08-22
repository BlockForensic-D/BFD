'use strict';
const { BlockForensicWorkloadBase } = require('./_base');
const { jsonArg } = require('../lib/caliper-utils');
const { buildDestructionRequest } = require('../lib/payload-builders');
class RequestDestructionWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);
    await this.seedItems('COMMITTED', this.txCount(), 'reqdestroy');
  }
  async submitTransaction() {
    const item = this.currentItem();
    return this.invoke('requestEvidenceDestruction', [item.evidence.evidenceId, jsonArg(buildDestructionRequest(this.next))], 'DataProtectionOfficer', false);
  }
}
module.exports.createWorkloadModule = () => new RequestDestructionWorkload();
