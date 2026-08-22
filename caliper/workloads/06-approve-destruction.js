'use strict';
const { BlockForensicWorkloadBase } = require('./_base');
const { jsonArg } = require('../lib/caliper-utils');
const { buildDestructionApproval } = require('../lib/payload-builders');
class ApproveDestructionWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);
    await this.seedItems('DESTRUCTION_REQUESTED', this.txCount(), 'approvedestroy');
  }
  async submitTransaction() {
    const item = this.currentItem();
    return this.invoke('approveEvidenceDestruction', [item.evidence.evidenceId, jsonArg(buildDestructionApproval(this.next))], 'JudicialReviewer', false);
  }
}
module.exports.createWorkloadModule = () => new ApproveDestructionWorkload();
