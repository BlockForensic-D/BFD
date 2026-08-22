'use strict';
const { BlockForensicWorkloadBase } = require('./_base');
const { jsonArg } = require('../lib/caliper-utils');
class IssueDisclosureCapabilityWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);
    await this.seedItems('COMMITTED', this.txCount(), 'issuecap', this.roundArguments.scopeProfile || 'HASH_ONLY');
  }
  async submitTransaction() {
    const item = this.currentItem();
    return this.invoke('issueDisclosureCapability', [jsonArg(item.capabilityToken)], 'EvidenceCustodian', false);
  }
}
module.exports.createWorkloadModule = () => new IssueDisclosureCapabilityWorkload();
