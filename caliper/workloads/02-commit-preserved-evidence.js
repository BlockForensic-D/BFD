'use strict';
const { BlockForensicWorkloadBase } = require('./_base');
const { jsonArg } = require('../lib/caliper-utils');
class CommitPreservedEvidenceWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);
    await this.seedItems('PRESERVED', this.txCount(), 'commit');
  }
  async submitTransaction() {
    const item = this.currentItem();
    return this.invoke('commitPreservedEvidence', [item.evidence.evidenceId, jsonArg(item.commitPayload)], 'EvidenceCustodian', false);
  }
}
module.exports.createWorkloadModule = () => new CommitPreservedEvidenceWorkload();
