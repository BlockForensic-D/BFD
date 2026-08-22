'use strict';
const { BlockForensicWorkloadBase } = require('./_base');
class QueryDestructionRecordWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);
    await this.seedItems('DESTROYED', this.txCount(), 'querydestroy');
  }
  async submitTransaction() {
    const item = this.currentItem();
    return this.invoke('getEvidenceDestructionRecord', [item.evidence.evidenceId], 'ExternalAuditor', true);
  }
}
module.exports.createWorkloadModule = () => new QueryDestructionRecordWorkload();
