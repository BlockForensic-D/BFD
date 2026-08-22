'use strict';

const { BlockForensicWorkloadBase } = require('./_base');
const { jsonArg } = require('../lib/caliper-utils');
const {
  withMandatoryThresholdDestructionReceipt,
  assertMandatoryThresholdDestructionReceipt,
  registerDestructionAttestationKeys
} = require('../lib/threshold-destruction-receipt');

class ReportDestroyedWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);

    await registerDestructionAttestationKeys(this.sutAdapter, this.contractId, {
      workerIndex: this.workerIndex,
      totalWorkers: this.totalWorkers
    });

    await this.seedItems('DESTRUCTION_APPROVED', this.txCount(), 'reportdestroy');
  }

  async submitTransaction() {
    const item = this.currentItem();
    const evidenceId = item.evidence.evidenceId;

    const receipt = await withMandatoryThresholdDestructionReceipt(
      item.destructionReceipt,
      evidenceId
    );

    assertMandatoryThresholdDestructionReceipt(receipt, evidenceId);

    return this.invoke(
      'reportEvidenceDestroyed',
      [
        evidenceId,
        jsonArg(receipt)
      ],
      'EvidenceCustodian',
      false
    );
  }
}

module.exports.createWorkloadModule = () => new ReportDestroyedWorkload();
