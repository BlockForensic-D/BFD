'use strict';

const { BlockForensicWorkloadBase } = require('./_base');

class RetrieveEvidenceWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);
    await this.seedItems(
      'COMMITTED',
      this.txCount(),
      'retrieve'
    );
  }

  async submitTransaction() {
    const item = this.currentItem();

    // retrieveEvidence(evidenceId, isPublic, requestPRE)
    // For the read-only benchmark, use the custodian private retrieval path:
    // isPublic=false, requestPRE=false.
    return this.invoke(
      'retrieveEvidence',
      [
        item.evidence.evidenceId,
        'false',
        'false'
      ],
      'EvidenceCustodian',
      true
    );
  }
}

module.exports.createWorkloadModule = () => new RetrieveEvidenceWorkload();
