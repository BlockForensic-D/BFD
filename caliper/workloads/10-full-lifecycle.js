'use strict';
const { BlockForensicWorkloadBase } = require('./_base');
const { jsonArg } = require('../lib/caliper-utils');
const { buildItem } = require('../lib/seed-flow');
const { buildDestructionRequest, buildDestructionApproval } = require('../lib/payload-builders');

class FullLifecycleWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);
    // Only keys are registered in seedToState. Use a dummy preserve seed to register keys.
    await this.seedItems('PRESERVED', 1, 'fulllifecycle-keyinit');
    this.items = this.buildItems(this.txCount(), 'fulllifecycle', this.roundArguments.scopeProfile || 'HASH_ONLY');
  }

  async submitTransaction() {
    const item = this.currentItem();
    const evId = item.evidence.evidenceId;
    await this.invoke('preserveEvidence', [jsonArg(item.evidence)], 'GatewayCollector', false);
    await this.invoke('commitPreservedEvidence', [evId, jsonArg(item.commitPayload)], 'EvidenceCustodian', false);
    await this.invoke('issueDisclosureCapability', [jsonArg(item.capabilityToken)], 'EvidenceCustodian', false);
    await this.invoke('requestDisclosure', [evId, jsonArg(item.capabilityToken), jsonArg(item.requestedChunkIndices)], 'ExternalVendor', false);
    await this.invoke('requestEvidenceDestruction', [evId, jsonArg(buildDestructionRequest(this.next))], 'DataProtectionOfficer', false);
    await this.invoke('approveEvidenceDestruction', [evId, jsonArg(buildDestructionApproval(this.next))], 'JudicialReviewer', false);
    await this.invoke('reportEvidenceDestroyed', [evId, jsonArg(item.destructionReceipt)], 'EvidenceCustodian', false);
    return this.invoke('getEvidenceDestructionRecord', [evId], 'ExternalAuditor', true);
  }
}
module.exports.createWorkloadModule = () => new FullLifecycleWorkload();
