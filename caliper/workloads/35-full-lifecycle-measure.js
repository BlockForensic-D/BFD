'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

const {
  getIdentityConfig,
  getDefaults,
  send,
  jsonArg
} = require('../lib/caliper-utils');

const {
  registerCorePublicKeys,
  buildItem
} = require('../lib/seed-flow');

const {
  buildDestructionRequest,
  buildDestructionApproval
} = require('../lib/payload-builders');

const {
  withMandatoryThresholdDestructionReceipt,
  assertMandatoryThresholdDestructionReceipt,
  registerDestructionAttestationKeys
} = require('../lib/threshold-destruction-receipt');

class FullLifecycleMeasureWorkload extends WorkloadModuleBase {
  async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
    await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);

    this.workerIndex = workerIndex;
    this.totalWorkers = totalWorkers;
    this.roundIndex = roundIndex;
    this.roundArguments = roundArguments || {};
    this.sutAdapter = sutAdapter;

    this.defaults = getDefaults();
    this.contractId = this.roundArguments.contractId || this.defaults.contractId;

    this.poolPrefix = this.roundArguments.poolPrefix || 'fulllifecycle';
    this.poolWorkerIndex = Number(this.roundArguments.poolWorkerIndex || 0);
    this.sliceOffset = Number(this.roundArguments.sliceOffset || 0);
    this.itemCount = Number(this.roundArguments.itemCount || 100);
    this.scopeProfile = this.roundArguments.scopeProfile || 'HASH_ONLY';

    this.next = 0;

    console.log(
      `[full-lifecycle-measure] poolPrefix=${this.poolPrefix} ` +
      `worker=${this.workerIndex}/${this.totalWorkers} ` +
      `sliceOffset=${this.sliceOffset} itemCount=${this.itemCount} ` +
      `scopeProfile=${this.scopeProfile}`
    );

    await registerCorePublicKeys(this.sutAdapter, this.contractId);

    await registerDestructionAttestationKeys(this.sutAdapter, this.contractId, {
      workerIndex: this.workerIndex,
      totalWorkers: this.totalWorkers
    });
  }

  identity(logicalName) {
    return getIdentityConfig(logicalName).caliperIdentity;
  }

  async invokeAs(fcn, args, logicalIdentity, readOnly = false, opts = {}) {
    return send(this.sutAdapter, {
      contractId: this.contractId,
      identity: this.identity(logicalIdentity),
      fcn,
      args,
      readOnly,
      ...opts
    });
  }

  globalIndexFor(localIndex) {
    return this.sliceOffset + this.workerIndex + (localIndex * this.totalWorkers);
  }

  itemFor(localIndex) {
    return buildItem({
      prefix: this.poolPrefix,
      workerIndex: this.poolWorkerIndex,
      index: this.globalIndexFor(localIndex),
      scopeProfile: this.scopeProfile
    });
  }

  async submitTransaction() {
    const localIndex = this.next;
    this.next += 1;

    if (localIndex >= this.itemCount) {
      throw new Error(`full lifecycle itemCount exhausted: localIndex=${localIndex}, itemCount=${this.itemCount}`);
    }

    const globalIndex = this.globalIndexFor(localIndex);
    const item = this.itemFor(localIndex);
    const evId = item.evidence.evidenceId;

    await this.invokeAs(
      'preserveEvidence',
      [jsonArg(item.evidence)],
      'GatewayCollector',
      false
    );

    await this.invokeAs(
      'commitPreservedEvidence',
      [evId, jsonArg(item.commitPayload)],
      'EvidenceCustodian',
      false
    );

    await this.invokeAs(
      'issueDisclosureCapability',
      [jsonArg(item.capabilityToken)],
      'EvidenceCustodian',
      false
    );

    await this.invokeAs(
      'requestDisclosure',
      [
        evId,
        jsonArg(item.capabilityToken),
        jsonArg(item.requestedChunkIndices)
      ],
      'ExternalVendor',
      false,
      {
        endorsingOrganizations: ['Org1MSP', 'Org2MSP']
      }
    );

    await this.invokeAs(
      'requestEvidenceDestruction',
      [
        evId,
        jsonArg(buildDestructionRequest(globalIndex))
      ],
      'DataProtectionOfficer',
      false
    );

    await this.invokeAs(
      'approveEvidenceDestruction',
      [
        evId,
        jsonArg(buildDestructionApproval(globalIndex))
      ],
      'JudicialReviewer',
      false
    );

    const destructionReceipt = await withMandatoryThresholdDestructionReceipt(
      item.destructionReceipt,
      evId
    );

    assertMandatoryThresholdDestructionReceipt(destructionReceipt, evId);

    await this.invokeAs(
      'reportEvidenceDestroyed',
      [
        evId,
        jsonArg(destructionReceipt)
      ],
      'EvidenceCustodian',
      false
    );

    return this.invokeAs(
      'getEvidenceDestructionRecord',
      [evId],
      'EvidenceCustodian',
      true
    );
  }
}

module.exports.createWorkloadModule = () => new FullLifecycleMeasureWorkload();
