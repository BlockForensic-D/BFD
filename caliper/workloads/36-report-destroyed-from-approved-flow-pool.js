'use strict';

const fs = require('fs');
const path = require('path');

const { BlockForensicWorkloadBase } = require('./_base');
const { jsonArg } = require('../lib/caliper-utils');
const { buildItem } = require('../lib/seed-flow');
const {
  withMandatoryThresholdDestructionReceipt,
  assertMandatoryThresholdDestructionReceipt,
  registerDestructionAttestationKeys
} = require('../lib/threshold-destruction-receipt');

class ReportDestroyedFromApprovedFlowPoolWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);

    this.poolPrefix = this.roundArguments.poolPrefix || 'drs';
    this.poolWorkerIndex = Number(this.roundArguments.poolWorkerIndex || 0);
    this.sliceOffset = Number(this.roundArguments.sliceOffset || 0);
    this.itemCount = Number(this.roundArguments.itemCount || this.txCount());
    this.scopeProfile = this.roundArguments.scopeProfile || 'HASH_ONLY';
    this.manifestDir = this.roundArguments.manifestDir || 'config/destruction-requestable-manifests';

    await registerDestructionAttestationKeys(this.sutAdapter, this.contractId, {
      workerIndex: this.workerIndex,
      totalWorkers: this.totalWorkers
    });

    if (!fs.existsSync(this.manifestDir)) {
      throw new Error(`manifestDir not found: ${this.manifestDir}`);
    }

    const files = fs.readdirSync(this.manifestDir)
      .filter((name) => name.startsWith(`${this.poolPrefix}-worker`) && name.endsWith('.jsonl'))
      .sort()
      .map((name) => path.join(this.manifestDir, name));

    if (files.length === 0) {
      throw new Error(`no approved-flow manifest files found for poolPrefix=${this.poolPrefix} in ${this.manifestDir}`);
    }

    this.records = [];

    for (const file of files) {
      const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean);
      for (const line of lines) {
        const rec = JSON.parse(line);
        if (rec.evidenceId && Number.isFinite(rec.globalIndex)) {
          this.records.push(rec);
        }
      }
    }

    this.records.sort((a, b) => a.globalIndex - b.globalIndex);

    console.log(
      `[report-destroyed-from-approved-flow-pool] poolPrefix=${this.poolPrefix} ` +
      `worker=${this.workerIndex}/${this.totalWorkers} ` +
      `sliceOffset=${this.sliceOffset} itemCount=${this.itemCount} ` +
      `manifestFiles=${files.length} loadedApprovedFlow=${this.records.length}`
    );
  }

  recordIndexFor(localIndex) {
    return this.sliceOffset + this.workerIndex + (localIndex * this.totalWorkers);
  }

  itemFor(rec) {
    return buildItem({
      prefix: this.poolPrefix,
      workerIndex: this.poolWorkerIndex,
      index: rec.globalIndex,
      scopeProfile: this.scopeProfile
    });
  }

  async submitTransaction() {
    const localIndex = this.next;
    this.next += 1;

    if (localIndex >= this.itemCount) {
      throw new Error(`report destroyed itemCount exhausted: localIndex=${localIndex}, itemCount=${this.itemCount}`);
    }

    const recordIndex = this.recordIndexFor(localIndex);
    const rec = this.records[recordIndex];

    if (!rec) {
      throw new Error(`approved-flow record not found for recordIndex=${recordIndex}, loadedApprovedFlow=${this.records.length}`);
    }

    const item = this.itemFor(rec);

    const receipt = await withMandatoryThresholdDestructionReceipt(
      item.destructionReceipt,
      rec.evidenceId
    );

    assertMandatoryThresholdDestructionReceipt(receipt, rec.evidenceId);

    return this.invoke(
      'reportEvidenceDestroyed',
      [
        rec.evidenceId,
        jsonArg(receipt)
      ],
      'EvidenceCustodian',
      false
    );
  }
}

module.exports.createWorkloadModule = () => new ReportDestroyedFromApprovedFlowPoolWorkload();
