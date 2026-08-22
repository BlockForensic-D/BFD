'use strict';

const fs = require('fs');
const path = require('path');

const { BlockForensicWorkloadBase } = require('./_base');
const { jsonArg } = require('../lib/caliper-utils');
const {
  withMandatoryThresholdDestructionReceipt,
  assertMandatoryThresholdDestructionReceipt,
  registerDestructionAttestationKeys
} = require('../lib/threshold-destruction-receipt');

class ReportDestroyedFromApprovedPoolWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);

    this.poolPrefix = this.roundArguments.poolPrefix || 'destpool';
    this.sliceOffset = Number(this.roundArguments.sliceOffset || 0);
    this.itemCount = Number(this.roundArguments.itemCount || this.txCount());
    this.manifestDir = this.roundArguments.manifestDir || 'config/destruction-approved-manifests';

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
      throw new Error(`no destruction-approved manifest files found for poolPrefix=${this.poolPrefix} in ${this.manifestDir}`);
    }

    this.records = [];

    for (const file of files) {
      const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean);
      for (const line of lines) {
        const rec = JSON.parse(line);
        if (rec.evidenceId && rec.destructionReceipt) {
          this.records.push(rec);
        }
      }
    }

    this.records.sort((a, b) => {
      const ga = Number.isFinite(a.globalIndex) ? a.globalIndex : 0;
      const gb = Number.isFinite(b.globalIndex) ? b.globalIndex : 0;
      return ga - gb;
    });

    console.log(
      `[report-destroyed-from-approved-pool] poolPrefix=${this.poolPrefix} ` +
      `worker=${this.workerIndex}/${this.totalWorkers} ` +
      `sliceOffset=${this.sliceOffset} itemCount=${this.itemCount} ` +
      `manifestFiles=${files.length} loadedApproved=${this.records.length}`
    );
  }

  recordIndexFor(localIndex) {
    return this.sliceOffset + this.workerIndex + (localIndex * this.totalWorkers);
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
      throw new Error(`approved destruction record not found in manifest for recordIndex=${recordIndex}, loadedApproved=${this.records.length}`);
    }

    const receipt = await withMandatoryThresholdDestructionReceipt(
      rec.destructionReceipt,
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
      false,
      {
        endorsingOrganizations: ['Org1MSP', 'Org2MSP']
      }
    );
  }
}

module.exports.createWorkloadModule = () => new ReportDestroyedFromApprovedPoolWorkload();
