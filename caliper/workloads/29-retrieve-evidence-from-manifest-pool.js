'use strict';

const fs = require('fs');
const path = require('path');

const { BlockForensicWorkloadBase } = require('./_base');

class RetrieveEvidenceFromManifestPoolWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);

    this.poolPrefix = this.roundArguments.poolPrefix || 'retrpool';
    this.sliceOffset = Number(this.roundArguments.sliceOffset || 0);
    this.manifestDir = this.roundArguments.manifestDir || 'config/retrieve-committed-manifests';

    if (!fs.existsSync(this.manifestDir)) {
      throw new Error(`manifestDir not found: ${this.manifestDir}`);
    }

    const files = fs.readdirSync(this.manifestDir)
      .filter((name) => name.startsWith(`${this.poolPrefix}-worker`) && name.endsWith('.jsonl'))
      .sort()
      .map((name) => path.join(this.manifestDir, name));

    if (files.length === 0) {
      throw new Error(`no retrieve manifest files found for poolPrefix=${this.poolPrefix} in ${this.manifestDir}`);
    }

    this.records = [];

    for (const file of files) {
      const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean);
      for (const line of lines) {
        const rec = JSON.parse(line);
        if (rec.evidenceId) {
          this.records.push(rec);
        }
      }
    }

    this.records.sort((a, b) => {
      const ga = Number.isFinite(a.globalIndex) ? a.globalIndex : 0;
      const gb = Number.isFinite(b.globalIndex) ? b.globalIndex : 0;
      return ga - gb;
    });

    if (this.records.length === 0) {
      throw new Error(`retrieve manifest loaded zero records for poolPrefix=${this.poolPrefix}`);
    }

    console.log(
      `[retrieve-evidence-from-manifest-pool] poolPrefix=${this.poolPrefix} ` +
      `worker=${this.workerIndex}/${this.totalWorkers} ` +
      `sliceOffset=${this.sliceOffset} manifestFiles=${files.length} ` +
      `loadedRecords=${this.records.length}`
    );
  }

  recordIndexFor(localIndex) {
    return (this.sliceOffset + this.workerIndex + (localIndex * this.totalWorkers)) % this.records.length;
  }

  async submitTransaction() {
    const localIndex = this.next;
    this.next += 1;

    const recordIndex = this.recordIndexFor(localIndex);
    const rec = this.records[recordIndex];

    return this.invoke(
      'retrieveEvidence',
      [
        rec.evidenceId,
        'false',
        'false'
      ],
      'EvidenceCustodian',
      true
    );
  }
}

module.exports.createWorkloadModule = () => new RetrieveEvidenceFromManifestPoolWorkload();
