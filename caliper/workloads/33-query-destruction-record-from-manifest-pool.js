'use strict';

const fs = require('fs');
const path = require('path');

const { BlockForensicWorkloadBase } = require('./_base');

class QueryDestructionRecordFromManifestPoolWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);

    this.poolPrefix = this.roundArguments.poolPrefix || 'destreqpool';
    this.sliceOffset = Number(this.roundArguments.sliceOffset || 0);
    this.recordLimit = Number(this.roundArguments.recordLimit || 0);
    this.manifestDir = this.roundArguments.manifestDir || 'config/destruction-requestable-manifests';

    if (!fs.existsSync(this.manifestDir)) {
      throw new Error(`manifestDir not found: ${this.manifestDir}`);
    }

    const files = fs.readdirSync(this.manifestDir)
      .filter((name) => name.startsWith(`${this.poolPrefix}-worker`) && name.endsWith('.jsonl'))
      .sort()
      .map((name) => path.join(this.manifestDir, name));

    if (files.length === 0) {
      throw new Error(`no destruction manifest files found for poolPrefix=${this.poolPrefix} in ${this.manifestDir}`);
    }

    const records = [];

    for (const file of files) {
      const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean);
      for (const line of lines) {
        const rec = JSON.parse(line);
        if (rec.evidenceId && Number.isFinite(rec.globalIndex)) {
          records.push(rec);
        }
      }
    }

    records.sort((a, b) => a.globalIndex - b.globalIndex);

    if (records.length === 0) {
      throw new Error(`query destruction manifest loaded zero records for poolPrefix=${this.poolPrefix}`);
    }

    const available = records.length - this.sliceOffset;
    const limit = this.recordLimit > 0 ? this.recordLimit : available;

    if (this.sliceOffset < 0 || this.sliceOffset >= records.length) {
      throw new Error(`invalid sliceOffset=${this.sliceOffset}, loadedRecords=${records.length}`);
    }

    if (limit <= 0 || limit > available) {
      throw new Error(`invalid recordLimit=${limit}, sliceOffset=${this.sliceOffset}, loadedRecords=${records.length}`);
    }

    this.records = records.slice(this.sliceOffset, this.sliceOffset + limit);

    console.log(
      `[query-destruction-record-from-manifest-pool] poolPrefix=${this.poolPrefix} ` +
      `worker=${this.workerIndex}/${this.totalWorkers} ` +
      `sliceOffset=${this.sliceOffset} recordLimit=${limit} ` +
      `manifestFiles=${files.length} loadedRecords=${records.length} activeRecords=${this.records.length}`
    );
  }

  recordIndexFor(localIndex) {
    return (this.workerIndex + (localIndex * this.totalWorkers)) % this.records.length;
  }

  async submitTransaction() {
    const localIndex = this.next;
    this.next += 1;

    const recordIndex = this.recordIndexFor(localIndex);
    const rec = this.records[recordIndex];

    return this.invoke(
      'getEvidenceDestructionRecord',
      [
        rec.evidenceId
      ],
      'EvidenceCustodian',
      true
    );
  }
}

module.exports.createWorkloadModule = () => new QueryDestructionRecordFromManifestPoolWorkload();
