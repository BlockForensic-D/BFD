'use strict';

const fs = require('fs');
const path = require('path');

const { BlockForensicWorkloadBase } = require('./_base');
const {
  buildItem,
  requestDestruction
} = require('../lib/seed-flow');

class RequestDestructionFromRequestablePoolWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);

    this.poolPrefix = this.roundArguments.poolPrefix || 'destreqpool';
    this.poolWorkerIndex = Number(this.roundArguments.poolWorkerIndex || 0);
    this.sliceOffset = Number(this.roundArguments.sliceOffset || 0);
    this.itemCount = Number(this.roundArguments.itemCount || this.txCount());
    this.scopeProfile = this.roundArguments.scopeProfile || 'HASH_ONLY';
    this.manifestDir = this.roundArguments.manifestDir || 'config/destruction-requestable-manifests';

    if (!fs.existsSync(this.manifestDir)) {
      throw new Error(`manifestDir not found: ${this.manifestDir}`);
    }

    const files = fs.readdirSync(this.manifestDir)
      .filter((name) => name.startsWith(`${this.poolPrefix}-worker`) && name.endsWith('.jsonl'))
      .sort()
      .map((name) => path.join(this.manifestDir, name));

    if (files.length === 0) {
      throw new Error(`no destruction-requestable manifest files found for poolPrefix=${this.poolPrefix} in ${this.manifestDir}`);
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
      `[request-destruction-from-requestable-pool] poolPrefix=${this.poolPrefix} ` +
      `worker=${this.workerIndex}/${this.totalWorkers} ` +
      `sliceOffset=${this.sliceOffset} itemCount=${this.itemCount} ` +
      `manifestFiles=${files.length} loadedRequestable=${this.records.length}`
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
      throw new Error(`request destruction itemCount exhausted: localIndex=${localIndex}, itemCount=${this.itemCount}`);
    }

    const recordIndex = this.recordIndexFor(localIndex);
    const rec = this.records[recordIndex];

    if (!rec) {
      throw new Error(`requestable destruction record not found in manifest for recordIndex=${recordIndex}, loadedRequestable=${this.records.length}`);
    }

    const item = this.itemFor(rec);

    return requestDestruction(
      this.sutAdapter,
      this.contractId,
      item,
      null,
      rec.globalIndex
    );
  }
}

module.exports.createWorkloadModule = () => new RequestDestructionFromRequestablePoolWorkload();
