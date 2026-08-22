'use strict';

const fs = require('fs');
const path = require('path');

const { BlockForensicWorkloadBase } = require('./_base');
const {
  buildItem,
  registerCorePublicKeys,
  preserveEvidence
} = require('../lib/seed-flow');

class PreserveEvidenceMeasureWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);

    this.poolPrefix = this.roundArguments.poolPrefix || 'preservepool';
    this.poolWorkerIndex = Number(this.roundArguments.poolWorkerIndex || 0);
    this.sliceOffset = Number(this.roundArguments.sliceOffset || 0);
    this.itemCount = Number(this.roundArguments.itemCount || this.txCount());
    this.scopeProfile = this.roundArguments.scopeProfile || 'HASH_ONLY';

    this.manifestDir = this.roundArguments.manifestDir || '';
    this.manifestFile = null;

    if (this.manifestDir) {
      fs.mkdirSync(this.manifestDir, { recursive: true });
      this.manifestFile = path.join(
        this.manifestDir,
        `${this.poolPrefix}-worker${this.workerIndex}.jsonl`
      );

      try {
        fs.unlinkSync(this.manifestFile);
      } catch {}
    }

    console.log(
      `[preserve-evidence-measure] poolPrefix=${this.poolPrefix} ` +
      `worker=${this.workerIndex}/${this.totalWorkers} ` +
      `sliceOffset=${this.sliceOffset} itemCount=${this.itemCount} ` +
      `manifestFile=${this.manifestFile || 'disabled'}`
    );

    await registerCorePublicKeys(this.sutAdapter, this.contractId);
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
      throw new Error(`preserve evidence itemCount exhausted: localIndex=${localIndex}, itemCount=${this.itemCount}`);
    }

    const item = this.itemFor(localIndex);
    const globalIndex = this.globalIndexFor(localIndex);
    const evidenceId = item.evidence?.evidenceId || item.evidenceId;

    const result = await preserveEvidence(this.sutAdapter, this.contractId, item);

    if (this.manifestFile) {
      fs.appendFileSync(
        this.manifestFile,
        JSON.stringify({
          evidenceId,
          globalIndex,
          state: 'PRESERVED'
        }) + '\n',
        'utf8'
      );
    }

    return result;
  }
}

module.exports.createWorkloadModule = () => new PreserveEvidenceMeasureWorkload();
