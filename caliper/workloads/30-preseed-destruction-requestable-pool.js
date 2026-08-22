'use strict';

const fs = require('fs');
const path = require('path');

const { BlockForensicWorkloadBase } = require('./_base');
const {
  buildItem,
  registerCorePublicKeys,
  preserveEvidence,
  commitEvidence,
  issueCapability
} = require('../lib/seed-flow');

class PreseedDestructionRequestablePoolWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);

    this.poolPrefix = this.roundArguments.poolPrefix || 'destreqpool';
    this.poolWorkerIndex = Number(this.roundArguments.poolWorkerIndex || 0);
    this.sliceOffset = Number(this.roundArguments.sliceOffset || 0);
    this.itemCount = Number(this.roundArguments.itemCount || this.txCount());
    this.scopeProfile = this.roundArguments.scopeProfile || 'HASH_ONLY';
    this.issueCapabilityBeforeDestruction =
      this.roundArguments.issueCapabilityBeforeDestruction !== false;

    this.manifestDir = this.roundArguments.manifestDir || 'config/destruction-requestable-manifests';
    fs.mkdirSync(this.manifestDir, { recursive: true });

    this.manifestFile = path.join(
      this.manifestDir,
      `${this.poolPrefix}-worker${this.workerIndex}.jsonl`
    );

    try {
      fs.unlinkSync(this.manifestFile);
    } catch {}

    console.log(
      `[preseed-destruction-requestable-pool] poolPrefix=${this.poolPrefix} ` +
      `worker=${this.workerIndex}/${this.totalWorkers} ` +
      `sliceOffset=${this.sliceOffset} itemCount=${this.itemCount} ` +
      `issueCapabilityBeforeDestruction=${this.issueCapabilityBeforeDestruction} ` +
      `manifestFile=${this.manifestFile}`
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
      throw new Error(`preseed destruction-requestable itemCount exhausted: localIndex=${localIndex}, itemCount=${this.itemCount}`);
    }

    const item = this.itemFor(localIndex);
    const globalIndex = this.globalIndexFor(localIndex);
    const evidenceId = item.evidence?.evidenceId || item.evidenceId;

    if (!evidenceId) {
      throw new Error(`missing evidenceId in requestable preseed item`);
    }

    await preserveEvidence(this.sutAdapter, this.contractId, item);
    const result = await commitEvidence(this.sutAdapter, this.contractId, item);

    if (this.issueCapabilityBeforeDestruction) {
      await issueCapability(this.sutAdapter, this.contractId, item);
    }

    const record = {
      evidenceId,
      globalIndex,
      state: this.issueCapabilityBeforeDestruction ? 'AUTHORIZED' : 'COMMITTED'
    };

    fs.appendFileSync(this.manifestFile, JSON.stringify(record) + '\n', 'utf8');

    return result;
  }
}

module.exports.createWorkloadModule = () => new PreseedDestructionRequestablePoolWorkload();
