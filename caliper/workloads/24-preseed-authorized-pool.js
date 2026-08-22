'use strict';

const fs = require('fs');
const path = require('path');

const { BlockForensicWorkloadBase } = require('./_base');
const { jsonArg } = require('../lib/caliper-utils');
const {
  buildItem,
  registerCorePublicKeys,
  preserveEvidence,
  commitEvidence
} = require('../lib/seed-flow');

class PreseedAuthorizedPoolWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);

    this.poolPrefix = this.roundArguments.poolPrefix || 'requestpool';
    this.poolWorkerIndex = Number(this.roundArguments.poolWorkerIndex || 0);
    this.sliceOffset = Number(this.roundArguments.sliceOffset || 0);
    this.itemCount = Number(this.roundArguments.itemCount || this.txCount());
    this.scopeProfile = this.roundArguments.scopeProfile || 'HASH_ONLY';

    this.tokensDir = this.roundArguments.tokensDir || 'config/request-capability-tokens';
    fs.mkdirSync(this.tokensDir, { recursive: true });

    this.tokenFile = path.join(
      this.tokensDir,
      `${this.poolPrefix}-worker${this.workerIndex}.jsonl`
    );

    // Preseed has one round per pool. Remove stale token file for this worker.
    try {
      fs.unlinkSync(this.tokenFile);
    } catch {}

    console.log(
      `[preseed-authorized-pool] poolPrefix=${this.poolPrefix} ` +
      `worker=${this.workerIndex}/${this.totalWorkers} ` +
      `sliceOffset=${this.sliceOffset} itemCount=${this.itemCount} ` +
      `tokenFile=${this.tokenFile}`
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
      throw new Error(`preseed authorized itemCount exhausted: localIndex=${localIndex}, itemCount=${this.itemCount}`);
    }

    const item = this.itemFor(localIndex);
    const evidenceId = item.evidenceId || item.capabilityToken.evidenceId;

    await preserveEvidence(this.sutAdapter, this.contractId, item);
    await commitEvidence(this.sutAdapter, this.contractId, item);

    const result = await this.invoke(
      'issueDisclosureCapability',
      [jsonArg(item.capabilityToken)],
      'EvidenceCustodian',
      false
    );

    const record = {
      evidenceId,
      capId: item.capabilityToken.capId,
      globalIndex: this.globalIndexFor(localIndex),
      capabilityToken: item.capabilityToken
    };

    fs.appendFileSync(this.tokenFile, JSON.stringify(record) + '\n', 'utf8');

    return result;
  }
}

module.exports.createWorkloadModule = () => new PreseedAuthorizedPoolWorkload();
