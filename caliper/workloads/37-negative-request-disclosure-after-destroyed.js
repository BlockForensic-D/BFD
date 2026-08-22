'use strict';

const fs = require('fs');
const path = require('path');

const { BlockForensicWorkloadBase } = require('./_base');
const { jsonArg } = require('../lib/caliper-utils');
const { buildItem } = require('../lib/seed-flow');

class NegativeRequestDisclosureAfterDestroyedWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);

    this.poolPrefix = this.roundArguments.poolPrefix || 'drs';
    this.poolWorkerIndex = Number(this.roundArguments.poolWorkerIndex || 0);
    this.sliceOffset = Number(this.roundArguments.sliceOffset || 0);
    this.recordLimit = Number(this.roundArguments.recordLimit || 0);
    this.scopeProfile = this.roundArguments.scopeProfile || 'HASH_ONLY';
    this.manifestDir = this.roundArguments.manifestDir || 'config/destruction-requestable-manifests';

    const pattern = this.roundArguments.expectedRejectionRegex ||
      'DESTROYED|destroyed|revoked|capability|lifecycle|state|not.*disclos|not.*authorized';

    this.expectedRejectionRegex = new RegExp(pattern, 'i');

    if (!fs.existsSync(this.manifestDir)) {
      throw new Error(`manifestDir not found: ${this.manifestDir}`);
    }

    const files = fs.readdirSync(this.manifestDir)
      .filter((name) => name.startsWith(`${this.poolPrefix}-worker`) && name.endsWith('.jsonl'))
      .sort()
      .map((name) => path.join(this.manifestDir, name));

    if (files.length === 0) {
      throw new Error(`no destroyed manifest files found for poolPrefix=${this.poolPrefix} in ${this.manifestDir}`);
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
      `[negative-request-disclosure-after-destroyed] poolPrefix=${this.poolPrefix} ` +
      `worker=${this.workerIndex}/${this.totalWorkers} ` +
      `sliceOffset=${this.sliceOffset} recordLimit=${limit} ` +
      `loadedRecords=${records.length} activeDestroyedRecords=${this.records.length} ` +
      `expectedRejectionRegex=${this.expectedRejectionRegex}`
    );
  }

  recordIndexFor(localIndex) {
    return (this.workerIndex + (localIndex * this.totalWorkers)) % this.records.length;
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

    const recordIndex = this.recordIndexFor(localIndex);
    const rec = this.records[recordIndex];
    const item = this.itemFor(rec);

    try {
      await this.invoke(
        'requestDisclosure',
        [
          rec.evidenceId,
          jsonArg(item.capabilityToken),
          jsonArg(item.requestedChunkIndices)
        ],
        'ExternalVendor',
        false,
        {
          endorsingOrganizations: ['Org1MSP', 'Org2MSP']
        }
      );

      throw new Error(`UNEXPECTED_SUCCESS: requestDisclosure succeeded for destroyed evidence ${rec.evidenceId}`);
    } catch (err) {
      const msg = String(err && (err.message || err.stack || err));

      if (msg.includes('UNEXPECTED_SUCCESS')) {
        throw err;
      }

      if (!this.expectedRejectionRegex.test(msg)) {
        throw new Error(`UNEXPECTED_REJECTION_REASON for ${rec.evidenceId}: ${msg}`);
      }

      return {
        expectedRejected: true,
        evidenceId: rec.evidenceId
      };
    }
  }
}

module.exports.createWorkloadModule = () => new NegativeRequestDisclosureAfterDestroyedWorkload();
