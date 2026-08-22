'use strict';

const fs = require('fs');
const path = require('path');

const { BlockForensicWorkloadBase } = require('./_base');
const { jsonArg } = require('../lib/caliper-utils');

class RequestDisclosureFromAuthorizedPoolWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);

    this.poolPrefix = this.roundArguments.poolPrefix || 'requestpool';
    this.sliceOffset = Number(this.roundArguments.sliceOffset || 0);
    this.itemCount = Number(this.roundArguments.itemCount || this.txCount());
    this.tokensDir = this.roundArguments.tokensDir || 'config/request-capability-tokens';

    if (!fs.existsSync(this.tokensDir)) {
      throw new Error(`tokensDir not found: ${this.tokensDir}`);
    }

    const files = fs.readdirSync(this.tokensDir)
      .filter((name) => name.startsWith(`${this.poolPrefix}-worker`) && name.endsWith('.jsonl'))
      .sort()
      .map((name) => path.join(this.tokensDir, name));

    if (files.length === 0) {
      throw new Error(`no token files found for poolPrefix=${this.poolPrefix} in ${this.tokensDir}`);
    }

    this.records = [];

    for (const file of files) {
      const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean);
      for (const line of lines) {
        const rec = JSON.parse(line);
        if (rec.evidenceId && rec.capabilityToken && rec.capabilityToken.capId) {
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
      `[request-disclosure-from-authorized-pool] poolPrefix=${this.poolPrefix} ` +
      `worker=${this.workerIndex}/${this.totalWorkers} ` +
      `sliceOffset=${this.sliceOffset} itemCount=${this.itemCount} ` +
      `tokenFiles=${files.length} loadedTokens=${this.records.length}`
    );
  }

  recordIndexFor(localIndex) {
    return this.sliceOffset + this.workerIndex + (localIndex * this.totalWorkers);
  }

  async submitTransaction() {
    const localIndex = this.next;
    this.next += 1;

    if (localIndex >= this.itemCount) {
      throw new Error(`request disclosure itemCount exhausted: localIndex=${localIndex}, itemCount=${this.itemCount}`);
    }

    const recordIndex = this.recordIndexFor(localIndex);
    const rec = this.records[recordIndex];

    if (!rec) {
      throw new Error(`capability token not found in token array for recordIndex=${recordIndex}, loadedTokens=${this.records.length}`);
    }

    const evidenceId = rec.evidenceId;
    const capabilityToken = rec.capabilityToken;
    const requestedChunkIndices = [];

    return this.invoke(
      'requestDisclosure',
      [
        evidenceId,
        jsonArg(capabilityToken),
        JSON.stringify(requestedChunkIndices)
      ],
      'ExternalVendor',
      false,
      {
        endorsingOrganizations: ['Org1MSP', 'Org2MSP']
      }
    );
  }
}

module.exports.createWorkloadModule = () => new RequestDisclosureFromAuthorizedPoolWorkload();
