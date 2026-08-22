'use strict';

const fs = require('fs');
const path = require('path');

const { BlockForensicWorkloadBase } = require('./_base');
const { jsonArg } = require('../lib/caliper-utils');
const { buildItem, registerCorePublicKeys } = require('../lib/seed-flow');
const { buildDestructionRequest, buildDestructionApproval } = require('../lib/payload-builders');
const {
  withMandatoryThresholdDestructionReceipt,
  assertMandatoryThresholdDestructionReceipt,
  registerDestructionAttestationKeys
} = require('../lib/threshold-destruction-receipt');

function hrMs() {
  return Number(process.hrtime.bigint()) / 1e6;
}

function safeError(err) {
  const msg = String(err && (err.message || err.stack || err));
  return msg.replace(/\s+/g, ' ').slice(0, 2000);
}

class FullLifecycleLogicalE2EWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);

    this.runId = this.roundArguments.runId || `e2e-${Date.now()}`;
    this.scopeProfile = this.roundArguments.scopeProfile || 'HASH_ONLY';
    this.prefix = this.roundArguments.poolPrefix || this.roundArguments.prefix || this.runId;
    this.sliceOffset = Number(this.roundArguments.sliceOffset || 0);
    this.metricsDir = this.roundArguments.metricsDir || path.join('results', 'e2e-logical', this.runId);

    fs.mkdirSync(this.metricsDir, { recursive: true });

    this.metricsFile = path.join(
      this.metricsDir,
      `${this.runId}-round${this.roundIndex}-worker${this.workerIndex}.jsonl`
    );

    console.log(
      `[full-lifecycle-logical-e2e] runId=${this.runId} ` +
      `worker=${this.workerIndex}/${this.totalWorkers} round=${this.roundIndex} ` +
      `prefix=${this.prefix} sliceOffset=${this.sliceOffset} ` +
      `scopeProfile=${this.scopeProfile} metricsFile=${this.metricsFile}`
    );

    await registerCorePublicKeys(this.sutAdapter, this.contractId);

    await registerDestructionAttestationKeys(this.sutAdapter, this.contractId, {
      workerIndex: this.workerIndex,
      totalWorkers: this.totalWorkers
    });
  }

  globalIndexFor(localIndex) {
    return this.sliceOffset + this.workerIndex + (localIndex * this.totalWorkers);
  }

  async stage(row, name, fn) {
    const t0 = hrMs();
    try {
      const result = await fn();
      row.stageMs[name] = Number((hrMs() - t0).toFixed(3));
      return result;
    } catch (err) {
      row.stageMs[name] = Number((hrMs() - t0).toFixed(3));
      row.failedStage = name;
      throw err;
    }
  }

  appendMetric(row) {
    fs.appendFileSync(this.metricsFile, JSON.stringify(row) + '\n');
  }

  async submitTransaction() {
    const localIndex = this.next;
    this.next += 1;

    const globalIndex = this.globalIndexFor(localIndex);

    const item = buildItem({
      prefix: this.prefix,
      workerIndex: this.workerIndex,
      index: globalIndex,
      scopeProfile: this.scopeProfile
    });

    const evId = item.evidence.evidenceId;

    const row = {
      runId: this.runId,
      roundIndex: this.roundIndex,
      workerIndex: this.workerIndex,
      totalWorkers: this.totalWorkers,
      localIndex,
      globalIndex,
      evidenceId: evId,
      scopeProfile: this.scopeProfile,
      startedAt: new Date().toISOString(),
      startedAtEpochMs: Date.now(),
      status: 'STARTED',
      failedStage: null,
      error: null,
      stageMs: {}
    };

    const tAll = hrMs();

    try {
      await this.stage(row, 'preserveEvidence', async () => {
        return this.invoke(
          'preserveEvidence',
          [jsonArg(item.evidence)],
          'GatewayCollector',
          false
        );
      });

      await this.stage(row, 'commitPreservedEvidence', async () => {
        return this.invoke(
          'commitPreservedEvidence',
          [evId, jsonArg(item.commitPayload)],
          'EvidenceCustodian',
          false
        );
      });

      await this.stage(row, 'issueDisclosureCapability', async () => {
        return this.invoke(
          'issueDisclosureCapability',
          [jsonArg(item.capabilityToken)],
          'EvidenceCustodian',
          false
        );
      });

      await this.stage(row, 'requestDisclosure', async () => {
        return this.invoke(
          'requestDisclosure',
          [
            evId,
            jsonArg(item.capabilityToken),
            jsonArg(item.requestedChunkIndices)
          ],
          'ExternalVendor',
          false,
          {
            endorsingOrganizations: ['Org1MSP', 'Org2MSP']
          }
        );
      });

      await this.stage(row, 'requestEvidenceDestruction', async () => {
        return this.invoke(
          'requestEvidenceDestruction',
          [evId, jsonArg(buildDestructionRequest(globalIndex))],
          'DataProtectionOfficer',
          false
        );
      });

      await this.stage(row, 'approveEvidenceDestruction', async () => {
        return this.invoke(
          'approveEvidenceDestruction',
          [evId, jsonArg(buildDestructionApproval(globalIndex))],
          'JudicialReviewer',
          false
        );
      });

      await this.stage(row, 'reportEvidenceDestroyed', async () => {
        const destructionReceipt = await withMandatoryThresholdDestructionReceipt(
          item.destructionReceipt,
          evId
        );

        assertMandatoryThresholdDestructionReceipt(destructionReceipt, evId);

        return this.invoke(
          'reportEvidenceDestroyed',
          [evId, jsonArg(destructionReceipt)],
          'EvidenceCustodian',
          false
        );
      });

      await this.stage(row, 'getEvidenceDestructionRecord', async () => {
        return this.invoke(
          'getEvidenceDestructionRecord',
          [evId],
          'ExternalAuditor',
          true
        );
      });

      row.status = 'COMPLETED';
      return row;
    } catch (err) {
      row.status = 'FAILED';
      row.error = safeError(err);
      throw err;
    } finally {
      row.endedAt = new Date().toISOString();
      row.endedAtEpochMs = Date.now();
      row.totalMs = Number((hrMs() - tAll).toFixed(3));
      this.appendMetric(row);
    }
  }
}

module.exports.createWorkloadModule = () => new FullLifecycleLogicalE2EWorkload();
