'use strict';
const { BlockForensicWorkloadBase } = require('./_base');
const { jsonArg, send, getIdentityConfig } = require('../lib/caliper-utils');
const { buildItem, seedToState, getKeyStore } = require('../lib/seed-flow');
const { buildCapabilityForEvidence } = require('../lib/payload-builders');

class NegativeControlsWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);
    this.caseName = String(this.roundArguments.case || 'post_destroy_requestDisclosure');
    const count = this.txCount();
    this.items = this.buildItems(count, `neg-${this.caseName}`, this.roundArguments.scopeProfile || 'HASH_ONLY');

    if (this.caseName.includes('attestation') || this.caseName.includes('threshold')) {
      for (let i = 0; i < this.items.length; i++) await seedToState(this.sutAdapter, this.contractId, this.items[i], 'DESTRUCTION_APPROVED', i);
    } else if (this.caseName.includes('post_destroy')) {
      for (let i = 0; i < this.items.length; i++) await seedToState(this.sutAdapter, this.contractId, this.items[i], 'DESTROYED', i);
    } else {
      for (let i = 0; i < this.items.length; i++) await seedToState(this.sutAdapter, this.contractId, this.items[i], 'AUTHORIZED', i);
    }
  }

  async submitTransaction() {
    const item = this.currentItem();
    const evId = item.evidence.evidenceId;
    let fcn;
    let args;
    let identity;

    if (this.caseName === 'tampered_attestation_reportDestroyed') {
      const bad = JSON.parse(JSON.stringify(item.destructionReceipt));
      bad.destructionAttestations[0].signature = '00'.repeat(64);
      fcn = 'reportEvidenceDestroyed';
      args = [evId, jsonArg(bad)];
      identity = 'EvidenceCustodian';
    } else if (this.caseName === 'insufficient_threshold_reportDestroyed') {
      const bad = JSON.parse(JSON.stringify(item.destructionReceipt));
      bad.thresholdPolicy.required = 3;
      bad.destructionAttestations = bad.destructionAttestations.slice(0, 1);
      fcn = 'reportEvidenceDestroyed';
      args = [evId, jsonArg(bad)];
      identity = 'EvidenceCustodian';
    } else if (this.caseName === 'wrong_grantee_requestDisclosure') {
      fcn = 'requestDisclosure';
      args = [evId, jsonArg(item.capabilityToken), jsonArg(item.requestedChunkIndices)];
      identity = 'ExternalAuditor';
    } else if (this.caseName === 'wrong_root_requestDisclosure') {
      const badToken = { ...item.capabilityToken, chunkMerkleRoot: 'a'.repeat(64) };
      fcn = 'requestDisclosure';
      args = [evId, jsonArg(badToken), jsonArg(item.requestedChunkIndices)];
      identity = 'ExternalVendor';
    } else if (this.caseName === 'scope_escalation_requestDisclosure') {
      fcn = 'requestDisclosure';
      args = [evId, jsonArg(item.capabilityToken), jsonArg([999999])];
      identity = 'ExternalVendor';
    } else {
      // default: stale/post-destruction or otherwise invalid capability request
      fcn = 'requestDisclosure';
      args = [evId, jsonArg(item.capabilityToken), jsonArg(item.requestedChunkIndices)];
      identity = 'ExternalVendor';
    }

    // Expected failure. Caliper would mark thrown errors as failed requests, which is fine
    // for negative-control rounds. The paper-level metric is expected rejection rate.
    return this.invoke(fcn, args, identity, false);
  }
}
module.exports.createWorkloadModule = () => new NegativeControlsWorkload();
