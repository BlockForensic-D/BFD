'use strict';

const { BlockForensicWorkloadBase } = require('./_base');
const { jsonArg } = require('../lib/caliper-utils');

class RequestDisclosureWorkload extends BlockForensicWorkloadBase {
  async initializeWorkloadModule(...args) {
    await super.initializeWorkloadModule(...args);
    await this.seedItems(
      'AUTHORIZED',
      this.txCount(),
      'requestdisc',
      this.roundArguments.scopeProfile || 'HASH_ONLY'
    );
  }

  async submitTransaction() {
    const item = this.currentItem();

    return this.invoke(
      'requestDisclosure',
      [
        item.evidence.evidenceId,
        jsonArg(item.capabilityToken),
        jsonArg(item.requestedChunkIndices)
      ],
      'ExternalVendor',
      false,
      {
        // Chaincode validation policy requires Org1MSP + Org2MSP.
        // ExternalVendor remains the invoker/requester; Org1+Org2 endorse the ledger state change.
        endorsingOrganizations: ['Org1MSP', 'Org2MSP']
      }
    );
  }
}

module.exports.createWorkloadModule = () => new RequestDisclosureWorkload();
