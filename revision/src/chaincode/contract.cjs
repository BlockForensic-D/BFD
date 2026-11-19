"use strict";
const { Contract } = require("fabric-contract-api");
const { RevisionService } = require("./service.cjs");
const C = require("../shared/canonical.cjs");
const { POLICY } = require("../shared/policy.cjs");
const { peer } = require("@hyperledger/fabric-protos");
const service = new RevisionService();
class RevisionContract extends Contract {
  constructor() {
    super("BFDRevision");
  }
  async beforeTransaction(ctx) {
    const payload = ctx.stub.getSignedProposal()?.proposal?.payload;
    if (!payload) C.fail("SIGNED_PROPOSAL_REQUIRED");
    const invocation = peer.ChaincodeInvocationSpec.deserializeBinary(
      payload.getInput_asU8(),
    );
    if (
      invocation.getChaincodeSpec()?.getChaincodeId()?.getName() !==
      POLICY.chaincodeName
    )
      C.fail("DEPLOYED_CHAINCODE_DOMAIN");
  }
  async registerPublicKey(ctx, input) {
    return C.canonical(
      await service.registerPublicKey(ctx, C.parseStrict(input)),
    );
  }
  async rotatePublicKey(ctx, input) {
    return C.canonical(
      await service.rotatePublicKey(ctx, C.parseStrict(input)),
    );
  }
  async revokePublicKey(ctx, input) {
    return C.canonical(
      await service.revokePublicKey(ctx, C.parseStrict(input)),
    );
  }
  async setPrincipalSuspension(ctx, input) {
    return C.canonical(
      await service.setPrincipalSuspension(ctx, C.parseStrict(input)),
    );
  }
  async preserveEvidence(ctx, input) {
    return C.canonical(
      await service.preserveEvidence(ctx, C.parseStrict(input)),
    );
  }
  async assignAcquisitionAuditor(ctx, input) {
    return C.canonical(
      await service.assignAcquisitionAuditor(ctx, C.parseStrict(input)),
    );
  }
  async revokeAcquisitionAssignment(ctx, input) {
    return C.canonical(
      await service.revokeAcquisitionAssignment(ctx, C.parseStrict(input)),
    );
  }
  async commitPreservedEvidence(ctx, input) {
    return C.canonical(
      await service.commitPreservedEvidence(ctx, C.parseStrict(input)),
    );
  }
  async issueDisclosureCapability(ctx, input) {
    return C.canonical(
      await service.issueDisclosureCapability(ctx, C.parseStrict(input)),
    );
  }
  async requestDisclosure(ctx, input) {
    return C.canonical(
      await service.requestDisclosure(ctx, C.parseStrict(input)),
    );
  }
  async finalizeDisclosure(ctx, input) {
    return C.canonical(
      await service.finalizeDisclosure(ctx, C.parseStrict(input)),
    );
  }
  async revokeDisclosureCapability(ctx, input) {
    return C.canonical(
      await service.revokeDisclosureCapability(ctx, C.parseStrict(input)),
    );
  }
  async placeLegalHold(ctx, input) {
    return C.canonical(await service.placeLegalHold(ctx, C.parseStrict(input)));
  }
  async releaseLegalHold(ctx, input) {
    return C.canonical(
      await service.releaseLegalHold(ctx, C.parseStrict(input)),
    );
  }
  async restrictEvidence(ctx, input) {
    return C.canonical(
      await service.restrictEvidence(ctx, C.parseStrict(input)),
    );
  }
  async withdrawEvidence(ctx, input) {
    return C.canonical(
      await service.withdrawEvidence(ctx, C.parseStrict(input)),
    );
  }
  async requestEvidenceDestruction(ctx, input) {
    return C.canonical(
      await service.requestEvidenceDestruction(ctx, C.parseStrict(input)),
    );
  }
  async approveEvidenceDestruction(ctx, input) {
    return C.canonical(
      await service.approveEvidenceDestruction(ctx, C.parseStrict(input)),
    );
  }
  async beginKeyErasure(ctx, input) {
    return C.canonical(
      await service.beginKeyErasure(ctx, C.parseStrict(input)),
    );
  }
  async reportEvidenceDestroyed(ctx, input) {
    return C.canonical(
      await service.reportEvidenceDestroyed(ctx, C.parseStrict(input)),
    );
  }
  async getEvidenceAnchor(ctx, input) {
    return C.canonical(
      await service.getEvidenceAnchor(ctx, C.parseStrict(input)),
    );
  }
  async getDisclosureSession(ctx, input) {
    return C.canonical(
      await service.getDisclosureSession(ctx, C.parseStrict(input)),
    );
  }
  async getFinalizationReceipt(ctx, input) {
    return C.canonical(
      await service.getFinalizationReceipt(ctx, C.parseStrict(input)),
    );
  }
  async getKeyVersion(ctx, input) {
    return C.canonical(await service.getKeyVersion(ctx, C.parseStrict(input)));
  }
  async getEligibility(ctx, input) {
    return C.canonical(await service.getEligibility(ctx, C.parseStrict(input)));
  }
  async getErasureOperation(ctx, input) {
    return C.canonical(
      await service.getErasureOperation(ctx, C.parseStrict(input)),
    );
  }
  async getReleaseAuthorization(ctx, input) {
    return C.canonical(
      await service.getReleaseAuthorization(ctx, C.parseStrict(input)),
    );
  }
}
module.exports = { RevisionContract };
