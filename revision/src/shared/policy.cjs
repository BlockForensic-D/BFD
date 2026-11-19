"use strict";
const POLICY = Object.freeze({
  profile: "BFD_REVISION_V1_G",
  policyVersion: 1,
  schemaVersion: 1,
  chaincodeName: "bfdRevisionV1",
  commitmentVersion: "chunk-merkle-v3-hmac-opening",
  oddNodeRule: "DUPLICATE_LAST",
  validationMethodVersion: "FULL_STREAM_V1",
  maxCapTTL: 604800,
  maxSessionTTL: 86400,
  issuanceSkew: 300,
  maxAssignmentTTL: 604800,
  maxChunkSize: 262144,
  maxScopeIndices: 16384,
  maxLedgerBytes: 524288,
  requiredKeyClasses: ["DEK", "EMK", "K_META", "K_SALT"],
  purposes: {
    CAPABILITY_ISSUER: ["EvidenceCustodian"],
    ACQUISITION_VALIDATION: ["AcquisitionAuditor"],
    DESTRUCTION_ATTESTATION: [
      "EvidenceCustodian",
      "DataProtectionOfficer",
      "JudicialReviewer",
    ],
  },
});
module.exports = { POLICY };
