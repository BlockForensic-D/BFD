// SPDX-License-Identifier: Apache-2.0

export const GOVERNANCE_EVENTS = Object.freeze({
  CAPABILITY_ISSUED: 'CapabilityIssued',
  CAPABILITY_USED: 'CapabilityUsed',
  CAPABILITY_EXPIRED: 'CapabilityExpired',
  CAPABILITY_REVOKED: 'CapabilityRevoked',
  CAPABILITY_ACCESS_STATE_CHANGED: 'CapabilityAccessStateChanged',
  EVIDENCE_LIFECYCLE_STATE_CHANGED: 'EvidenceLifecycleStateChanged',
  EVIDENCE_RESTRICTED: 'EvidenceRestricted',
  EVIDENCE_WITHDRAWN: 'EvidenceWithdrawn',
  KEY_DESTRUCTION_REQUESTED: 'KeyDestructionRequested',
  KEY_DESTRUCTION_COMPLETED: 'KeyDestructionCompleted',
  DISCLOSURE_VERIFIED: 'DisclosureVerified',
});

export function buildGovernanceEvent(eventType, payload = {}) {
  return {
    eventType,
    version: 'governance-event-v1',
    emittedAt: payload.emittedAt || new Date().toISOString(),
    ...payload,
  };
}

export function summarizeGovernanceTransition({ objectType, objectId, from, to, reason, actor, at }) {
  return { objectType, objectId, from, to, reason: reason || null, actor: actor || null, at: at || new Date().toISOString() };
}

export default { GOVERNANCE_EVENTS, buildGovernanceEvent, summarizeGovernanceTransition };
