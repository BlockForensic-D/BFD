'use strict';

const EVIDENCE_LIFECYCLE_STATES = Object.freeze({
  PRESERVED: 'PRESERVED',
  COMMITTED: 'COMMITTED',
  AUTHORIZED: 'AUTHORIZED',
  DISCLOSED: 'DISCLOSED',
  DESTRUCTION_REQUESTED: 'DESTRUCTION_REQUESTED',
  DESTRUCTION_APPROVED: 'DESTRUCTION_APPROVED',
  DESTROYED: 'DESTROYED'
});

const DISCLOSURE_PERMISSIBLE_STATES = Object.freeze([
  EVIDENCE_LIFECYCLE_STATES.COMMITTED,
  EVIDENCE_LIFECYCLE_STATES.AUTHORIZED,
  EVIDENCE_LIFECYCLE_STATES.DISCLOSED
]);

function normalizeEvidenceLifecycleState(value, fieldName = 'evidenceLifecycleState') {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new TypeError(`${fieldName} must be a non-empty string`);
  }
  const normalized = value.trim().toUpperCase();
  if (!Object.values(EVIDENCE_LIFECYCLE_STATES).includes(normalized)) {
    throw new Error(`Unknown evidence lifecycle state: ${normalized}`);
  }
  return normalized;
}

function isDisclosurePermissibleState(value) {
  try {
    return DISCLOSURE_PERMISSIBLE_STATES.includes(normalizeEvidenceLifecycleState(value));
  } catch {
    return false;
  }
}

export {
  EVIDENCE_LIFECYCLE_STATES,
  DISCLOSURE_PERMISSIBLE_STATES,
  normalizeEvidenceLifecycleState,
  isDisclosurePermissibleState
};
