// SPDX-License-Identifier: Apache-2.0
/**
 * Capability governance state helper for delegated access contribution.
 * Client-side ESM variant. Chaincode embeds equivalent deterministic helpers.
 */

export const CAPABILITY_ACCESS_STATES = Object.freeze({
  ISSUED: 'ISSUED',
  ACTIVE: 'ACTIVE',
  USED: 'USED',
  EXPIRED: 'EXPIRED',
  REVOKED: 'REVOKED',
});

export const REVOCATION_REASONS = Object.freeze([
  'EXPIRED_AUTHORIZATION',
  'GRANTEE_ROLE_CHANGE',
  'SCOPE_VIOLATION',
  'INVESTIGATION_CLOSED',
  'SECURITY_INCIDENT',
  'POLICY_CHANGE',
  'GRANTEE_REQUEST',
  'ADMINISTRATIVE',
  'OTHER',
]);

export const RESTRICTION_REASONS = Object.freeze([
  'PENDING_LEGAL_REVIEW',
  'INVESTIGATION_HOLD',
  'INTEGRITY_QUESTION',
  'PRIVACY_REVIEW',
  'STAKEHOLDER_DISPUTE',
  'TEMPORARY_QUARANTINE',
  'ADMINISTRATIVE',
  'OTHER',
]);

const VALID_TRANSITIONS = Object.freeze({
  ISSUED: ['ACTIVE', 'REVOKED'],
  ACTIVE: ['USED', 'EXPIRED', 'REVOKED'],
  USED: ['USED', 'EXPIRED', 'REVOKED'],
  EXPIRED: [],
  REVOKED: [],
});

export function normalizeCapabilityAccessState(value, fallback = CAPABILITY_ACCESS_STATES.ACTIVE) {
  const raw = typeof value === 'object' && value !== null
    ? (value.accessState ?? value.state ?? value.status)
    : value;
  const state = String(raw || '').trim().toUpperCase();
  if (Object.values(CAPABILITY_ACCESS_STATES).includes(state)) return state;
  if (typeof value === 'object' && value?.active === false) return CAPABILITY_ACCESS_STATES.REVOKED;
  return fallback;
}

export function isCapabilityUsableState(state) {
  return [CAPABILITY_ACCESS_STATES.ACTIVE, CAPABILITY_ACCESS_STATES.USED]
    .includes(normalizeCapabilityAccessState(state));
}

export function canTransitionCapability(from, to) {
  const src = normalizeCapabilityAccessState(from);
  const dst = normalizeCapabilityAccessState(to);
  return (VALID_TRANSITIONS[src] || []).includes(dst);
}

export function deriveCapabilityStateOnUse(state) {
  const normalized = normalizeCapabilityAccessState(state);
  return normalized === CAPABILITY_ACCESS_STATES.ACTIVE
    ? CAPABILITY_ACCESS_STATES.USED
    : normalized;
}

export function normalizeReasonCode(value, allowed, fallback = 'OTHER') {
  const out = String(value || fallback).trim().toUpperCase();
  return allowed.includes(out) ? out : fallback;
}

export function buildCapabilityStateFields(state = CAPABILITY_ACCESS_STATES.ACTIVE) {
  const accessState = normalizeCapabilityAccessState(state);
  const active = isCapabilityUsableState(accessState);
  return {
    accessState,
    state: accessState,
    active,
    status: active ? 'active' : accessState.toLowerCase(),
  };
}

export function applyCapabilityUse(record, at = new Date().toISOString()) {
  const previousState = normalizeCapabilityAccessState(record);
  const nextState = deriveCapabilityStateOnUse(previousState);
  if (!isCapabilityUsableState(previousState)) {
    throw new Error(`Capability is not usable in state ${previousState}`);
  }
  return {
    ...record,
    ...buildCapabilityStateFields(nextState),
    verificationCount: Number(record?.verificationCount || 0) + 1,
    lastVerifiedAt: at,
    lastUsedAt: at,
    transition: { from: previousState, to: nextState, at, reason: 'DISCLOSURE_VERIFIED' },
  };
}

export default {
  CAPABILITY_ACCESS_STATES,
  REVOCATION_REASONS,
  RESTRICTION_REASONS,
  normalizeCapabilityAccessState,
  isCapabilityUsableState,
  canTransitionCapability,
  deriveCapabilityStateOnUse,
  normalizeReasonCode,
  buildCapabilityStateFields,
  applyCapabilityUse,
};
