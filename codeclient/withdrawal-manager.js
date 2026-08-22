// SPDX-License-Identifier: Apache-2.0

export const WITHDRAWAL_REASONS = Object.freeze([
  'PRIVACY_REQUEST',
  'REGULATORY_DIRECTIVE',
  'RETENTION_POLICY',
  'STAKEHOLDER_AGREEMENT',
  'INVESTIGATION_CLOSURE',
  'ERRONEOUS_DISCLOSURE',
  'CONTRACTUAL_OBLIGATION',
  'ADMINISTRATIVE',
  'OTHER',
]);

export function normalizeWithdrawalReason(value, fallback = 'OTHER') {
  const out = String(value || fallback).trim().toUpperCase();
  return WITHDRAWAL_REASONS.includes(out) ? out : fallback;
}

export function buildWithdrawalRequest({ evidenceId, reasonCode, justification, requestRef, requestedBy, requestedAt = new Date().toISOString() }) {
  if (!evidenceId || !String(evidenceId).trim()) throw new TypeError('evidenceId is required');
  if (!justification || !String(justification).trim()) throw new TypeError('withdrawal justification is required');
  return {
    version: 'confidentiality-withdrawal-request-v1',
    evidenceId: String(evidenceId).trim(),
    reasonCode: normalizeWithdrawalReason(reasonCode),
    justification: String(justification).trim(),
    requestRef: requestRef ? String(requestRef).trim() : null,
    requestedBy: requestedBy ? String(requestedBy).trim() : null,
    requestedAt,
  };
}

export function buildKeyDestructionReceipt({ evidenceId, keyId, erased, method = 'CRYPTOGRAPHIC_KEY_DESTRUCTION', receiptHash, completedAt = new Date().toISOString(), details = {} }) {
  if (!evidenceId || !String(evidenceId).trim()) throw new TypeError('evidenceId is required');
  return {
    version: 'key-destruction-receipt-v1',
    evidenceId: String(evidenceId).trim(),
    keyId: keyId ? String(keyId).trim() : null,
    erased: !!erased,
    method,
    receiptHash: receiptHash || null,
    completedAt,
    details,
  };
}

export default { WITHDRAWAL_REASONS, normalizeWithdrawalReason, buildWithdrawalRequest, buildKeyDestructionReceipt };
