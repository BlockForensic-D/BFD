'use strict';

const crypto = require('node:crypto');

function pad(n, width = 6) {
  return String(n).padStart(width, '0');
}

function safeFragment(value, maxLen = 24) {
  const out = String(value || '')
    .replace(/[^A-Za-z0-9._-]/g, '')
    .slice(0, maxLen);
  return out || crypto.randomBytes(4).toString('hex');
}

function runId(prefix = 'caliper') {
  const now = new Date().toISOString().replace(/[-:.TZ]/g, '').slice(0, 14);
  return `${prefix}-${now}-${crypto.randomBytes(3).toString('hex')}`;
}

function evidenceId(prefix, workerIndex, index) {
  return `${safeFragment(prefix, 18)}-w${pad(workerIndex, 3)}-${pad(index, 8)}`.slice(0, 64);
}

function capId(evidenceIdValue, granteeId, nonce, prefix = 'DCAP') {
  return `${prefix}-${safeFragment(evidenceIdValue, 18)}-${safeFragment(granteeId, 18)}-${safeFragment(nonce, 12)}`.slice(0, 64);
}

function receiptRef(evidenceIdValue, index) {
  return `receipt-${safeFragment(evidenceIdValue, 24)}-${pad(index, 8)}`.slice(0, 64);
}

module.exports = { pad, safeFragment, runId, evidenceId, capId, receiptRef };
