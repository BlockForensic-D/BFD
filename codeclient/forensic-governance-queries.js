// SPDX-License-Identifier: Apache-2.0

import { normalizeEvidenceLifecycleState, explainEvidenceLifecycleState } from './evidence-lifecycle-manager.js';
import { normalizeCapabilityAccessState, isCapabilityUsableState } from './governance-state-manager.js';

export function summarizeEvidenceGovernance(record) {
  const lifecycleState = normalizeEvidenceLifecycleState(record);
  return {
    evidenceId: record?.evidenceId || null,
    lifecycleState,
    lifecycle: explainEvidenceLifecycleState(lifecycleState),
    restrictedAt: record?.restrictedAt || null,
    withdrawnAt: record?.withdrawnAt || null,
    lifecycleHistoryCount: Array.isArray(record?.lifecycleHistory) ? record.lifecycleHistory.length : 0,
  };
}

export function summarizeCapabilityGovernance(record) {
  const accessState = normalizeCapabilityAccessState(record);
  return {
    capId: record?.capId || null,
    evidenceId: record?.evidenceId || null,
    granteeId: record?.granteeId || null,
    accessState,
    usable: isCapabilityUsableState(accessState),
    requestCount: Number(record?.requestCount || 0),
    verificationCount: Number(record?.verificationCount || 0),
    expiresAt: record?.expiresAt || null,
    revokedAt: record?.revokedAt || null,
  };
}

export default { summarizeEvidenceGovernance, summarizeCapabilityGovernance };
