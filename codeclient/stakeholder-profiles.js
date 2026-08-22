'use strict';

/**
 * stakeholder-profiles.js
 * ---------------------------------------------------------------------------
 * Section III.A canonical stakeholder profiles (Layer 5 update).
 *
 * Eight profiles spanning three organizations:
 *
 *   Org1MSP — Operational Custody
 *     - acquisition_operator
 *     - evidence_custodian (custody authority + capability issuer)
 *     - forensic_investigator
 *
 *   Org2MSP — Regulatory Oversight
 *     - judicial_reviewer
 *     - dpo (data protection officer — Algorithm 4 sole authority)
 *     - internal_auditor
 *
 *   Org3MSP — External Collaborators
 *     - external_vendor (CHUNK_SET disclosure receiver)
 *     - external_auditor (HASH_ONLY verification)
 *
 * Each profile carries:
 *   - identityKey:          short key used for wallet identity lookup
 *   - role:                 MSP role attribute (matches registerEnroll.sh)
 *   - org:                  organization MSP id ('Org1MSP', 'Org2MSP', 'Org3MSP')
 *   - clearance:            'Low' | 'Medium' | 'High'
 *   - description:          human-readable role description
 *   - isCustodyAuthority:   true if can issue capabilities (Algorithm 1)
 *   - isWithdrawalAuthority:true if can initiate withdrawal (Algorithm 4)
 *   - isOversightAuthority: true if can perform restriction (Algorithm 3 Phase E)
 *   - defaultMode:          default disclosure mode this profile receives
 *   - processScope:         optional scope-narrowing metadata (legacy field)
 *
 * Module style: ESM. Used by client orchestration code (paper3-client.js,
 * e6-hlf-runner.js, experiment-runner.js).
 * ---------------------------------------------------------------------------
 */

export const STAKEHOLDER_PROFILES = {

  // ==========================================================================
  // Org1MSP — Operational Custody
  // ==========================================================================

  acquisition_operator: {
    identityKey: 'operator',
    role: 'AcquisitionOperator',
    org: 'Org1MSP',
    clearance: 'Medium',
    description: 'Acquires evidence at the edge / OT gateway and submits to ledger',
    isAcquisitionAuthority: true,
    defaultMode: null  // does not receive disclosures
  },

  evidence_custodian: {
    identityKey: 'custodian',
    role: 'EvidenceCustodian',
    org: 'Org1MSP',
    clearance: 'High',
    description: 'Custody authority — issues capabilities (Algorithm 1) and revokes (Algorithm 3 Phase D)',
    isCustodyAuthority: true,
    isIssuer: true,             // legacy field for backward compat
    defaultMode: 'FULL_CHUNKS'
  },

  forensic_investigator: {
    identityKey: 'forensic',
    role: 'ForensicInvestigator',
    org: 'Org1MSP',
    clearance: 'High',
    description: 'Internal investigator — full examination/analysis access',
    defaultMode: 'FULL_CHUNKS'
  },

  // ==========================================================================
  // Org2MSP — Regulatory Oversight
  // ==========================================================================

  judicial_reviewer: {
    identityKey: 'judge',
    role: 'JudicialReviewer',
    org: 'Org2MSP',
    clearance: 'High',
    description: 'Judicial-mandated restriction authority (Algorithm 3 Phase E)',
    isOversightAuthority: true,
    defaultMode: 'FULL_CHUNKS'
  },

  dpo: {
    identityKey: 'dpo',
    role: 'DataProtectionOfficer',
    org: 'Org2MSP',
    clearance: 'High',
    description: 'Sole authority for confidentiality withdrawal (Algorithm 4)',
    isWithdrawalAuthority: true,
    defaultMode: null  // DPO does NOT receive disclosures
  },

  internal_auditor: {
    identityKey: 'audit_int',
    role: 'InternalAuditor',
    org: 'Org2MSP',
    clearance: 'Medium',
    description: 'Internal audit — oversight verification within the consortium',
    isOversightAuthority: true,
    defaultMode: 'HASH_ONLY'
  },

  // ==========================================================================
  // Org3MSP — External Collaborators
  // ==========================================================================

  external_vendor: {
    identityKey: 'vendor',
    role: 'ExternalVendor',
    org: 'Org3MSP',
    clearance: 'Medium',
    description: 'External equipment vendor — receives CHUNK_SET disclosure for bounded diagnosis',
    defaultMode: 'CHUNK_SET',
    processScope: {
      plantStage: 'P5',
      tags: ['PIT501', 'PIT503', 'AIT502'],
      rationale: 'Reverse Osmosis (P5) stage selected from Historian deep-dive as the stage with the strongest observable disruption during Wave 2'
    }
  },

  external_auditor: {
    identityKey: 'audit_ext',
    role: 'ExternalAuditor',
    org: 'Org3MSP',
    clearance: 'Medium',
    description: 'External assurance role for integrity verification without payload',
    defaultMode: 'HASH_ONLY'
  }
};

// ============================================================================
// LEGACY ALIASES (backward compat for pre-Layer-3 code)
// ============================================================================

/**
 * Legacy alias: forensic_lead -> forensic_investigator
 * Pre-Layer-3 code using `forensic_lead` will continue to resolve.
 */
STAKEHOLDER_PROFILES.forensic_lead = STAKEHOLDER_PROFILES.forensic_investigator;

/**
 * Legacy alias: vendor_engineer_p5 -> external_vendor
 */
STAKEHOLDER_PROFILES.vendor_engineer_p5 = STAKEHOLDER_PROFILES.external_vendor;

/**
 * Legacy alias: independent_auditor -> external_auditor
 * (assumes external auditor was the most common consumer of HASH_ONLY)
 */
STAKEHOLDER_PROFILES.independent_auditor = STAKEHOLDER_PROFILES.external_auditor;

// ============================================================================
// HELPERS
// ============================================================================

export function getStakeholderProfile(id) {
  const profile = STAKEHOLDER_PROFILES[id];
  if (!profile) {
    throw new Error(`Unknown stakeholder profile: ${id}`);
  }
  return profile;
}

/**
 * Returns all profiles in a given org.
 * @param {string} orgMspId - 'Org1MSP' | 'Org2MSP' | 'Org3MSP'
 * @returns {Array<{key: string, profile: Object}>}
 */
export function getProfilesByOrg(orgMspId) {
  // Filter out legacy aliases by deduplicating on identityKey
  const seen = new Set();
  const result = [];
  for (const [key, profile] of Object.entries(STAKEHOLDER_PROFILES)) {
    if (profile.org !== orgMspId) continue;
    const dedupKey = profile.identityKey;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);
    result.push({ key, profile });
  }
  return result;
}

/**
 * Returns the canonical profile that has a given authority flag.
 * Throws if zero or multiple profiles match.
 *
 * @param {string} authorityFlag - e.g., 'isWithdrawalAuthority', 'isCustodyAuthority'
 * @returns {Object}
 */
export function getAuthorityProfile(authorityFlag) {
  const seen = new Set();
  const matches = [];
  for (const [key, profile] of Object.entries(STAKEHOLDER_PROFILES)) {
    if (!profile[authorityFlag]) continue;
    const dedupKey = profile.identityKey;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);
    matches.push({ key, profile });
  }
  if (matches.length === 0) {
    throw new Error(`No profile with authority flag: ${authorityFlag}`);
  }
  if (matches.length > 1) {
    throw new Error(
      `Multiple profiles with authority flag ${authorityFlag}: ` +
      matches.map(m => m.key).join(', ')
    );
  }
  return matches[0];
}

/**
 * Returns all profiles eligible to RECEIVE a given disclosure mode.
 * Used for routing logic.
 *
 * @param {string} mode - 'FULL_CHUNKS' | 'CHUNK_SET' | 'HASH_ONLY'
 */
export function getReceiversForMode(mode) {
  const seen = new Set();
  const result = [];
  for (const [key, profile] of Object.entries(STAKEHOLDER_PROFILES)) {
    if (profile.defaultMode !== mode) continue;
    const dedupKey = profile.identityKey;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);
    result.push({ key, profile });
  }
  return result;
}

/**
 * Returns the count of canonical profiles (excluding legacy aliases).
 */
export function getCanonicalProfileCount() {
  const seen = new Set();
  for (const profile of Object.values(STAKEHOLDER_PROFILES)) {
    seen.add(profile.identityKey);
  }
  return seen.size;
}
