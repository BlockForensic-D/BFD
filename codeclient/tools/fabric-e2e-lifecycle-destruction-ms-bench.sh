#!/usr/bin/env bash
set -euo pipefail

RUN_ID="$(date +%s%N)"

OUT_DIR="${LIFEDEST_OUT_DIR:-artifacts/experiments/fabric-e2e-lifecycle-destruction}"
LOG_DIR="${OUT_DIR}/logs-${RUN_ID}"
KEY_DIR="${LIFEDEST_KEY_DIR:-artifacts/keys}"

RAW_JSONL="${OUT_DIR}/lifecycle-destruction-raw.jsonl"
RAW_CSV="${OUT_DIR}/lifecycle-destruction-raw.csv"
SUMMARY_JSON="${OUT_DIR}/lifecycle-destruction-summary.json"
SUMMARY_MD="${OUT_DIR}/lifecycle-destruction-summary.md"

ITERATIONS="${LIFEDEST_ITERATIONS:-2}"
EVIDENCE_COUNT="${LIFEDEST_EVIDENCE_COUNT:-1}"

SOURCE_FILE="${LIFEDEST_SOURCE_FILE:-experiments/datasets/Edge-IIoTset/Attack traffic/Vulnerability scanner attack.pcap}"
SOURCE_LABEL="${LIFEDEST_SOURCE_LABEL:-edge_vulnerability_scanner_attack_pcap}"
WINDOW_BYTES="${LIFEDEST_WINDOW_BYTES:-1048576}"
WINDOW_OFFSET_BASE="${LIFEDEST_WINDOW_OFFSET_BASE:-0}"

CHUNK_SIZE="${LIFEDEST_CHUNK_SIZE:-4096}"
DISCLOSED_INDICES="${LIFEDEST_INDICES:-[0,1,2,3]}"
COMMITMENT_VERSION="${LIFEDEST_COMMITMENT_VERSION:-chunk-merkle-v3-hmac-opening}"
EVIDENCE_MASTER_KEY="${LIFEDEST_EVIDENCE_MASTER_KEY:-$(node -e "console.log(require('crypto').createHash('sha256').update('e7-v3-${RUN_ID}').digest('hex'))")}"

COLLECTOR_IDENTITY="${LIFEDEST_COLLECTOR_IDENTITY:-gateway}"
CUSTODIAN_IDENTITY="${LIFEDEST_CUSTODIAN_IDENTITY:-custodian}"
VERIFIER_IDENTITY="${LIFEDEST_VERIFIER_IDENTITY:-forensic}"
DPO_IDENTITY="${LIFEDEST_DPO_IDENTITY:-dpo}"
JUDGE_IDENTITY="${LIFEDEST_JUDGE_IDENTITY:-judge}"

ISSUER_ID="${LIFEDEST_ISSUER_ID:-EvidenceCustodian}"
GRANTEE_ID="${LIFEDEST_GRANTEE_ID:-ForensicInvestigator}"

# E7_MS_PATCH_V1
# Multi-stakeholder disclosure profiles. By default, Fabric identity execution reuses
# VERIFIER_IDENTITY for recipient-side request/verify unless explicitly overridden.
FORENSIC_GRANTEE_ID="${LIFEDEST_FORENSIC_GRANTEE_ID:-ForensicInvestigator}"
VENDOR_GRANTEE_ID="${LIFEDEST_VENDOR_GRANTEE_ID:-ExternalVendor}"
AUDITOR_GRANTEE_ID="${LIFEDEST_AUDITOR_GRANTEE_ID:-ExternalAuditor}"

FORENSIC_IDENTITY="${LIFEDEST_FORENSIC_IDENTITY:-forensic}"
VENDOR_IDENTITY="${LIFEDEST_VENDOR_IDENTITY:-vendor}"
EXTERNAL_AUDITOR_IDENTITY="${LIFEDEST_EXTERNAL_AUDITOR_IDENTITY:-auditor}"

DATASET_ROLE="${LIFEDEST_DATASET_ROLE:-headline_attack_evidence}"
TRAFFIC_TYPE="${LIFEDEST_TRAFFIC_TYPE:-attack}"
WINDOW_POLICY="${LIFEDEST_WINDOW_POLICY:-sequential_non_overlapping}"

PRIVATE_KEY_FILE="${KEY_DIR}/custodian-ed25519-private.pem"
PUBLIC_KEY_FILE="${KEY_DIR}/custodian-ed25519-public.pem"

DPO_ATTEST_PRIVATE_KEY_FILE="${KEY_DIR}/dpo-destruction-attestation-private.pem"
DPO_ATTEST_PUBLIC_KEY_FILE="${KEY_DIR}/dpo-destruction-attestation-public.pem"
JUDGE_ATTEST_PRIVATE_KEY_FILE="${KEY_DIR}/judge-destruction-attestation-private.pem"
JUDGE_ATTEST_PUBLIC_KEY_FILE="${KEY_DIR}/judge-destruction-attestation-public.pem"
CUSTODIAN_ATTEST_PRIVATE_KEY_FILE="${KEY_DIR}/custodian-destruction-attestation-private.pem"
CUSTODIAN_ATTEST_PUBLIC_KEY_FILE="${KEY_DIR}/custodian-destruction-attestation-public.pem"

export RUN_ID
export SOURCE_FILE
export SOURCE_LABEL
export WINDOW_BYTES
export CHUNK_SIZE
export DISCLOSED_INDICES
export COMMITMENT_VERSION
export EVIDENCE_MASTER_KEY
export DATASET_ROLE
export TRAFFIC_TYPE
export WINDOW_POLICY

mkdir -p "$OUT_DIR" "$LOG_DIR" "$KEY_DIR" artifacts/evidence
: > "$RAW_JSONL"

echo "============================================================"
echo "FABRIC E2E BENCHMARK - LIFECYCLE + MULTI-STAKEHOLDER DISCLOSURE + DESTRUCTION"
echo "Run id          : $RUN_ID"
echo "Output dir      : $OUT_DIR"
echo "Iterations      : $ITERATIONS"
echo "Evidence/run    : $EVIDENCE_COUNT"
echo "Source file     : $SOURCE_FILE"
echo "Source label    : $SOURCE_LABEL"
echo "Window bytes    : $WINDOW_BYTES"
echo "Chunk size      : $CHUNK_SIZE"
echo "Disclosure idx  : $DISCLOSED_INDICES"
echo "Commitment ver  : $COMMITMENT_VERSION"
echo "V3 EMK hash     : $(node -e "console.log(require('crypto').createHash('sha256').update(process.env.EVIDENCE_MASTER_KEY || '').digest('hex'))")"
echo "============================================================"

if [ ! -f "$SOURCE_FILE" ]; then
  echo "ERROR: source evidence file not found: $SOURCE_FILE" >&2
  exit 1
fi

for port in 7051 9051 11051; do
  if timeout 1 bash -c "cat < /dev/null > /dev/tcp/127.0.0.1/$port" 2>/dev/null; then
    echo "OK: port $port open"
  else
    echo "ERROR: port $port is not reachable. Fabric network may not be running." >&2
    exit 1
  fi
done

if [ ! -f "$PRIVATE_KEY_FILE" ] || [ ! -f "$PUBLIC_KEY_FILE" ]; then
  echo "Generating custodian Ed25519 keypair"
  node - "$PRIVATE_KEY_FILE" "$PUBLIC_KEY_FILE" <<'NODE'
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const [privPath, pubPath] = process.argv.slice(2);
fs.mkdirSync(path.dirname(privPath), { recursive: true });

const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

fs.writeFileSync(
  privPath,
  privateKey.export({ type: 'pkcs8', format: 'pem' })
);

fs.writeFileSync(
  pubPath,
  publicKey.export({ type: 'spki', format: 'pem' })
);
NODE
else
  echo "Using existing custodian Ed25519 keypair"
fi

record_step() {
  local iteration="$1"
  local evidence_id="$2"
  local op="$3"
  local group="$4"
  local rc="$5"
  local latency_ms="$6"
  local output_file="$7"
  local stdout_file="$8"
  local stderr_file="$9"

  node - "$RAW_JSONL" "$iteration" "$evidence_id" "$op" "$group" "$rc" "$latency_ms" "$output_file" "$stdout_file" "$stderr_file" <<'NODE'
const fs = require('fs');

const [
  rawJsonl,
  iteration,
  evidenceId,
  operation,
  operationGroup,
  rcRaw,
  latencyMsRaw,
  outputFile,
  stdoutFile,
  stderrFile
] = process.argv.slice(2);

let output = null;
if (outputFile && fs.existsSync(outputFile)) {
  try { output = JSON.parse(fs.readFileSync(outputFile, 'utf8')); } catch {}
}

const stderr = stderrFile && fs.existsSync(stderrFile)
  ? fs.readFileSync(stderrFile, 'utf8').slice(0, 4000)
  : '';

const stdout = stdoutFile && fs.existsSync(stdoutFile)
  ? fs.readFileSync(stdoutFile, 'utf8').slice(0, 4000)
  : '';

const rc = Number(rcRaw);
const record = {
  runId: process.env.RUN_ID || null,
  experimentId: 'E7_lifecycle_disclosure_destruction',
  iterationIndex: Number(iteration),
  evidenceId: evidenceId || null,
  operation,
  operationGroup,
  success: rc === 0,
  returnCode: rc,
  latencyMs: Number(latencyMsRaw),
  outputFile,
  stdoutFile,
  stderrFile,
  timestamp: new Date().toISOString(),
  sourceLabel: process.env.SOURCE_LABEL || null,
  sourceFile: process.env.SOURCE_FILE || null,
  chunkSizeBytes: Number(process.env.CHUNK_SIZE || 0),
  windowBytes: Number(process.env.WINDOW_BYTES || 0),
  disclosedIndices: (() => {
    try { return JSON.parse(process.env.DISCLOSED_INDICES || '[]'); } catch { return []; }
  })(),
  lifecycleState: output?.lifecycleState ?? output?.evidenceLifecycleState ?? null,
  previousState: output?.previousState ?? null,
  nextState: output?.nextState ?? null,
  valid: output?.valid ?? null,
  bundleHashValid: output?.bundleHashValid ?? null,
  rootMatch: output?.rootMatch ?? null,
  capabilityValid: output?.capabilityValid ?? null,
  capabilityStateBefore: output?.capabilityStateBefore ?? null,
  capabilityStateAfter: output?.capabilityStateAfter ?? null,
  destructionMethod: output?.destructionMethod ?? null,
  commitmentPreserved: output?.commitmentPreserved ?? null,
  auditTrailPreserved: output?.auditTrailPreserved ?? null,
  capabilitiesRevoked: output?.capabilitiesRevoked ?? null,
  inspectedCapabilities: output?.inspectedCapabilities ?? null,
  rejectionObserved: rc !== 0,
  rejectionMatched:
    /DESTROYED|REVOKED|not_active|not_authorizable|not_disclosable|lifecycle/i.test(stderr + '\n' + stdout),
  errorText: rc === 0 ? '' : stderr
};

fs.appendFileSync(rawJsonl, JSON.stringify(record) + '\n');
NODE
}

run_step() {
  local iteration="$1"
  local evidence_id="$2"
  local op="$3"
  local group="$4"
  local output_file="$5"
  shift 5

  local stdout_file="${LOG_DIR}/${evidence_id}-${op}.stdout.txt"
  local stderr_file="${LOG_DIR}/${evidence_id}-${op}.stderr.txt"

  local start_ns end_ns latency_ms rc
  start_ns="$(date +%s%N)"
  set +e
  "$@" >"$stdout_file" 2>"$stderr_file"
  rc=$?
  set -e
  end_ns="$(date +%s%N)"
  latency_ms="$(python3 - <<PY
print(round(($end_ns - $start_ns) / 1000000, 3))
PY
)"

  record_step "$iteration" "$evidence_id" "$op" "$group" "$rc" "$latency_ms" "$output_file" "$stdout_file" "$stderr_file"

  if [ "$rc" -ne 0 ]; then
    echo "ERROR: step failed: $op for $evidence_id" >&2
    echo "--- stderr ---" >&2
    cat "$stderr_file" >&2 || true
    exit "$rc"
  fi
}

run_negative_step() {
  local iteration="$1"
  local evidence_id="$2"
  local op="$3"
  local group="$4"
  local expected_pattern="$5"
  local output_file="$6"
  shift 6

  local stdout_file="${LOG_DIR}/${evidence_id}-${op}.stdout.txt"
  local stderr_file="${LOG_DIR}/${evidence_id}-${op}.stderr.txt"

  local start_ns end_ns latency_ms rc
  start_ns="$(date +%s%N)"
  set +e
  "$@" >"$stdout_file" 2>"$stderr_file"
  rc=$?
  set -e
  end_ns="$(date +%s%N)"
  latency_ms="$(python3 - <<PY
print(round(($end_ns - $start_ns) / 1000000, 3))
PY
)"

  record_step "$iteration" "$evidence_id" "$op" "$group" "$rc" "$latency_ms" "$output_file" "$stdout_file" "$stderr_file"

  if [ "$rc" -eq 0 ]; then
    echo "ERROR: negative step unexpectedly succeeded: $op" >&2
    cat "$output_file" 2>/dev/null || true
    exit 1
  fi

  if ! grep -E "$expected_pattern" "$stderr_file" >/dev/null 2>&1; then
    echo "ERROR: negative step failed, but rejection reason did not match expectation: $op" >&2
    echo "Expected pattern: $expected_pattern" >&2
    echo "--- stderr ---" >&2
    cat "$stderr_file" >&2 || true
    exit 1
  fi
}

prepare_evidence_window() {
  local evidence_id="$1"
  local iteration="$2"
  local item="$3"
  local evidence_file="$4"
  local info_file="$5"
  local preserve_payload="$6"
  local commit_input="$7"
  local cap_input="$8"
  local offset="$9"

  node - "$SOURCE_FILE" "$evidence_file" "$info_file" "$preserve_payload" "$commit_input" "$cap_input" "$evidence_id" "$SOURCE_LABEL" "$WINDOW_BYTES" "$offset" "$CHUNK_SIZE" "$DISCLOSED_INDICES" "$ISSUER_ID" "$GRANTEE_ID" "$EVIDENCE_MASTER_KEY" "$COMMITMENT_VERSION" <<'NODE'
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const [
  sourceFile,
  evidenceFile,
  infoFile,
  preservePayloadFile,
  commitInputFile,
  capInputFile,
  evidenceId,
  sourceLabel,
  windowBytesRaw,
  offsetRaw,
  chunkSizeRaw,
  disclosedIndicesRaw,
  issuerId,
  granteeId,
  evidenceMasterKey,
  commitmentVersion
] = process.argv.slice(2);

const windowBytes = Number(windowBytesRaw);
const offset = Number(offsetRaw);
const chunkSize = Number(chunkSizeRaw);
const disclosedIndices = JSON.parse(disclosedIndicesRaw);

if (!Number.isSafeInteger(windowBytes) || windowBytes <= 0) {
  throw new Error('invalid windowBytes');
}
if (!Number.isSafeInteger(offset) || offset < 0) {
  throw new Error('invalid offset');
}
if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
  throw new Error('invalid chunkSize');
}

const stat = fs.statSync(sourceFile);
const available = Math.max(0, stat.size - offset);
const actualLength = Math.min(windowBytes, available);
if (actualLength <= 0) {
  throw new Error(`window offset is outside source file: offset=${offset}, size=${stat.size}`);
}

fs.mkdirSync(path.dirname(evidenceFile), { recursive: true });

const fd = fs.openSync(sourceFile, 'r');
const buffer = Buffer.alloc(actualLength);
try {
  const bytesRead = fs.readSync(fd, buffer, 0, actualLength, offset);
  if (bytesRead !== actualLength) {
    throw new Error(`short read: expected=${actualLength}, actual=${bytesRead}`);
  }
} finally {
  fs.closeSync(fd);
}

fs.writeFileSync(evidenceFile, buffer);

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function uint32be(value) {
  const out = Buffer.allocUnsafe(4);
  out.writeUInt32BE(value >>> 0, 0);
  return out;
}

function uint64be(value) {
  const out = Buffer.allocUnsafe(8);
  out.writeBigUInt64BE(BigInt(value), 0);
  return out;
}

function lengthPrefixedUtf8(value) {
  const bytes = Buffer.from(String(value), 'utf8');
  return Buffer.concat([uint32be(bytes.length), bytes]);
}

function hkdfHex(secret, label, evidenceId) {
  const salt = Buffer.concat([Buffer.from('FDEM-HKDF-SALT-v3', 'ascii'), lengthPrefixedUtf8(evidenceId)]);
  const info = Buffer.concat([Buffer.from(label, 'ascii'), lengthPrefixedUtf8(evidenceId)]);
  return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(String(secret), /^[a-fA-F0-9]{64}$/.test(String(secret)) ? 'hex' : 'utf8'), salt, info, 32)).toString('hex');
}

function hmacSha256Hex(keyHex, message) {
  return crypto.createHmac('sha256', Buffer.from(keyHex, 'hex')).update(message).digest('hex');
}

function buildContext(evidenceId, chunkIndex, actualLength) {
  return Buffer.concat([
    lengthPrefixedUtf8(evidenceId),
    uint64be(chunkIndex),
    uint32be(actualLength)
  ]);
}

function hashChunkV2(chunk) {
  return sha256Hex(Buffer.concat([Buffer.from([0x00]), chunk]));
}

const kSalt = commitmentVersion === 'chunk-merkle-v3-hmac-opening'
  ? hkdfHex(evidenceMasterKey, 'FDEM-KSALT-v3', evidenceId)
  : null;

function hashChunkV3(chunk, chunkIndex) {
  const actualChunkLength = chunk.length;
  const context = buildContext(evidenceId, chunkIndex, actualChunkLength);
  const saltHex = hmacSha256Hex(kSalt, Buffer.concat([Buffer.from('FDEM-SALT-v3', 'ascii'), context]));
  const chunkDigestHex = sha256Hex(Buffer.concat([
    Buffer.from('FDEM-CHUNK-v3', 'ascii'),
    uint32be(actualChunkLength),
    chunk
  ]));
  return sha256Hex(Buffer.concat([
    Buffer.from('FDEM-LEAF-v3', 'ascii'),
    context,
    Buffer.from(saltHex, 'hex'),
    Buffer.from(chunkDigestHex, 'hex')
  ]));
}

function parentHash(leftHex, rightHex) {
  if (commitmentVersion === 'chunk-merkle-v3-hmac-opening') {
    return sha256Hex(Buffer.concat([
      Buffer.from('FDEM-NODE-v3', 'ascii'),
      Buffer.from(leftHex, 'hex'),
      Buffer.from(rightHex, 'hex')
    ]));
  }
  return sha256Hex(Buffer.concat([
    Buffer.from([0x01]),
    Buffer.from(leftHex, 'hex'),
    Buffer.from(rightHex, 'hex')
  ]));
}

const leaves = [];
for (let i = 0, idx = 0; i < buffer.length; i += chunkSize, idx += 1) {
  const chunk = buffer.subarray(i, Math.min(i + chunkSize, buffer.length));
  leaves.push(commitmentVersion === 'chunk-merkle-v3-hmac-opening' ? hashChunkV3(chunk, idx) : hashChunkV2(chunk));
}

let level = leaves.slice();
if (level.length === 0) {
  level = [sha256Hex(Buffer.concat([Buffer.from([0xff]), Buffer.from('empty')]))];
}
while (level.length > 1) {
  const next = [];
  for (let i = 0; i < level.length; i += 2) {
    const left = level[i];
    const right = i + 1 < level.length ? level[i + 1] : level[i];
    next.push(parentHash(left, right));
  }
  level = next;
}

const fileHash = sha256Hex(buffer);
const chunkMerkleRoot = level[0];
const chunkCount = leaves.length;

for (const idx of disclosedIndices) {
  if (!Number.isSafeInteger(idx) || idx < 0 || idx >= chunkCount) {
    throw new Error(`disclosed index out of bounds: idx=${idx}, chunkCount=${chunkCount}`);
  }
}

const masterCID = `ipfs://bafybei${fileHash.slice(0, 52)}`;

const info = {
  evidenceId,
  sourceFile,
  sourceLabel,
  datasetRole: process.env.DATASET_ROLE || process.env.LIFEDEST_DATASET_ROLE || 'headline_attack_evidence',
  trafficType: process.env.TRAFFIC_TYPE || process.env.LIFEDEST_TRAFFIC_TYPE || 'attack',
  windowSelectionPolicy: process.env.WINDOW_POLICY || process.env.LIFEDEST_WINDOW_POLICY || 'sequential_non_overlapping',
  sourceSizeBytes: stat.size,
  windowOffsetBytes: offset,
  windowSizeBytes: actualLength,
  evidenceFile,
  fileHash,
  chunkMerkleRoot,
  chunkCount,
  chunkSize,
  disclosedIndices,
  commitmentVersion,
  preparedAt: new Date().toISOString()
};

const preservePayload = {
  evidenceId,
  evidenceType: 'DATASET_WINDOW_PCAP',
  evidenceTitle: `Dataset-derived lifecycle destruction evidence: ${sourceLabel}`,
  integrityHash: fileHash,
  collectionMethod: 'gateway-collector',
  sourceSystem: sourceLabel,
  custodyOwnerId: issuerId,
  disclosureAuthorityId: issuerId,
  storageMode: 'hybrid',
  storageVersion: '2.1',
  masterCID,
  chunkMerkleRoot,
  chunkCount,
  chunkSize,
  commitmentVersion,
  datasetSource: {
    sourceFile,
    sourceLabel,
    sourceSizeBytes: stat.size,
    windowOffsetBytes: offset,
    windowSizeBytes: actualLength
  }
};

const commitInput = {
  custodyOwnerId: issuerId,
  disclosureAuthorityId: issuerId,
  chunkMerkleRoot,
  chunkCount,
  chunkSize,
  commitmentVersion,
  note: 'Custodian commits dataset-derived preserved evidence before lifecycle-aware disclosure and destruction.'
};

const capInput = {
  evidenceId,
  issuerId,
  granteeId,
  scope: {
    type: 'CHUNK_SET',
    indices: disclosedIndices
  },
  purpose: 'E7_LIFECYCLE_DISCLOSURE_DESTRUCTION_DATASET_WINDOW',
  ttlHours: 24,
  version: commitmentVersion === 'chunk-merkle-v3-hmac-opening' ? 'cap-v3' : 'cap-v1',
  commitmentVersion,
  chunkMerkleRoot,
  lifecycleStateAtIssuance: 'COMMITTED',
  evidenceLifecycleEpoch: 1,
  allowedLifecycleStates: ['COMMITTED', 'AUTHORIZED', 'DISCLOSED']
};

for (const [file, obj] of [
  [infoFile, info],
  [preservePayloadFile, preservePayload],
  [commitInputFile, commitInput],
  [capInputFile, capInput]
]) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(obj, null, 2));
}

console.log(JSON.stringify(info, null, 2));
NODE
}

echo
echo "0) Register custodian public key"
run_step 0 "SETUP" "register-public-key" "setup" "${OUT_DIR}/register-public-key-result.json" \
  node paper3-client.js register-public-key \
    --identity "$CUSTODIAN_IDENTITY" \
    --userId "$ISSUER_ID" \
    --publicKeyFile "$PUBLIC_KEY_FILE" \
    --purpose DISCLOSURE_CAPABILITY \
    --keyType Ed25519 \
    --output "${OUT_DIR}/register-public-key-result.json"


echo
echo "0b) Prepare and register destruction attestation keys"

node - "$DPO_ATTEST_PRIVATE_KEY_FILE" "$DPO_ATTEST_PUBLIC_KEY_FILE" "$JUDGE_ATTEST_PRIVATE_KEY_FILE" "$JUDGE_ATTEST_PUBLIC_KEY_FILE" "$CUSTODIAN_ATTEST_PRIVATE_KEY_FILE" "$CUSTODIAN_ATTEST_PUBLIC_KEY_FILE" <<'NODE'
const fs = require('fs');
const crypto = require('crypto');

const files = process.argv.slice(2);

function ensureKeyPair(privPath, pubPath) {
  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) return;
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(privPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  fs.writeFileSync(pubPath, publicKey.export({ type: 'spki', format: 'pem' }));
}

ensureKeyPair(files[0], files[1]);
ensureKeyPair(files[2], files[3]);
ensureKeyPair(files[4], files[5]);
NODE

node paper3-client.js register-public-key \
  --identity "$DPO_IDENTITY" \
  --userId "DataProtectionOfficer" \
  --keyType Ed25519 \
  --purpose DESTRUCTION_ATTESTATION \
  --publicKeyFile "$DPO_ATTEST_PUBLIC_KEY_FILE" >/dev/null

node paper3-client.js register-public-key \
  --identity "$JUDGE_IDENTITY" \
  --userId "JudicialReviewer" \
  --keyType Ed25519 \
  --purpose DESTRUCTION_ATTESTATION \
  --publicKeyFile "$JUDGE_ATTEST_PUBLIC_KEY_FILE" >/dev/null

node paper3-client.js register-public-key \
  --identity "$CUSTODIAN_IDENTITY" \
  --userId "EvidenceCustodian" \
  --keyType Ed25519 \
  --purpose DESTRUCTION_ATTESTATION \
  --publicKeyFile "$CUSTODIAN_ATTEST_PUBLIC_KEY_FILE" >/dev/null


for iteration in $(seq 1 "$ITERATIONS"); do
  for item in $(seq 1 "$EVIDENCE_COUNT"); do
    evidence_id="ev-life-destroy-${RUN_ID}-${iteration}-${item}"
    echo
    echo "Iteration ${iteration}/${ITERATIONS}, evidence ${item}/${EVIDENCE_COUNT}: ${evidence_id}"

    window_offset=$((WINDOW_OFFSET_BASE + ((iteration - 1) * EVIDENCE_COUNT + (item - 1)) * WINDOW_BYTES))

    evidence_file="artifacts/evidence/${evidence_id}.bin"
    info_file="${OUT_DIR}/${evidence_id}-evidence-info.json"
    preserve_payload="${OUT_DIR}/${evidence_id}-preserve-payload.json"
    commit_input="${OUT_DIR}/${evidence_id}-commit-input.json"
    cap_input="${OUT_DIR}/${evidence_id}-capability-input.json"
    cap_token="${OUT_DIR}/${evidence_id}-capability-token.json"

    preserve_result="${OUT_DIR}/${evidence_id}-preserve-result.json"
    lifecycle_preserve="${OUT_DIR}/${evidence_id}-lifecycle-after-preserve.json"
    lifecycle_committed="${OUT_DIR}/${evidence_id}-lifecycle-after-commit.json"
    commit_result="${OUT_DIR}/${evidence_id}-commit-result.json"
    commitment_result="${OUT_DIR}/${evidence_id}-commitment-after-commit.json"
    issue_result="${OUT_DIR}/${evidence_id}-issue-capability-result.json"
    lifecycle_auth="${OUT_DIR}/${evidence_id}-lifecycle-after-authorization.json"
    request_result="${OUT_DIR}/${evidence_id}-request-disclosure-result.json"
    bundle_debug="${OUT_DIR}/${evidence_id}-bundle-debug.json"
    bundle_file="${OUT_DIR}/${evidence_id}-disclosure-bundle.json"
    verify_result="${OUT_DIR}/${evidence_id}-verify-disclosure-result.json"
    lifecycle_disclosed="${OUT_DIR}/${evidence_id}-lifecycle-after-disclosure.json"

    destruction_request="${OUT_DIR}/${evidence_id}-destruction-request.json"
    destruction_request_result="${OUT_DIR}/${evidence_id}-destruction-request-result.json"
    lifecycle_destruction_requested="${OUT_DIR}/${evidence_id}-lifecycle-after-destruction-request.json"

    destruction_approval="${OUT_DIR}/${evidence_id}-destruction-approval.json"
    destruction_approval_result="${OUT_DIR}/${evidence_id}-destruction-approval-result.json"
    lifecycle_destruction_approved="${OUT_DIR}/${evidence_id}-lifecycle-after-destruction-approval.json"

    destruction_receipt="${OUT_DIR}/${evidence_id}-destruction-receipt.json"
    destruction_report_result="${OUT_DIR}/${evidence_id}-destruction-report-result.json"
    destruction_record="${OUT_DIR}/${evidence_id}-destruction-record.json"
    lifecycle_destroyed="${OUT_DIR}/${evidence_id}-lifecycle-after-destroyed.json"
    commitment_after_destroy="${OUT_DIR}/${evidence_id}-commitment-after-destroyed.json"

    post_destroy_cap_input="${OUT_DIR}/${evidence_id}-post-destroy-capability-input.json"
    post_destroy_cap_token="${OUT_DIR}/${evidence_id}-post-destroy-capability-token.json"
    post_destroy_issue_result="${OUT_DIR}/${evidence_id}-post-destroy-issue-result.json"

    prepare_evidence_window \
      "$evidence_id" "$iteration" "$item" \
      "$evidence_file" "$info_file" "$preserve_payload" "$commit_input" "$cap_input" \
      "$window_offset" > "${LOG_DIR}/${evidence_id}-prepare-evidence.stdout.txt"

    run_step "$iteration" "$evidence_id" "preserve-evidence" "fabricSubmit" "$preserve_result" \
      node paper3-client.js preserve-evidence \
        --identity "$COLLECTOR_IDENTITY" \
        --input "$preserve_payload" \
        --output "$preserve_result"

    run_step "$iteration" "$evidence_id" "query-lifecycle-after-preserve" "fabricEvaluate" "$lifecycle_preserve" \
      node paper3-client.js query-evidence-lifecycle \
        --identity "$CUSTODIAN_IDENTITY" \
        --evidenceId "$evidence_id" \
        --output "$lifecycle_preserve"

    run_step "$iteration" "$evidence_id" "commit-preserved-evidence" "fabricSubmit" "$commit_result" \
      node paper3-client.js commit-preserved-evidence \
        --identity "$CUSTODIAN_IDENTITY" \
        --evidenceId "$evidence_id" \
        --input "$commit_input" \
        --output "$commit_result"

    run_step "$iteration" "$evidence_id" "get-commitment-after-commit" "fabricEvaluate" "$commitment_result" \
      node paper3-client.js get-commitment \
        --identity "$CUSTODIAN_IDENTITY" \
        --evidenceId "$evidence_id" \
        --output "$commitment_result"

    run_step "$iteration" "$evidence_id" "query-lifecycle-after-commit" "fabricEvaluate" "$lifecycle_committed" \
      node paper3-client.js query-evidence-lifecycle \
        --identity "$CUSTODIAN_IDENTITY" \
        --evidenceId "$evidence_id" \
        --output "$lifecycle_committed"

    all_indices="$(
      python3 - "$info_file" <<'PY_IDX'
import json
import sys

info = json.load(open(sys.argv[1]))
chunk_count = int(info["chunkCount"])
print(json.dumps(list(range(chunk_count)), separators=(",", ":")))
PY_IDX
    )"

    chunk_merkle_root="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["chunkMerkleRoot"])' "$info_file")"

    current_lifecycle_epoch="$(python3 - "$lifecycle_committed" <<'PY_EPOCH'
import json
import sys

data = json.load(open(sys.argv[1]))

def find_epoch(x):
    if isinstance(x, dict):
        for k in ("evidenceLifecycleEpoch", "lifecycleEpoch"):
            if k in x and x[k] is not None:
                return x[k]
        for v in x.values():
            r = find_epoch(v)
            if r is not None:
                return r
    elif isinstance(x, list):
        for v in x:
            r = find_epoch(v)
            if r is not None:
                return r
    return None

epoch = find_epoch(data)

# Protocol fallback: after commit, lifecycle capability epoch is 1.
# This is only used if an older query-evidence-lifecycle output does not expose epoch.
if epoch is None:
    epoch = 1

print(int(epoch))
PY_EPOCH
    )"
    cap_version="$(if [ "$COMMITMENT_VERSION" = "chunk-merkle-v3-hmac-opening" ]; then echo cap-v3; else echo cap-v1; fi)"


    wrong_epoch_cap_input="${OUT_DIR}/${evidence_id}-wrong-epoch-capability-input.json"
    wrong_epoch_cap_token="${OUT_DIR}/${evidence_id}-wrong-epoch-capability-token.json"
    wrong_epoch_issue_result="${OUT_DIR}/${evidence_id}-wrong-epoch-issue-capability-result.json"
    wrong_epoch_request_result="${OUT_DIR}/${evidence_id}-negative-wrong-epoch-request-disclosure-result.json"

    wrong_lifecycle_epoch="$(( current_lifecycle_epoch > 0 ? current_lifecycle_epoch - 1 : current_lifecycle_epoch + 1 ))"

    cat > "$wrong_epoch_cap_input" <<EOF_JSON
{
  "evidenceId": "$evidence_id",
  "issuerId": "$ISSUER_ID",
  "granteeId": "$FORENSIC_GRANTEE_ID",
  "scope": {"type":"HASH_ONLY"},
  "purpose": "WRONG_EPOCH_DISCLOSURE_NEGATIVE_CONTROL",
  "ttlHours": 24,
  "version": "$cap_version",
  "commitmentVersion": "$COMMITMENT_VERSION",
  "chunkMerkleRoot": "$chunk_merkle_root",
  "lifecycleStateAtIssuance": "COMMITTED",
  "evidenceLifecycleEpoch": $wrong_lifecycle_epoch,
  "allowedLifecycleStates": ["COMMITTED", "AUTHORIZED", "DISCLOSED"]
}
EOF_JSON

    run_step "$iteration" "$evidence_id" "create-wrong-epoch-capability-token" "localCrypto" "$wrong_epoch_cap_token" \
      node paper3-client.js create-capability-token \
        --input "$wrong_epoch_cap_input" \
        --privateKeyFile "$PRIVATE_KEY_FILE" \
        --output "$wrong_epoch_cap_token"

    run_step "$iteration" "$evidence_id" "issue-wrong-epoch-capability" "fabricSubmit" "$wrong_epoch_issue_result" \
      node paper3-client.js issue-capability \
        --identity "$CUSTODIAN_IDENTITY" \
        --tokenFile "$wrong_epoch_cap_token" \
        --output "$wrong_epoch_issue_result"

    run_negative_step "$iteration" "$evidence_id" "negative-wrong-epoch-request-disclosure-before-destruction" "negativeControl" "capability_lifecycle_epoch_mismatch" "$wrong_epoch_request_result" \
      node paper3-client.js request-disclosure \
        --identity "$FORENSIC_IDENTITY" \
        --evidenceId "$evidence_id" \
        --tokenFile "$wrong_epoch_cap_token" \
        --indices "[]" \
        --output "$wrong_epoch_request_result"


    PROFILE_ROWS=(
      "forensic_full|$FORENSIC_GRANTEE_ID|$FORENSIC_IDENTITY|FULL_CHUNKS|$all_indices"
      "vendor_chunk_set|$VENDOR_GRANTEE_ID|$VENDOR_IDENTITY|CHUNK_SET|$DISCLOSED_INDICES"
      "auditor_hash_only|$AUDITOR_GRANTEE_ID|$EXTERNAL_AUDITOR_IDENTITY|HASH_ONLY|[]"
    )

    # Phase A: issue all stakeholder capabilities before disclosure changes lifecycle state.
    for profile_row in "${PROFILE_ROWS[@]}"; do
      IFS='|' read -r profile_id profile_grantee profile_identity profile_scope profile_indices <<< "$profile_row"

      profile_cap_input="${OUT_DIR}/${evidence_id}-${profile_id}-capability-input.json"
      profile_cap_token="${OUT_DIR}/${evidence_id}-${profile_id}-capability-token.json"
      profile_issue_result="${OUT_DIR}/${evidence_id}-${profile_id}-issue-capability-result.json"

      if [[ "$profile_scope" == "CHUNK_SET" ]]; then
        profile_scope_json="{\"type\":\"CHUNK_SET\",\"indices\":${profile_indices}}"
      else
        profile_scope_json="{\"type\":\"${profile_scope}\"}"
      fi

      cat > "$profile_cap_input" <<EOF_JSON
{
  "evidenceId": "$evidence_id",
  "issuerId": "$ISSUER_ID",
  "granteeId": "$profile_grantee",
  "scope": $profile_scope_json,
  "purpose": "E7_MULTI_STAKEHOLDER_LIFECYCLE_DISCLOSURE_${profile_scope}",
  "ttlHours": 24,
  "version": "$cap_version",
  "commitmentVersion": "$COMMITMENT_VERSION",
  "chunkMerkleRoot": "$chunk_merkle_root",
  "lifecycleStateAtIssuance": "COMMITTED",
  "evidenceLifecycleEpoch": $current_lifecycle_epoch,
  "allowedLifecycleStates": ["COMMITTED", "AUTHORIZED", "DISCLOSED"]
}
EOF_JSON

      run_step "$iteration" "$evidence_id" "create-capability-token" "localCrypto" "$profile_cap_token" \
        node paper3-client.js create-capability-token \
          --input "$profile_cap_input" \
          --privateKeyFile "$PRIVATE_KEY_FILE" \
          --output "$profile_cap_token"

      run_step "$iteration" "$evidence_id" "issue-capability" "fabricSubmit" "$profile_issue_result" \
        node paper3-client.js issue-capability \
          --identity "$CUSTODIAN_IDENTITY" \
          --tokenFile "$profile_cap_token" \
          --output "$profile_issue_result"
    done


    stale_epoch_cap_input="${OUT_DIR}/${evidence_id}-stale-epoch-capability-input.json"
    stale_epoch_cap_token="${OUT_DIR}/${evidence_id}-stale-epoch-capability-token.json"
    stale_epoch_issue_result="${OUT_DIR}/${evidence_id}-stale-epoch-issue-capability-result.json"

    cat > "$stale_epoch_cap_input" <<EOF_JSON
{
  "evidenceId": "$evidence_id",
  "issuerId": "$ISSUER_ID",
  "granteeId": "$FORENSIC_GRANTEE_ID",
  "scope": {"type":"HASH_ONLY"},
  "purpose": "STALE_CAPABILITY_EPOCH_NEGATIVE_CONTROL",
  "ttlHours": 24,
  "version": "$cap_version",
  "commitmentVersion": "$COMMITMENT_VERSION",
  "chunkMerkleRoot": "$chunk_merkle_root",
  "lifecycleStateAtIssuance": "COMMITTED",
  "evidenceLifecycleEpoch": $current_lifecycle_epoch,
  "allowedLifecycleStates": ["COMMITTED", "AUTHORIZED", "DISCLOSED"]
}
EOF_JSON

    run_step "$iteration" "$evidence_id" "create-stale-epoch-capability-token" "localCrypto" "$stale_epoch_cap_token" \
      node paper3-client.js create-capability-token \
        --input "$stale_epoch_cap_input" \
        --privateKeyFile "$PRIVATE_KEY_FILE" \
        --output "$stale_epoch_cap_token"

    run_step "$iteration" "$evidence_id" "issue-stale-epoch-capability" "fabricSubmit" "$stale_epoch_issue_result" \
      node paper3-client.js issue-capability \
        --identity "$CUSTODIAN_IDENTITY" \
        --tokenFile "$stale_epoch_cap_token" \
        --output "$stale_epoch_issue_result"

    run_step "$iteration" "$evidence_id" "query-lifecycle-after-authorization" "fabricEvaluate" "$lifecycle_auth" \
      node paper3-client.js query-evidence-lifecycle \
        --identity "$CUSTODIAN_IDENTITY" \
        --evidenceId "$evidence_id" \
        --output "$lifecycle_auth"

    # Phase B: request all stakeholder disclosures.
    for profile_row in "${PROFILE_ROWS[@]}"; do
      IFS='|' read -r profile_id profile_grantee profile_identity profile_scope profile_indices <<< "$profile_row"

      profile_cap_token="${OUT_DIR}/${evidence_id}-${profile_id}-capability-token.json"
      profile_request_result="${OUT_DIR}/${evidence_id}-${profile_id}-request-disclosure-result.json"

      run_step "$iteration" "$evidence_id" "request-disclosure" "fabricSubmit" "$profile_request_result" \
        node paper3-client.js request-disclosure \
          --identity "$profile_identity" \
          --evidenceId "$evidence_id" \
          --tokenFile "$profile_cap_token" \
          --indices "$profile_indices" \
          --output "$profile_request_result"
    done

    # Phase C: build and verify all disclosure bundles.
    for profile_row in "${PROFILE_ROWS[@]}"; do
      IFS='|' read -r profile_id profile_grantee profile_identity profile_scope profile_indices <<< "$profile_row"

      profile_cap_token="${OUT_DIR}/${evidence_id}-${profile_id}-capability-token.json"
      profile_request_result="${OUT_DIR}/${evidence_id}-${profile_id}-request-disclosure-result.json"
      profile_bundle_debug="${OUT_DIR}/${evidence_id}-${profile_id}-bundle-debug.json"
      profile_bundle_file="${OUT_DIR}/${evidence_id}-${profile_id}-disclosure-bundle.json"
      profile_verify_result="${OUT_DIR}/${evidence_id}-${profile_id}-verify-disclosure-result.json"

      run_step "$iteration" "$evidence_id" "build-bundle" "localCrypto" "$profile_bundle_file" \
        node paper3-client.js build-bundle \
          --tokenFile "$profile_cap_token" \
          --requestFile "$profile_request_result" \
          --issuerPublicKeyFile "$PUBLIC_KEY_FILE" \
          --evidenceFile "$evidence_file" \
          --evidenceType DATASET_WINDOW_PCAP \
          --emk "$EVIDENCE_MASTER_KEY" \
          --debugInfoOutput "$profile_bundle_debug" \
          --output "$profile_bundle_file"

      run_step "$iteration" "$evidence_id" "verify-disclosure" "fabricSubmit" "$profile_verify_result" \
        node paper3-client.js verify-disclosure \
          --identity "$profile_identity" \
          --evidenceId "$evidence_id" \
          --bundleFile "$profile_bundle_file" \
          --output "$profile_verify_result"
    done

    run_step "$iteration" "$evidence_id" "query-lifecycle-after-disclosure" "fabricEvaluate" "$lifecycle_disclosed" \
      node paper3-client.js query-evidence-lifecycle \
        --identity "$CUSTODIAN_IDENTITY" \
        --evidenceId "$evidence_id" \
        --output "$lifecycle_disclosed"


    cat > "$destruction_request" <<EOF_JSON
{
  "reasonCode": "RETENTION_POLICY",
  "requestRef": "REQ-DESTRUCTION-${evidence_id}",
  "justification": "Dataset-derived multi-stakeholder lifecycle destruction benchmark after v3 selective disclosures."
}
EOF_JSON

    run_step "$iteration" "$evidence_id" "request-destruction" "fabricSubmit" "$destruction_request_result" \
      node paper3-client.js request-destruction \
        --identity "$DPO_IDENTITY" \
        --evidenceId "$evidence_id" \
        --input "$destruction_request" \
        --output "$destruction_request_result"

    run_step "$iteration" "$evidence_id" "query-lifecycle-after-destruction-request" "fabricEvaluate" "$lifecycle_destruction_requested" \
      node paper3-client.js query-evidence-lifecycle \
        --identity "$CUSTODIAN_IDENTITY" \
        --evidenceId "$evidence_id" \
        --output "$lifecycle_destruction_requested"

    cat > "$destruction_approval" <<EOF_JSON
{
  "approvalRef": "APPROVAL-DESTRUCTION-${evidence_id}",
  "approvalNote": "Judicial reviewer approves dataset-derived lifecycle destruction benchmark."
}
EOF_JSON

    run_step "$iteration" "$evidence_id" "approve-destruction" "fabricSubmit" "$destruction_approval_result" \
      node paper3-client.js approve-destruction \
        --identity "$JUDGE_IDENTITY" \
        --evidenceId "$evidence_id" \
        --input "$destruction_approval" \
        --output "$destruction_approval_result"

    run_step "$iteration" "$evidence_id" "query-lifecycle-after-destruction-approval" "fabricEvaluate" "$lifecycle_destruction_approved" \
      node paper3-client.js query-evidence-lifecycle \
        --identity "$CUSTODIAN_IDENTITY" \
        --evidenceId "$evidence_id" \
        --output "$lifecycle_destruction_approved"

    destruction_method="ATTESTED_KEY_DESTRUCTION"
    destruction_completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    destruction_receipt_ref="RECEIPT-DESTRUCTION-${evidence_id}"

    node - "$destruction_receipt" "$evidence_id" "$destruction_method" "$destruction_receipt_ref" "$destruction_completed_at" "$DPO_ATTEST_PRIVATE_KEY_FILE" "$JUDGE_ATTEST_PRIVATE_KEY_FILE" "$CUSTODIAN_ATTEST_PRIVATE_KEY_FILE" <<'NODE'
const fs = require('fs');
const crypto = require('crypto');

const [
  outFile,
  evidenceId,
  destructionMethod,
  receiptRef,
  completedAt,
  dpoPrivateKeyFile,
  judgePrivateKeyFile,
  custodianPrivateKeyFile
] = process.argv.slice(2);

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

const destroyedKeyClasses = ['DEK', 'EMK', 'K_META', 'K_SALT'];

function signAttestation(role, actorId, privateKeyFile) {
  const privateKeyPem = fs.readFileSync(privateKeyFile, 'utf8');

  const statement = {
    purpose: 'EVIDENCE_DESTRUCTION_ATTESTATION',
    evidenceId,
    destructionMethod,
    receiptRef,
    completedAt,
    destroyedKeyClasses,
    role,
    actorId,
    attestedAt: completedAt
  };

  const canonical = canonicalize(statement);
  const signature = crypto.sign(null, Buffer.from(canonical, 'utf8'), privateKeyPem).toString('hex');

  return {
    role,
    actorId,
    attestedAt: completedAt,
    publicKeyRef: actorId,
    statement,
    statementHash: sha256Hex(canonical),
    signature
  };
}

const receipt = {
  destroyed: true,
  destructionMethod,
  receiptRef,
  completedAt,
  destroyedKeyClasses,
  emkDestroyed: true,
  dekDestroyed: true,
  saltKeyDestroyed: true,
  metadataKeyDestroyed: true,
  keyMaterialDestroyed: true,
  offChainAccessDestroyed: true,
  rawEvidenceAccessRevoked: true,
  requireThresholdAttestation: true,
  thresholdPolicy: {
    required: 2,
    eligibleRoles: [
      'DataProtectionOfficer',
      'JudicialReviewer',
      'EvidenceCustodian'
    ]
  },
  destructionAttestations: [
    signAttestation('DataProtectionOfficer', 'DataProtectionOfficer', dpoPrivateKeyFile),
    signAttestation('JudicialReviewer', 'JudicialReviewer', judgePrivateKeyFile),
    signAttestation('EvidenceCustodian', 'EvidenceCustodian', custodianPrivateKeyFile)
  ],
  note: 'Attested key-destruction event; on-chain commitment and audit trail are preserved.'
};

fs.writeFileSync(outFile, `${JSON.stringify(receipt, null, 2)}\n`);
NODE


    bad_destruction_receipt="${OUT_DIR}/${evidence_id}-negative-tampered-destruction-receipt.json"
    bad_destruction_report_result="${OUT_DIR}/${evidence_id}-negative-tampered-destruction-report-result.json"

    node - "$destruction_receipt" "$bad_destruction_receipt" <<'NODE'
const fs = require('fs');

const [inputFile, outputFile] = process.argv.slice(2);
const receipt = JSON.parse(fs.readFileSync(inputFile, 'utf8'));

function tamperSignature(sig) {
  const s = String(sig || '');
  if (!s) return '00';

  // Toggle the first hex/base64-looking character while preserving length.
  if (s[0] === '0') return `1${s.slice(1)}`;
  if (s[0] === '1') return `0${s.slice(1)}`;
  if (s[0] === 'a') return `b${s.slice(1)}`;
  if (s[0] === 'A') return `B${s.slice(1)}`;
  return `0${s.slice(1)}`;
}

if (!Array.isArray(receipt.destructionAttestations) || receipt.destructionAttestations.length === 0) {
  throw new Error('destructionAttestations not found in receipt');
}

// Tamper all attestation signatures so validCount drops below threshold.
receipt.destructionAttestations = receipt.destructionAttestations.map((att) => ({
  ...att,
  signature: tamperSignature(att.signature)
}));

receipt.note = `${receipt.note || ''} [NEGATIVE_CONTROL_TAMPERED_SIGNATURE]`;

fs.writeFileSync(outputFile, `${JSON.stringify(receipt, null, 2)}\n`);
NODE

    run_negative_step "$iteration" "$evidence_id" "negative-tampered-destruction-attestation-before-valid-report" "negativeControl" "attestation_signature_invalid|destruction_threshold_attestation_not_satisfied|threshold_attestation_not_satisfied|signature_invalid|invalid" "$bad_destruction_report_result" \
      node paper3-client.js report-destroyed \
        --identity "$CUSTODIAN_IDENTITY" \
        --evidenceId "$evidence_id" \
        --receiptFile "$bad_destruction_receipt" \
        --output "$bad_destruction_report_result"

    run_step "$iteration" "$evidence_id" "report-destroyed" "fabricSubmit" "$destruction_report_result" \
      node paper3-client.js report-destroyed \
        --identity "$CUSTODIAN_IDENTITY" \
        --evidenceId "$evidence_id" \
        --receiptFile "$destruction_receipt" \
        --output "$destruction_report_result"

    run_step "$iteration" "$evidence_id" "query-destruction-record" "fabricEvaluate" "$destruction_record" \
      node paper3-client.js query-destruction-record \
        --identity "$DPO_IDENTITY" \
        --evidenceId "$evidence_id" \
        --output "$destruction_record"

    run_step "$iteration" "$evidence_id" "query-lifecycle-after-destroyed" "fabricEvaluate" "$lifecycle_destroyed" \
      node paper3-client.js query-evidence-lifecycle \
        --identity "$CUSTODIAN_IDENTITY" \
        --evidenceId "$evidence_id" \
        --output "$lifecycle_destroyed"

    run_step "$iteration" "$evidence_id" "get-commitment-after-destroyed" "fabricEvaluate" "$commitment_after_destroy" \
      node paper3-client.js get-commitment \
        --identity "$CUSTODIAN_IDENTITY" \
        --evidenceId "$evidence_id" \
        --output "$commitment_after_destroy"

    # Historical audit verification remains allowed after destruction for bundles created before destruction.
    for profile_row in "${PROFILE_ROWS[@]}"; do
      IFS='|' read -r profile_id profile_grantee profile_identity profile_scope profile_indices <<< "$profile_row"
      profile_bundle_file="${OUT_DIR}/${evidence_id}-${profile_id}-disclosure-bundle.json"
      profile_historical_verify_result="${OUT_DIR}/${evidence_id}-${profile_id}-verify-historical-after-destroyed-result.json"

      run_step "$iteration" "$evidence_id" "verify-historical-disclosure-after-destroyed" "fabricEvaluate" "$profile_historical_verify_result" \
        node paper3-client.js verify-historical-disclosure \
          --identity "$profile_identity" \
          --evidenceId "$evidence_id" \
          --bundleFile "$profile_bundle_file" \
          --output "$profile_historical_verify_result"
    done


    stale_epoch_request_result="${OUT_DIR}/${evidence_id}-negative-stale-epoch-request-disclosure-result.json"

    run_negative_step "$iteration" "$evidence_id" "negative-stale-epoch-request-disclosure-after-destroyed" "negativeControl" "capability_lifecycle_epoch_mismatch|DESTROYED|not_authorizable|revoked|inactive|not_active|EVIDENCE_DESTROYED" "$stale_epoch_request_result" \
      node paper3-client.js request-disclosure \
        --identity "$FORENSIC_IDENTITY" \
        --evidenceId "$evidence_id" \
        --tokenFile "$stale_epoch_cap_token" \
        --indices "[]" \
        --output "$stale_epoch_request_result"

    NEGATIVE_PROFILE_ROWS=(
      "post_full|$FORENSIC_GRANTEE_ID|FULL_CHUNKS|[]"
      "post_chunk_set|$VENDOR_GRANTEE_ID|CHUNK_SET|$DISCLOSED_INDICES"
      "post_hash_only|$AUDITOR_GRANTEE_ID|HASH_ONLY|[]"
    )

    for negative_row in "${NEGATIVE_PROFILE_ROWS[@]}"; do
      IFS='|' read -r negative_id negative_grantee negative_scope negative_indices <<< "$negative_row"

      post_destroy_cap_input="${OUT_DIR}/${evidence_id}-${negative_id}-post-destroy-capability-input.json"
      post_destroy_cap_token="${OUT_DIR}/${evidence_id}-${negative_id}-post-destroy-capability-token.json"
      post_destroy_issue_result="${OUT_DIR}/${evidence_id}-${negative_id}-post-destroy-issue-result.json"

      if [[ "$negative_scope" == "CHUNK_SET" ]]; then
        negative_scope_json="{\"type\":\"CHUNK_SET\",\"indices\":${negative_indices}}"
      else
        negative_scope_json="{\"type\":\"${negative_scope}\"}"
      fi

      cat > "$post_destroy_cap_input" <<EOF_JSON
{
  "evidenceId": "$evidence_id",
  "issuerId": "$ISSUER_ID",
  "granteeId": "$negative_grantee",
  "scope": $negative_scope_json,
  "purpose": "NEGATIVE_POST_DESTRUCTION_AUTHORIZATION_TEST_${negative_scope}",
  "ttlHours": 24,
  "version": "$cap_version",
  "commitmentVersion": "$COMMITMENT_VERSION",
  "chunkMerkleRoot": "$chunk_merkle_root",
  "lifecycleStateAtIssuance": "DESTROYED",
  "evidenceLifecycleEpoch": $current_lifecycle_epoch,
  "allowedLifecycleStates": ["COMMITTED", "AUTHORIZED", "DISCLOSED"]
}
EOF_JSON

      run_step "$iteration" "$evidence_id" "create-post-destroy-capability-token" "localCrypto" "$post_destroy_cap_token" \
        node paper3-client.js create-capability-token \
          --input "$post_destroy_cap_input" \
          --privateKeyFile "$PRIVATE_KEY_FILE" \
          --output "$post_destroy_cap_token"

      run_negative_step "$iteration" "$evidence_id" "negative-post-destroy-issue-capability" "negativeControl" "DESTROYED|not_authorizable|evidence_lifecycle_not_authorizable" "$post_destroy_issue_result" \
        node paper3-client.js issue-capability \
          --identity "$CUSTODIAN_IDENTITY" \
          --tokenFile "$post_destroy_cap_token" \
          --output "$post_destroy_issue_result"
    done


  done
done

node - "$RAW_JSONL" "$RAW_CSV" "$SUMMARY_JSON" "$SUMMARY_MD" "$RUN_ID" "$ITERATIONS" "$EVIDENCE_COUNT" <<'NODE'
const fs = require('fs');

const [rawJsonl, rawCsv, summaryJson, summaryMd, runId, iterations, evidenceCount] = process.argv.slice(2);

const records = fs.readFileSync(rawJsonl, 'utf8')
  .split(/\r?\n/)
  .filter(Boolean)
  .map((line) => JSON.parse(line));

function csvEscape(v) {
  if (v === null || v === undefined) return '';
  const s = typeof v === 'object' ? JSON.stringify(v) : String(v);
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

const csvHeaders = [
  'runId',
  'experimentId',
  'iterationIndex',
  'evidenceId',
  'operation',
  'operationGroup',
  'success',
  'returnCode',
  'latencyMs',
  'sourceLabel',
  'chunkSizeBytes',
  'windowBytes',
  'lifecycleState',
  'previousState',
  'nextState',
  'valid',
  'bundleHashValid',
  'rootMatch',
  'capabilityValid',
  'capabilityStateBefore',
  'capabilityStateAfter',
  'destructionMethod',
  'commitmentPreserved',
  'auditTrailPreserved',
  'capabilitiesRevoked',
  'inspectedCapabilities',
  'rejectionObserved',
  'rejectionMatched',
  'outputFile'
];

fs.writeFileSync(rawCsv, [
  csvHeaders.join(','),
  ...records.map((r) => csvHeaders.map((h) => csvEscape(r[h])).join(','))
].join('\n') + '\n');

const successfulRecords = records.filter((r) => r.success);
const failedRecords = records.filter((r) => !r.success);
const negativeRecords = records.filter((r) => r.operationGroup === 'negativeControl');

const lifecycleByEvidence = {};
for (const r of records) {
  if (!r.evidenceId || r.evidenceId === 'SETUP') continue;
  lifecycleByEvidence[r.evidenceId] ??= [];
  if (r.lifecycleState) lifecycleByEvidence[r.evidenceId].push(r.lifecycleState);
}

const expectedLifecycle = [
  'PRESERVED',
  'COMMITTED',
  'AUTHORIZED',
  'DISCLOSED',
  'DESTRUCTION_REQUESTED',
  'DESTRUCTION_APPROVED',
  'DESTROYED'
];

const evidenceIds = Object.keys(lifecycleByEvidence);
const lifecycleMatched = evidenceIds.every((id) => {
  const observed = lifecycleByEvidence[id];
  return expectedLifecycle.every((state) => observed.includes(state));
});

const verifyRecords = records.filter((r) => r.operation === 'verify-disclosure');
const destructionRecords = records.filter((r) => r.operation === 'query-destruction-record');
const commitmentAfterDestroy = records.filter((r) => r.operation === 'get-commitment-after-destroyed');

const summary = {
  success: true,
  runId,
  generatedAt: new Date().toISOString(),
  benchmark: 'fabric-e2e-lifecycle-disclosure-destruction',
  iterationsConfigured: Number(iterations),
  evidenceCountConfigured: Number(evidenceCount),
  totalOperationRecords: records.length,
  positiveOperationRecords: records.filter((r) => r.operationGroup !== 'negativeControl').length,
  negativeOperationRecords: negativeRecords.length,
  allPositiveSuccessful: records
    .filter((r) => r.operationGroup !== 'negativeControl')
    .every((r) => r.success),
  negativeControlsRejected: negativeRecords.every((r) => r.rejectionObserved === true),
  negativeControlsMatched: negativeRecords.every((r) => r.rejectionMatched === true),
  allDisclosureVerified: verifyRecords.every((r) =>
    r.valid === true &&
    r.bundleHashValid === true &&
    r.rootMatch === true &&
    r.capabilityValid === true
  ),
  allDestructionRecordsPreserveCommitment: destructionRecords.every((r) => r.commitmentPreserved === true),
  allDestructionRecordsPreserveAuditTrail: destructionRecords.every((r) => r.auditTrailPreserved === true),
  allCommitmentsReadableAfterDestroyed: commitmentAfterDestroy.every((r) => r.success === true),
  lifecycleMatched,
  expectedLifecycle,
  evidenceIds,
  sourceLabel: records.find((r) => r.sourceLabel)?.sourceLabel ?? null,
  sourceFile: records.find((r) => r.sourceFile)?.sourceFile ?? null,
  chunkSizeBytes: records.find((r) => r.chunkSizeBytes)?.chunkSizeBytes ?? null,
  windowBytes: records.find((r) => r.windowBytes)?.windowBytes ?? null,
  files: {
    rawJsonl,
    rawCsv,
    summaryJson,
    summaryMd
  }
};

summary.overallStatus =
  summary.allPositiveSuccessful &&
  summary.negativeControlsRejected &&
  summary.negativeControlsMatched &&
  summary.allDisclosureVerified &&
  summary.allDestructionRecordsPreserveCommitment &&
  summary.allDestructionRecordsPreserveAuditTrail &&
  summary.allCommitmentsReadableAfterDestroyed &&
  summary.lifecycleMatched
    ? 'PASS'
    : 'FAIL';

fs.writeFileSync(summaryJson, JSON.stringify(summary, null, 2));

fs.writeFileSync(summaryMd, `# Fabric E2E Lifecycle Disclosure Destruction Benchmark

Generated at: ${summary.generatedAt}

## Status

| Metric | Value |
| --- | --- |
| Overall status | ${summary.overallStatus} |
| Records | ${summary.totalOperationRecords} |
| Positive records | ${summary.positiveOperationRecords} |
| Negative records | ${summary.negativeOperationRecords} |
| Lifecycle matched | ${summary.lifecycleMatched} |
| Disclosure verified | ${summary.allDisclosureVerified} |
| Commitment preserved after destruction | ${summary.allDestructionRecordsPreserveCommitment} |
| Audit trail preserved after destruction | ${summary.allDestructionRecordsPreserveAuditTrail} |
| Commitment readable after destroyed | ${summary.allCommitmentsReadableAfterDestroyed} |
| Post-destroy negative controls rejected | ${summary.negativeControlsRejected} |
| Negative rejection matched expected reason | ${summary.negativeControlsMatched} |

## Expected Lifecycle

\`\`\`
${summary.expectedLifecycle.join(' -> ')}
\`\`\`

## Dataset Source

| Field | Value |
| --- | --- |
| Source label | ${summary.sourceLabel} |
| Source file | ${summary.sourceFile} |
| Window bytes | ${summary.windowBytes} |
| Chunk size | ${summary.chunkSizeBytes} |

## Output Files

| File | Path |
| --- | --- |
| Raw JSONL | ${rawJsonl} |
| Raw CSV | ${rawCsv} |
| Summary JSON | ${summaryJson} |
| Summary Markdown | ${summaryMd} |
`);
console.log(JSON.stringify(summary, null, 2));
NODE

echo
echo "============================================================"
echo "FABRIC E2E LIFECYCLE + DESTRUCTION BENCHMARK COMPLETED"
echo "Summary : $SUMMARY_JSON"
echo "Markdown: $SUMMARY_MD"
echo "Raw     : $RAW_JSONL"
echo "CSV     : $RAW_CSV"
echo "============================================================"
