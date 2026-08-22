'use strict';

const METRIC_FIELDS = Object.freeze([
  'experiment_id',
  'experiment_group',
  'scenario',
  'dataset_name',
  'evidence_id',
  'file_name',
  'commitment_version',
  'disclosure_mode',
  'disclosure_policy',
  'file_size_bytes',
  'chunk_size',
  'total_chunks',
  'disclosed_chunk_count',
  'withheld_chunk_count',
  'disclosure_ratio',
  'withheld_ratio',
  'bundle_size_bytes',
  'proof_size_bytes',
  'opening_size_bytes',
  'manifest_size_bytes',
  'capability_size_bytes',
  'disclosed_data_bytes',
  'withheld_data_bytes',
  'disclosure_expansion_ratio',
  'generation_time_ms',
  'verification_time_ms',
  'total_time_ms',
  'wallclock_total_ms',
  'wallclock_total_seconds',
  'throughput_mib_per_sec',
  'peak_memory_bytes',
  'rss_before_bytes',
  'rss_after_bytes',
  'heap_used_before_bytes',
  'heap_used_after_bytes',
  'valid',
  'failure_reason',
  'tamper_type',
  'platform',
  'timestamp'
]);

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function normalizeNumber(value, fieldName, { allowNull = false } = {}) {
  if (value == null || value === '') {
    if (allowNull) return null;
    return 0;
  }

  const n = Number(value);
  if (!Number.isFinite(n)) {
    throw new TypeError(`${fieldName} must be a finite number`);
  }
  return n;
}

function normalizeInteger(value, fieldName, { allowNull = false, min = null } = {}) {
  if (value == null || value === '') {
    if (allowNull) return null;
    return 0;
  }

  const n = Number(value);
  if (!Number.isInteger(n)) {
    throw new TypeError(`${fieldName} must be an integer`);
  }

  if (min != null && n < min) {
    throw new RangeError(`${fieldName} must be >= ${min}`);
  }

  return n;
}

function normalizeString(value, { allowNull = false } = {}) {
  if (value == null) {
    return allowNull ? null : '';
  }
  return String(value);
}

function normalizeBoolean(value) {
  if (typeof value === 'boolean') return value;
  if (value === 'true') return true;
  if (value === 'false') return false;
  return Boolean(value);
}

function normalizeIsoTimestamp(value) {
  if (!value) {
    return new Date().toISOString();
  }

  const d = new Date(value);
  if (Number.isNaN(d.getTime())) {
    throw new TypeError('timestamp must be a valid ISO timestamp');
  }
  return d.toISOString();
}

function normalizeDisclosureRatio(value, disclosedChunkCount, totalChunks) {
  if (value != null && value !== '') {
    const n = Number(value);
    if (!Number.isFinite(n)) {
      throw new TypeError('disclosure_ratio must be a finite number');
    }
    return n;
  }

  if (totalChunks <= 0) return 0;
  return disclosedChunkCount / totalChunks;
}

function normalizeMetricRecord(record) {
  if (!isPlainObject(record)) {
    throw new TypeError('record must be a plain object');
  }

  const totalChunks = normalizeInteger(record.total_chunks, 'total_chunks', { min: 0 });
  const disclosedChunkCount = normalizeInteger(
    record.disclosed_chunk_count,
    'disclosed_chunk_count',
    { min: 0 }
  );

  const withheldChunkCount = normalizeInteger(
    record.withheld_chunk_count ?? Math.max(totalChunks - disclosedChunkCount, 0),
    'withheld_chunk_count',
    { min: 0 }
  );
  const disclosedDataBytes = normalizeInteger(
    record.disclosed_data_bytes,
    'disclosed_data_bytes',
    { min: 0 }
  );
  const fileSizeBytes = normalizeInteger(record.file_size_bytes, 'file_size_bytes', { min: 0 });
  const withheldDataBytes = normalizeInteger(
    record.withheld_data_bytes ?? Math.max(fileSizeBytes - disclosedDataBytes, 0),
    'withheld_data_bytes',
    { min: 0 }
  );
  const bundleSizeBytes = normalizeInteger(record.bundle_size_bytes, 'bundle_size_bytes', { min: 0 });

  const normalized = {
    experiment_id: normalizeString(record.experiment_id),
    experiment_group: normalizeString(record.experiment_group),
    scenario: normalizeString(record.scenario),
    dataset_name: normalizeString(record.dataset_name),
    evidence_id: normalizeString(record.evidence_id),
    file_name: normalizeString(record.file_name),
    commitment_version: normalizeString(record.commitment_version),
    disclosure_mode: normalizeString(record.disclosure_mode),
    disclosure_policy: normalizeString(record.disclosure_policy, { allowNull: true }),

    file_size_bytes: fileSizeBytes,
    chunk_size: normalizeInteger(record.chunk_size, 'chunk_size', { min: 0 }),
    total_chunks: totalChunks,
    disclosed_chunk_count: disclosedChunkCount,
    withheld_chunk_count: withheldChunkCount,
    disclosure_ratio: normalizeDisclosureRatio(
      record.disclosure_ratio,
      disclosedChunkCount,
      totalChunks
    ),
    withheld_ratio: normalizeNumber(
      record.withheld_ratio ?? (totalChunks > 0 ? withheldChunkCount / totalChunks : 0),
      'withheld_ratio'
    ),

    bundle_size_bytes: bundleSizeBytes,
    proof_size_bytes: normalizeInteger(record.proof_size_bytes, 'proof_size_bytes', { min: 0 }),
    opening_size_bytes: normalizeInteger(record.opening_size_bytes, 'opening_size_bytes', { min: 0 }),
    manifest_size_bytes: normalizeInteger(record.manifest_size_bytes, 'manifest_size_bytes', { min: 0 }),
    capability_size_bytes: normalizeInteger(record.capability_size_bytes, 'capability_size_bytes', { min: 0 }),
    disclosed_data_bytes: disclosedDataBytes,
    withheld_data_bytes: withheldDataBytes,
    disclosure_expansion_ratio: normalizeNumber(
      record.disclosure_expansion_ratio ?? (disclosedDataBytes > 0 ? bundleSizeBytes / disclosedDataBytes : 0),
      'disclosure_expansion_ratio'
    ),

    generation_time_ms: normalizeNumber(record.generation_time_ms, 'generation_time_ms'),
    verification_time_ms: normalizeNumber(record.verification_time_ms, 'verification_time_ms'),
    total_time_ms: normalizeNumber(record.total_time_ms, 'total_time_ms'),
    wallclock_total_ms: normalizeNumber(record.wallclock_total_ms, 'wallclock_total_ms'),
    wallclock_total_seconds: normalizeNumber(record.wallclock_total_seconds, 'wallclock_total_seconds'),
    throughput_mib_per_sec: normalizeNumber(record.throughput_mib_per_sec, 'throughput_mib_per_sec'),
    peak_memory_bytes: normalizeInteger(record.peak_memory_bytes, 'peak_memory_bytes', { min: 0 }),
    rss_before_bytes: normalizeInteger(record.rss_before_bytes, 'rss_before_bytes', { min: 0 }),
    rss_after_bytes: normalizeInteger(record.rss_after_bytes, 'rss_after_bytes', { min: 0 }),
    heap_used_before_bytes: normalizeInteger(record.heap_used_before_bytes, 'heap_used_before_bytes', { min: 0 }),
    heap_used_after_bytes: normalizeInteger(record.heap_used_after_bytes, 'heap_used_after_bytes', { min: 0 }),

    valid: normalizeBoolean(record.valid),
    failure_reason: normalizeString(record.failure_reason, { allowNull: true }),
    tamper_type: normalizeString(record.tamper_type, { allowNull: true }),
    platform: normalizeString(record.platform),
    timestamp: normalizeIsoTimestamp(record.timestamp)
  };

  return normalized;
}

function escapeCsv(value) {
  if (value == null) return '';

  const str = String(value);
  if (/[",\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function toCsvHeader(fields = METRIC_FIELDS) {
  return fields.join(',');
}

function toCsvRow(record, fields = METRIC_FIELDS) {
  const normalized = normalizeMetricRecord(record);
  return fields.map((field) => escapeCsv(normalized[field])).join(',');
}

function normalizeMetricRecords(records) {
  if (!Array.isArray(records)) {
    throw new TypeError('records must be an array');
  }

  return records.map((record, index) => {
    try {
      return normalizeMetricRecord(record);
    } catch (err) {
      throw new Error(`Invalid metric record at index ${index}: ${err.message}`);
    }
  });
}

function recordsToCsv(records, fields = METRIC_FIELDS) {
  const normalized = normalizeMetricRecords(records);
  const lines = [toCsvHeader(fields)];

  for (const record of normalized) {
    lines.push(toCsvRow(record, fields));
  }

  return lines.join('\n');
}

export {
  METRIC_FIELDS,
  normalizeMetricRecord,
  normalizeMetricRecords,
  toCsvHeader,
  toCsvRow,
  recordsToCsv
};