'use strict';

const fs = require('node:fs');
const path = require('node:path');

function repoRoot() {
  return path.resolve(__dirname, '..');
}

function readJson(relPath, fallback = null) {
  const abs = path.isAbsolute(relPath) ? relPath : path.join(repoRoot(), relPath);
  if (!fs.existsSync(abs)) {
    if (fallback !== null) return fallback;
    throw new Error(`JSON file not found: ${abs}`);
  }
  return JSON.parse(fs.readFileSync(abs, 'utf8'));
}

function getIdentityConfig(logicalName) {
  const ids = readJson('config/identities.json');
  const cfg = ids[logicalName];
  if (!cfg) throw new Error(`Missing identity in config/identities.json: ${logicalName}`);
  return cfg;
}

function getDefaults() {
  return readJson('config/experiment-defaults.json');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function jsonArg(value) {
  return JSON.stringify(value);
}

function asBoolString(value) {
  return value ? 'true' : 'false';
}

function resultToJson(result) {
  if (!result) return null;
  if (Buffer.isBuffer(result)) {
    const s = result.toString('utf8');
    try { return JSON.parse(s); } catch { return s; }
  }
  if (typeof result === 'string') {
    try { return JSON.parse(result); } catch { return result; }
  }
  return result;
}

async function send(sutAdapter, {
  contractId,
  identity,
  fcn,
  args = [],
  readOnly = false,
  endorsingOrganizations,
  transientMap
}) {
  const request = {
    contractId,
    contractFunction: fcn,
    invokerIdentity: identity,
    contractArguments: args,
    readOnly
  };

  if (Array.isArray(endorsingOrganizations) && endorsingOrganizations.length > 0) {
    request.endorsingOrganizations = endorsingOrganizations;
  }

  if (transientMap) {
    request.transientMap = transientMap;
  }

  return sutAdapter.sendRequests(request);
}

function sliceForWorker(items, workerIndex, totalWorkers) {
  return items.filter((_, i) => (i % totalWorkers) === workerIndex);
}

module.exports = {
  repoRoot,
  readJson,
  getIdentityConfig,
  getDefaults,
  sleep,
  jsonArg,
  asBoolString,
  resultToJson,
  send,
  sliceForWorker
};
