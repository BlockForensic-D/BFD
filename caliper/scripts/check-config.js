'use strict';

const fs = require('node:fs');
const path = require('node:path');
const yaml = require('js-yaml');

const root = path.resolve(__dirname, '..');
const networkPath = path.join(root, 'networks/forensic-hlfv3-network.yaml');
const identitiesPath = path.join(root, 'config/identities.json');
const defaultsPath = path.join(root, 'config/experiment-defaults.json');

function die(msg) {
  console.error(`ERROR: ${msg}`);
  process.exitCode = 1;
}

for (const file of [networkPath, identitiesPath, defaultsPath]) {
  if (!fs.existsSync(file)) die(`Missing file: ${file}`);
}

const network = yaml.load(fs.readFileSync(networkPath, 'utf8'));
const identities = JSON.parse(fs.readFileSync(identitiesPath, 'utf8'));
const defaults = JSON.parse(fs.readFileSync(defaultsPath, 'utf8'));

if (!network.channels || !network.channels.length) die('network config has no channels');
if (!defaults.contractId) die('config/experiment-defaults.json missing contractId');

const names = Object.values(identities).map((x) => x.caliperIdentity);
for (const req of ['GatewayCollector','EvidenceCustodian','ExternalVendor','ExternalAuditor','DataProtectionOfficer','JudicialReviewer']) {
  if (!identities[req]) die(`identities.json missing ${req}`);
  if (!identities[req].actorId) die(`${req} missing actorId`);
}

const raw = fs.readFileSync(networkPath, 'utf8');
if (raw.includes('/ABS/PATH/TO/')) {
  console.warn('WARNING: networks/forensic-hlfv3-network.yaml still contains /ABS/PATH/TO placeholders. Edit paths before running Caliper.');
}

console.log('Configuration files parsed successfully.');
console.log(`Contract ID: ${defaults.contractId}`);
console.log(`Identity names: ${names.join(', ')}`);
