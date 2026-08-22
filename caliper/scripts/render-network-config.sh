#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$WORKSPACE"

BASE_DIR="${FABRIC_TEST_NETWORK_DIR:-/home/labnuc/2labforensic/fabric-samples/test-network}"
TEMPLATE="networks/networkConfig.template.yaml"
OUT="networks/networkConfig.yaml"

declare -A USER_ORG=(
  ["GatewayCollector"]="org1.example.com"
  ["EvidenceCustodian"]="org1.example.com"
  ["DataProtectionOfficer"]="org2.example.com"
  ["JudicialReviewer"]="org2.example.com"
  ["ExternalVendor"]="org3.example.com"
  ["ExternalAuditor"]="org3.example.com"
)

USERS=(
  "GatewayCollector"
  "EvidenceCustodian"
  "DataProtectionOfficer"
  "JudicialReviewer"
  "ExternalVendor"
  "ExternalAuditor"
)

if [[ ! -f "$TEMPLATE" ]]; then
  echo "ERROR: template not found: $TEMPLATE" >&2
  exit 1
fi

cp "$TEMPLATE" "$OUT"

find_private_key() {
  local user="$1"
  local org_domain="$2"
  local ks_dir="${BASE_DIR}/organizations/peerOrganizations/${org_domain}/users/${user}@${org_domain}/msp/keystore"

  if [[ ! -d "$ks_dir" ]]; then
    echo ""
    return
  fi

  find "$ks_dir" -type f \( -name '*_sk' -o -name 'priv_sk' -o -name '*.pem' \) | head -n 1 || true
}

find_cert() {
  local user="$1"
  local org_domain="$2"
  local cert="${BASE_DIR}/organizations/peerOrganizations/${org_domain}/users/${user}@${org_domain}/msp/signcerts/cert.pem"

  if [[ -f "$cert" ]]; then
    echo "$cert"
  else
    find "${BASE_DIR}/organizations/peerOrganizations/${org_domain}/users/${user}@${org_domain}/msp/signcerts" -type f -name "*.pem" 2>/dev/null | head -n 1 || true
  fi
}

for user in "${USERS[@]}"; do
  org_domain="${USER_ORG[$user]}"
  key_path="$(find_private_key "$user" "$org_domain")"
  cert_path="$(find_cert "$user" "$org_domain")"

  if [[ -z "$key_path" ]]; then
    echo "ERROR: private key not found for user: $user" >&2
    echo "Expected under: ${BASE_DIR}/organizations/peerOrganizations/${org_domain}/users/${user}@${org_domain}/msp/keystore/" >&2
    exit 1
  fi

  if [[ -z "$cert_path" ]]; then
    echo "ERROR: certificate not found for user: $user" >&2
    echo "Expected under: ${BASE_DIR}/organizations/peerOrganizations/${org_domain}/users/${user}@${org_domain}/msp/signcerts/" >&2
    exit 1
  fi

  sed -i "s#__${user}_PRIVATE_KEY__#${key_path}#g" "$OUT"
  sed -i "s#__${user}_CERT__#${cert_path}#g" "$OUT"

  echo "Mapped ${user} (${org_domain}):"
  echo "  key : ${key_path}"
  echo "  cert: ${cert_path}"
done

if grep -q "__.*__" "$OUT"; then
  echo "ERROR: unresolved placeholders remain in $OUT" >&2
  grep "__.*__" "$OUT" >&2 || true
  exit 1
fi

echo
echo "Generated: $OUT"
