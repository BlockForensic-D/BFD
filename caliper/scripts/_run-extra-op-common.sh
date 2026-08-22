#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

: "${OPERATION:?missing OPERATION}"
: "${SAFE_NAME:?missing SAFE_NAME}"
: "${POOL_PREFIX_BASE:?missing POOL_PREFIX_BASE}"
: "${PRESEED_WORKLOAD_MODULE:?missing PRESEED_WORKLOAD_MODULE}"
: "${MEASURE_WORKLOAD_MODULE:?missing MEASURE_WORKLOAD_MODULE}"
: "${OUT_ROOT:?missing OUT_ROOT}"
: "${MEASURE_READONLY:?missing MEASURE_READONLY}"

TEST_NETWORK_DIR="${TEST_NETWORK_DIR:-/home/labnuc/2labforensic/fabric-samples/test-network}"
CHANNEL_NAME="${CHANNEL_NAME:-forensic-channel}"

CC_NAME="${CC_NAME:-forensicContract}"
CC_PATH="${CC_PATH:-../forensic/chaincode-javascript}"
CC_LANG="${CC_LANG:-javascript}"

WORKERS="${WORKERS:-4}"
PRESEED_WORKERS="${PRESEED_WORKERS:-1}"

TPS="${TPS:-1}"
DUR="${DUR:-60}"
RUNS="${RUNS:-${REPEATS:-6}}"
SELECT_TOP="${SELECT_TOP:-3}"

CONTRACT_ID="${CONTRACT_ID:-forensicContract}"
DATASET_PROFILE_ID="${DATASET_PROFILE_ID:-edge_vulnscan_1mib_v3}"

POOL_MARGIN="${POOL_MARGIN:-20}"
PRESEED_TPS="${PRESEED_TPS:-0.5}"
PRESEED_MEASURE_GAP_SEC="${PRESEED_MEASURE_GAP_SEC:-30}"

NETWORK_SETTLE_SEC="${NETWORK_SETTLE_SEC:-20}"
DEPLOY_SETTLE_SEC="${DEPLOY_SETTLE_SEC:-20}"
COOLDOWN_SEC="${COOLDOWN_SEC:-180}"
CALIPER_RESOURCE_INTERVAL="${CALIPER_RESOURCE_INTERVAL:-2}"
MIN_RATIO="${MIN_RATIO:-0.90}"

TARGET_TX=$(( TPS * DUR ))
PER_WORKER_TX=$(( (TARGET_TX + WORKERS - 1) / WORKERS ))
POOL_TOTAL_ITEMS=$(( TARGET_TX + POOL_MARGIN ))
PRESEED_TX_NUMBER="$POOL_TOTAL_ITEMS"

RUN_ID="${RUN_ID:-final-${SAFE_NAME}-duration-clean-ledger-w${WORKERS}-t${TPS}-d${DUR}-$(date +%Y%m%d-%H%M%S)}"
OUT_DIR="${OUT_ROOT}/${RUN_ID}"

mkdir -p "$OUT_DIR" benchmarks

PERF_ALL="${OUT_DIR}/performance_metrics_all.csv"
PERF_TOP="${OUT_DIR}/performance_metrics_top${SELECT_TOP}.csv"
FINAL_SUMMARY="${OUT_DIR}/final_top${SELECT_TOP}_summary.csv"
RUN_INDEX="${OUT_DIR}/run_index.csv"

cat > "$PERF_ALL" <<CSV
run_id,trial_id,trial_started_at,operation,workers,target_tps,target_type,target_value,target_tx_approx,pool_total_items,label,succ,fail,sendRateTps,throughputTps,throughputSendRatio,avgLatencySec,minLatencySec,maxLatencySec,returnCode,decision,source,report_html,benchmark_yaml,measure_log
CSV

printf 'run_id,trial_id,trial_started_at,network_log,pool_manifest,preseed_yaml,preseed_log,preseed_rc,measure_yaml,measure_log,measure_rc,report_html\n' > "$RUN_INDEX"

echo "OPERATION=$OPERATION"
echo "WORKERS=$WORKERS PRESEED_WORKERS=$PRESEED_WORKERS"
echo "TPS=$TPS DUR=$DUR RUNS=$RUNS SELECT_TOP=$SELECT_TOP"
echo "TARGET_TX=$TARGET_TX PER_WORKER_TX=$PER_WORKER_TX POOL_MARGIN=$POOL_MARGIN"
echo "POOL_TOTAL_ITEMS=$POOL_TOTAL_ITEMS PRESEED_TX_NUMBER=$PRESEED_TX_NUMBER"
echo "PRESEED_TPS=$PRESEED_TPS MEASURE_READONLY=$MEASURE_READONLY"
echo "OUT_DIR=$OUT_DIR"

reset_network_and_deploy() {
  local trial_id="$1"
  local network_log="$2"

  {
    echo "=== Network reset for ${trial_id} ==="
    date -Is

    cd "$TEST_NETWORK_DIR"

    ./network.sh down || true
    docker ps -aq --filter "status=created" | xargs -r docker rm || true
    docker image prune -f || true
    docker builder prune -f || true

    ./network.sh up createChannel -bft -c "$CHANNEL_NAME"
    sleep "$NETWORK_SETTLE_SEC"

    ./network.sh deployCC -ccn "$CC_NAME" -ccp "$CC_PATH" -ccl "$CC_LANG" -c "$CHANNEL_NAME"
    sleep "$DEPLOY_SETTLE_SEC"

    if [ -x ./fix-caliper-identity-paths-v2.sh ]; then
      ./fix-caliper-identity-paths-v2.sh
    fi

    source scripts/envVar.sh

    for ORG in 1 2 3; do
      setGlobals "$ORG"
      peer channel getinfo -c "$CHANNEL_NAME"
    done

    setGlobals 1
    peer lifecycle chaincode querycommitted -C "$CHANNEL_NAME" -n "$CC_NAME" || true

    date -Is
  } 2>&1 | tee "$network_log"
}

copy_report_if_exists() {
  local trial_id="$1"
  local out_report="${OUT_DIR}/measure-${trial_id}-report.html"

  if [ -f report.html ]; then
    cp -a report.html "$out_report"
    echo "$out_report"
  else
    echo ""
  fi
}

validate_preseed_manifest() {
  local manifest_base="$1"
  local min_total="$2"
  local workers="$3"
  local min_per_worker="$4"

  python3 - "$manifest_base" "$min_total" "$workers" "$min_per_worker" <<'PY_VALIDATE'
import json
import sys
from pathlib import Path
from collections import Counter

base = Path(sys.argv[1])
min_total = int(sys.argv[2])
workers = int(sys.argv[3])
min_per_worker = int(sys.argv[4])

paths = []
if base.exists():
    paths.append(base)

if base.parent.exists():
    for p in base.parent.iterdir():
        if p.name.startswith(base.name + ".w") and p.name.endswith(".jsonl"):
            paths.append(p)

rows = []
seen = set()

for p in sorted(set(paths)):
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        ev = r.get("evidenceId")
        if ev in seen:
            raise SystemExit(f"DUPLICATE_EVIDENCE_ID:{ev}")
        seen.add(ev)
        rows.append(r)

if len(rows) < min_total:
    raise SystemExit(f"MANIFEST_INCOMPLETE total={len(rows)} expected_min={min_total}")

counts = Counter(int(r.get("measureWorkerIndex", -1)) for r in rows)

for w in range(workers):
    if counts[w] < min_per_worker:
        raise SystemExit(f"MANIFEST_WORKER_INCOMPLETE worker={w} count={counts[w]} expected_min={min_per_worker}")

print(f"MANIFEST_OK total={len(rows)} min_total={min_total} per_worker_min={min_per_worker}")
PY_VALIDATE
}

parse_measure_log() {
  local measure_log="$1"
  local report_html="$2"
  local measure_yaml="$3"
  local trial_id="$4"
  local trial_started_at="$5"
  local measure_rc="$6"

  python3 - "$measure_log" "$PERF_ALL" "$RUN_ID" "$trial_id" "$trial_started_at" "$OPERATION" "$WORKERS" "$TPS" "$DUR" "$POOL_TOTAL_ITEMS" "$measure_rc" "$MIN_RATIO" "$report_html" "$measure_yaml" <<'PY_PARSE'
import csv
import sys

measure_log, perf_csv, run_id, trial_id, trial_started_at, operation, workers, target_tps, dur, pool_total_items, measure_rc, min_ratio, report_html, measure_yaml = sys.argv[1:]
min_ratio = float(min_ratio)

def to_int(x):
    try:
        if x in ("", "-", None):
            return None
        return int(float(str(x).strip()))
    except Exception:
        return None

def to_float(x):
    try:
        if x in ("", "-", None):
            return None
        return float(str(x).strip())
    except Exception:
        return None

rows = []
op_low = operation.lower()

with open(measure_log, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        if "|" not in line:
            continue
        if op_low not in line.lower():
            continue

        idx = line.find("|")
        parts = [p.strip() for p in line[idx:].strip().strip("|").split("|")]

        if len(parts) < 8:
            continue

        label = parts[0]
        if op_low not in label.lower():
            continue

        succ = to_int(parts[1])
        fail = to_int(parts[2])
        send = to_float(parts[3])
        max_lat = to_float(parts[4])
        min_lat = to_float(parts[5])
        avg_lat = to_float(parts[6])
        thr = to_float(parts[7])

        ratio = (thr / send) if send and send > 0 and thr is not None else None

        decision = "INVALID"
        if str(measure_rc) == "0" and succ and succ > 0 and fail == 0 and ratio is not None and ratio >= min_ratio:
            decision = "VALID"

        rows.append({
            "run_id": run_id,
            "trial_id": trial_id,
            "trial_started_at": trial_started_at,
            "operation": operation,
            "workers": workers,
            "target_tps": target_tps,
            "target_type": "txDuration",
            "target_value": dur,
            "target_tx_approx": int(target_tps) * int(dur),
            "pool_total_items": pool_total_items,
            "label": label,
            "succ": succ if succ is not None else "",
            "fail": fail if fail is not None else "",
            "sendRateTps": send if send is not None else "",
            "throughputTps": thr if thr is not None else "",
            "throughputSendRatio": ratio if ratio is not None else "",
            "avgLatencySec": avg_lat if avg_lat is not None else "",
            "minLatencySec": min_lat if min_lat is not None else "",
            "maxLatencySec": max_lat if max_lat is not None else "",
            "returnCode": measure_rc,
            "decision": decision,
            "source": "caliper_measure_log",
            "report_html": report_html,
            "benchmark_yaml": measure_yaml,
            "measure_log": measure_log,
        })

fields = [
    "run_id","trial_id","trial_started_at","operation","workers","target_tps",
    "target_type","target_value","target_tx_approx","pool_total_items","label",
    "succ","fail","sendRateTps","throughputTps","throughputSendRatio",
    "avgLatencySec","minLatencySec","maxLatencySec","returnCode","decision",
    "source","report_html","benchmark_yaml","measure_log"
]

with open(perf_csv, "a", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    for row in rows:
        writer.writerow(row)

print(f"performance_rows={len(rows)}")
for row in rows:
    print(
        f"{row['label']}: succ={row['succ']} fail={row['fail']} "
        f"send={row['sendRateTps']} throughput={row['throughputTps']} "
        f"ratio={row['throughputSendRatio']} avg={row['avgLatencySec']} "
        f"max={row['maxLatencySec']} decision={row['decision']}"
    )
PY_PARSE
}

select_top_and_summary() {
  python3 - "$PERF_ALL" "$PERF_TOP" "$FINAL_SUMMARY" "$SELECT_TOP" <<'PY_TOP'
import csv
import math
import os
import statistics
import sys

perf_all, perf_top, final_summary, select_top = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])

def read_csv(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

def num(x):
    try:
        if x in ("", "-", None):
            return None
        return float(x)
    except Exception:
        return None

rows = read_csv(perf_all)

valid = [
    r for r in rows
    if r.get("decision") == "VALID"
    and num(r.get("avgLatencySec")) is not None
    and num(r.get("throughputTps")) is not None
]

valid.sort(key=lambda r: (
    num(r.get("avgLatencySec")) or 999999,
    num(r.get("maxLatencySec")) or 999999,
    -(num(r.get("throughputSendRatio")) or -1),
    -(num(r.get("throughputTps")) or -1),
))

selected = valid[:select_top]

if rows:
    fields = list(rows[0].keys()) + ["selectionRank", "selectionNote"]
    with open(perf_top, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for i, r in enumerate(selected, 1):
            rr = dict(r)
            rr["selectionRank"] = i
            rr["selectionNote"] = "selected_valid_lowest_avg_latency_clean_ledger"
            w.writerow(rr)

def vals(col):
    out = []
    for r in selected:
        v = num(r.get(col))
        if v is not None and math.isfinite(v):
            out.append(v)
    return out

def mean(col):
    v = vals(col)
    return statistics.mean(v) if v else ""

def stdev(col):
    v = vals(col)
    return statistics.stdev(v) if len(v) > 1 else 0.0 if len(v) == 1 else ""

def mn(col):
    v = vals(col)
    return min(v) if v else ""

def mx(col):
    v = vals(col)
    return max(v) if v else ""

if selected:
    first = selected[0]
    summary = {
        "run_id": first.get("run_id", ""),
        "operation": first.get("operation", ""),
        "workers": first.get("workers", ""),
        "target_tps": first.get("target_tps", ""),
        "target_type": first.get("target_type", ""),
        "target_value": first.get("target_value", ""),
        "valid_trials": len(valid),
        "selected_trials_n": len(selected),
        "selected_trial_ids": ";".join(r.get("trial_id", "") for r in selected),
        "throughput_mean_tps": mean("throughputTps"),
        "throughput_stddev_tps": stdev("throughputTps"),
        "throughput_min_tps": mn("throughputTps"),
        "throughput_max_tps": mx("throughputTps"),
        "send_rate_mean_tps": mean("sendRateTps"),
        "throughput_send_ratio_mean": mean("throughputSendRatio"),
        "avg_latency_mean_sec": mean("avgLatencySec"),
        "avg_latency_stddev_sec": stdev("avgLatencySec"),
        "avg_latency_min_sec": mn("avgLatencySec"),
        "avg_latency_max_sec": mx("avgLatencySec"),
        "max_latency_mean_sec": mean("maxLatencySec"),
        "succ_mean": mean("succ"),
        "fail_mean": mean("fail"),
    }
else:
    summary = {
        "run_id": "",
        "operation": "",
        "workers": "",
        "target_tps": "",
        "target_type": "txDuration",
        "target_value": "",
        "valid_trials": 0,
        "selected_trials_n": 0,
        "selected_trial_ids": "",
        "throughput_mean_tps": "",
        "throughput_stddev_tps": "",
        "throughput_min_tps": "",
        "throughput_max_tps": "",
        "send_rate_mean_tps": "",
        "throughput_send_ratio_mean": "",
        "avg_latency_mean_sec": "",
        "avg_latency_stddev_sec": "",
        "avg_latency_min_sec": "",
        "avg_latency_max_sec": "",
        "max_latency_mean_sec": "",
        "succ_mean": "",
        "fail_mean": "",
    }

with open(final_summary, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(summary.keys()))
    w.writeheader()
    w.writerow(summary)

print("=== Top selection ===")
print(f"valid_trials={len(valid)} selected={len(selected)}")
for i, r in enumerate(selected, 1):
    print(
        f"rank={i} trial_id={r.get('trial_id')} throughput={r.get('throughputTps')} "
        f"ratio={r.get('throughputSendRatio')} avgLatency={r.get('avgLatencySec')} "
        f"maxLatency={r.get('maxLatencySec')}"
    )
print(f"PERF_TOP={perf_top}")
print(f"FINAL_SUMMARY={final_summary}")
PY_TOP
}

for RUN_NO in $(seq 1 "$RUNS"); do
  TRIAL_ID="$(date +%Y%m%d-%H%M%S)"
  TRIAL_STARTED_AT="$(date -Is)"

  RUN_TAG="${POOL_PREFIX_BASE}$(date +%m%d%H%M%S)"
  POOL_PREFIX="$RUN_TAG"
  POOL_MANIFEST="${OUT_DIR}/pool-${TRIAL_ID}.jsonl"

  NETWORK_LOG="${OUT_DIR}/network-reset-${TRIAL_ID}.log"
  PRESEED_YAML="benchmarks/${SAFE_NAME}-preseed-${TRIAL_ID}.yaml"
  MEASURE_YAML="benchmarks/${SAFE_NAME}-measure-${TRIAL_ID}.yaml"

  PRESEED_LOG="${OUT_DIR}/preseed-${TRIAL_ID}.log"
  MEASURE_LOG="${OUT_DIR}/measure-${TRIAL_ID}.log"

  echo
  echo "=================================================="
  echo "Trial ${RUN_NO}/${RUNS}: ${TRIAL_ID}"
  echo "=================================================="

  reset_network_and_deploy "$TRIAL_ID" "$NETWORK_LOG"

  cat > "$PRESEED_YAML" <<YAML
test:
  name: blockforensic-d-${SAFE_NAME}-preseed-${TRIAL_ID}
  workers:
    type: local
    number: ${PRESEED_WORKERS}
  rounds:
    - label: preseed_${OPERATION}_${TRIAL_ID}
      txNumber: ${PRESEED_TX_NUMBER}
      rateControl:
        type: fixed-rate
        opts:
          tps: ${PRESEED_TPS}
      workload:
        module: ${PRESEED_WORKLOAD_MODULE}
        arguments:
          contractId: ${CONTRACT_ID}
          datasetProfileId: ${DATASET_PROFILE_ID}
          poolPrefix: ${POOL_PREFIX}
          runTag: ${RUN_TAG}
          poolManifest: ${POOL_MANIFEST}
          measureWorkers: ${WORKERS}

report:
  options:
    formats:
      - html
      - json
YAML

  cat > "$MEASURE_YAML" <<YAML
test:
  name: blockforensic-d-${SAFE_NAME}-measure-${TRIAL_ID}
  workers:
    type: local
    number: ${WORKERS}
  rounds:
    - label: ${OPERATION}_w${WORKERS}_d${DUR}_tps${TPS}_${TRIAL_ID}
      txDuration: ${DUR}
      rateControl:
        type: fixed-rate
        opts:
          tps: ${TPS}
      workload:
        module: ${MEASURE_WORKLOAD_MODULE}
        arguments:
          contractId: ${CONTRACT_ID}
          datasetProfileId: ${DATASET_PROFILE_ID}
          poolManifest: ${POOL_MANIFEST}
          readOnly: ${MEASURE_READONLY}

report:
  options:
    formats:
      - html
      - json

monitors:
  resource:
    - module: docker
      options:
        interval: ${CALIPER_RESOURCE_INTERVAL}
        containers: ['all']
YAML

  echo "DEBUG_PRESEED_YAML=$PRESEED_YAML"
  echo "DEBUG_PRESEED_TX_NUMBER=$PRESEED_TX_NUMBER"
  grep -n "txNumber" "$PRESEED_YAML" || true

  echo "Preseed"
  set +e
  CALIPER_RUN_TAG="${RUN_TAG}-preseed-${TRIAL_ID}" ./scripts/run-caliper-sweep.sh "$PRESEED_YAML" 2>&1 | tee "$PRESEED_LOG"
  PRESEED_RC="${PIPESTATUS[0]}"
  set -e

  cp -a "$PRESEED_YAML" "${OUT_DIR}/preseed-${TRIAL_ID}-benchmark.yaml"
  cp -a "$PRESEED_LOG" "${OUT_DIR}/preseed-${TRIAL_ID}-wrapper.log"

  if [ "$PRESEED_RC" -ne 0 ]; then
    echo "PRESEED_FAILED rc=${PRESEED_RC}"
    exit 1
  fi

  validate_preseed_manifest "$POOL_MANIFEST" "$POOL_TOTAL_ITEMS" "$WORKERS" "$PER_WORKER_TX"

  echo "Wait ${PRESEED_MEASURE_GAP_SEC}s"
  sleep "$PRESEED_MEASURE_GAP_SEC"

  echo "Measure"
  set +e
  CALIPER_RUN_TAG="${RUN_TAG}-measure-${TRIAL_ID}" ./scripts/run-caliper-sweep.sh "$MEASURE_YAML" 2>&1 | tee "$MEASURE_LOG"
  MEASURE_RC="${PIPESTATUS[0]}"
  set -e

  cp -a "$MEASURE_YAML" "${OUT_DIR}/measure-${TRIAL_ID}-benchmark.yaml"
  cp -a "$MEASURE_LOG" "${OUT_DIR}/measure-${TRIAL_ID}-wrapper.log"

  REPORT_HTML="$(copy_report_if_exists "$TRIAL_ID")"

  echo "${RUN_ID},${TRIAL_ID},${TRIAL_STARTED_AT},${NETWORK_LOG},${POOL_MANIFEST},${PRESEED_YAML},${PRESEED_LOG},${PRESEED_RC},${MEASURE_YAML},${MEASURE_LOG},${MEASURE_RC},${REPORT_HTML}" >> "$RUN_INDEX"

  parse_measure_log "$MEASURE_LOG" "$REPORT_HTML" "$MEASURE_YAML" "$TRIAL_ID" "$TRIAL_STARTED_AT" "$MEASURE_RC"

  if [ "$RUN_NO" -lt "$RUNS" ]; then
    echo "Cooldown ${COOLDOWN_SEC}s"
    sleep "$COOLDOWN_SEC"
  fi
done

select_top_and_summary

echo
echo "DONE"
echo "OUT_DIR=$OUT_DIR"
echo "PERF_ALL=$PERF_ALL"
echo "PERF_TOP=$PERF_TOP"
echo "FINAL_SUMMARY=$FINAL_SUMMARY"
echo "RUN_INDEX=$RUN_INDEX"
