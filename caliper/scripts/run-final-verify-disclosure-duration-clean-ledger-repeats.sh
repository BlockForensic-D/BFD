#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

OPERATION="verifyDisclosure"
WORKLOAD_MODULE="workloads/40-verify-disclosure-inline-seeded.js"

TEST_NETWORK_DIR="${TEST_NETWORK_DIR:-/home/labnuc/2labforensic/fabric-samples/test-network}"
CHANNEL_NAME="${CHANNEL_NAME:-forensic-channel}"

CC_NAME="${CC_NAME:-forensicContract}"
CC_PATH="${CC_PATH:-../forensic/chaincode-javascript}"
CC_LANG="${CC_LANG:-javascript}"

WORKERS="${WORKERS:-4}"
TPS="${TPS:-1}"
DUR="${DUR:-20}"
RUNS="${RUNS:-${REPEATS:-6}}"
SELECT_TOP="${SELECT_TOP:-3}"

CONTRACT_ID="${CONTRACT_ID:-forensicContract}"
DATASET_PROFILE_ID="${DATASET_PROFILE_ID:-edge_vulnscan_1mib_v3}"

POOL_MARGIN="${POOL_MARGIN:-5}"
NETWORK_SETTLE_SEC="${NETWORK_SETTLE_SEC:-20}"
DEPLOY_SETTLE_SEC="${DEPLOY_SETTLE_SEC:-20}"
COOLDOWN_SEC="${COOLDOWN_SEC:-180}"
CALIPER_RESOURCE_INTERVAL="${CALIPER_RESOURCE_INTERVAL:-2}"
MIN_RATIO="${MIN_RATIO:-0.90}"
READ_ONLY="${READ_ONLY:-false}"

TARGET_TX=$(( TPS * DUR ))
PER_WORKER_TX=$(( (TARGET_TX + WORKERS - 1) / WORKERS ))
SEED_COUNT=$(( PER_WORKER_TX + POOL_MARGIN ))

OUT_ROOT="results/final-verify-disclosure-duration-clean-ledger"
RUN_ID="${RUN_ID:-final-verify-disclosure-duration-clean-ledger-w${WORKERS}-t${TPS}-d${DUR}-$(date +%Y%m%d-%H%M%S)}"
OUT_DIR="${OUT_ROOT}/${RUN_ID}"

mkdir -p "$OUT_DIR" benchmarks

PERF_ALL="${OUT_DIR}/performance_metrics_all.csv"
PERF_TOP="${OUT_DIR}/performance_metrics_top${SELECT_TOP}.csv"
FINAL_SUMMARY="${OUT_DIR}/final_top${SELECT_TOP}_summary.csv"
RUN_INDEX="${OUT_DIR}/run_index.csv"

cat > "$PERF_ALL" <<CSV
run_id,trial_id,trial_started_at,operation,workers,target_tps,target_type,target_value,target_tx_approx,seed_count_per_worker,label,succ,fail,sendRateTps,throughputTps,throughputSendRatio,avgLatencySec,minLatencySec,maxLatencySec,returnCode,decision,source,report_html,benchmark_yaml,measure_log
CSV

printf 'run_id,trial_id,trial_started_at,network_log,measure_yaml,measure_log,measure_rc,report_html\n' > "$RUN_INDEX"

echo "OPERATION=$OPERATION"
echo "WORKERS=$WORKERS TPS=$TPS DUR=$DUR RUNS=$RUNS SELECT_TOP=$SELECT_TOP"
echo "TARGET_TX=$TARGET_TX PER_WORKER_TX=$PER_WORKER_TX POOL_MARGIN=$POOL_MARGIN"
echo "SEED_COUNT_PER_WORKER=$SEED_COUNT"
echo "READ_ONLY=$READ_ONLY"
echo "OUT_DIR=$OUT_DIR"

reset_network_and_deploy() {
  local trial_id="$1"
  local network_log="$2"

  {
    echo "=== Network reset for ${trial_id} ==="
    date -Is

    cd "$TEST_NETWORK_DIR"

    echo "[1/6] network down"
    ./network.sh down || true

    echo "[2/6] cleanup docker"
    docker ps -aq --filter "status=created" | xargs -r docker rm || true
    docker image prune -f || true
    docker builder prune -f || true

    echo "[3/6] network up createChannel BFT"
    ./network.sh up createChannel -bft -c "$CHANNEL_NAME"

    echo "Waiting ${NETWORK_SETTLE_SEC}s"
    sleep "$NETWORK_SETTLE_SEC"

    echo "[4/6] deploy chaincode"
    ./network.sh deployCC \
      -ccn "$CC_NAME" \
      -ccp "$CC_PATH" \
      -ccl "$CC_LANG" \
      -c "$CHANNEL_NAME"

    echo "Waiting ${DEPLOY_SETTLE_SEC}s"
    sleep "$DEPLOY_SETTLE_SEC"

    echo "[5/6] fix Caliper identity paths"
    if [ -x ./fix-caliper-identity-paths-v2.sh ]; then
      ./fix-caliper-identity-paths-v2.sh
    fi

    echo "[6/6] verify channel and chaincode"
    source scripts/envVar.sh

    for ORG in 1 2 3; do
      setGlobals "$ORG"
      peer channel getinfo -c "$CHANNEL_NAME"
    done

    setGlobals 1
    peer lifecycle chaincode querycommitted -C "$CHANNEL_NAME" -n "$CC_NAME" || true

    echo "=== Network ready ==="
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

parse_measure_log() {
  local measure_log="$1"
  local report_html="$2"
  local measure_yaml="$3"
  local trial_id="$4"
  local trial_started_at="$5"
  local measure_rc="$6"

  python3 - "$measure_log" "$PERF_ALL" "$RUN_ID" "$trial_id" "$trial_started_at" "$OPERATION" "$WORKERS" "$TPS" "$DUR" "$SEED_COUNT" "$measure_rc" "$MIN_RATIO" "$report_html" "$measure_yaml" <<'PY_PARSE'
import csv
import sys

measure_log = sys.argv[1]
perf_csv = sys.argv[2]
run_id = sys.argv[3]
trial_id = sys.argv[4]
trial_started_at = sys.argv[5]
operation = sys.argv[6]
workers = sys.argv[7]
target_tps = sys.argv[8]
dur = sys.argv[9]
seed_count = sys.argv[10]
measure_rc = sys.argv[11]
min_ratio = float(sys.argv[12])
report_html = sys.argv[13]
measure_yaml = sys.argv[14]

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

        ratio = None
        if send and send > 0 and thr is not None:
            ratio = thr / send

        decision = "INVALID"
        if (
            str(measure_rc) == "0"
            and succ is not None
            and succ > 0
            and fail == 0
            and ratio is not None
            and ratio >= min_ratio
        ):
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
            "seed_count_per_worker": seed_count,
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

# DEDUP_BY_LABEL_TRIAL
dedup = {}
for row in rows:
    dedup[(row.get("trial_id"), row.get("label"))] = row
rows = list(dedup.values())

fields = [
    "run_id",
    "trial_id",
    "trial_started_at",
    "operation",
    "workers",
    "target_tps",
    "target_type",
    "target_value",
    "target_tx_approx",
    "seed_count_per_worker",
    "label",
    "succ",
    "fail",
    "sendRateTps",
    "throughputTps",
    "throughputSendRatio",
    "avgLatencySec",
    "minLatencySec",
    "maxLatencySec",
    "returnCode",
    "decision",
    "source",
    "report_html",
    "benchmark_yaml",
    "measure_log",
]

with open(perf_csv, "a", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    for row in rows:
        writer.writerow(row)

print(f"performance_rows={len(rows)}")
for row in rows:
    print(
        f"{row['label']}: "
        f"succ={row['succ']} fail={row['fail']} "
        f"send={row['sendRateTps']} throughput={row['throughputTps']} "
        f"ratio={row['throughputSendRatio']} "
        f"avg={row['avgLatencySec']} max={row['maxLatencySec']} "
        f"decision={row['decision']}"
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

perf_all = sys.argv[1]
perf_top = sys.argv[2]
final_summary = sys.argv[3]
select_top = int(sys.argv[4])

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

valid = []
for r in rows:
    if r.get("decision") != "VALID":
        continue
    if num(r.get("avgLatencySec")) is None:
        continue
    if num(r.get("throughputTps")) is None:
        continue
    valid.append(r)

valid.sort(
    key=lambda r: (
        num(r.get("avgLatencySec")) or 999999,
        num(r.get("maxLatencySec")) or 999999,
        -(num(r.get("throughputSendRatio")) or -1),
        -(num(r.get("throughputTps")) or -1),
    )
)

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
        f"rank={i} trial_id={r.get('trial_id')} "
        f"throughput={r.get('throughputTps')} "
        f"ratio={r.get('throughputSendRatio')} "
        f"avgLatency={r.get('avgLatencySec')} "
        f"maxLatency={r.get('maxLatencySec')}"
    )

print(f"PERF_TOP={perf_top}")
print(f"FINAL_SUMMARY={final_summary}")
PY_TOP
}

for RUN_NO in $(seq 1 "$RUNS"); do
  TRIAL_ID="$(date +%Y%m%d-%H%M%S)"
  TRIAL_STARTED_AT="$(date -Is)"
  RUN_TAG="vdis$(date +%m%d%H%M%S)"

  NETWORK_LOG="${OUT_DIR}/network-reset-${TRIAL_ID}.log"
  MEASURE_YAML="benchmarks/verify-disclosure-measure-${TRIAL_ID}.yaml"
  MEASURE_LOG="${OUT_DIR}/measure-${TRIAL_ID}.log"

  echo
  echo "=================================================="
  echo "Trial ${RUN_NO}/${RUNS}: ${TRIAL_ID}"
  echo "=================================================="

  reset_network_and_deploy "$TRIAL_ID" "$NETWORK_LOG"

  cat > "$MEASURE_YAML" <<YAML
test:
  name: blockforensic-d-verify-disclosure-measure-${TRIAL_ID}
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
        module: ${WORKLOAD_MODULE}
        arguments:
          contractId: ${CONTRACT_ID}
          datasetProfileId: ${DATASET_PROFILE_ID}
          poolPrefix: ${RUN_TAG}
          seedCount: ${SEED_COUNT}
          readOnly: ${READ_ONLY}

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

  echo "MEASURE_YAML=$MEASURE_YAML"
  echo "SEED_COUNT_PER_WORKER=$SEED_COUNT"
  grep -nE "txDuration|seedCount|module" "$MEASURE_YAML" || true

  echo "Measure"
  set +e
  CALIPER_RUN_TAG="${RUN_TAG}-measure-${TRIAL_ID}" ./scripts/run-caliper-sweep.sh "$MEASURE_YAML" 2>&1 | tee "$MEASURE_LOG"
  MEASURE_RC="${PIPESTATUS[0]}"
  set -e

  cp -a "$MEASURE_YAML" "${OUT_DIR}/measure-${TRIAL_ID}-benchmark.yaml"
  cp -a "$MEASURE_LOG" "${OUT_DIR}/measure-${TRIAL_ID}-wrapper.log"

  REPORT_HTML="$(copy_report_if_exists "$TRIAL_ID")"

  echo "${RUN_ID},${TRIAL_ID},${TRIAL_STARTED_AT},${NETWORK_LOG},${MEASURE_YAML},${MEASURE_LOG},${MEASURE_RC},${REPORT_HTML}" >> "$RUN_INDEX"

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
