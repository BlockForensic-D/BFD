#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

OPERATION="${OPERATION:-issueDisclosureCapability}"
PRESEED_WORKLOAD_MODULE="${PRESEED_WORKLOAD_MODULE:-workloads/22-preseed-committed-pool.js}"
MEASURE_WORKLOAD_MODULE="${MEASURE_WORKLOAD_MODULE:-workloads/23-issue-from-committed-pool.js}"

WORKERS="${WORKERS:-4}"
TPS="${TPS:-60}"
DUR="${DUR:-60}"
RUNS="${RUNS:-${REPEATS:-6}}"
SELECT_TOP="${SELECT_TOP:-3}"

CONTRACT_ID="${CONTRACT_ID:-forensicContract}"
CHANNEL_NAME="${CHANNEL_NAME:-forensic-channel}"
DATASET_PROFILE_ID="${DATASET_PROFILE_ID:-edge_vulnscan_1mib_v3}"
SCOPE_PROFILE="${SCOPE_PROFILE:-HASH_ONLY}"

PRESEED_TPS="${PRESEED_TPS:-10}"
CALIPER_RESOURCE_INTERVAL="${CALIPER_RESOURCE_INTERVAL:-2}"
PRESEED_MEASURE_GAP_SEC="${PRESEED_MEASURE_GAP_SEC:-60}"
COOLDOWN_SEC="${COOLDOWN_SEC:-120}"
NETWORK_SETTLE_SEC="${NETWORK_SETTLE_SEC:-20}"
CLEAN_DOCKER="${CLEAN_DOCKER:-true}"

TARGET_TX=$(( TPS * DUR ))
TOKEN_MARGIN="${TOKEN_MARGIN:-1200}"

ITEM_COUNT="${ITEM_COUNT:-$(( TARGET_TX + TOKEN_MARGIN ))}"
TOTAL_CAPACITY=$(( ITEM_COUNT * WORKERS ))

PRESEED_ITEM_COUNT="${PRESEED_ITEM_COUNT:-$ITEM_COUNT}"
PRESEED_TX_NUMBER="${PRESEED_TX_NUMBER:-$TOTAL_CAPACITY}"

TEST_NETWORK_DIR="${TEST_NETWORK_DIR:-$(cd .. && pwd)}"

OUT_ROOT="${OUT_ROOT:-results/final-issue-duration-clean-ledger}"
RUN_ID="${RUN_ID:-final-issue-duration-clean-ledger-${SCOPE_PROFILE}-w${WORKERS}-t${TPS}-d${DUR}-$(date +%Y%m%d-%H%M%S)}"
OUT_DIR="${OUT_ROOT}/${RUN_ID}"

mkdir -p "$OUT_DIR" benchmarks

PERF_ALL="${OUT_DIR}/performance_metrics_all.csv"
PERF_TOP3="${OUT_DIR}/performance_metrics_top3.csv"
RESOURCE_SUMMARY="${OUT_DIR}/resource_utilization_summary.csv"
RESOURCE_TOP3="${OUT_DIR}/resource_utilization_top3_summary.csv"
PERF_STATS="${OUT_DIR}/performance_top3_statistics.csv"
RESOURCE_STATS="${OUT_DIR}/resource_top3_statistics.csv"
FINAL_SUMMARY="${OUT_DIR}/final_top3_summary.csv"
RUN_INDEX="${OUT_DIR}/run_index.csv"

echo "run_id,trial_id,trial_started_at,network_reset_started_at,network_reset_finished_at,preseed_yaml,preseed_result_dir,preseed_log,preseed_return_code,benchmark_yaml,caliper_result_dir,wrapper_log,return_code,report_html" > "$RUN_INDEX"

echo "OPERATION=$OPERATION"
echo "SCOPE_PROFILE=$SCOPE_PROFILE"
echo "WORKERS=$WORKERS TPS=$TPS DUR=$DUR RUNS=$RUNS SELECT_TOP=$SELECT_TOP"
echo "TARGET_TX=$TARGET_TX TOKEN_MARGIN=$TOKEN_MARGIN"
echo "ITEM_COUNT=$ITEM_COUNT TOTAL_CAPACITY=$TOTAL_CAPACITY"
echo "PRESEED_ITEM_COUNT=$PRESEED_ITEM_COUNT PRESEED_TX_NUMBER=$PRESEED_TX_NUMBER PRESEED_TPS=$PRESEED_TPS"
echo "TEST_NETWORK_DIR=$TEST_NETWORK_DIR"
echo "OUT_DIR=$OUT_DIR"

reset_network() {
  local trial_id="$1"
  local log_file="${OUT_DIR}/network-reset-${trial_id}.log"

  echo "Network reset for ${trial_id}"

  (
    cd "$TEST_NETWORK_DIR"

    echo "[$(date -Is)] network down"
    ./network.sh down

    if [ "$CLEAN_DOCKER" = "true" ]; then
      echo "[$(date -Is)] remove orphan created containers"
      docker ps -aq --filter "status=created" | xargs -r docker rm

      echo "[$(date -Is)] prune dangling images"
      docker image prune -f

      echo "[$(date -Is)] prune docker builder cache"
      docker builder prune -f
    fi

    echo "[$(date -Is)] network up createChannel -bft -c forensic-channel"
    ./network.sh up createChannel -bft -c forensic-channel

    echo "[$(date -Is)] deploy chaincode forensicContract"
    ./network.sh deployCC \
      -ccn forensicContract \
      -ccp ../forensic/chaincode-javascript \
      -ccl javascript \
      -c forensic-channel

    echo "[$(date -Is)] fix caliper identity paths"
    ./fix-caliper-identity-paths-v2.sh

    echo "[$(date -Is)] wait network settle ${NETWORK_SETTLE_SEC}s"
    sleep "$NETWORK_SETTLE_SEC"
  ) 2>&1 | tee "$log_file"
}

copy_artifacts_flat() {
  local prefix="$1"
  local latest="$2"
  local yaml_file="$3"
  local wrapper_log="$4"

  if [ -z "$latest" ] || [ ! -d "$latest" ]; then
    echo "No Caliper result directory for ${prefix}"
    return 0
  fi

  find "$latest" -maxdepth 1 -type f | while read -r src; do
    base="$(basename "$src")"
    cp -a "$src" "${OUT_DIR}/${prefix}-${base}"
  done

  [ -f "$yaml_file" ] && cp -a "$yaml_file" "${OUT_DIR}/${prefix}-benchmark.yaml"
  [ -f "$wrapper_log" ] && cp -a "$wrapper_log" "${OUT_DIR}/${prefix}-wrapper.log"

  mapfile -t subdirs < <(find "$latest" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null || true)

  if [ "${#subdirs[@]}" -gt 0 ]; then
    (
      cd "$latest"
      tar -czf "${OUT_DIR}/${prefix}-extra-artifacts.tar.gz" "${subdirs[@]}"
    )
  fi
}

find_report_html() {
  local prefix="$1"
  local latest="$2"
  local candidate=""

  candidate="$(find "$OUT_DIR" -maxdepth 1 -type f -name "${prefix}-*.html" | head -n 1 || true)"
  if [ -n "$candidate" ] && [ -f "$candidate" ]; then
    echo "$candidate"
    return 0
  fi

  if [ -n "$latest" ] && [ -d "$latest" ]; then
    candidate="$(find "$latest" -maxdepth 1 -type f -name "*.html" | head -n 1 || true)"
    if [ -n "$candidate" ] && [ -f "$candidate" ]; then
      echo "$candidate"
      return 0
    fi
  fi

  echo ""
}

extract_caliper_report_to_csv() {
  local report_html="$1"
  local trial_id="$2"
  local trial_started_at="$3"
  local result_dir="$4"
  local yaml_file="$5"
  local rc="$6"

  if [ -z "$report_html" ] || [ ! -f "$report_html" ]; then
    echo "WARNING: report.html not found for trial ${trial_id}"
    return 0
  fi

  python3 - "$report_html" "$PERF_ALL" "$RESOURCE_SUMMARY" "$RUN_ID" "$trial_id" "$trial_started_at" "$OPERATION" "$WORKERS" "$TPS" "txDuration" "$DUR" "$ITEM_COUNT" "$TOTAL_CAPACITY" "$result_dir" "$yaml_file" "$rc" "$SCOPE_PROFILE" <<'PY'
import csv
import html
import os
import re
import sys
from html.parser import HTMLParser

report_html, perf_csv, resource_csv, run_id, trial_id, trial_started_at, operation, workers, target_tps, target_type, target_value, item_count, total_capacity, result_dir, yaml_file, rc, scope_profile = sys.argv[1:18]

class TableParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.tables = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == "table":
            self.stack.append({"rows": [], "row": None, "cell": None})
        elif tag == "tr" and self.stack:
            self.stack[-1]["row"] = []
        elif tag in ("td", "th") and self.stack:
            self.stack[-1]["cell"] = []

    def handle_data(self, data):
        if self.stack and self.stack[-1]["cell"] is not None:
            self.stack[-1]["cell"].append(data)

    def handle_entityref(self, name):
        if self.stack and self.stack[-1]["cell"] is not None:
            self.stack[-1]["cell"].append(html.unescape(f"&{name};"))

    def handle_charref(self, name):
        if self.stack and self.stack[-1]["cell"] is not None:
            self.stack[-1]["cell"].append(html.unescape(f"&#{name};"))

    def handle_endtag(self, tag):
        tag = tag.lower()
        if not self.stack:
            return

        top = self.stack[-1]

        if tag in ("td", "th") and top["cell"] is not None:
            text = html.unescape("".join(top["cell"])).strip()
            text = re.sub(r"\s+", " ", text)
            if top["row"] is not None:
                top["row"].append(text)
            top["cell"] = None

        elif tag == "tr":
            if top["row"]:
                top["rows"].append(top["row"])
            top["row"] = None

        elif tag == "table":
            finished = self.stack.pop()
            if finished["rows"]:
                self.tables.append(finished["rows"])

def nh(x):
    return re.sub(r"[^a-z0-9]+", "_", str(x).strip().lower()).strip("_")

def dict_rows(table):
    if len(table) < 2:
        return []
    header = [nh(x) for x in table[0]]
    out = []
    for row in table[1:]:
        row = row + [""] * max(0, len(header) - len(row))
        out.append(dict(zip(header, row[:len(header)])))
    return out

def to_float(x):
    try:
        return float(str(x).strip())
    except Exception:
        return ""

def to_int(x):
    try:
        return int(float(str(x).strip()))
    except Exception:
        return ""

with open(report_html, "r", encoding="utf-8", errors="ignore") as f:
    raw = f.read()

p = TableParser()
p.feed(raw)

perf = []
res = []

for table in p.tables:
    if not table:
        continue

    hs = set(nh(x) for x in table[0])

    if {"name", "succ", "fail", "send_rate_tps", "max_latency_s", "min_latency_s", "avg_latency_s", "throughput_tps"}.issubset(hs):
        perf.extend(dict_rows(table))

    if "name" in hs and "cpu_max" in hs and "cpu_avg" in hs and "memory_max_mb" in hs and "memory_avg_mb" in hs:
        res.extend(dict_rows(table))

filtered = []
for r in perf:
    name = r.get("name", "").lower()
    if "issuedisclosurecapability" in name or "issue_disclosure" in name or "issue" in name or "capability" in name:
        filtered.append(r)

if filtered:
    perf = filtered

seen = set()
dedup = []

for r in perf:
    key = (r.get("name", ""), r.get("succ", ""), r.get("fail", ""), r.get("send_rate_tps", ""), r.get("throughput_tps", ""))
    if key not in seen:
        seen.add(key)
        dedup.append(r)

perf = dedup

perf_fields = [
    "run_id", "trial_id", "trial_started_at", "operation", "scopeProfile", "workers", "target_tps", "target_type", "target_value",
    "actual_tx", "item_count_per_worker", "total_capacity", "label", "succ", "fail",
    "sendRateTps", "throughputTps", "throughputSendRatio", "avgLatencySec",
    "minLatencySec", "maxLatencySec", "returnCode", "decision", "source",
    "report_html", "result_dir", "benchmark_yaml"
]

need_header = not os.path.exists(perf_csv) or os.path.getsize(perf_csv) == 0

with open(perf_csv, "a", newline="") as f:
    w = csv.DictWriter(f, fieldnames=perf_fields)
    if need_header:
        w.writeheader()

    for r in perf:
        succ = to_int(r.get("succ", ""))
        fail = to_int(r.get("fail", ""))
        send = to_float(r.get("send_rate_tps", ""))
        thr = to_float(r.get("throughput_tps", ""))
        max_lat = to_float(r.get("max_latency_s", ""))
        min_lat = to_float(r.get("min_latency_s", ""))
        avg_lat = to_float(r.get("avg_latency_s", ""))

        actual_tx = ""
        if isinstance(succ, int) and isinstance(fail, int):
            actual_tx = succ + fail

        ratio = ""
        if isinstance(send, float) and send > 0 and isinstance(thr, float):
            ratio = thr / send

        valid = (
            str(rc) == "0"
            and fail == 0
            and isinstance(succ, int)
            and succ > 0
            and isinstance(ratio, float)
            and ratio >= 0.90
        )

        w.writerow({
            "run_id": run_id,
            "trial_id": trial_id,
            "trial_started_at": trial_started_at,
            "operation": operation,
            "scopeProfile": scope_profile,
            "workers": workers,
            "target_tps": target_tps,
            "target_type": target_type,
            "target_value": target_value,
            "actual_tx": actual_tx,
            "item_count_per_worker": item_count,
            "total_capacity": total_capacity,
            "label": r.get("name", ""),
            "succ": succ,
            "fail": fail,
            "sendRateTps": send,
            "throughputTps": thr,
            "throughputSendRatio": ratio,
            "avgLatencySec": avg_lat,
            "minLatencySec": min_lat,
            "maxLatencySec": max_lat,
            "returnCode": rc,
            "decision": "VALID" if valid else "INVALID",
            "source": "caliper_report_html",
            "report_html": report_html,
            "result_dir": result_dir,
            "benchmark_yaml": yaml_file,
        })

res_fields = [
    "run_id", "trial_id", "trial_started_at", "operation", "scopeProfile", "workers", "target_tps", "target_type", "target_value",
    "label", "container_name", "cpu_max_percent", "cpu_avg_percent", "memory_max_mb",
    "memory_avg_mb", "traffic_in_mb", "traffic_out_mb", "disc_write_mb", "disc_read_b",
    "source", "report_html", "result_dir", "benchmark_yaml"
]

need_header = not os.path.exists(resource_csv) or os.path.getsize(resource_csv) == 0

with open(resource_csv, "a", newline="") as f:
    w = csv.DictWriter(f, fieldnames=res_fields)
    if need_header:
        w.writeheader()

    label = perf[0].get("name", "") if perf else ""

    for r in res:
        w.writerow({
            "run_id": run_id,
            "trial_id": trial_id,
            "trial_started_at": trial_started_at,
            "operation": operation,
            "scopeProfile": scope_profile,
            "workers": workers,
            "target_tps": target_tps,
            "target_type": target_type,
            "target_value": target_value,
            "label": label,
            "container_name": r.get("name", ""),
            "cpu_max_percent": to_float(r.get("cpu_max", "")),
            "cpu_avg_percent": to_float(r.get("cpu_avg", "")),
            "memory_max_mb": to_float(r.get("memory_max_mb", "")),
            "memory_avg_mb": to_float(r.get("memory_avg_mb", "")),
            "traffic_in_mb": to_float(r.get("traffic_in_mb", "")),
            "traffic_out_mb": to_float(r.get("traffic_out_mb", "")),
            "disc_write_mb": to_float(r.get("disc_write_mb", "")),
            "disc_read_b": to_float(r.get("disc_read_b", "")),
            "source": "caliper_report_html",
            "report_html": report_html,
            "result_dir": result_dir,
            "benchmark_yaml": yaml_file,
        })

print(f"Extracted: {report_html}")
print(f"performance_rows={len(perf)} resource_rows={len(res)}")
PY
}

select_top_runs() {
  python3 - "$PERF_ALL" "$PERF_TOP3" "$RESOURCE_SUMMARY" "$RESOURCE_TOP3" "$SELECT_TOP" <<'PY'
import csv
import os
import statistics
import sys

perf_all, perf_top, res_all, res_top, select_top = sys.argv[1:6]
select_top = int(select_top)

def fnum(x, default=None):
    try:
        return float(x)
    except Exception:
        return default

def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

rows = read_csv(perf_all)
valid = []

for r in rows:
    if r.get("decision") != "VALID":
        continue
    if fnum(r.get("avgLatencySec")) is None:
        continue
    if fnum(r.get("maxLatencySec")) is None:
        continue
    if fnum(r.get("throughputTps")) is None:
        continue
    if fnum(r.get("throughputSendRatio")) is None:
        continue
    valid.append(r)

pool = valid

if len(valid) >= 4:
    lats = sorted(fnum(r.get("avgLatencySec")) for r in valid)
    q1 = statistics.median(lats[:len(lats)//2])
    q3 = statistics.median(lats[(len(lats)+1)//2:])
    iqr = q3 - q1
    upper = q3 + 1.5 * iqr
    filtered = [r for r in valid if fnum(r.get("avgLatencySec")) <= upper]
    if len(filtered) >= select_top:
        pool = filtered

pool.sort(
    key=lambda r: (
        fnum(r.get("avgLatencySec"), 999999),
        fnum(r.get("maxLatencySec"), 999999),
        -fnum(r.get("throughputSendRatio"), -1),
        -fnum(r.get("throughputTps"), -1),
    )
)

selected = pool[:select_top]
selected_trials = {r.get("trial_id") for r in selected}

if rows:
    with open(perf_top, "w", newline="") as f:
        fields = list(rows[0].keys()) + ["selectionRank", "selectionNote"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for rank, r in enumerate(selected, 1):
            rr = dict(r)
            rr["selectionRank"] = rank
            rr["selectionNote"] = "selected_lowest_avg_latency_from_clean_ledger_trial"
            w.writerow(rr)

res_rows = read_csv(res_all)

if res_rows:
    with open(res_top, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=res_rows[0].keys())
        w.writeheader()
        for r in res_rows:
            if r.get("trial_id") in selected_trials:
                w.writerow(r)

print("=== Top selection: clean ledger trials, lowest avg latency ===")
print(f"valid_trials={len(valid)} selected={len(selected)}")

for rank, r in enumerate(selected, 1):
    print(
        f"rank={rank} trial_id={r.get('trial_id')} "
        f"avgLatency={r.get('avgLatencySec')} "
        f"maxLatency={r.get('maxLatencySec')} "
        f"throughput={r.get('throughputTps')} "
        f"ratio={r.get('throughputSendRatio')}"
    )
PY
}

compute_top3_statistics() {
  python3 - "$PERF_TOP3" "$RESOURCE_TOP3" "$PERF_STATS" "$RESOURCE_STATS" "$FINAL_SUMMARY" "$RUN_ID" "$OPERATION" "$SCOPE_PROFILE" "$WORKERS" "$TPS" "txDuration" "$DUR" <<'PY'
import csv
import math
import os
import statistics
import sys

perf_top, resource_top, perf_stats, resource_stats, final_summary, run_id, operation, scope_profile, workers, target_tps, target_type, target_value = sys.argv[1:13]

def read_csv(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

def num(x):
    try:
        if x in ("", None):
            return None
        return float(x)
    except Exception:
        return None

def stats(values):
    values = [v for v in values if v is not None and math.isfinite(v)]
    n = len(values)
    if n == 0:
        return {
            "n": 0, "mean": "", "median": "", "min": "", "max": "", "range": "",
            "stddev_sample": "", "stddev_population": "", "sem": "", "cv_percent": ""
        }

    mean = statistics.mean(values)
    median = statistics.median(values)
    mn = min(values)
    mx = max(values)
    rng = mx - mn
    std_s = statistics.stdev(values) if n > 1 else 0.0
    std_p = statistics.pstdev(values) if n > 1 else 0.0
    sem = std_s / math.sqrt(n) if n > 1 else 0.0
    cv = (std_s / mean * 100.0) if mean != 0 else ""

    return {
        "n": n,
        "mean": mean,
        "median": median,
        "min": mn,
        "max": mx,
        "range": rng,
        "stddev_sample": std_s,
        "stddev_population": std_p,
        "sem": sem,
        "cv_percent": cv,
    }

def write_stats(path, rows, metric_map, group_fields=None):
    group_fields = group_fields or []
    out = []

    if group_fields:
        groups = {}
        for r in rows:
            key = tuple(r.get(g, "") for g in group_fields)
            groups.setdefault(key, []).append(r)
    else:
        groups = {tuple(): rows}

    for key, group_rows in groups.items():
        for metric_name, column in metric_map.items():
            s = stats([num(r.get(column)) for r in group_rows])
            row = {g: key[i] for i, g in enumerate(group_fields)}
            row.update({
                "metric": metric_name,
                "source_column": column,
                **s
            })
            out.append(row)

    if out:
        fields = list(out[0].keys())
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(out)

perf_rows = read_csv(perf_top)
res_rows = read_csv(resource_top)

perf_metric_map = {
    "send_rate_tps": "sendRateTps",
    "throughput_tps": "throughputTps",
    "throughput_send_ratio": "throughputSendRatio",
    "avg_latency_sec": "avgLatencySec",
    "min_latency_sec": "minLatencySec",
    "max_latency_sec": "maxLatencySec",
    "actual_tx": "actual_tx",
    "succ": "succ",
    "fail": "fail",
}

write_stats(perf_stats, perf_rows, perf_metric_map)

resource_metric_map = {
    "cpu_max_percent": "cpu_max_percent",
    "cpu_avg_percent": "cpu_avg_percent",
    "memory_max_mb": "memory_max_mb",
    "memory_avg_mb": "memory_avg_mb",
    "traffic_in_mb": "traffic_in_mb",
    "traffic_out_mb": "traffic_out_mb",
    "disc_write_mb": "disc_write_mb",
    "disc_read_b": "disc_read_b",
}

if res_rows:
    write_stats(resource_stats, res_rows, resource_metric_map, ["container_name"])

def values(col):
    vals = [num(r.get(col)) for r in perf_rows]
    return [v for v in vals if v is not None and math.isfinite(v)]

def mean_col(col):
    vals = values(col)
    return statistics.mean(vals) if vals else ""

def std_col(col):
    vals = values(col)
    return statistics.stdev(vals) if len(vals) > 1 else 0.0 if len(vals) == 1 else ""

def min_col(col):
    vals = values(col)
    return min(vals) if vals else ""

def max_col(col):
    vals = values(col)
    return max(vals) if vals else ""

def cv_col(col):
    m = mean_col(col)
    s = std_col(col)
    if m in ("", 0) or s == "":
        return ""
    return s / m * 100.0

summary = {
    "run_id": run_id,
    "operation": operation,
    "scopeProfile": scope_profile,
    "workers": workers,
    "target_tps": target_tps,
    "target_type": target_type,
    "target_value": target_value,
    "selected_trials_n": len(perf_rows),
    "selected_trial_ids": ";".join(r.get("trial_id", "") for r in perf_rows),
    "avg_latency_mean_sec": mean_col("avgLatencySec"),
    "avg_latency_stddev_sec": std_col("avgLatencySec"),
    "avg_latency_min_sec": min_col("avgLatencySec"),
    "avg_latency_max_sec": max_col("avgLatencySec"),
    "avg_latency_cv_percent": cv_col("avgLatencySec"),
    "max_latency_mean_sec": mean_col("maxLatencySec"),
    "min_latency_mean_sec": mean_col("minLatencySec"),
    "throughput_mean_tps": mean_col("throughputTps"),
    "throughput_stddev_tps": std_col("throughputTps"),
    "throughput_min_tps": min_col("throughputTps"),
    "throughput_max_tps": max_col("throughputTps"),
    "throughput_cv_percent": cv_col("throughputTps"),
    "send_rate_mean_tps": mean_col("sendRateTps"),
    "throughput_send_ratio_mean": mean_col("throughputSendRatio"),
    "throughput_send_ratio_min": min_col("throughputSendRatio"),
    "throughput_send_ratio_max": max_col("throughputSendRatio"),
    "success_total_mean": mean_col("succ"),
    "fail_total_mean": mean_col("fail"),
}

with open(final_summary, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(summary.keys()))
    w.writeheader()
    w.writerow(summary)

print("=== Top 3 statistics ===")
print(f"performance_stats={perf_stats}")
print(f"resource_stats={resource_stats}")
print(f"final_summary={final_summary}")
PY
}

for RUN_NO in $(seq 1 "$RUNS"); do
  TRIAL_ID="$(date +%Y%m%d-%H%M%S)"
  TRIAL_STARTED_AT="$(date -Is)"
  PREFIX_SHORT="$(date +%m%d%H%M%S)"
  RUN_TAG="isd${PREFIX_SHORT}"
  POOL_PREFIX="isd${PREFIX_SHORT}"

  NETWORK_RESET_STARTED_AT="$(date -Is)"
  reset_network "$TRIAL_ID"
  NETWORK_RESET_FINISHED_AT="$(date -Is)"

  PRESEED_YAML="benchmarks/final-issue-duration-preseed-${TRIAL_ID}.yaml"
  PRESEED_LOG="${OUT_DIR}/preseed-${TRIAL_ID}.log"
  MEASURE_YAML="benchmarks/final-issue-duration-${TRIAL_ID}.yaml"
  WRAPPER_LOG="${OUT_DIR}/measure-${TRIAL_ID}.log"

  cat > "$PRESEED_YAML" <<YAML
test:
  name: blockforensic-d-preseed-committed-for-issue-${SCOPE_PROFILE}-${TRIAL_ID}
  description: clean-ledger preseed COMMITTED evidence pool for issueDisclosureCapability ${SCOPE_PROFILE}
  workers:
    type: local
    number: ${WORKERS}
  rounds:
    - label: preseed_committed_pool_for_issue_${SCOPE_PROFILE}_${TRIAL_ID}
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
          itemCount: ${PRESEED_ITEM_COUNT}
          txNumber: ${PRESEED_TX_NUMBER}
          scopeProfile: ${SCOPE_PROFILE}
YAML

  cat > "$MEASURE_YAML" <<YAML
test:
  name: blockforensic-d-final-issue-duration-${SCOPE_PROFILE}-${TRIAL_ID}
  description: clean-ledger issueDisclosureCapability ${SCOPE_PROFILE} duration trial ${TRIAL_ID}
  workers:
    type: local
    number: ${WORKERS}
  rounds:
    - label: issueDisclosureCapability_${SCOPE_PROFILE}_w${WORKERS}_d${DUR}_tps${TPS}_${TRIAL_ID}
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
          poolPrefix: ${POOL_PREFIX}
          runTag: ${RUN_TAG}
          itemCount: ${ITEM_COUNT}
          txNumber: ${TOTAL_CAPACITY}
          scopeProfile: ${SCOPE_PROFILE}

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

  echo "Trial ${TRIAL_ID}: preseed committed pool"
  BEFORE_PRESEED="$(ls -td results/sweeps/* 2>/dev/null | head -n 1 || true)"

  set +e
  CALIPER_RUN_TAG="${RUN_TAG}-preseed-${TRIAL_ID}" ./scripts/run-caliper-sweep.sh "$PRESEED_YAML" 2>&1 | tee "$PRESEED_LOG"
  PRESEED_RC="${PIPESTATUS[0]}"
  set -e

  AFTER_PRESEED="$(ls -td results/sweeps/* 2>/dev/null | head -n 1 || true)"
  PRESEED_LATEST="$AFTER_PRESEED"

  if [ -n "$BEFORE_PRESEED" ] && [ "$AFTER_PRESEED" = "$BEFORE_PRESEED" ] && [ "$PRESEED_RC" -ne 0 ]; then
    PRESEED_LATEST=""
  fi

  copy_artifacts_flat "preseed-${TRIAL_ID}" "$PRESEED_LATEST" "$PRESEED_YAML" "$PRESEED_LOG"

  PRESEED_FAIL_COUNT="$(
    python3 - "$PRESEED_LOG" <<'PY_FAIL'
import re
import sys

text = open(sys.argv[1], "r", encoding="utf-8", errors="ignore").read()
rows = re.findall(r"\|\s*preseed[^|]*\|\s*(\d+)\s*\|\s*(\d+)\s*\|", text, flags=re.I)
print(sum(int(fail) for _, fail in rows) if rows else 0)
PY_FAIL
  )"

  echo "Preseed application fail count: ${PRESEED_FAIL_COUNT}"

  if [ "$PRESEED_RC" -ne 0 ] || [ "${PRESEED_FAIL_COUNT:-0}" -ne 0 ]; then
    echo "${RUN_ID},${TRIAL_ID},${TRIAL_STARTED_AT},${NETWORK_RESET_STARTED_AT},${NETWORK_RESET_FINISHED_AT},${PRESEED_YAML},${PRESEED_LATEST},${PRESEED_LOG},${PRESEED_RC},${MEASURE_YAML},,,," >> "$RUN_INDEX"
    echo "Preseed failed or has application-level failed transactions for ${TRIAL_ID}"
    exit 1
  fi

  echo "Cooling down after preseed for ${PRESEED_MEASURE_GAP_SEC}s"
  sleep "$PRESEED_MEASURE_GAP_SEC"

  echo "Trial ${TRIAL_ID}: measure issueDisclosureCapability ${SCOPE_PROFILE}"
  BEFORE_MEASURE="$(ls -td results/sweeps/* 2>/dev/null | head -n 1 || true)"

  set +e
  CALIPER_RUN_TAG="${RUN_TAG}-measure-${TRIAL_ID}" ./scripts/run-caliper-sweep.sh "$MEASURE_YAML" 2>&1 | tee "$WRAPPER_LOG"
  RC="${PIPESTATUS[0]}"
  set -e

  AFTER_MEASURE="$(ls -td results/sweeps/* 2>/dev/null | head -n 1 || true)"
  LATEST="$AFTER_MEASURE"

  if [ -n "$BEFORE_MEASURE" ] && [ "$AFTER_MEASURE" = "$BEFORE_MEASURE" ] && [ "$RC" -ne 0 ]; then
    LATEST=""
  fi

  copy_artifacts_flat "measure-${TRIAL_ID}" "$LATEST" "$MEASURE_YAML" "$WRAPPER_LOG"

  REPORT_HTML="$(find_report_html "measure-${TRIAL_ID}" "$LATEST")"

  echo "${RUN_ID},${TRIAL_ID},${TRIAL_STARTED_AT},${NETWORK_RESET_STARTED_AT},${NETWORK_RESET_FINISHED_AT},${PRESEED_YAML},${PRESEED_LATEST},${PRESEED_LOG},${PRESEED_RC},${MEASURE_YAML},${LATEST},${WRAPPER_LOG},${RC},${REPORT_HTML}" >> "$RUN_INDEX"

  extract_caliper_report_to_csv "$REPORT_HTML" "$TRIAL_ID" "$TRIAL_STARTED_AT" "$LATEST" "$MEASURE_YAML" "$RC"

  if [ "$RUN_NO" -lt "$RUNS" ]; then
    echo "Cooldown before next clean-ledger trial for ${COOLDOWN_SEC}s"
    sleep "$COOLDOWN_SEC"
  fi
done

select_top_runs
compute_top3_statistics

echo "OUT_DIR=$OUT_DIR"
echo "PERF_ALL=$PERF_ALL"
echo "PERF_TOP3=$PERF_TOP3"
echo "RESOURCE_SUMMARY=$RESOURCE_SUMMARY"
echo "RESOURCE_TOP3=$RESOURCE_TOP3"
echo "PERF_STATS=$PERF_STATS"
echo "RESOURCE_STATS=$RESOURCE_STATS"
echo "FINAL_SUMMARY=$FINAL_SUMMARY"
echo "RUN_INDEX=$RUN_INDEX"
