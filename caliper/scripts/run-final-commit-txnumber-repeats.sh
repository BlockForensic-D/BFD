#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

OPERATION="${OPERATION:-commitPreservedEvidence}"
PRESEED_WORKLOAD_MODULE="${PRESEED_WORKLOAD_MODULE:-workloads/20-preseed-preserved-pool.js}"
MEASURE_WORKLOAD_MODULE="${MEASURE_WORKLOAD_MODULE:-workloads/21-commit-from-preserved-pool.js}"

WORKERS="${WORKERS:-4}"
TPS="${TPS:-100}"
TX_NUMBER="${TX_NUMBER:-3000}"
REPEATS="${REPEATS:-6}"
SELECT_TOP="${SELECT_TOP:-3}"
PRESEED_TPS="${PRESEED_TPS:-100}"

CONTRACT_ID="${CONTRACT_ID:-forensicContract}"
DATASET_PROFILE_ID="${DATASET_PROFILE_ID:-edge_vulnscan_1mib_v3}"
SCOPE_PROFILE="${SCOPE_PROFILE:-HASH_ONLY}"
CALIPER_RESOURCE_INTERVAL="${CALIPER_RESOURCE_INTERVAL:-2}"
COOLDOWN_SEC="${COOLDOWN_SEC:-30}"

PER_WORKER=$(( (TX_NUMBER + WORKERS - 1) / WORKERS ))
ITEM_COUNT="${ITEM_COUNT:-$(( PER_WORKER + 500 ))}"
TOTAL_CAPACITY=$(( ITEM_COUNT * WORKERS ))
PRESEED_TX_NUMBER="${PRESEED_TX_NUMBER:-$TOTAL_CAPACITY}"

OUT_ROOT="${OUT_ROOT:-results/final-commit-txnumber}"
RUN_ID="${RUN_ID:-final-commit-txnumber-w${WORKERS}-t${TPS}-tx${TX_NUMBER}-$(date +%Y%m%d-%H%M%S)}"
OUT_DIR="${OUT_ROOT}/${RUN_ID}"

mkdir -p "$OUT_DIR" benchmarks

PERF_ALL="${OUT_DIR}/performance_metrics_all.csv"
PERF_TOP3="${OUT_DIR}/performance_metrics_top3.csv"
RESOURCE_SUMMARY="${OUT_DIR}/resource_utilization_summary.csv"
RESOURCE_TOP3="${OUT_DIR}/resource_utilization_top3_summary.csv"
RUN_INDEX="${OUT_DIR}/run_index.csv"

echo "run_id,repeat,preseed_yaml,preseed_result_dir,preseed_log,preseed_return_code,benchmark_yaml,caliper_result_dir,wrapper_log,return_code,report_html" > "$RUN_INDEX"

echo "OPERATION=$OPERATION"
echo "WORKERS=$WORKERS TPS=$TPS TX_NUMBER=$TX_NUMBER REPEATS=$REPEATS SELECT_TOP=$SELECT_TOP"
echo "ITEM_COUNT=$ITEM_COUNT TOTAL_CAPACITY=$TOTAL_CAPACITY PRESEED_TX_NUMBER=$PRESEED_TX_NUMBER"
echo "OUT_DIR=$OUT_DIR"

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
  local repeat="$2"
  local result_dir="$3"
  local yaml_file="$4"
  local rc="$5"

  if [ -z "$report_html" ] || [ ! -f "$report_html" ]; then
    echo "WARNING: report.html not found for repeat ${repeat}"
    return 0
  fi

  python3 - "$report_html" "$PERF_ALL" "$RESOURCE_SUMMARY" "$RUN_ID" "$repeat" "$OPERATION" "$WORKERS" "$TPS" "txNumber" "$TX_NUMBER" "$ITEM_COUNT" "$TOTAL_CAPACITY" "$result_dir" "$yaml_file" "$rc" <<'PY'
import csv
import html
import os
import re
import sys
from html.parser import HTMLParser

report_html, perf_csv, resource_csv, run_id, repeat, operation, workers, target_tps, target_type, target_value, item_count, total_capacity, result_dir, yaml_file, rc = sys.argv[1:16]

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
    if "commit" in name or "commitpreservedevidence" in name:
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
    "run_id", "repeat", "operation", "workers", "target_tps", "target_type", "target_value",
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

        target_i = to_int(target_value)

        valid = (
            str(rc) == "0"
            and fail == 0
            and isinstance(succ, int)
            and isinstance(target_i, int)
            and succ == target_i
            and isinstance(ratio, float)
            and ratio >= 0.90
        )

        w.writerow({
            "run_id": run_id,
            "repeat": repeat,
            "operation": operation,
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
    "run_id", "repeat", "operation", "workers", "target_tps", "target_type", "target_value",
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
            "repeat": repeat,
            "operation": operation,
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
selected_repeats = {r.get("repeat") for r in selected}

if rows:
    with open(perf_top, "w", newline="") as f:
        fields = list(rows[0].keys()) + ["selectionRank", "selectionNote"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for rank, r in enumerate(selected, 1):
            rr = dict(r)
            rr["selectionRank"] = rank
            rr["selectionNote"] = "selected_lowest_avg_latency_from_caliper_report_valid_run"
            w.writerow(rr)

res_rows = read_csv(res_all)

if res_rows:
    with open(res_top, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=res_rows[0].keys())
        w.writeheader()
        for r in res_rows:
            if r.get("repeat") in selected_repeats:
                w.writerow(r)

print("=== Top selection: lowest avg latency ===")
print(f"valid_runs={len(valid)} selected={len(selected)}")

for rank, r in enumerate(selected, 1):
    print(
        f"rank={rank} repeat={r.get('repeat')} "
        f"avgLatency={r.get('avgLatencySec')} "
        f"maxLatency={r.get('maxLatencySec')} "
        f"throughput={r.get('throughputTps')} "
        f"ratio={r.get('throughputSendRatio')}"
    )
PY
}

for REP in $(seq 1 "$REPEATS"); do
  REP_PAD="$(printf "%02d" "$REP")"
  STAMP_NOW="$(date +%H%M%S)"
  RUN_TAG="cmn${REP_PAD}${STAMP_NOW}"
  POOL_PREFIX="cmn${REP_PAD}${STAMP_NOW}"

  PRESEED_YAML="benchmarks/final-commit-txnumber-preseed-w${WORKERS}-r${REP_PAD}-${STAMP_NOW}.yaml"
  PRESEED_LOG="${OUT_DIR}/preseed-r${REP_PAD}.log"
  MEASURE_YAML="benchmarks/final-commit-txnumber-w${WORKERS}-tps${TPS}-tx${TX_NUMBER}-r${REP_PAD}-${STAMP_NOW}.yaml"
  WRAPPER_LOG="${OUT_DIR}/wrapper-r${REP_PAD}.log"

  cat > "$PRESEED_YAML" <<YAML
test:
  name: blockforensic-d-preseed-preserved-for-commit-txnumber-w${WORKERS}-r${REP_PAD}-${STAMP_NOW}
  description: preseed preserved pool
  workers:
    type: local
    number: ${WORKERS}
  rounds:
    - label: preseed_preserved_pool_for_commit_txnumber_w${WORKERS}_r${REP_PAD}
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
          itemCount: ${ITEM_COUNT}
          txNumber: ${PRESEED_TX_NUMBER}
          scopeProfile: ${SCOPE_PROFILE}
YAML

  cat > "$MEASURE_YAML" <<YAML
test:
  name: blockforensic-d-final-commit-txnumber-w${WORKERS}-tps${TPS}-tx${TX_NUMBER}-r${REP_PAD}-${STAMP_NOW}
  description: commitPreservedEvidence txNumber repeat ${REP_PAD}
  workers:
    type: local
    number: ${WORKERS}
  rounds:
    - label: commitPreservedEvidence_w${WORKERS}_tx${TX_NUMBER}_tps${TPS}_r${REP_PAD}
      txNumber: ${TX_NUMBER}
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

  echo "Repeat ${REP_PAD}/${REPEATS}: preseed"
  BEFORE_PRESEED="$(ls -td results/sweeps/* 2>/dev/null | head -n 1 || true)"

  set +e
  CALIPER_RUN_TAG="${RUN_TAG}-preseed" ./scripts/run-caliper-sweep.sh "$PRESEED_YAML" 2>&1 | tee "$PRESEED_LOG"
  PRESEED_RC="${PIPESTATUS[0]}"
  set -e

  AFTER_PRESEED="$(ls -td results/sweeps/* 2>/dev/null | head -n 1 || true)"
  PRESEED_LATEST="$AFTER_PRESEED"

  if [ -n "$BEFORE_PRESEED" ] && [ "$AFTER_PRESEED" = "$BEFORE_PRESEED" ] && [ "$PRESEED_RC" -ne 0 ]; then
    PRESEED_LATEST=""
  fi

  copy_artifacts_flat "preseed-r${REP_PAD}" "$PRESEED_LATEST" "$PRESEED_YAML" "$PRESEED_LOG"

  if [ "$PRESEED_RC" -ne 0 ]; then
    echo "${RUN_ID},${REP_PAD},${PRESEED_YAML},${PRESEED_LATEST},${PRESEED_LOG},${PRESEED_RC},${MEASURE_YAML},,,," >> "$RUN_INDEX"
    exit 1
  fi

  echo "Repeat ${REP_PAD}/${REPEATS}: measure"
  BEFORE_MEASURE="$(ls -td results/sweeps/* 2>/dev/null | head -n 1 || true)"

  set +e
  CALIPER_RUN_TAG="${RUN_TAG}-measure" ./scripts/run-caliper-sweep.sh "$MEASURE_YAML" 2>&1 | tee "$WRAPPER_LOG"
  RC="${PIPESTATUS[0]}"
  set -e

  AFTER_MEASURE="$(ls -td results/sweeps/* 2>/dev/null | head -n 1 || true)"
  LATEST="$AFTER_MEASURE"

  if [ -n "$BEFORE_MEASURE" ] && [ "$AFTER_MEASURE" = "$BEFORE_MEASURE" ] && [ "$RC" -ne 0 ]; then
    LATEST=""
  fi

  copy_artifacts_flat "caliper-r${REP_PAD}" "$LATEST" "$MEASURE_YAML" "$WRAPPER_LOG"

  REPORT_HTML="$(find_report_html "caliper-r${REP_PAD}" "$LATEST")"

  echo "${RUN_ID},${REP_PAD},${PRESEED_YAML},${PRESEED_LATEST},${PRESEED_LOG},${PRESEED_RC},${MEASURE_YAML},${LATEST},${WRAPPER_LOG},${RC},${REPORT_HTML}" >> "$RUN_INDEX"

  extract_caliper_report_to_csv "$REPORT_HTML" "$REP_PAD" "$LATEST" "$MEASURE_YAML" "$RC"

  [ "$REP" -lt "$REPEATS" ] && sleep "$COOLDOWN_SEC"
done

select_top_runs

echo "OUT_DIR=$OUT_DIR"
echo "PERF_ALL=$PERF_ALL"
echo "PERF_TOP3=$PERF_TOP3"
echo "RESOURCE_SUMMARY=$RESOURCE_SUMMARY"
echo "RESOURCE_TOP3=$RESOURCE_TOP3"
