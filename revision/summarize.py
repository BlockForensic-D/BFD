"""Recompute selected manuscript rows from the archived measurement exports."""
import argparse
import csv
import gzip
import json
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev

RESULTS = Path(__file__).resolve().parent / "results"


def ledger(writer):
    groups = defaultdict(list)
    with (RESULTS / "ledger-runs.csv").open() as stream:
        for row in csv.DictReader(stream):
            groups[row["method"]].append(row)
    selected = json.loads((RESULTS / "ledger-protocol.json").read_text())["selection"]["repetitions"]
    if groups.keys() != selected.keys():
        raise ValueError("Ledger operation coverage differs from the selection")
    writer.writerow(["method", "n", "offered_tps", "mean_tps", "sd_tps", "mean_latency_ms", "sd_latency_ms"])
    for method, rows in groups.items():
        if sorted(int(r["original_repetition"]) for r in rows) != sorted(selected[method]):
            raise ValueError(f"Unexpected run selection for {method}")
        rates = [int(r["measured_requests"]) / float(r["completion_window_s"]) for r in rows]
        latencies = [float(r["mean_latency_ms"]) for r in rows]
        writer.writerow([method, len(rows), rows[0]["offered_tps"], mean(rates), stdev(rates),
                         mean(latencies), stdev(latencies)])


def openings(writer):
    groups = defaultdict(list)
    with gzip.open(RESULTS / "openings.csv.gz", "rt") as stream:
        for row in csv.DictReader(stream):
            groups[row["cohort"], row["artifact"], row["scope"], row["profile"]].append(row)
    counts = json.loads((RESULTS / "opening-protocol.json").read_text())["blocksByArtifact"]
    if len(groups) != 180:
        raise ValueError("Incomplete confirmation campaign")
    writer.writerow(["cohort", "artifact", "scope", "profile", "n", "proof_bytes", "generation_ms",
                     "generation_sd_ms", "verification_ms", "verification_sd_ms", "bundle_bytes"])
    for key, rows in sorted(groups.items()):
        if sorted(int(r["block"]) for r in rows) != list(range(1, counts[key[1]] + 1)):
            raise ValueError(f"Invalid block set for {key}")
        generate = [float(r["proofGenerateMs"]) for r in rows]
        verify = [float(r["verifyBundleMs"]) for r in rows]
        writer.writerow([*key, len(rows), mean(int(r["proofBytes"]) for r in rows),
                         mean(generate), stdev(generate), mean(verify), stdev(verify),
                         mean(int(r["bundleBytes"]) for r in rows)])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("panel", choices=["ledger", "openings"])
    panel = parser.parse_args().panel
    {"ledger": ledger, "openings": openings}[panel](csv.writer(sys.stdout, lineterminator="\n"))
