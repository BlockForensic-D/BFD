"use strict";
const { execFile } = require("node:child_process"),
  { performance } = require("node:perf_hooks");
function systemClockHealth({ cacheMs = 5000 } = {}) {
  if (cacheMs < 0 || cacheMs > 5000) throw Error("CLOCK_CACHE_BOUND");
  let checked = -Infinity,
    healthy = false,
    pending = null;
  return async () => {
    if (performance.now() - checked < cacheMs) return healthy;
    if (!pending)
      pending = new Promise((resolve) => {
        execFile(
          "timedatectl",
          ["show", "--property=NTPSynchronized", "--value"],
          { timeout: 2000, maxBuffer: 128 },
          (error, stdout) => {
            healthy = !error && stdout.trim() === "yes";
            checked = performance.now();
            pending = null;
            resolve(healthy);
          },
        );
      });
    return pending;
  };
}
module.exports = { systemClockHealth };
