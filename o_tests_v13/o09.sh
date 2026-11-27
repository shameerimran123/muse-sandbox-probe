#!/bin/sh
# O9 - Time exhaustion (threat T6)
# Spec: O_TESTS_SPEC_V8.md, O9. Environment: M8_PROPOSAL_V9.md Sec. 7.1, Sec. 7.2.
# Runs as UID 1001 inside the sandbox. The harness invokes it via the
# Sec. 4.2 sandbox command. NOT YET EXECUTED - written for review only.
#
# Purpose: verify the per-case timeout is enforced, independently of the
# harness, and that the CPU cap (1 OCPU) is genuinely enforced.
#
# *** THIS TEST CANNOT PRINT ITS OWN RESULT. ***
# This script is the WORKLOAD HALF ONLY: a CPU-bound workload that is
# intentionally killed - it never exits on its own and never prints an
# O9_RESULT line. The HARNESS records the result, as documented below.
# That is not a gap in this script; it is the nature of a timeout test
# (a process cannot report its own kill). See O_TESTS_README.md.
#
# The workload is FOUR CONCURRENT BUSY PROCESSES (separate processes,
# not threads - a multi-threaded Python loop would be serialized by the
# GIL and could not exceed 1 CPU even without a cap).
#
# BASELINE FIRST (spec V4 blocker C): before spawning the workers, the
# script samples cpu.stat usage_usec, sleeps 30 s idle, and samples
# again - the baseline rate (CPU-seconds per wall-clock second consumed
# by the script itself with no workers running). It prints
# O9_BASELINE lines. If the baseline cannot be measured, the script
# exits 2 (INCONCLUSIVE) before spawning any worker - the corrected
# ratio cannot be computed without it.
# Then the workers start, and the script samples cpu.stat usage_usec
# every 30 s and prints O9_CPU_SAMPLE lines (elapsed wall seconds, CPU
# microseconds consumed since the workers started, the raw ratio, the
# baseline rate, and the CORRECTED ratio = raw ratio - baseline rate).
# The raw ratio is computed from the DELTA of usage_usec since the workers
# were spawned, so pre-worker CPU (the baseline period and script startup)
# is excluded - a cumulative ratio would understate the workers' rate by
# up to the baseline rate. The harness PASS criterion is that EVERY
# corrected ratio is <= 1.05.
#
# HARNESS HALF (the verdict - performed by the harness, root):
#   Run 1 (harness timeout): run this script under `timeout 600`.
#     Record the wall-clock kill time.
#   Run 2 (watchdog sub-check): run this script a second time with the
#     harness `timeout` DELIBERATELY DISABLED. The root-owned systemd
#     watchdog must kill the workload cgroup at 600 s - proving the
#     timeout does not depend on the harness alone.
#   PASS (both runs) requires ALL of:
#     - the case is killed at the 10-minute per-case timeout (600 s);
#     - cgroup.procs is empty after the kill;
#     - the result is recorded as TIMEOUT, not PASS;
#     - EVERY O9_CPU_SAMPLE ratio is <= 1.05 CPU-seconds per
#       wall-clock second (1 OCPU + 5% measurement margin) - proving
#       the 1-OCPU cap against a workload demanding 4 CPUs.
#   FAIL (either run): the case runs past 10 minutes under either
#     mechanism; cgroup.procs is not empty after the kill; the result is
#     recorded as PASS; ANY CORRECTED CPU sample ratio exceeds 1.05.
#   INCONCLUSIVE: the script errors, times out in a way that leaves the
#     cgroup non-empty, the baseline cannot be measured, or the watchdog
#     sub-check cannot be performed.
# The harness writes the O9_RESULT line into the case manifest from its
# own observations; this script's exit status (124 from `timeout`, or
# 137 from the watchdog kill) is the harness's evidence, not a verdict.
# Exact harness commands are in O_TESTS_README.md.
set -u

# Sanity: this test is only meaningful as the workload user.
if [ "$(id -u 2>/dev/null)" != "1001" ]; then
    echo "O9_ERROR=not running as UID 1001 (got $(id -u 2>/dev/null || echo unknown))"
    exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "O9_ERROR=required tool missing: python3"
    exit 2
fi

if ! _v=$(cat /sys/fs/cgroup/cpu.stat 2>/dev/null) || [ -z "$_v" ]; then
    echo "O9_ERROR=cannot read /sys/fs/cgroup/cpu.stat"
    exit 2
fi

echo "O9_STARTED pid=$$ time=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "O9_NOTE=this script never exits on its own; the harness or the systemd watchdog kills it at 600s"
echo "O9_NOTE=four concurrent busy processes; cpu.stat sampled every 30s"

# Baseline first (30 s idle), then four CPU-bound busy processes,
# plus a sampler in the parent. No sleep, no I/O, no allocation in the
# workers - pure CPU. The parent samples cpu.stat usage_usec every 30 s
# and prints O9_CPU_SAMPLE lines with the raw ratio, the baseline rate,
# and the corrected ratio (raw - baseline).
exec python3 - <<'PYEOF'
import subprocess, sys, time
def read_usage():
    with open("/sys/fs/cgroup/cpu.stat") as f:
        for line in f:
            if line.startswith("usage_usec"):
                return int(line.split()[1])
    return None
# --- 30 s idle baseline, BEFORE any worker is spawned. ---
try:
    usage_before = read_usage()
except Exception as e:
    print("O9_BASELINE_ERROR cannot_read_cpu_stat error=%s" % e, flush=True)
    sys.exit(2)
if usage_before is None:
    print("O9_BASELINE_ERROR usage_usec_not_found", flush=True)
    sys.exit(2)
time.sleep(30)
try:
    usage_after = read_usage()
except Exception as e:
    print("O9_BASELINE_ERROR cannot_read_cpu_stat error=%s" % e, flush=True)
    sys.exit(2)
if usage_after is None:
    print("O9_BASELINE_ERROR usage_usec_not_found", flush=True)
    sys.exit(2)
baseline_rate = ((usage_after - usage_before) / 1000000.0) / 30.0
print("O9_BASELINE cpu_usec_before=%d cpu_usec_after=%d baseline_rate=%.6f" % (
    usage_before, usage_after, baseline_rate), flush=True)
workers = []
for _ in range(4):
    workers.append(subprocess.Popen(
        [sys.executable, "-c", "while True: pass"]))
start = time.monotonic()
print("O9_WORKERS started=%d" % len(workers), flush=True)
# Anchor for the ratio: usage_usec at the moment the workers start.
# The ratio is computed from the DELTA since this anchor, so pre-worker
# CPU (the baseline period and script startup) is excluded.
usage_start = read_usage()
if usage_start is None:
    print("O9_CPU_SAMPLE_ERROR usage_usec_not_found", flush=True)
    sys.exit(2)
while True:
    time.sleep(30)
    elapsed = time.monotonic() - start
    usage = read_usage()
    if usage is None:
        print("O9_CPU_SAMPLE elapsed_s=%.0f cpu_usec=unknown ratio=unknown baseline_rate=%.6f corrected_ratio=unknown" % (elapsed, baseline_rate), flush=True)
    else:
        delta = usage - usage_start
        ratio = (delta / 1000000.0) / elapsed if elapsed > 0 else 0.0
        corrected = ratio - baseline_rate
        print("O9_CPU_SAMPLE elapsed_s=%.0f cpu_usec=%d ratio=%.3f baseline_rate=%.6f corrected_ratio=%.3f" % (elapsed, delta, ratio, baseline_rate, corrected), flush=True)
PYEOF
