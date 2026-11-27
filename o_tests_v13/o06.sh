#!/bin/sh
# O6 - Memory exhaustion (threat T6)
# Spec: O_TESTS_SPEC_V8.md, O6. Environment: M8_PROPOSAL_V9.md Sec. 7.1, Sec. 7.2.
# Runs as UID 1001 inside the sandbox. The harness invokes it via the
# Sec. 4.2 sandbox command. NOT YET EXECUTED - written for review only.
#
# Purpose: verify the memory limits are enforced, that the soft limit
# (memory.high) genuinely throttles, and that the tmpfs counts against them.
#
# PASS: (a) tmpfs sub-check: memory.current rises by the amount written
# to /tmp (256 MiB +/- 64 MiB); (b) memory.high sub-check: the above-high
# average chunk time is at least 1.25x the baseline average chunk time,
# OR pgscan + pgsteal increased during the above-high phase (either
# observable counts, and both numbers are recorded); (c) memory.max
# sub-check: allocation is killed at 4 GB (exit 137 / SIGKILL);
# memory.events shows oom_kill incrementing FOR THE WORKLOAD CGROUP ONLY;
# the VM survives; the harness, proxy, and results server keep running;
# memory.peak <= 4 GB + 64 MiB; memory.swap.current stays 0.
# FAIL: allocation exceeds 4 GB; the OOM killer acts outside the workload
# cgroup; the VM does not survive; the harness, proxy, or results server
# dies; memory.swap.current becomes non-zero; the tmpfs sub-check fails;
# or the memory.high sub-check shows NEITHER the >=1.25x slowdown NOR
# any reclaim activity.
# INCONCLUSIVE (exit 2): the script errors, times out, or memory.peak /
# memory.events / memory.stat / memory.high cannot be read, or the
# per-chunk timing measurements cannot be obtained.
#
# Exit: 0 = PASS, 1 = FAIL, 2 = error/inconclusive.
# Result line: O6_RESULT=PASS | FAIL | INCONCLUSIVE
#
# Numbers used (documented, not assumed): memory.max is 4 GiB
# (4294967296 bytes). memory.high is 3 GiB (3072 MiB). The peak margin
# is 64 MiB (67108864 bytes) for accounting granularity. The tmpfs write
# is 256 MiB; the accepted memory.current delta is 256 MiB +/- 64 MiB.
# The memory.high sub-check allocates timed 128 MiB chunks from 0 to
# 3.75 GiB: baseline = average time per chunk while cumulative usage is
# below 2.5 GiB; above-high = average time per chunk while cumulative
# usage is at or above 3.0 GiB (chunks in the 2.5-3.0 GiB transition zone
# are in neither average).
#
# HARNESS HALF (not in this script): after this script exits, the harness
# verifies the VM survived and the harness, proxy, and results server are
# still running. If any of them died, O6 is FAIL. See O_TESTS_README.md.
#
# The cgroup files are read from /sys/fs/cgroup/ as seen inside the
# sandbox (the cgroup-namespace view, where the workload cgroup is the
# root). memory.current / memory.peak / memory.events / memory.swap.current
# / memory.stat / memory.high are world-readable (0444); the workload
# cannot write them.
set -u

FAIL=0
INCONCLUSIVE=0
CG=/sys/fs/cgroup
MEM_MAX=4294967296
PEAK_MARGIN=67108864
TMPFILL_MIB=256
TMPFILL_TOL_MIB=64

# Sanity: this test is only meaningful as the workload user.
if [ "$(id -u 2>/dev/null)" != "1001" ]; then
    echo "O6_ERROR=not running as UID 1001 (got $(id -u 2>/dev/null || echo unknown))"
    echo "O6_RESULT=INCONCLUSIVE"
    exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "O6_ERROR=required tool missing: python3"
    echo "O6_RESULT=INCONCLUSIVE"
    exit 2
fi

# All cgroup files this test reads must be readable up front. If any
# is not, the test cannot produce its measurements - INCONCLUSIVE.
for _f in memory.current memory.peak memory.events memory.swap.current memory.stat memory.high; do
    if ! _v=$(cat "$CG/$_f" 2>/dev/null) || [ -z "$_v" ]; then
        echo "O6_ERROR=cannot read $CG/$_f"
        echo "O6_RESULT=INCONCLUSIVE"
        exit 2
    fi
done
echo "O6_MEMORY_HIGH=$(cat "$CG/memory.high")"
echo "O6_MEMORY_MAX=$(cat "$CG/memory.max")"

# --- Tmpfs sub-check (runs FIRST, at baseline memory) ---
# Fill /tmp (the 1 GiB tmpfs inside the sandbox) with 256 MiB and confirm
# memory.current rises by about that amount.
_mem_before=$(cat "$CG/memory.current")
if ! dd if=/dev/zero of=/tmp/o6_tmpfill bs=1M count=$TMPFILL_MIB >/dev/null 2>&1; then
    echo "O6_TMPFS result=write_failed"
    echo "O6_RESULT=INCONCLUSIVE"
    exit 2
fi
_mem_after=$(cat "$CG/memory.current")
rm -f /tmp/o6_tmpfill
_delta=$((_mem_after - _mem_before))
_delta_mib=$((_delta / 1048576))
echo "O6_TMPFS before_bytes=$_mem_before after_bytes=$_mem_after delta_mib=$_delta_mib"
_low=$((TMPFILL_MIB - TMPFILL_TOL_MIB))
_high=$((TMPFILL_MIB + TMPFILL_TOL_MIB))
if [ "$_delta_mib" -lt "$_low" ] || [ "$_delta_mib" -gt "$_high" ]; then
    echo "O6_TMPFS result=not_charged expected_mib=$TMPFILL_MIB tolerance_mib=$TMPFILL_TOL_MIB"
    FAIL=1
else
    echo "O6_TMPFS result=charged"
fi

# --- Memory allocation to the limit, with the memory.high sub-check ---
# Record the oom_kill count before, then allocate timed 128 MiB chunks
# from 0 to 3.75 GiB, recording the time per chunk; read memory.stat
# pgscan + pgsteal before the above-high phase (after chunk 23, 2944
# MiB, still below 3.0 GiB) and after it (after chunk 30, 3840 MiB);
# then keep allocating until the kernel OOM-kills the allocator
# (exit 137, SIGKILL).
_oom_before=$(awk '/^oom_kill / {print $2}' "$CG/memory.events")
if [ -z "$_oom_before" ]; then
    _oom_before=0
fi
echo "O6_OOM_KILL_BEFORE=$_oom_before"

timeout 600 python3 - <<'PYEOF' >/tmp/o6_alloc.log 2>&1
import sys, time
CG = "/sys/fs/cgroup"
CHUNK = 128 * 1024 * 1024
def read_stat():
    pgscan = pgsteal = None
    with open(CG + "/memory.stat") as f:
        for line in f:
            k, _, v = line.partition(" ")
            if k == "pgscan":
                pgscan = int(v)
            elif k == "pgsteal":
                pgsteal = int(v)
    return pgscan, pgsteal
chunks = []
times = []
n = 0
# Phase 1: timed allocation from 0 to 3.75 GiB (30 chunks of 128 MiB).
while n < 30:
    t0 = time.monotonic()
    b = bytearray(CHUNK)
    for i in range(0, len(b), 4096):
        b[i] = 1
    dt = time.monotonic() - t0
    chunks.append(b)
    n += 1
    cum = n * 128
    times.append((cum, dt))
    print("O6_CHUNK n=%d cum_mib=%d secs=%.6f" % (n, cum, dt), flush=True)
    if n == 23:
        ps, pt = read_stat()
        print("O6_PGSCAN_BEFORE=%s" % ps, flush=True)
        print("O6_PGSTEAL_BEFORE=%s" % pt, flush=True)
ps, pt = read_stat()
print("O6_PGSCAN_AFTER=%s" % ps, flush=True)
print("O6_PGSTEAL_AFTER=%s" % pt, flush=True)
base = [t for (c, t) in times if c < 2560]
above = [t for (c, t) in times if c >= 3072]
base_avg = sum(base) / len(base)
above_avg = sum(above) / len(above)
ratio = above_avg / base_avg if base_avg > 0 else 0.0
print("O6_HIGH_BASELINE_AVG=%.6f" % base_avg, flush=True)
print("O6_HIGH_ABOVE_AVG=%.6f" % above_avg, flush=True)
print("O6_HIGH_RATIO=%.4f" % ratio, flush=True)
# Phase 2: keep allocating until the kernel OOM-kills this process.
while True:
    b = bytearray(CHUNK)
    for i in range(0, len(b), 4096):
        b[i] = 1
    chunks.append(b)
    n += 1
    if n % 4 == 0:
        print("allocated %d MiB" % (n * 128), flush=True)
PYEOF
_alloc_rc=$?
echo "O6_ALLOC_RC=$_alloc_rc"
grep '^O6_CHUNK' /tmp/o6_alloc.log 2>/dev/null | sed 's/^/O6_ALLOC_LOG /'
grep '^O6_PGSCAN\|^O6_PGSTEAL\|^O6_HIGH' /tmp/o6_alloc.log 2>/dev/null | sed 's/^/O6_ALLOC_LOG /'
tail -n 3 /tmp/o6_alloc.log 2>/dev/null | sed 's/^/O6_ALLOC_LOG /'

# --- memory.high sub-check verdict (from the recorded measurements) ---
_ratio=$(grep '^O6_HIGH_RATIO=' /tmp/o6_alloc.log 2>/dev/null | cut -d= -f2)
_ps_before=$(grep '^O6_PGSCAN_BEFORE=' /tmp/o6_alloc.log 2>/dev/null | cut -d= -f2)
_pt_before=$(grep '^O6_PGSTEAL_BEFORE=' /tmp/o6_alloc.log 2>/dev/null | cut -d= -f2)
_ps_after=$(grep '^O6_PGSCAN_AFTER=' /tmp/o6_alloc.log 2>/dev/null | cut -d= -f2)
_pt_after=$(grep '^O6_PGSTEAL_AFTER=' /tmp/o6_alloc.log 2>/dev/null | cut -d= -f2)
if [ -z "$_ratio" ] || [ -z "$_ps_before" ] || [ -z "$_pt_before" ] || [ -z "$_ps_after" ] || [ -z "$_pt_after" ]; then
    echo "O6_HIGH result=measurements_missing"
    INCONCLUSIVE=1
else
    _slow=$(awk -v r="$_ratio" 'BEGIN {print (r >= 1.25) ? 1 : 0}')
    _reclaim_before=$((_ps_before + _pt_before))
    _reclaim_after=$((_ps_after + _pt_after))
    echo "O6_HIGH ratio=$_ratio slowdown_1_25x=$_slow reclaim_before=$_reclaim_before reclaim_after=$_reclaim_after"
    if [ "$_slow" -eq 1 ] || [ "$_reclaim_after" -gt "$_reclaim_before" ]; then
        echo "O6_HIGH result=throttled"
    else
        echo "O6_HIGH result=not_throttled"
        FAIL=1
    fi
fi

# --- memory.max sub-check verdict ---
# Outcome classification. 137 (SIGKILL) is the OOM killer acting.
# Any other outcome means the limit did not demonstrably kill the
# allocation: FAIL (per Correction 9, a timeout is a failure, not a pass).
if [ "$_alloc_rc" -ne 137 ]; then
    echo "O6_ALLOC result=not_oom_killed rc=$_alloc_rc"
    FAIL=1
else
    echo "O6_ALLOC result=oom_killed"
fi
rm -f /tmp/o6_alloc.log

_oom_after=$(awk '/^oom_kill / {print $2}' "$CG/memory.events")
if [ -z "$_oom_after" ]; then
    _oom_after=0
fi
echo "O6_OOM_KILL_AFTER=$_oom_after"
if [ "$_oom_after" -le "$_oom_before" ]; then
    echo "O6_OOM_KILL result=not_incremented"
    FAIL=1
else
    echo "O6_OOM_KILL result=incremented"
fi

_peak=$(cat "$CG/memory.peak")
echo "O6_MEMORY_PEAK_BYTES=$_peak"
_peak_limit=$((MEM_MAX + PEAK_MARGIN))
if [ "$_peak" -gt "$_peak_limit" ]; then
    echo "O6_PEAK result=exceeded limit_bytes=$_peak_limit"
    FAIL=1
else
    echo "O6_PEAK result=within_limit"
fi

_swap=$(cat "$CG/memory.swap.current")
echo "O6_SWAP_CURRENT_BYTES=$_swap"
if [ "$_swap" != "0" ]; then
    echo "O6_SWAP result=nonzero"
    FAIL=1
else
    echo "O6_SWAP result=zero"
fi

if [ "$INCONCLUSIVE" -gt 0 ]; then
    echo "O6_RESULT=INCONCLUSIVE"
    exit 2
fi
if [ "$FAIL" -gt 0 ]; then
    echo "O6_RESULT=FAIL"
    exit 1
fi
echo "O6_RESULT=PASS"
exit 0
