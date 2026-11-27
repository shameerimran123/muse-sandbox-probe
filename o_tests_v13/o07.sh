#!/bin/sh
# O7 - Fork exhaustion (threat T6)
# Spec: O_TESTS_SPEC_V8.md, O7. Environment: M8_PROPOSAL_V9.md Sec. 7.1, Sec. 7.2.
# Runs as UID 1001 inside the sandbox. The harness invokes it via the
# Sec. 4.2 sandbox command. NOT YET EXECUTED - written for review only.
#
# Purpose: verify the process-count limit is enforced.
#
# PASS: fork fails at 512 processes (pids.max); the OBSERVED PEAK of
# pids.current (polled every 50 ms by a sampler thread) is <= 512
# throughout; pids.events max INCREMENTED by at least 1 across the
# fork-failure window AND pids.current at the moment of fork failure is
# >= 500 AND the fork failure errno is EAGAIN (11) (the causation proof,
# spec V4 blocker B); the VM survives; the fork bomb is killed with the
# cgroup.
# FAIL: the observed peak exceeds 512; fork never fails (the loop times
# out without an OSError); the VM does not survive; the fork bomb is not
# killed with the cgroup.
# INCONCLUSIVE (exit 2): the script errors, times out, or pids.current
# cannot be read, or the observed peak cannot be obtained. ALSO
# INCONCLUSIVE: fork fails but pids.events max did NOT increment, or
# pids.current at failure is below 500, or the fork failure errno is
# not EAGAIN (11) - the failure was not proven to be caused by
# pids.max. A fork failure with errno EACCES, EPERM, ENOMEM or any
# other value is a different failure mode, not a pids.max exhaustion.
# ALSO INCONCLUSIVE (blocker B, 2026-11-25 ~23:04 PKT): the sampler
# never read pids.current (sampler_reads=0), or it went blind for
# more than 1 s (more than 20 consecutive 50 ms read failures) - the
# observed peak cannot be trusted, because the peak is only what the
# sampler saw. In V5 the sampler swallowed every read error
# (except: pass) and a dead sampler was invisible; here every sampler
# read error is counted and the sampler health is a verdict input.
#
# Exit: 0 = PASS, 1 = FAIL, 2 = error/inconclusive.
# Result line: O7_RESULT=PASS | FAIL | INCONCLUSIVE
#
# How it works: a Python parent forks children that only sleep. Forked
# children share the parent's pages copy-on-write and allocate nothing,
# so the test exercises the process count, not memory (it must not trip
# the O6 memory limit). A sampler thread polls pids.current every 50 ms
# and records the OBSERVED PEAK; the verdict uses that peak. The parent
# catches the fork failure (OSError), records pids.current at the
# failure, then kills and reaps every child and records pids.current
# again. pids.events "max" is an event counter (the number of times the
# limit was hit), not a peak - but its INCREMENT across the
# fork-failure window IS the causation evidence: it is read BEFORE the
# fork loop and AFTER the failure, and the verdict requires it to have
# incremented by at least 1 AND pids.current at failure to be >= 500.
# The harness kills the cgroup after the script exits, which is what
# finally guarantees no process survives.
#
# HARNESS HALF (not in this script): after this script exits, the harness
# verifies the VM survived and that the cgroup is empty (cgroup.procs).
# See O_TESTS_README.md.
set -u

FAIL=0
CG=/sys/fs/cgroup
PIDS_MAX=512

# Sanity: this test is only meaningful as the workload user.
if [ "$(id -u 2>/dev/null)" != "1001" ]; then
    echo "O7_ERROR=not running as UID 1001 (got $(id -u 2>/dev/null || echo unknown))"
    echo "O7_RESULT=INCONCLUSIVE"
    exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "O7_ERROR=required tool missing: python3"
    echo "O7_RESULT=INCONCLUSIVE"
    exit 2
fi

if ! _v=$(cat "$CG/pids.current" 2>/dev/null) || [ -z "$_v" ]; then
    echo "O7_ERROR=cannot read $CG/pids.current"
    echo "O7_RESULT=INCONCLUSIVE"
    exit 2
fi

# Fork until the kernel refuses. The child sleeps without allocating, so
# memory stays shared copy-on-write with the parent.
timeout 120 python3 - <<'PYEOF' >/tmp/o7_fork.log 2>&1
import os, sys, time, signal, threading
peak = [0]
stop = [False]
reads = [0]
consec_errors = [0]
max_consec_errors = [0]
def sampler():
    # Every read error is COUNTED (blocker B, 2026-11-25 ~23:04 PKT):
    # in V5 the except branch was `pass`, so a sampler that could not
    # read pids.current was invisible and the peak it reported was
    # trusted anyway. Here a sampler that never reads, or that goes
    # blind for more than 1 s (20 consecutive 50 ms failures), makes
    # the test INCONCLUSIVE - the peak cannot be trusted.
    while not stop[0]:
        try:
            with open("/sys/fs/cgroup/pids.current") as f:
                v = int(f.read().strip())
            if v > peak[0]:
                peak[0] = v
            reads[0] += 1
            consec_errors[0] = 0
        except Exception:
            consec_errors[0] += 1
            if consec_errors[0] > max_consec_errors[0]:
                max_consec_errors[0] = consec_errors[0]
        time.sleep(0.05)
t = threading.Thread(target=sampler, daemon=True)
t.start()
def read_events_max():
    with open("/sys/fs/cgroup/pids.events") as f:
        for line in f:
            k, _, v = line.partition(" ")
            if k.strip() == "max":
                return int(v.strip())
    return None
events_before = read_events_max()
print("pids_events_max_before=%s" % events_before, flush=True)
children = []
try:
    while True:
        pid = os.fork()
        if pid == 0:
            time.sleep(600)
            os._exit(0)
        children.append(pid)
except OSError as e:
    print("fork_failed children=%d error=%s" % (len(children), e), flush=True)
    # The errno is the third leg of the causation proof (spec V4
    # blocker B): a pids.max exhaustion fails fork with EAGAIN (11,
    # "Resource temporarily unavailable"). Any other errno is a
    # different failure mode and must NOT count as a pids.max proof.
    print("fork_errno=%s" % (e.errno,), flush=True)
stop[0] = True
time.sleep(0.1)
# Record the live process count at the moment fork failed.
with open("/sys/fs/cgroup/pids.current") as f:
    print("pids_current_at_failure=%s" % f.read().strip(), flush=True)
print("pids_peak_observed=%d" % peak[0], flush=True)
print("sampler_reads=%d" % reads[0], flush=True)
print("sampler_max_consec_errors=%d" % max_consec_errors[0], flush=True)
# sampler_ok: the sampler read at least once AND never went blind for
# more than 1 s (20 consecutive 50 ms read failures). A sampler that
# never read, or that missed a whole second around the fork failure,
# cannot prove the observed peak.
print("sampler_ok=%d" % (1 if reads[0] >= 1 and max_consec_errors[0] <= 20 else 0), flush=True)
events_after = read_events_max()
print("pids_events_max_after=%s" % events_after, flush=True)
# Kill and reap every child, then record the count again.
for pid in children:
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
while children:
    try:
        done, _status = os.waitpid(-1, 0)
        children.remove(done)
    except OSError:
        break
with open("/sys/fs/cgroup/pids.current") as f:
    print("pids_current_after_cleanup=%s" % f.read().strip(), flush=True)
print("cleanup_done", flush=True)
PYEOF
_fork_rc=$?
cat /tmp/o7_fork.log 2>/dev/null | sed 's/^/O7_FORK /'

# The Python program exits 0 only if fork failed as expected (OSError
# caught) and cleanup completed. A timeout (124) means fork never failed
# - the limit did not stop it. Any other exit is a test error.
if [ "$_fork_rc" -eq 124 ]; then
    echo "O7_FORK result=timeout_limit_not_reached"
    rm -f /tmp/o7_fork.log
    echo "O7_RESULT=FAIL"
    exit 1
fi
if [ "$_fork_rc" -ne 0 ]; then
    echo "O7_FORK result=error rc=$_fork_rc"
    rm -f /tmp/o7_fork.log
    echo "O7_RESULT=INCONCLUSIVE"
    exit 2
fi

# The verdict uses the OBSERVED PEAK recorded by the sampler thread
# (printed into the log above as O7_FORK pids_peak_observed=...). The
# peak must be <= 512.
_peak=$(grep '^pids_peak_observed=' /tmp/o7_fork.log 2>/dev/null | cut -d= -f2)
_events_before=$(grep '^pids_events_max_before=' /tmp/o7_fork.log 2>/dev/null | cut -d= -f2)
_events_after=$(grep '^pids_events_max_after=' /tmp/o7_fork.log 2>/dev/null | cut -d= -f2)
_current_at_failure=$(grep '^pids_current_at_failure=' /tmp/o7_fork.log 2>/dev/null | cut -d= -f2)
_fork_errno=$(grep '^fork_errno=' /tmp/o7_fork.log 2>/dev/null | cut -d= -f2)
_sampler_ok=$(grep '^sampler_ok=' /tmp/o7_fork.log 2>/dev/null | cut -d= -f2)
_sampler_reads=$(grep '^sampler_reads=' /tmp/o7_fork.log 2>/dev/null | cut -d= -f2)
_sampler_maxerr=$(grep '^sampler_max_consec_errors=' /tmp/o7_fork.log 2>/dev/null | cut -d= -f2)
rm -f /tmp/o7_fork.log
echo "O7_PIDS_PEAK_OBSERVED=${_peak:-unknown}"
echo "O7_PIDS_EVENTS_MAX before=${_events_before:-unknown} after=${_events_after:-unknown}"
echo "O7_PIDS_CURRENT_AT_FAILURE=${_current_at_failure:-unknown}"
echo "O7_FORK_ERRNO=${_fork_errno:-unknown}"
echo "O7_SAMPLER reads=${_sampler_reads:-unknown} max_consec_errors=${_sampler_maxerr:-unknown} ok=${_sampler_ok:-unknown}"
# Sampler health (blocker B, 2026-11-25 ~23:04 PKT): the observed
# peak is only trustworthy if the sampler was alive. A missing
# sampler_ok line, zero reads, or a blind gap over 1 s is
# INCONCLUSIVE - the peak cannot be proven.
if [ "${_sampler_ok:-}" != "1" ]; then
    echo "O7_SAMPLER result=unhealthy_or_missing reads=${_sampler_reads:-unknown} max_consec_errors=${_sampler_maxerr:-unknown}"
    echo "O7_RESULT=INCONCLUSIVE"
    exit 2
fi
echo "O7_SAMPLER result=healthy"
if [ -z "$_peak" ]; then
    echo "O7_ERROR=observed peak not recorded"
    echo "O7_RESULT=INCONCLUSIVE"
    exit 2
fi
if [ "$_peak" -gt "$PIDS_MAX" ]; then
    echo "O7_PIDS result=exceeded peak=$_peak limit=$PIDS_MAX"
    FAIL=1
else
    echo "O7_PIDS result=within_limit peak=$_peak"
fi

# Causation proof (spec V4 blocker B): the fork failure is only
# attributed to pids.max if ALL THREE hold: (1) pids.events max
# incremented by at least 1 across the fork-failure window; (2)
# pids.current at the moment of fork failure was >= 500; (3) the fork
# failure errno was EAGAIN (11). If fork failed but any condition is
# unmet, or any measurement is missing, the result is INCONCLUSIVE
# - the failure was not proven to be caused by pids.max. (A peak
# above 512 above is already FAIL and takes precedence in the final
# verdict only if the causation check also passes; an inconclusive
# causation check exits 2 here, before the PASS/FAIL verdict.)
case "$_events_before" in ''|*[!0-9]*) _events_missing=1 ;; *) _events_missing=0 ;; esac
case "$_events_after" in ''|*[!0-9]*) _events_missing=1 ;; esac
case "$_current_at_failure" in ''|*[!0-9]*) _events_missing=1 ;; esac
case "$_fork_errno" in ''|*[!0-9]*) _events_missing=1 ;; esac
if [ "${_events_missing:-1}" -eq 1 ]; then
    echo "O7_CAUSATION result=measurements_missing"
    echo "O7_RESULT=INCONCLUSIVE"
    exit 2
fi
_events_delta=$((_events_after - _events_before))
echo "O7_CAUSATION events_max_delta=$_events_delta current_at_failure=$_current_at_failure fork_errno=$_fork_errno"
if [ "$_events_delta" -lt 1 ] || [ "$_current_at_failure" -lt 500 ] || [ "$_fork_errno" -ne 11 ]; then
    echo "O7_CAUSATION result=not_proven delta=$_events_delta current_at_failure=$_current_at_failure fork_errno=$_fork_errno want_errno=11"
    echo "O7_RESULT=INCONCLUSIVE"
    exit 2
fi
echo "O7_CAUSATION result=proven_by_pids_max"

if [ "$FAIL" -gt 0 ]; then
    echo "O7_RESULT=FAIL"
    exit 1
fi
echo "O7_RESULT=PASS"
exit 0
