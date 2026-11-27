#!/bin/sh
# O2 - Filesystem write boundary (threat T1)
# Spec: O_TESTS_SPEC_V8.md, O2. Environment: M8_PROPOSAL_V9.md Sec. 4.4.
# Runs as UID 1001 inside the sandbox. The harness invokes it via the
# Sec. 4.2 sandbox command. NOT YET EXECUTED - written for review only.
#
# Purpose: attempt, from the workload UID, to write outside /work.
# Every write must fail (permission denied / read-only filesystem).
#
# PASS: every write fails. Nothing is written outside the work image.
# FAIL: any write succeeds, or any new file appears outside /work.
# INCONCLUSIVE (exit 2): the script errors, times out, or the post-test
# verification cannot be performed.
#
# Exit: 0 = PASS, 1 = FAIL, 2 = error/inconclusive.
# Result line: O2_RESULT=PASS | FAIL | INCONCLUSIVE
#
# HARNESS HALF (not in this script - the workload cannot verify it):
# after this script runs, the harness (root) verifies that no new file
# exists at any of the four paths below. If a file exists, O2 is FAIL
# regardless of what this script printed. Exact procedure:
#   test ! -e /usr/o2_test && test ! -e /etc/o2_test \
#     && test ! -e /results/o2_test && test ! -e /opt/harness/o2_test
# See O_TESTS_README.md.
# A file that succeeded in being written is deliberately NOT removed by
# this script - removing it would hide the evidence.
set -u

FAIL=0
INCONCLUSIVE=0

# Sanity: this test is only meaningful as the workload user.
if [ "$(id -u 2>/dev/null)" != "1001" ]; then
    echo "O2_ERROR=not running as UID 1001 (got $(id -u 2>/dev/null || echo unknown))"
    echo "O2_RESULT=INCONCLUSIVE"
    exit 2
fi

# attempt_write <path>
# If the path already exists before the attempt, that is itself evidence
# a previous write succeeded - FAIL. Otherwise try to create it; success
# is FAIL, failure is the expected (denied) outcome.
attempt_write() {
    _path=$1
    if [ -e "$_path" ]; then
        echo "O2_ATTEMPT path=$_path result=already_exists"
        FAIL=1
        return
    fi
    if printf 'o2-probe\n' > "$_path" 2>/dev/null; then
        echo "O2_ATTEMPT path=$_path result=writable"
        FAIL=1
    else
        echo "O2_ATTEMPT path=$_path result=denied"
    fi
}

attempt_write /usr/o2_test
attempt_write /etc/o2_test
attempt_write /results/o2_test
attempt_write /opt/harness/o2_test

if [ "$INCONCLUSIVE" -gt 0 ]; then
    echo "O2_RESULT=INCONCLUSIVE"
    exit 2
fi
if [ "$FAIL" -gt 0 ]; then
    echo "O2_RESULT=FAIL"
    exit 1
fi
echo "O2_RESULT=PASS"
exit 0
