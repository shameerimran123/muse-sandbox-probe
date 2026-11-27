#!/bin/sh
# O10 - Persistence (threat T4)
# Spec: O_TESTS_SPEC_V8.md, O10. Environment: M8_PROPOSAL_V9.md Sec. 4.4.
# Runs as UID 1001 inside the sandbox. The harness invokes it via the
# Sec. 4.2 sandbox command. NOT YET EXECUTED - written for review only.
#
# Purpose: verify nothing survives a case except the declared results.
#
# Two modes (the harness runs them in TWO DIFFERENT CASES):
#   o10.sh write   - case N: writes the sentinel file into /work.
#                    Prints O10_SENTINEL_WRITTEN and the token. Exits 0
#                    if the write succeeded, 2 on error. (The write mode
#                    has no PASS/FAIL verdict of its own - it sets up
#                    the test.)
#   o10.sh check   - case N+1 (fresh cgroup, fresh loopback image):
#                    checks for the sentinel.
#                    PASS: the sentinel is absent. Nothing survives
#                    except the declared results (written by the harness).
#                    FAIL: the sentinel is present.
#                    INCONCLUSIVE (exit 2): the script errors, times out,
#                    or the second case cannot be run.
#
# Exit (check mode): 0 = PASS, 1 = FAIL, 2 = error/inconclusive.
# Result line (check mode): O10_RESULT=PASS | FAIL | INCONCLUSIVE
#
# WARNING: write and check MUST run in different cases (fresh loopback
# image between them). Running check in the same case as write will
# always find the sentinel and report FAIL - that is a harness error,
# not a persistence failure. See O_TESTS_README.md.
set -u

SENTINEL=/work/.o10_sentinel

# Sanity: this test is only meaningful as the workload user.
if [ "$(id -u 2>/dev/null)" != "1001" ]; then
    echo "O10_ERROR=not running as UID 1001 (got $(id -u 2>/dev/null || echo unknown))"
    exit 2
fi

mode=${1:-}
case "$mode" in
    write)
        _token="o10-$(date +%s)-$$"
        if printf '%s\n' "$_token" > "$SENTINEL" 2>/dev/null; then
            echo "O10_SENTINEL_WRITTEN token=$_token"
            exit 0
        else
            echo "O10_ERROR=cannot write $SENTINEL"
            exit 2
        fi
        ;;
    check)
        if [ -e "$SENTINEL" ]; then
            echo "O10_SENTINEL result=present content=$(cat "$SENTINEL" 2>/dev/null || echo unreadable)"
            echo "O10_RESULT=FAIL"
            exit 1
        else
            echo "O10_SENTINEL result=absent"
            echo "O10_RESULT=PASS"
            exit 0
        fi
        ;;
    *)
        echo "O10_ERROR=usage: o10.sh write|check"
        exit 2
        ;;
esac
