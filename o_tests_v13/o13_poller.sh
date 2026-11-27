#!/bin/sh
# o13_poller.sh - host-side lifecycle-state poller for O13
# Spec: O_TESTS_SPEC_V8.md, O13 (blocker L, 2026-11-25 ~23:04 PKT;
# liveness check after TERMINATED, 2026-11-25 ~23:30 PKT; liveness
# count corrected to THREE, 2026-11-26 ~00:15 PKT).
# Proposal: M8_PROPOSAL_V9.md Sec. 11.4.
#
# *** HOST-SIDE SCRIPT. It does NOT run on the VM and NOT as UID 1001. ***
# It runs on the host (the coordinator machine) from the moment the
# batch VM is created until the instance is TERMINATED, polling the
# instance lifecycle-state every 30 seconds and appending one line per
# poll to INSTANCE_STATE_LOG:
#   ISO_TIMESTAMP STATE
# where STATE is an OCI lifecycle state (PROVISIONING, RUNNING,
# STOPPING, STOPPED, TERMINATING, TERMINATED) or QUERY_FAILED (a
# transient OCI API failure on that poll - the poller keeps polling;
# QUERY_FAILED lines are skipped by the O13 parsers, which look only
# for exact STOPPED / TERMINATED states).
#
# This script is the IMPLEMENTED poller, not a described step: the
# harness starts it at VM creation (background, PID recorded in the
# run manifest) and it is the ONLY writer of INSTANCE_STATE_LOG. The
# controller (the Muse cron job, Sec. 11.4) does NOT write to this
# log - it writes only its own run record, and runs its own bounded
# 600 s poll after issuing terminate. O13 (e2) and (e4) read this log
# and apply coverage rules: the log must show the poller was alive
# through the window it is used to prove, or the check is
# INCONCLUSIVE (a dead poller is a harness failure, not a VM failure).
#
# NOT YET EXECUTED - written for review only.
#
# Required environment variables (set by the harness; recorded in the
# run manifest before the VM is created):
#   INSTANCE_OCID       OCID of the batch VM.
#   INSTANCE_STATE_LOG  Path of the polling record to append to.
#                       The parent directory must exist. The file is
#                       created if missing; if it already exists, this
#                       script APPENDS (it never truncates).
#   POLLER_DEADLINE     ISO 8601 UTC: stop polling after this time
#                       (test mode: creation + 150 minutes; production:
#                       creation + 25 hours). The poller must cover the
#                       VM-side timer deadline (creation + 90 min test
#                       mode) and the controller firing (creation +
#                       120 min test mode) with margin.
# Optional:
#   OCI_CLI             OCI CLI to use (default: oci).
#   POLL_INTERVAL       Seconds between polls (default: 30).
#
# Exit: 0 = TERMINATED was observed AND THREE liveness queries
#       after termination each returned TERMINATED (blocker L,
#       2026-11-26 ~00:15 PKT - the V7 poller exited 0 on the FIRST
#       successful liveness query, although the spec requires three;
#       see the liveness loop below). 2 = error or timeout: the OCI
#       query failed 10 times in a row, the deadline passed without
#       TERMINATED, a required variable/tool is missing, the liveness
#       check after TERMINATED failed (fewer than 3 successful
#       liveness queries in 3 attempts, the liveness deadline passed,
#       or a liveness query returned a different valid state - a
#       state regression), or the log could not be appended. The log
#       written up to that point is left in place - O13's coverage
#       rules decide whether it proves anything. This script prints
#       no O13_RESULT line - the verdict is o13.sh.
#
# Harness liveness checks (proposal Sec. 11.4): the harness checks
# the poller PID is alive (a) at batch start, (b) just before the
# VM-side timer deadline, and (c) after termination, and records each
# check with a timestamp in the batch record. If any liveness check
# fails, the batch is INVALID (not a pass) - a dead poller cannot
# evidence the STOPPED or TERMINATED transitions.
set -u

for _v in INSTANCE_OCID INSTANCE_STATE_LOG POLLER_DEADLINE; do
    eval "_val=\${$_v:-}"
    if [ -z "$_val" ]; then
        echo "O13_POLLER_ERROR=required variable unset: $_v" >&2
        exit 2
    fi
done
OCI_CLI=${OCI_CLI:-oci}
POLL_INTERVAL=${POLL_INTERVAL:-30}
case "$POLL_INTERVAL" in ''|*[!0-9]*) echo "O13_POLLER_ERROR=POLL_INTERVAL not a number: $POLL_INTERVAL" >&2; exit 2 ;; esac
if [ "$POLL_INTERVAL" -lt 1 ]; then
    echo "O13_POLLER_ERROR=POLL_INTERVAL must be >= 1" >&2
    exit 2
fi

for _tool in "$OCI_CLI" date; do
    if ! command -v "$_tool" >/dev/null 2>&1; then
        echo "O13_POLLER_ERROR=required tool missing: $_tool" >&2
        exit 2
    fi
done

_logdir=$(dirname "$INSTANCE_STATE_LOG")
if [ ! -d "$_logdir" ]; then
    echo "O13_POLLER_ERROR=log directory missing: $_logdir" >&2
    exit 2
fi
if [ -e "$INSTANCE_STATE_LOG" ] && [ ! -f "$INSTANCE_STATE_LOG" ]; then
    echo "O13_POLLER_ERROR=log path is not a regular file: $INSTANCE_STATE_LOG" >&2
    exit 2
fi
# The log must be appendable. If it already has content, that is a
# harness restart (appending is correct); warn on stderr but continue.
if [ -s "$INSTANCE_STATE_LOG" ]; then
    echo "O13_POLLER_WARN=log already non-empty, appending: $INSTANCE_STATE_LOG" >&2
fi
if ! touch "$INSTANCE_STATE_LOG" 2>/dev/null; then
    echo "O13_POLLER_ERROR=log not appendable: $INSTANCE_STATE_LOG" >&2
    exit 2
fi

# deadline_epoch: POLLER_DEADLINE as seconds since epoch (UTC). date -d
# parses ISO 8601; a deadline that cannot be parsed is a harness error.
_deadline_epoch=$(date -u -d "$POLLER_DEADLINE" +%s 2>/dev/null) || {
    echo "O13_POLLER_ERROR=POLLER_DEADLINE unparseable: $POLLER_DEADLINE" >&2
    exit 2
}
echo "O13_POLLER started instance=$INSTANCE_OCID interval_s=$POLL_INTERVAL deadline=$POLLER_DEADLINE log=$INSTANCE_STATE_LOG" >&2

_consec_fail=0
while true; do
    _now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    _now_epoch=$(date -u +%s)
    if [ "$_now_epoch" -gt "$_deadline_epoch" ]; then
        echo "O13_POLLER result=timeout deadline=$POLLER_DEADLINE" >&2
        exit 2
    fi
    if _state=$("$OCI_CLI" compute instance get --instance-id "$INSTANCE_OCID" \
        --query 'data."lifecycle-state"' --raw-output 2>/dev/null); then
        _consec_fail=0
        # The state must be a bare lifecycle-state token. Anything
        # else (empty, multi-word, JSON) is not a valid observation:
        # log it as QUERY_FAILED, not as a state.
        case "$_state" in
            PROVISIONING|RUNNING|STOPPING|STOPPED|TERMINATING|TERMINATED)
                printf '%s %s\n' "$_now" "$_state" >> "$INSTANCE_STATE_LOG" || {
                    echo "O13_POLLER_ERROR=cannot append to log" >&2
                    exit 2
                }
                ;;
            *)
                printf '%s QUERY_FAILED\n' "$_now" >> "$INSTANCE_STATE_LOG" || {
                    echo "O13_POLLER_ERROR=cannot append to log" >&2
                    exit 2
                }
                _consec_fail=$((_consec_fail + 1))
                ;;
        esac
        if [ "$_state" = "TERMINATED" ]; then
            # Liveness check AFTER termination (blocker L,
            # 2026-11-25 ~23:30 PKT; count corrected 2026-11-26
            # ~00:15 PKT): the poller must NOT exit immediately
            # after observing TERMINATED, and must NOT exit on the
            # FIRST successful liveness query either (that was the
            # V7 bug - the poller exited 0 after one confirmation
            # although the spec requires THREE). The proposal
            # requires THREE liveness queries after the termination
            # observation, proving the poller was still alive and
            # the instance still TERMINATED after it. Exactly 3
            # attempts, one POLL_INTERVAL apart; each must return
            # TERMINATED. A different valid state is a regression
            # (exit 2 immediately). A failed query is logged as
            # QUERY_FAILED and consumes one of the 3 attempts (it
            # is NOT retried beyond the 3 attempts). Only after 3
            # successful TERMINATED liveness observations does the
            # poller exit 0. Each liveness observation is appended
            # to the state log, so O13 (e4b) can check it.
            _live_attempt=0
            _live_ok=0
            while [ "$_live_attempt" -lt 3 ]; do
                sleep "$POLL_INTERVAL"
                _live_now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
                _live_now_epoch=$(date -u +%s)
                if [ "$_live_now_epoch" -gt "$_deadline_epoch" ]; then
                    echo "O13_POLLER result=liveness_deadline_exceeded attempts=$_live_attempt confirmed=$_live_ok" >&2
                    exit 2
                fi
                if _live_out=$("$OCI_CLI" compute instance get --instance-id "$INSTANCE_OCID" --query 'data."lifecycle-state"' --raw-output 2>/dev/null); then
                    case "$_live_out" in
                        TERMINATED)
                            if ! printf '%s %s\n' "$_live_now" "$_live_out" >> "$INSTANCE_STATE_LOG"; then
                                echo "O13_POLLER_ERROR=cannot append to log" >&2
                                exit 2
                            fi
                            # One of the three required confirmations.
                            # Do NOT exit here - the V7 bug was
                            # exiting 0 on this first success.
                            _live_ok=$((_live_ok + 1))
                            ;;
                        PROVISIONING|RUNNING|STOPPING|STOPPED|TERMINATING)
                            if ! printf '%s %s\n' "$_live_now" "$_live_out" >> "$INSTANCE_STATE_LOG"; then
                                echo "O13_POLLER_ERROR=cannot append to log" >&2
                                exit 2
                            fi
                            echo "O13_POLLER result=liveness_state_regressed state=$_live_out after_terminated_at=$_now attempts=$_live_attempt confirmed=$_live_ok" >&2
                            exit 2
                            ;;
                        *)
                            printf '%s QUERY_FAILED\n' "$_live_now" >> "$INSTANCE_STATE_LOG" || {
                                echo "O13_POLLER_ERROR=cannot append to log" >&2
                                exit 2
                            }
                            ;;
                    esac
                else
                    printf '%s QUERY_FAILED\n' "$_live_now" >> "$INSTANCE_STATE_LOG" || {
                        echo "O13_POLLER_ERROR=cannot append to log" >&2
                        exit 2
                    }
                fi
                _live_attempt=$((_live_attempt + 1))
            done
            if [ "$_live_ok" -eq 3 ]; then
                echo "O13_POLLER result=terminated_liveness_confirmed observed_at=$_now confirmed_at=$_live_now liveness_confirmed=3" >&2
                exit 0
            fi
            echo "O13_POLLER result=liveness_unconfirmed attempts=3 confirmed=$_live_ok" >&2
            exit 2
        fi
    else
        _consec_fail=$((_consec_fail + 1))
        printf '%s QUERY_FAILED\n' "$_now" >> "$INSTANCE_STATE_LOG" || {
            echo "O13_POLLER_ERROR=cannot append to log" >&2
            exit 2
        }
    fi
    if [ "$_consec_fail" -ge 10 ]; then
        echo "O13_POLLER result=query_failed_10_consecutive" >&2
        exit 2
    fi
    sleep "$POLL_INTERVAL"
done
