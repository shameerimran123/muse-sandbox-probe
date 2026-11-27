#!/bin/sh
# O5 harness script - fixture setup verification + proxy-log verification
# Spec: O_TESTS_SPEC_V8.md, O5 (blocker G, 2026-11-25 ~23:30 PKT). Proposal:
# M8_PROPOSAL_V9.md Sec. 5.3, Sec. 8 O5.
# *** HARNESS-SIDE SCRIPT. Runs as ROOT on the VM, not as UID 1001. ***
# It is an IMPLEMENTED TEST, not a described harness step: the harness
# runs it before and after the workload o05.sh, and O5 passes only if
# the workload script PASSES and all three harness modes exit 0.
# NOT YET EXECUTED - written for review only.
#
# Usage:
#   o05_harness.sh setup  - BEFORE pre. ADDS both test-only entries:
#                           (1) "127.0.0.1 o5-test-private.invalid"
#                           to /etc/hosts; (2) the anchored test-only
#                           line for that host to /opt/proxy/filter.
#                           Idempotent: any existing test-host line is
#                           removed first, then exactly one of each is
#                           appended. Verifies both entries are present
#                           after insertion and records the production
#                           allow-list SHA-256. (Blocker G, 2026-11-25
#                           ~23:04 PKT: in V5 this script only VERIFIED
#                           entries the harness was described as adding;
#                           the addition is now an implemented mode of
#                           this script, not a described harness step.)
#   o05_harness.sh pre    - BEFORE the workload o05.sh. VERIFIES the
#                           test-only fixture exists: (1) /etc/hosts
#                           resolves o5-test-private.invalid to
#                           127.0.0.1; (2) the proxy filter contains the
#                           test-only allow-list entry for that host;
#                           (3) records the production allow-list
#                           SHA-256 (the filter hash with the test-only
#                           line removed) for the post check. Pre does
#                           NOT add anything - setup does that.
#   o05_harness.sh post   - AFTER the workload o05.sh. Verifies from
#                           the proxy log that the (f3) denial was for
#                           the resolved IP (exactly one log entry for
#                           that host, reason=resolved-private-ip) and
#                           that (f1) produced a single proxy-log entry
#                           for github.com (the proxy made no second
#                           request, i.e. it did not follow the
#                           redirect); then REMOVES both test-only
#                           entries and re-verifies the production
#                           allow-list SHA-256. LOG ISOLATION (blocker G,
#                           2026-11-25 ~23:30 PKT): post greps ONLY the
#                           log lines written after the marker setup
#                           recorded (the line count of the proxy log at
#                           setup time) - entries from earlier tests
#                           (e.g. O3's proxy requests) can no longer
#                           contaminate the counts; a log shorter than
#                           the marker (truncated/rotated) is
#                           INCONCLUSIVE. Cleanup is GUARANTEED on
#                           every exit path (blocker G, 2026-11-25
#                           ~23:04 PKT): post installs
#                           `trap cleanup_entries EXIT` before doing
#                           anything else, so the entries are removed
#                           even if the log verification fails or the
#                           script exits early; AND the runner
#                           (run_batch.sh vm mode) runs the whole O5
#                           sequence inside a subshell with
#                           `trap 'o05_harness.sh post' EXIT` in code,
#                           so post runs even if setup, pre, or the
#                           workload script fails. Post is idempotent
#                           and safe to run twice: removing
#                           already-removed entries is a no-op, and the
#                           removal verification passes.
#
# The proxy re-reads the filter on every CONNECT and getaddrinfo
# re-reads /etc/hosts on every resolution, so the entries take effect
# without restarting the proxy.
#
# Result lines: O5_HARNESS_SETUP result=ok|inconclusive;
#               O5_HARNESS_PRE result=ok|inconclusive;
#               O5_HARNESS_POST result=ok|fail|inconclusive.
# Exit: 0 = ok, 1 = fail, 2 = error/inconclusive. This script prints no
# O5_RESULT line - the verdict is the workload o05.sh combined with
# these three modes (spec V5 O5).
#
# Environment (set by the harness; defaults are the proposal paths):
#   PROXY_FILTER  Path to the proxy allow-list filter file
#                 (default /opt/proxy/filter).
#   PROXY_LOG     Path to the proxy log file
#                 (default /var/log/m8-proxy.log).
#   HOSTS_FILE    Path to the hosts file (default /etc/hosts).
#   ALLOWLIST_HASH_FILE
#                 Path where setup/pre record the production allow-list
#                 SHA-256 (default /opt/harness/allowlist.prod.sha256).
#   O5_LOG_MARKER_FILE
#                 Path where setup records the proxy-log line count at
#                 setup time (default /opt/harness/o5_log_marker).
#                 Post greps only the log lines after this marker
#                 (log isolation, blocker G, 2026-11-25 ~23:30 PKT).
set -u

TEST_HOST="o5-test-private.invalid"
TEST_IP="127.0.0.1"
# The sed removal below needs a regex-escaped host (dots are regex
# wildcards); grep -F needs no escaping.
PROXY_FILTER=${PROXY_FILTER:-/opt/proxy/filter}
PROXY_LOG=${PROXY_LOG:-/var/log/m8-proxy.log}
HOSTS_FILE=${HOSTS_FILE:-/etc/hosts}
ALLOWLIST_HASH_FILE=${ALLOWLIST_HASH_FILE:-/opt/harness/allowlist.prod.sha256}
O5_LOG_MARKER_FILE=${O5_LOG_MARKER_FILE:-/opt/harness/o5_log_marker}

mode=${1:-}
if [ "$mode" != "setup" ] && [ "$mode" != "pre" ] && [ "$mode" != "post" ]; then
    echo "O5_HARNESS_ERROR=usage: o05_harness.sh setup|pre|post"
    exit 2
fi

# Sanity: the harness runs as root.
if [ "$(id -u 2>/dev/null)" != "0" ]; then
    echo "O5_HARNESS_ERROR=not running as root (got $(id -u 2>/dev/null || echo unknown))"
    exit 2
fi

for _tool in grep sha256sum sed; do
    if ! command -v "$_tool" >/dev/null 2>&1; then
        echo "O5_HARNESS_ERROR=required tool missing: $_tool"
        exit 2
    fi
done

# The test-only filter line, exactly as the proxy expects it: anchored,
# the test host only. This is the one line setup appends and post
# removes. (The production filter has five anchored regexes, proposal
# Sec. 5.3; the test-only line is a sixth, temporary, anchored line.)
TEST_FILTER_LINE="^o5-test-private\\.invalid$"
_host_re=$(printf '%s' "$TEST_HOST" | sed 's/\./\\./g')

# prod_allowlist_hash: the SHA-256 of the filter file with every
# test-only line (any line mentioning the test host) removed. Computed
# the same way in setup/pre (recorded) and post (re-verified), so a
# changed production allow-list is caught even though the test line
# comes and goes.
prod_allowlist_hash() {
    # Exclude the exact test filter LINE (the regex), not the
    # literal host: the regex contains a backslash-dot, so a
    # fixed-string search for the plain-dot host does not match
    # it, and the test line would be included in the "production"
    # hash (Revision 8 fix - V7 recorded a 6-line hash, so post
    # always reported prod_allowlist_hash_mismatch).
    grep -v -F "$TEST_FILTER_LINE" "$PROXY_FILTER" 2>/dev/null | sha256sum | awk '{print $1}'
}

# cleanup_entries: remove every line mentioning the test host from
# /etc/hosts and from the proxy filter. Idempotent: if no such line
# exists, sed succeeds with no change. Never calls exit (it is also
# the EXIT trap body in post mode); failures are reported on stdout
# and counted by the caller through the re-verification greps.
cleanup_entries() {
    # Rewrite each file IN PLACE (grep -v to a temp file, then cat
    # back). sed -i renames a temp file over the target, which FAILS
    # on /etc/hosts in the mock VM (single-file bind mount - the rename
    # over a mount point is refused). cat > truncates and writes in
    # place, which works. Fixed-string match on the exact lines (the
    # old sed regex did not match the backslash-dot in the filter
    # regex line, so the filter entry was never removed).
    # (Revision 8 fix, found by the dry-run.)
    _tmp=$(mktemp /tmp/o5_cleanup.XXXXXX 2>/dev/null) || { echo "O5_HARNESS_CLEANUP mktemp_failed"; return 1; }
    grep -v -F "$TEST_HOST" "$HOSTS_FILE" > "$_tmp" 2>/dev/null
    _grc=$?
    if [ "$_grc" -eq 0 ] || [ "$_grc" -eq 1 ]; then
        cat "$_tmp" > "$HOSTS_FILE" 2>/dev/null || echo "O5_HARNESS_CLEANUP hosts_write_failed"
    else
        echo "O5_HARNESS_CLEANUP hosts_grep_failed"
    fi
    grep -v -F "$TEST_FILTER_LINE" "$PROXY_FILTER" > "$_tmp" 2>/dev/null
    _grc=$?
    if [ "$_grc" -eq 0 ] || [ "$_grc" -eq 1 ]; then
        cat "$_tmp" > "$PROXY_FILTER" 2>/dev/null || echo "O5_HARNESS_CLEANUP filter_write_failed"
    else
        echo "O5_HARNESS_CLEANUP filter_grep_failed"
    fi
    rm -f "$_tmp" 2>/dev/null || true
}

# record_prod_hash: compute the production allow-list hash and record
# it to ALLOWLIST_HASH_FILE. Returns 0 on success, 1 on failure.
record_prod_hash() {
    _hash=$(prod_allowlist_hash) || return 1
    [ -n "$_hash" ] || return 1
    printf '%s\n' "$_hash" > "$ALLOWLIST_HASH_FILE" || return 1
    echo "O5_HARNESS prod_allowlist_sha256=$_hash"
    return 0
}

case "$mode" in
setup)
    # (1) Remove any stale test-host line first (idempotency: setup
    # run twice must not duplicate the entries), then append exactly
    # one hosts entry and exactly one filter entry.
    cleanup_entries
    if ! printf '%s %s\n' "$TEST_IP" "$TEST_HOST" >> "$HOSTS_FILE"; then
        echo "O5_HARNESS_SETUP result=inconclusive detail=hosts_append_failed"
        exit 2
    fi
    if ! printf '%s\n' "$TEST_FILTER_LINE" >> "$PROXY_FILTER"; then
        echo "O5_HARNESS_SETUP result=inconclusive detail=filter_append_failed"
        exit 2
    fi
    # (2) Verify exactly one of each entry is now present.
    # (Revision 8 fix: `grep -c` prints 0 AND exits 1 on no match,
    # so `|| echo 0` produced "0\n0" and `[ ... -ne 1 ]` failed with
    # "Illegal number: 0". `|| true` keeps the single printed 0.)
    _hosts_n=$(grep -c -F "$TEST_HOST" "$HOSTS_FILE" 2>/dev/null || true)
    # The filter line is a REGEX (^o5-test-private\.invalid$), not
    # the literal host, so grep for the exact filter line, not
    # TEST_HOST (a fixed-string search for the literal host does not
    # match the backslash-dot in the regex - V7 found 0 entries).
    _filter_n=$(grep -c -F "$TEST_FILTER_LINE" "$PROXY_FILTER" 2>/dev/null || true)
    echo "O5_HARNESS_SETUP hosts_entries=${_hosts_n:-0} filter_entries=${_filter_n:-0}"
    if [ "${_hosts_n:-0}" -ne 1 ] || [ "${_filter_n:-0}" -ne 1 ]; then
        echo "O5_HARNESS_SETUP result=inconclusive detail=fixture_count_not_one"
        exit 2
    fi
    # (3) Verify the hosts entry resolves to 127.0.0.1 (same check as
    # pre) and record the production allow-list hash.
    _resolved=""
    if command -v getent >/dev/null 2>&1; then
        _resolved=$(getent hosts "$TEST_HOST" 2>/dev/null | awk '{print $1}')
    fi
    echo "O5_HARNESS_SETUP resolved_ip=${_resolved:-none}"
    if [ "$_resolved" != "$TEST_IP" ]; then
        echo "O5_HARNESS_SETUP result=inconclusive detail=hosts_fixture_not_resolving"
        exit 2
    fi
    if ! record_prod_hash; then
        echo "O5_HARNESS_SETUP result=inconclusive detail=cannot_record_hash"
        exit 2
    fi
    # (4) Record the proxy-log line count at setup time (log isolation,
    # blocker G, 2026-11-25 ~23:30 PKT): post greps only the lines
    # written after this marker, so entries from earlier tests cannot
    # contaminate the (f3)/(f1) counts. A missing log records 0.
    _log_lines=$(wc -l < "$PROXY_LOG" 2>/dev/null || echo 0)
    case "$_log_lines" in ''|*[!0-9]*) _log_lines=0 ;; esac
    if ! printf '%s\n' "$_log_lines" > "$O5_LOG_MARKER_FILE"; then
        echo "O5_HARNESS_SETUP result=inconclusive detail=cannot_record_marker"
        exit 2
    fi
    echo "O5_HARNESS_SETUP proxy_log_lines_before=$_log_lines"
    echo "O5_HARNESS_SETUP result=ok"
    exit 0
    ;;
pre)
    # (1) /etc/hosts must resolve the test host to 127.0.0.1. getent
    # is the resolution check (it reads /etc/hosts); the grep is the
    # belt-and-braces file check. Either failing means the fixture is
    # not in place. Pre does NOT add the entries - setup does that;
    # a missing entry here means setup did not run or did not work.
    _resolved=""
    if command -v getent >/dev/null 2>&1; then
        _resolved=$(getent hosts "$TEST_HOST" 2>/dev/null | awk '{print $1}')
    fi
    if grep -q -F "$TEST_HOST" "$HOSTS_FILE" 2>/dev/null; then
        _hosts_entry=present
    else
        _hosts_entry=absent
    fi
    echo "O5_HARNESS_PRE hosts_entry=$_hosts_entry resolved_ip=${_resolved:-none}"
    if [ "$_hosts_entry" != "present" ] || [ "$_resolved" != "$TEST_IP" ]; then
        echo "O5_HARNESS_PRE result=inconclusive detail=hosts_fixture_missing_or_wrong"
        exit 2
    fi
    # (2) The proxy filter must contain the test-only allow-list entry.
    if grep -q -F "$TEST_FILTER_LINE" "$PROXY_FILTER" 2>/dev/null; then
        echo "O5_HARNESS_PRE filter_entry=present"
    else
        echo "O5_HARNESS_PRE filter_entry=absent"
        echo "O5_HARNESS_PRE result=inconclusive detail=filter_fixture_missing"
        exit 2
    fi
    # (3) Record the production allow-list hash (test line excluded).
    # (Setup already recorded it; pre re-records it so a run that
    # skips setup still has a recorded hash for post to check.)
    if ! record_prod_hash; then
        echo "O5_HARNESS_PRE result=inconclusive detail=cannot_record_hash"
        exit 2
    fi
    # (4) The log marker must exist (setup recorded it). If it is
    # absent (setup was skipped), record it now as a fallback - the
    # marker is then at pre time, still before the workload, so the
    # isolation still holds. If the log is shorter than the marker,
    # it was truncated/rotated: INCONCLUSIVE.
    if [ ! -f "$O5_LOG_MARKER_FILE" ]; then
        _log_lines=$(wc -l < "$PROXY_LOG" 2>/dev/null || echo 0)
        case "$_log_lines" in ''|*[!0-9]*) _log_lines=0 ;; esac
        if ! printf '%s\n' "$_log_lines" > "$O5_LOG_MARKER_FILE"; then
            echo "O5_HARNESS_PRE result=inconclusive detail=cannot_record_marker"
            exit 2
        fi
        echo "O5_HARNESS_PRE proxy_log_marker=recorded_at_pre lines_before=$_log_lines"
    else
        _marker=$(cat "$O5_LOG_MARKER_FILE" 2>/dev/null)
        _log_total=$(wc -l < "$PROXY_LOG" 2>/dev/null || echo 0)
        case "$_marker" in ''|*[!0-9]*) _marker="" ;; esac
        case "$_log_total" in ''|*[!0-9]*) _log_total=0 ;; esac
        if [ -z "$_marker" ] || [ "$_log_total" -lt "$_marker" ]; then
            echo "O5_HARNESS_PRE result=inconclusive detail=log_marker_invalid_or_log_truncated"
            exit 2
        fi
        echo "O5_HARNESS_PRE proxy_log_marker=verified lines_before=$_marker"
    fi
    echo "O5_HARNESS_PRE result=ok"
    exit 0
    ;;
post)
    FAIL=0
    INCONCLUSIVE=0
    # Guaranteed cleanup (blocker G, 2026-11-25 ~23:04 PKT): install
    # the EXIT trap FIRST, before any verification, so the test-only
    # entries are removed on every exit path of this mode - including
    # an early exit below and a signal-driven exit. The trap body
    # never calls exit, so the script still exits with the verdict
    # code set at the end. The runner ALSO runs the whole O5 sequence
    # inside a subshell with its own EXIT trap that calls post
    # (run_batch.sh vm mode, spec V6 O5), so post runs even if setup,
    # pre, or the workload script fails.
    trap cleanup_entries EXIT
    # (1) The proxy log must show EXACTLY ONE entry for the test host,
    # and its denial reason must be resolved-private-ip. Zero entries
    # means no evidence (inconclusive); a different reason (e.g.
    # not-allow-listed) means the 403 did not prove the resolved-IP
    # check (FAIL); more than one entry means the host was requested
    # more than once (FAIL - the workload requests it once). NOTE: no
    # early exit here - the verdict is recorded in flags and the
    # script continues to cleanup (step 3) before exiting.
    # LOG ISOLATION (blocker G, 2026-11-25 ~23:30 PKT): every count
    # below is taken ONLY from the log lines written after the marker
    # setup recorded (or pre recorded as fallback). Entries from
    # earlier tests are excluded - the V6 code grepped the whole log,
    # so an old entry for the test host or github.com could
    # contaminate the counts. A missing/invalid marker, or a log
    # shorter than the marker (truncated/rotated), is INCONCLUSIVE.
    if [ ! -f "$PROXY_LOG" ]; then
        echo "O5_HARNESS_POST result=inconclusive detail=proxy_log_missing"
        INCONCLUSIVE=1
    elif [ ! -f "$O5_LOG_MARKER_FILE" ]; then
        echo "O5_HARNESS_POST result=inconclusive detail=log_marker_missing"
        INCONCLUSIVE=1
    else
        _marker=$(cat "$O5_LOG_MARKER_FILE" 2>/dev/null)
        _log_total=$(wc -l < "$PROXY_LOG" 2>/dev/null || echo 0)
        case "$_marker" in ''|*[!0-9]*) _marker="" ;; esac
        case "$_log_total" in ''|*[!0-9]*) _log_total=0 ;; esac
        if [ -z "$_marker" ] || [ "$_log_total" -lt "$_marker" ]; then
            echo "O5_HARNESS_POST result=inconclusive detail=log_marker_invalid_or_log_truncated"
            INCONCLUSIVE=1
        else
            _slice_lines=$((_log_total - _marker))
            echo "O5_HARNESS_POST log_slice_lines=$_slice_lines marker=$_marker"
            _f3_total=$(tail -n +$((_marker + 1)) "$PROXY_LOG" 2>/dev/null | grep -c -F "$TEST_HOST")
            _f3_reason=$(tail -n +$((_marker + 1)) "$PROXY_LOG" 2>/dev/null | grep -F "$TEST_HOST" | grep -c 'reason=resolved-private-ip')
            echo "O5_HARNESS_POST f3_entries=${_f3_total:-0} f3_resolved_private_ip=${_f3_reason:-0}"
            if [ "${_f3_total:-0}" -eq 0 ]; then
                echo "O5_HARNESS_POST detail=no_f3_log_entry"
                INCONCLUSIVE=1
            elif [ "${_f3_total:-0}" -ne 1 ]; then
                echo "O5_HARNESS_POST detail=f3_entry_count_not_one count=${_f3_total:-0}"
                FAIL=1
            elif [ "${_f3_reason:-0}" -ne 1 ]; then
                echo "O5_HARNESS_POST detail=f3_reason_not_resolved_private_ip"
                FAIL=1
            else
                echo "O5_HARNESS_POST f3=verified reason=resolved-private-ip"
            fi
            # (2) (f1) no-follow: exactly ONE proxy-log entry for github.com
            # in the isolated slice. The workload requests
            # https://github.com once (f1). A second entry would mean
            # the proxy followed the redirect itself (FAIL). Zero
            # entries means no evidence (inconclusive).
            # Count ONLY the exact f1 allow line. A substring
            # search for 'github.com:443' also matches the (e)
            # evasion entry 'evil-github.com:443' and counts 2.
            # (Revision 8 fix, found by the dry-run.)
            _f1_total=$(tail -n +$((_marker + 1)) "$PROXY_LOG" 2>/dev/null | grep -c -F 'CONNECT github.com:443')
            echo "O5_HARNESS_POST f1_github_entries=${_f1_total:-0}"
            if [ "${_f1_total:-0}" -eq 0 ]; then
                echo "O5_HARNESS_POST detail=no_f1_log_entry"
                INCONCLUSIVE=1
            elif [ "${_f1_total:-0}" -ne 1 ]; then
                echo "O5_HARNESS_POST detail=f1_entry_count_not_one count=${_f1_total:-0}"
                FAIL=1
            else
                echo "O5_HARNESS_POST f1=verified single_entry"
            fi
        fi
    fi
    # (3) Remove both test-only entries (explicitly, in addition to
    # the EXIT trap - the trap is the backstop if this step is
    # skipped), then verify they are gone. A leftover test entry
    # would contaminate the production allow-list for every later
    # case, so a failed removal is FAIL.
    cleanup_entries
    if grep -q -F "$TEST_HOST" "$HOSTS_FILE" 2>/dev/null; then
        echo "O5_HARNESS_POST detail=hosts_entry_remains"
        FAIL=1
    fi
    if grep -q -F "$TEST_FILTER_LINE" "$PROXY_FILTER" 2>/dev/null; then
        echo "O5_HARNESS_POST detail=filter_entry_remains"
        FAIL=1
    fi
    # (4) Re-verify the production allow-list hash against the value
    # setup/pre recorded. A mismatch means the production allow-list
    # changed during O5 (FAIL).
    if [ ! -f "$ALLOWLIST_HASH_FILE" ]; then
        echo "O5_HARNESS_POST detail=recorded_hash_missing"
        INCONCLUSIVE=1
    else
        _want=$(cat "$ALLOWLIST_HASH_FILE" 2>/dev/null)
        _got=$(prod_allowlist_hash)
        if [ -z "$_want" ] || [ -z "$_got" ]; then
            echo "O5_HARNESS_POST detail=cannot_hash_filter"
            INCONCLUSIVE=1
        elif [ "$_got" != "$_want" ]; then
            echo "O5_HARNESS_POST detail=prod_allowlist_hash_mismatch"
            FAIL=1
        else
            echo "O5_HARNESS_POST prod_allowlist_sha256=verified"
        fi
    fi
    if [ "$INCONCLUSIVE" -gt 0 ]; then
        echo "O5_HARNESS_POST result=inconclusive"
        exit 2
    fi
    if [ "$FAIL" -gt 0 ]; then
        echo "O5_HARNESS_POST result=fail"
        exit 1
    fi
    echo "O5_HARNESS_POST result=ok"
    exit 0
    ;;
esac
