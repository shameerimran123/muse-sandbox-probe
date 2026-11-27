#!/bin/sh
# O1 - Filesystem read boundary (threat T1)
# Spec: O_TESTS_SPEC_V8.md, O1. Environment: M8_PROPOSAL_V9.md Sec. 4.4.
# Runs as UID 1001 inside the sandbox. The harness invokes it via the
# Sec. 4.2 sandbox command. NOT YET EXECUTED - written for review only.
#
# Purpose: attempt, from the workload UID, to read files and directories
# outside the work directory. Every attempted read of a forbidden path must
# fail (permission denied).
#
# PASS: every protected path EXISTS (spec V4 rule 11 - absence is
# INCONCLUSIVE, not a pass) and every attempted read of it fails.
# /opt/harness and /opt/proxy must be mode 0710 (real) or 0711 (mock) (Revision 8 - was 0700 in V7, which broke the proxy/results server).
# /tmp must be the 1 GiB tmpfs (spec V4 rule 13, O1): df -B1 /tmp
# reports a total of exactly 1073741824 bytes (+/- 1 MiB) and the
# mount source is tmpfs (the harness pre-mounts
# tmpfs -o size=1G,mode=1777 at /opt/stage/tmp and the sandbox binds
# it to /tmp; bwrap --tmpfs takes no size argument and is NOT used).
# /tmp must be the 1 GiB tmpfs (spec V4 rule 13, O1): df -B1 /tmp
# reports a total of exactly 1073741824 bytes (+/- 1 MiB) and the
# mount source is tmpfs (the harness pre-mounts
# tmpfs -o size=1G,mode=1777 at /opt/stage/tmp and the sandbox binds
# it to /tmp; bwrap --tmpfs takes no size argument and is NOT used).
# /tmp must be the 1 GiB tmpfs (spec V4 rule 13, O1): df -B1 /tmp
# reports a total of exactly 1073741824 bytes (+/- 1 MiB) and the
# mount source is tmpfs (the harness pre-mounts
# tmpfs -o size=1G,mode=1777 at /opt/stage/tmp and the sandbox binds
# it to /tmp; bwrap --tmpfs takes no size argument and is NOT used).
# FAIL: any forbidden read succeeds, or /opt/harness or /opt/proxy is
# not mode 0710 (real) or 0711 (mock).
# INCONCLUSIVE (exit 2): the script errors, times out, any protected
# path does not exist, or no readable record of each attempt is produced.
#
# Exit: 0 = PASS, 1 = FAIL, 2 = error/inconclusive.
# Result line: O1_RESULT=PASS | FAIL | INCONCLUSIVE
set -u

FAIL=0
INCONCLUSIVE=0

# Sanity: this test is only meaningful as the workload user.
if [ "$(id -u 2>/dev/null)" != "1001" ]; then
    echo "O1_ERROR=not running as UID 1001 (got $(id -u 2>/dev/null || echo unknown))"
    echo "O1_RESULT=INCONCLUSIVE"
    exit 2
fi

# check_mode <path>
# /opt/harness and /opt/proxy must be mode 0710 (real VM, root:proxy /
# root:harness - the proxy UID 1002 and results UID 1000 must traverse
# their own directory) or 0711 (mock VM - this host's overlay cannot
# chown a directory to a non-root owner, so the mock cannot set the
# group). Mode 0700 is the OLD broken mode (V7): the proxy and results
# server could not read their own source, so they never started - it
# is FAIL, not PASS. Any other mode is FAIL. A missing path is
# INCONCLUSIVE (rule 11). (Revision 8 fix, found by the dry-run.)
check_mode() {
    _path=$1
    if [ ! -e "$_path" ]; then
        echo "O1_MODE path=$_path result=absent"
        INCONCLUSIVE=1
        return
    fi
    _mode=$(stat -c %a "$_path" 2>/dev/null)
    if [ -z "$_mode" ]; then
        echo "O1_MODE path=$_path result=unreadable_mode"
        INCONCLUSIVE=1
        return
    fi
    echo "O1_MODE path=$_path mode=$_mode"
    if [ "$_mode" != "710" ] && [ "$_mode" != "711" ]; then
        echo "O1_MODE path=$_path result=not_0710_or_0711"
        FAIL=1
    fi
}

check_mode /opt/harness
check_mode /opt/proxy

# attempt_read <path>
# Tries to read the path the way its type requires: `cat` for a file,
# `ls` for a directory. (Plain `ls` on a single file succeeds by stat
# alone and proves nothing about readability, so it is never used here.)
# Prints O1_ATTEMPT <path> <denied|readable|absent>. Absence of a
# protected path is INCONCLUSIVE (spec V4 rule 11).
attempt_read() {
    _path=$1
    if [ -d "$_path" ]; then
        if ls "$_path" >/dev/null 2>&1; then
            echo "O1_ATTEMPT path=$_path result=readable"
            FAIL=1
        else
            echo "O1_ATTEMPT path=$_path result=denied"
        fi
    elif [ -e "$_path" ]; then
        if cat "$_path" >/dev/null 2>&1; then
            echo "O1_ATTEMPT path=$_path result=readable"
            FAIL=1
        else
            echo "O1_ATTEMPT path=$_path result=denied"
        fi
    else
        echo "O1_ATTEMPT path=$_path result=absent"
        INCONCLUSIVE=1
    fi
}

# Forbidden paths, per the spec. /etc/passwd is deliberately NOT listed:
# it is readable by design and is not a failure.
attempt_read /etc/shadow
attempt_read /root
attempt_read /home/harness
attempt_read /opt/harness
attempt_read /opt/proxy
attempt_read /var/lib/cloud/instance/user-data.txt

# /tmp size check (spec V4 rule 13, O1). df -B1 columns are:
# Filesystem 1B-blocks Used Available Use% Mounted on, so $1 is the
# mount source and $2 is the total size in bytes. A total outside
# 1073741824 +/- 1048576, or a source other than tmpfs, is FAIL (the
# environment is not as specified); an unreadable/unparseable df
# output is INCONCLUSIVE.
_tmp_df=$(df -B1 /tmp 2>/dev/null | awk 'NR==2 {print $1, $2}')
_tmp_src=$(printf '%s' "$_tmp_df" | awk '{print $1}')
_tmp_total=$(printf '%s' "$_tmp_df" | awk '{print $2}')
case "$_tmp_total" in
    ''|*[!0-9]*)
        echo "O1_TMPFS result=unreadable df_output=$_tmp_df"
        INCONCLUSIVE=1
        ;;
    *)
        echo "O1_TMPFS source=$_tmp_src total_bytes=$_tmp_total"
        if [ "$_tmp_src" != "tmpfs" ]; then
            echo "O1_TMPFS result=not_tmpfs"
            FAIL=1
        elif [ "$_tmp_total" -lt 1072693248 ] || [ "$_tmp_total" -gt 1074790400 ]; then
            echo "O1_TMPFS result=wrong_size want_bytes=1073741824 tolerance_bytes=1048576"
            FAIL=1
        else
            echo "O1_TMPFS result=ok"
        fi
        ;;
esac

if [ "$INCONCLUSIVE" -gt 0 ]; then
    echo "O1_RESULT=INCONCLUSIVE"
    exit 2
fi
if [ "$FAIL" -gt 0 ]; then
    echo "O1_RESULT=FAIL"
    exit 1
fi
echo "O1_RESULT=PASS"
exit 0
