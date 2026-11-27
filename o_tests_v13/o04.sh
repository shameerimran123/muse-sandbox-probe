#!/bin/sh
# O4 - Privilege boundary (threat T3)
# Spec: O_TESTS_SPEC_V8.md, O4. Environment: M8_PROPOSAL_V9.md Sec. 4.2, Sec. 4.3.
# Runs as UID 1001 inside the sandbox. The harness invokes it via the
# Sec. 4.2 sandbox command. NOT YET EXECUTED - written for review only.
#
# Purpose: verify the workload has no privilege-escalation path.
#
# PASS: every attempt in (a)-(d) and (i) fails; `sudo`/`su` fail;
# /var/run/docker.sock does not exist; the uid_map write fails; effective
# capabilities are 0 (CapEff 0000000000000000) and NoNewPrivs is 1;
# the cgroup-file write and the cgroup move fail (HARNESS HALF, see
# below); every read in (i) fails (and the paths exist, spec V4 rule 11).
# FAIL: any escalation attempt succeeds; CapEff is non-zero; NoNewPrivs
# is 0; any cgroup-file write or cgroup move succeeds (harness half);
# any read of /root, /home/harness, /proc/1/root, or the user-data file
# succeeds.
# INCONCLUSIVE (exit 2): the script errors, times out, NoNewPrivs /
# CapEff cannot be read, or a path that (i) requires to exist is absent.
#
# Exit: 0 = PASS, 1 = FAIL, 2 = error/inconclusive.
# Result line: O4_RESULT=PASS | FAIL | INCONCLUSIVE
#
# INTERPRETATION NOTE - spec item (b), "attempt to read /proc/1/":
# a plain directory listing of /proc/1/ and a read of /proc/1/cmdline are
# world-readable by kernel design (procfs default, hidepid not set) and
# are NOT a privilege-escalation path. This script therefore tests (b) as
# the SENSITIVE entries under /proc/1/ - /proc/1/root, /proc/1/cwd,
# /proc/1/environ, /proc/1/mem - which must all fail, and records the
# plain listing / cmdline read as OBSERVED lines only (not counted toward
# the verdict). No hidepid requirement. See O_TESTS_README.md.
#
# HARNESS HALF - spec items (g) and (h) (blocker A):
# Inside the sandbox the workload runs in a new cgroup namespace, so its
# own cgroup is the root of /sys/fs/cgroup and the parent path
# /sys/fs/cgroup/workload/ is not visible there. The write/move attempts
# are only meaningful OUTSIDE the namespace, where the path exists. The
# harness performs them as UID 1001 (same user, same permissions) and
# records the outcome. THEY ARE NOT IN THIS SCRIPT. Exact procedure
# (run by the harness as root, on the VM, outside the sandbox):
#   (g) setpriv --reuid=1001 --regid=1001 --clear-groups \
#         sh -c 'printf x > /sys/fs/cgroup/workload/o04_test && echo WRITABLE || echo DENIED'
#       Expected output: DENIED. WRITABLE is FAIL.
#   (h) setpriv --reuid=1001 --regid=1001 --clear-groups \
#         sh -c 'echo $PPID > /sys/fs/cgroup/cgroup.procs && echo MOVED || echo DENIED'
#       (the harness substitutes the workload PID for $PPID; the attempt
#       is to write the workload PID to the parent/root cgroup.procs.)
#       Expected output: DENIED. MOVED is FAIL.
# If either harness-half check cannot be performed, O4 is INCONCLUSIVE.
set -u

FAIL=0
INCONCLUSIVE=0

# Sanity: this test is only meaningful as the workload user.
if [ "$(id -u 2>/dev/null)" != "1001" ]; then
    echo "O4_ERROR=not running as UID 1001 (got $(id -u 2>/dev/null || echo unknown))"
    echo "O4_RESULT=INCONCLUSIVE"
    exit 2
fi

for _tool in unshare capsh; do
    if ! command -v "$_tool" >/dev/null 2>&1; then
        echo "O4_ERROR=required tool missing: $_tool"
        echo "O4_RESULT=INCONCLUSIVE"
        exit 2
    fi
done

# (a) sudo and su must both fail. If sudo is not installed at all, there
# is no sudo to exploit - recorded, still a pass for this sub-check.
if command -v sudo >/dev/null 2>&1; then
    if sudo -n true >/dev/null 2>&1; then
        echo "O4_SUDO result=succeeded"
        FAIL=1
    else
        echo "O4_SUDO result=failed"
    fi
else
    echo "O4_SUDO result=not_installed"
fi
if command -v su >/dev/null 2>&1; then
    if su root -c true </dev/null >/dev/null 2>&1; then
        echo "O4_SU result=succeeded"
        FAIL=1
    else
        echo "O4_SU result=failed"
    fi
else
    echo "O4_SU result=not_installed"
fi

# (b) Sensitive entries under /proc/1/ must all fail to read/traverse.
# The plain listing and cmdline are OBSERVED only (see header note).
if ls /proc/1/root/ >/dev/null 2>&1; then
    echo "O4_PROC1_ROOT result=readable"
    FAIL=1
else
    echo "O4_PROC1_ROOT result=denied"
fi
if ls /proc/1/cwd/ >/dev/null 2>&1; then
    echo "O4_PROC1_CWD result=readable"
    FAIL=1
else
    echo "O4_PROC1_CWD result=denied"
fi
if cat /proc/1/environ >/dev/null 2>&1; then
    echo "O4_PROC1_ENVIRON result=readable"
    FAIL=1
else
    echo "O4_PROC1_ENVIRON result=denied"
fi
if cat /proc/1/mem >/dev/null 2>&1; then
    echo "O4_PROC1_MEM result=readable"
    FAIL=1
else
    echo "O4_PROC1_MEM result=denied"
fi
if ls /proc/1/ >/dev/null 2>&1; then
    echo "O4_OBSERVED proc1_listing=succeeded"
else
    echo "O4_OBSERVED proc1_listing=failed"
fi
if cat /proc/1/cmdline >/dev/null 2>&1; then
    echo "O4_OBSERVED proc1_cmdline=readable"
else
    echo "O4_OBSERVED proc1_cmdline=denied"
fi

# (c) Docker socket must not exist (no Docker installed by design).
if [ -e /var/run/docker.sock ]; then
    echo "O4_DOCKER_SOCKET result=exists"
    FAIL=1
else
    echo "O4_DOCKER_SOCKET result=absent"
fi

# (d) User-namespace creation + uid_map write must fail. Best-effort
# escalation attempt: deny setgroups first, then map outer UID 1001 to
# inner 0. If the word MAPPED is printed, the mapping succeeded.
_mapped=$(unshare --user sh -c 'echo deny > /proc/self/setgroups 2>/dev/null; echo "0 1001 1" > /proc/self/uid_map 2>/dev/null && echo MAPPED' 2>/dev/null)
if [ "$_mapped" = "MAPPED" ]; then
    echo "O4_USERNS result=mapped"
    FAIL=1
else
    echo "O4_USERNS result=failed"
fi

# (e) Effective capabilities, observed via capsh (informational; the
# authoritative check is (f) below, read from /proc/self/status).
capsh --print 2>/dev/null | grep -E 'Current|Bounding' | sed 's/^/O4_CAPSH /' || echo "O4_CAPSH result=unavailable"

# (f) NoNewPrivs must be 1 and CapEff must be 0000000000000000.
_status=$(cat /proc/self/status 2>/dev/null)
if [ -z "$_status" ]; then
    echo "O4_STATUS result=unreadable"
    INCONCLUSIVE=1
else
    _nnp=$(printf '%s\n' "$_status" | awk '/^NoNewPrivs:/ {print $2}')
    _capeff=$(printf '%s\n' "$_status" | awk '/^CapEff:/ {print $2}')
    echo "O4_NONEWPRIVS value=${_nnp:-unknown}"
    echo "O4_CAPEFF value=${_capeff:-unknown}"
    if [ "$_nnp" != "1" ]; then
        FAIL=1
    fi
    if [ "$_capeff" != "0000000000000000" ]; then
        FAIL=1
    fi
fi

# (g) and (h) are HARNESS HALF checks - see the header. They are NOT
# attempted here: inside the cgroup namespace the parent path
# /sys/fs/cgroup/workload/ is not visible, so an attempt here would
# prove nothing.
echo "O4_CGROUP_WRITE note=harness_half_see_header"
echo "O4_CGROUP_MOVE note=harness_half_see_header"

# (i) Reads of root/harness homes, /proc/1/root, and user-data must fail.
# Each path must EXIST (spec V4 rule 11); absence is INCONCLUSIVE.
check_denied_read() {
    _path=$1
    _label=$2
    # Existence check. For /proc/1/root, test /proc/1 (the process),
    # not /proc/1/root: UID 1001 cannot even stat /proc/1/root of a
    # root-owned process (ptrace access restriction), so `[ -e
    # /proc/1/root ]` is false even though PID 1 exists - on a real
    # VM too (PID 1 is systemd). Testing the process itself is the
    # correct existence check; the read attempt below then proves the
    # root is denied. (Revision 8 fix, found by the dry-run.)
    _exist_path="$_path"
    if [ "$_path" = "/proc/1/root" ]; then _exist_path="/proc/1"; fi
    if [ ! -e "$_exist_path" ]; then
        echo "O4_${_label} result=absent"
        INCONCLUSIVE=1
        return
    fi
    if ls "$_path/" >/dev/null 2>&1 || cat "$_path" >/dev/null 2>&1; then
        echo "O4_${_label} result=readable"
        FAIL=1
    else
        echo "O4_${_label} result=denied"
    fi
}

check_denied_read /root ROOT_HOME
check_denied_read /home/harness HARNESS_HOME
check_denied_read /proc/1/root PROC1_ROOT2
check_denied_read /var/lib/cloud/instance/user-data.txt USERDATA

if [ "$INCONCLUSIVE" -gt 0 ]; then
    echo "O4_RESULT=INCONCLUSIVE"
    exit 2
fi
if [ "$FAIL" -gt 0 ]; then
    echo "O4_RESULT=FAIL"
    exit 1
fi
echo "O4_RESULT=PASS"
exit 0
