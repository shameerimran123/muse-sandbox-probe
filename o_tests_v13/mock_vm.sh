#!/bin/sh
# mock_vm.sh - mock VM for the M8 --dry-run mode (Revision 12).
# Spec: O_TESTS_SPEC_V10.md rules 29, 40-42; proposal M8_PROPOSAL_V12.md Sec. 11.5.
#
# *** DRY-RUN ONLY. It creates NO cloud resource and spends nothing.
# It builds a fake VM root under $BATCH_DIR/mock_vm/root, enters a
# private mount namespace, and binds the fake tree over the real
# paths (so the runner's VM-side code sees the same layout as on a
# real VM: /opt/harness, /opt/proxy, /results, /work, /home/harness,
# /home/workload, /root, /var/lib/cloud, /sys/fs/cgroup, /etc/hosts
# and a 1 GiB tmpfs bound to /tmp). The VM driver
# (run_batch.sh vm, DRYRUN_VM=1) then runs inside that namespace.
#
# The fake tree is DISK-BACKED (there is no /dev/loop* on this host,
# so no loopback image exists) and the fake cgroup is a set of
# STATIC fixture files (the mock cgroup never contains processes,
# so cgroup.procs is always empty - recorded honestly, see the spec).
#
# Revision 12: the fake user-data is the HOST's generated user-data
# ($BATCH_DIR/user-data.txt - the real bootstrap + the host's
# per-batch PUBLIC key), not placeholder text, so the VM-side
# secret-delivery flow (generate secret in-VM, encrypt with the
# host public key, publish hmac_secret.enc) is exercised end to
# end. The fake tree also carries the proxy cgroup fixtures
# (/sys/fs/cgroup/proxy) with the Sec. 7.1 values, mirroring the
# workload cgroup fixtures.
#
# After the VM driver exits, this script simulates the VM-side timer
# and the external controller: it waits until the controller
# deadline, terminates the mock instance through the mock OCI layer,
# polls until TERMINATED, and writes the controller run record
# (the exact command + run_start/run_end/observed state) to
# $WATCHDOG_RUN_RECORD - the same record the host's O13 reads.
#
# A background disk guard kills the O8 fill workload if the fake
# work dir exceeds 256 MiB (the dry-run has no loopback device, so
# O8 would otherwise fill the host disk until ENOSPC). A background
# timer stops the results server at the timer deadline, as the real
# VM-side timer does.
#
# Required env: BATCH_DIR, M8_DIR, MOCK_OCI_STATE, INSTANCE_OCID,
# TIMER_MINUTES, CONTROLLER_MINUTES, WATCHDOG_RUN_RECORD,
# CONTROLLER_JOB_ID, OCI_CLI (the mock OCI script path).
set -u

for _v in BATCH_DIR M8_DIR MOCK_OCI_STATE INSTANCE_OCID TIMER_MINUTES CONTROLLER_MINUTES WATCHDOG_RUN_RECORD CONTROLLER_JOB_ID OCI_CLI; do
    eval "_val=\${$_v:-}"
    if [ -z "$_val" ]; then echo "mock_vm: $_v is not set" >&2; exit 2; fi
done

MOCK_DIR="$BATCH_DIR/mock_vm"
FAKE_ROOT="$MOCK_DIR/root"
MOCK_LOG="$BATCH_DIR/mock_vm.log"
mkdir -p "$MOCK_DIR" || exit 2
: > "$MOCK_LOG" || exit 2

mock_log() {
    printf '%s MOCK_VM %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$MOCK_LOG"
}

# --- creation time + timer epoch (from the mock instance state). ---
CREATION_EPOCH=$(python3 -c "import json; print(json.load(open('$MOCK_OCI_STATE/instance.json'))['created_epoch'])" 2>/dev/null) || {
    echo "mock_vm: cannot read creation epoch from $MOCK_OCI_STATE/instance.json" >&2; exit 2; }
TIMER_EPOCH=$((CREATION_EPOCH + TIMER_MINUTES * 60))
CONTROLLER_EPOCH=$((CREATION_EPOCH + CONTROLLER_MINUTES * 60))
mock_log "instance=$INSTANCE_OCID created_epoch=$CREATION_EPOCH timer_epoch=$TIMER_EPOCH controller_epoch=$CONTROLLER_EPOCH"

# Write the timer epoch into the mock instance state now, so the mock
# OCI layer flips the instance to STOPPED at the timer deadline
# (the state is computed from timestamps, see mock_oci.sh).
python3 - "$MOCK_OCI_STATE/instance.json" "$TIMER_EPOCH" <<'PYEOF'
import json, sys
p, timer = sys.argv[1], int(sys.argv[2])
doc = json.load(open(p))
doc["timer_epoch"] = timer
json.dump(doc, open(p, "w"))
PYEOF
mock_log "timer_epoch recorded in mock instance state"

# --- host root device major:minor (for the fake boot_device.txt). ---
BOOT_DEV=$(python3 -c "import os; d=os.stat('/').st_dev; print('%d:%d' % (os.major(d), os.minor(d)))")
mock_log "host boot device=$BOOT_DEV (loop device is a placeholder 7:0 - no /dev/loop* exists on this host)"

# --- build the fake VM root. ---
mkdir -p "$FAKE_ROOT/opt/harness" "$FAKE_ROOT/opt/proxy" "$FAKE_ROOT/opt/stage/tmp" \
    "$FAKE_ROOT/opt/stage/probe_home" "$FAKE_ROOT/results" "$FAKE_ROOT/work/home" \
    "$FAKE_ROOT/home/harness" "$FAKE_ROOT/home/workload" "$FAKE_ROOT/root" \
    "$FAKE_ROOT/var/lib/cloud/instance" "$FAKE_ROOT/sys/fs/cgroup/workload" \
    "$FAKE_ROOT/etc" "$FAKE_ROOT/var/log" || exit 2
# /opt/harness and /opt/proxy are mode 0711 in the MOCK (Revision 8
# fix): the results server runs as UID 1000 and the proxy as UID
# 1002, and each must traverse its own directory to read its source.
# The real VM uses 0710 root:harness / root:proxy, but this host's
# overlay filesystem REFUSES chown of a directory to a non-root
# owner (verified EPERM), so the mock cannot set either group on the
# directories. Mode 0711 still protects the contents: the HMAC
# secret is 600 root and the scripts are 700 root, so the workload
# UID 1001 can traverse the directories but cannot read anything
# sensitive in them.
chmod 0711 "$FAKE_ROOT/opt/harness" || exit 2
chmod 0711 "$FAKE_ROOT/opt/proxy" || exit 2
chmod 700 "$FAKE_ROOT/root" "$FAKE_ROOT/home/harness" || exit 2
# /var/lib/cloud is mode 755 on a real VM (cloud-init default),
# so UID 1001 can traverse it to stat the user-data file (mode
# 600, unreadable but stat-able). The dry-run umask 0007 makes
# mkdir create 770 dirs, which UID 1001 cannot traverse, so o01/o03/
# o04 reported the user-data file "absent". The instance subdir needs
# the same fix (it holds the file). (Revision 8 fix.)
chmod 755 "$FAKE_ROOT/var/lib/cloud" "$FAKE_ROOT/var/lib" "$FAKE_ROOT/var/lib/cloud/instance" || exit 2

# Fake /etc/hosts (a single file, bound over the real one so the O5
# harness's /etc/hosts edit cannot touch the host's real file).
cat > "$FAKE_ROOT/etc/hosts" <<'EOF'
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
127.0.0.1 results
EOF
chmod 644 "$FAKE_ROOT/etc/hosts"

# Fake cgroup tree (static fixtures; the mock cgroup never contains
# processes, so cgroup.procs is empty - see the spec, rule 29).
# Values match the Sec. 7.1 limits the real vm_setup writes; the
# dry-run vm_setup_dryrun re-writes them (mirroring the real setup).
printf '%s\n' 'cpu io memory pids' > "$FAKE_ROOT/sys/fs/cgroup/cgroup.controllers"
printf '%s\n' '+cpu +io +memory +pids' > "$FAKE_ROOT/sys/fs/cgroup/cgroup.subtree_control"
: > "$FAKE_ROOT/sys/fs/cgroup/cgroup.procs"
printf 'usage_usec 0\nuser_usec 0\nsystem_usec 0\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\n' > "$FAKE_ROOT/sys/fs/cgroup/cpu.stat"
printf '0\n' > "$FAKE_ROOT/sys/fs/cgroup/pids.current"
printf 'max 0\n' > "$FAKE_ROOT/sys/fs/cgroup/pids.events"
printf '%s\n' 'cpu io memory pids' > "$FAKE_ROOT/sys/fs/cgroup/workload/cgroup.controllers"
: > "$FAKE_ROOT/sys/fs/cgroup/workload/cgroup.procs"
printf '4194304K\n' > "$FAKE_ROOT/sys/fs/cgroup/workload/memory.max"
printf '3145728K\n' > "$FAKE_ROOT/sys/fs/cgroup/workload/memory.high"
printf '0\n' > "$FAKE_ROOT/sys/fs/cgroup/workload/memory.swap.max"
printf '100000 100000\n' > "$FAKE_ROOT/sys/fs/cgroup/workload/cpu.max"
printf '512\n' > "$FAKE_ROOT/sys/fs/cgroup/workload/pids.max"
printf '0\n' > "$FAKE_ROOT/sys/fs/cgroup/workload/memory.current"
printf 'anon 0\nfile 0\nkernel 0\nkernel_stack 0\npagetables 0\npercpu 0\nsock 0\nshmem 0\nfile_mapped 0\nfile_dirty 0\nfile_writeback 0\nanon_thp 0\ninactive_anon 0\nactive_anon 0\ninactive_file 0\nactive_file 0\nunevictable 0\nslab_reclaimable 0\nslab_unreclaimable 0\nslab 0\nworkingset_refault_anon 0\nworkingset_refault_file 0\nworkingset_node 0\n' > "$FAKE_ROOT/sys/fs/cgroup/workload/memory.stat"
printf 'usage_usec 0\nuser_usec 0\nsystem_usec 0\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\n' > "$FAKE_ROOT/sys/fs/cgroup/workload/cpu.stat"
printf 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n' > "$FAKE_ROOT/sys/fs/cgroup/workload/memory.events"
printf '0\n' > "$FAKE_ROOT/sys/fs/cgroup/workload/memory.peak"
printf '0\n' > "$FAKE_ROOT/sys/fs/cgroup/workload/pids.current"
printf 'max 0\n' > "$FAKE_ROOT/sys/fs/cgroup/workload/pids.events"
printf '%s rbytes=0 wbytes=0 rios=0 wios=0 dbytes=0 dios=0\n' "$BOOT_DEV" > "$FAKE_ROOT/sys/fs/cgroup/workload/io.stat"

# Fake proxy cgroup (Revision 12, spec rule 40): the proxy runs
# inside /sys/fs/cgroup/proxy/ with its own limits (Sec. 7.1).
# Static fixtures, mirroring the workload cgroup above; the values
# match the limits the real bootstrap writes, and vm_setup_dryrun
# re-writes them (mirroring the real setup). Enforcement is NOT
# proven by these fixtures - the dry-run proves the in-process cap
# (O5(h) + the driver concurrency regression); the cgroup limits
# are proven by the real-VM setup check (Sec. 7.4 item 21).
mkdir -p "$FAKE_ROOT/sys/fs/cgroup/proxy" || exit 2
printf '%s\n' 'cpu memory pids' > "$FAKE_ROOT/sys/fs/cgroup/proxy/cgroup.controllers"
: > "$FAKE_ROOT/sys/fs/cgroup/proxy/cgroup.procs"
printf '536870912\n' > "$FAKE_ROOT/sys/fs/cgroup/proxy/memory.max"
printf '50000 100000\n' > "$FAKE_ROOT/sys/fs/cgroup/proxy/cpu.max"
printf '64\n' > "$FAKE_ROOT/sys/fs/cgroup/proxy/pids.max"
printf '0\n' > "$FAKE_ROOT/sys/fs/cgroup/proxy/memory.current"
printf '0\n' > "$FAKE_ROOT/sys/fs/cgroup/proxy/pids.current"

# Fake user-data (Revision 12): the HOST's generated user-data
# ($BATCH_DIR/user-data.txt - the real bootstrap script + the host's
# per-batch PUBLIC key). The host generates it in
# host_phase_vm_create_dryrun before starting this mock, so it must
# exist here; a missing file is a hard failure, not a placeholder.
# The VM-side secret flow reads the public key from this file, so
# the dry-run exercises the real secret-delivery path end to end.
# The file is mode 600 (root-only), as on a real VM.
[ -f "$BATCH_DIR/user-data.txt" ] || { echo "mock_vm: $BATCH_DIR/user-data.txt missing (host did not generate it)" >&2; exit 2; }
cp "$BATCH_DIR/user-data.txt" "$FAKE_ROOT/var/lib/cloud/instance/user-data.txt" || exit 2
chmod 600 "$FAKE_ROOT/var/lib/cloud/instance/user-data.txt"

# Fake IMDS identity endpoints (V13, spec rule 43): the host plays
# OCI and issued the mock leaf certificate + key in
# host_phase_vm_create_dryrun (signed by the mock intermediate CA
# from host_phase_secret). The mock VM exposes them at the fake
# IMDS path /opt/harness/imds/ (the dry-run mirror of the real
# http://169.254.169.254/opc/v2/identity/ endpoints), so
# vm_setup_dryrun exercises the real signing flow end to end. All
# three files must exist; a missing one is a hard failure, not a
# placeholder. The private key is mode 600; the certificates 644.
mkdir -p "$FAKE_ROOT/opt/harness/imds" || exit 2
for _imds in cert.pem intermediate.pem key.pem; do
    [ -f "$BATCH_DIR/mock_identity/$_imds" ] || { echo "mock_vm: $BATCH_DIR/mock_identity/$_imds missing (host did not issue the mock identity)" >&2; exit 2; }
    cp "$BATCH_DIR/mock_identity/$_imds" "$FAKE_ROOT/opt/harness/imds/$_imds" || exit 2
done
chmod 600 "$FAKE_ROOT/opt/harness/imds/key.pem" || exit 2
chmod 644 "$FAKE_ROOT/opt/harness/imds/cert.pem" "$FAKE_ROOT/opt/harness/imds/intermediate.pem" || exit 2

# Harness device files (written by the harness as root, per spec V7).
printf '%s\n' "$BOOT_DEV" > "$FAKE_ROOT/opt/harness/boot_device.txt"
printf '%s\n' '7:0' > "$FAKE_ROOT/opt/harness/loop_dev.txt"
printf '%s\n' '7:0' > "$FAKE_ROOT/opt/harness/loop_device.txt"

# The batch env the VM driver reads (written by the host before the
# mock VM starts; the mock VM copies it into the fake tree).
if [ -f "$BATCH_DIR/batch.env" ]; then
    cp "$BATCH_DIR/batch.env" "$FAKE_ROOT/opt/harness/batch.env"
else
    echo "mock_vm: $BATCH_DIR/batch.env missing" >&2; exit 2
fi
# The O-test scripts + manifest + egress proxy (copied, not bound,
# so the fake tree is self-contained).
# (Revision 8 fix - V7 used o0*.sh, which missed o10.sh-o13.sh, so
# run_o10 failed 127 and run_workload o11 could not find its script.)
cp "$M8_DIR/o_tests_v13/o"*.sh "$M8_DIR/o_tests_v13/run_batch.sh" "$FAKE_ROOT/opt/harness/" || exit 2
# The O-test scripts run as the workload UID 1001 (run_sandbox setprivs
# to 1001 and execs the script), so they must be readable + executable
# by UID 1001: mode 755. The source files are mode 770 root:nogroup,
# which UID 1001 cannot read. (Revision 8 fix - V7 chmod 700 in the
# bootstrap made every case fail "Permission denied".)
chmod 755 "$FAKE_ROOT/opt/harness/"*.sh || exit 2
cp "$M8_DIR/o_tests_v13/o_tests_manifest.json" "$FAKE_ROOT/opt/harness/" || exit 2
cp "$M8_DIR/egress-proxy.py" "$FAKE_ROOT/opt/proxy/egress-proxy.py" || exit 2
# The proxy runs as UID 1002, so its source must be readable by
# that UID: mode 640 root:1002 (Revision 8 fix - the source is
# mode 660 root:nogroup, which UID 1002 cannot read).
chown root:1002 "$FAKE_ROOT/opt/proxy/egress-proxy.py" || exit 2
chmod 640 "$FAKE_ROOT/opt/proxy/egress-proxy.py" || exit 2
mock_log "fake tree built at $FAKE_ROOT"

# --- host mount-point dirs (created if missing; removed afterwards
# only if empty and created here). ---
CREATED_DIRS_FILE="$MOCK_DIR/created_mountpoints.txt"
: > "$CREATED_DIRS_FILE"
for _d in /opt/harness /opt/proxy /opt/stage /results /work /home/harness /home/workload /root /var/lib/cloud; do
    if [ ! -e "$_d" ]; then
        mkdir -p "$_d" || { echo "mock_vm: cannot create mount point $_d" >&2; exit 2; }
        printf '%s\n' "$_d" >> "$CREATED_DIRS_FILE"
    fi
done
mock_log "host mount points ready (created: $(tr '\n' ' ' < "$CREATED_DIRS_FILE"))"

# --- the namespace inner script (written to a file: no quoting hell). ---
INNER="$MOCK_DIR/inner.sh"
cat > "$INNER" <<'INNEREOF'
#!/bin/sh
# Runs inside the mock VM's private mount namespace.
set -u
BATCH_DIR="${BATCH_DIR:?}"
MOCK_DIR="$BATCH_DIR/mock_vm"
FAKE_ROOT="$MOCK_DIR/root"
MOCK_LOG="$BATCH_DIR/mock_vm.log"
M8_DIR="${M8_DIR:?}"
OCI_CLI="${OCI_CLI:?}"
INSTANCE_OCID="${INSTANCE_OCID:?}"
TIMER_EPOCH="${TIMER_EPOCH:?}"
CONTROLLER_EPOCH="${CONTROLLER_EPOCH:?}"
WATCHDOG_RUN_RECORD="${WATCHDOG_RUN_RECORD:?}"
CONTROLLER_JOB_ID="${CONTROLLER_JOB_ID:?}"
TIMER_MINUTES="${TIMER_MINUTES:?}"
CONTROLLER_MINUTES="${CONTROLLER_MINUTES:?}"
MOCK_OCI_STATE="${MOCK_OCI_STATE:?}"

mock_log() {
    printf '%s MOCK_VM_INNER %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$MOCK_LOG"
}

# --- binds (the fake tree over the real paths). ---
mount --bind "$FAKE_ROOT/opt/harness" /opt/harness || exit 2
mount --bind "$FAKE_ROOT/opt/proxy" /opt/proxy || exit 2
mount --bind "$FAKE_ROOT/opt/stage" /opt/stage || exit 2
mount --bind "$FAKE_ROOT/results" /results || exit 2
mount --bind "$FAKE_ROOT/work" /work || exit 2
mount --bind "$FAKE_ROOT/home/harness" /home/harness || exit 2
mount --bind "$FAKE_ROOT/home/workload" /home/workload || exit 2
mount --bind "$FAKE_ROOT/root" /root || exit 2
mount --bind "$FAKE_ROOT/var/lib/cloud" /var/lib/cloud || exit 2
mount --bind "$FAKE_ROOT/sys/fs/cgroup" /sys/fs/cgroup || exit 2
mount --bind "$FAKE_ROOT/etc/hosts" /etc/hosts || exit 2
# The 1 GiB /tmp tmpfs (Sec. 4.2): pre-mounted at /opt/stage/tmp and
# bound to /tmp, exactly as the real harness does it.
mount -t tmpfs -o size=1G,mode=1777 tmpfs /opt/stage/tmp || exit 2
mount --bind /opt/stage/tmp /tmp || exit 2
mock_log "binds + 1 GiB /tmp tmpfs ready"

# --- background timer: at the timer deadline, stop the results
# server (as the real VM-side timer does) and record it. The
# instance state flips to STOPPED at the same deadline through the
# mock OCI layer (timer_epoch, set before the namespace started).
_now=$(date -u +%s)
_timer_wait=$((TIMER_EPOCH - _now))
if [ "$_timer_wait" -lt 0 ]; then _timer_wait=0; fi
(
    sleep "$_timer_wait"
    pkill -u 1000 -f results_server.py 2>/dev/null || true
    printf '%s MOCK_TIMER fired: results server stopped (instance STOPPED via mock OCI)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$MOCK_LOG"
) &
TIMER_PID=$!

# --- background disk guard: the dry-run has no loopback device, so
# O8 would fill the host disk until ENOSPC. Kill the O8 fill if the
# fake work dir exceeds 256 MiB (poll every 0.5 s; worst case about
# one 1 GiB chunk is written before the kill lands - safe on this
# host's free disk). Records the event in the mock log.
(
    while true; do
        _used=$(du -sb /work 2>/dev/null | awk '{print $1}')
        case "$_used" in ''|*[!0-9]*) _used=0 ;; esac
        if [ "$_used" -gt 268435456 ]; then
            pkill -KILL -f 'o08.sh' 2>/dev/null || true
            pkill -KILL -f 'dd if=/dev/zero of=/work/o8_fill' 2>/dev/null || true
            printf '%s MOCK_DISK_GUARD tripped: /work=%s bytes (>256 MiB) - O8 fill killed\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_used" >> "$MOCK_LOG"
            sleep 5
        fi
        sleep 0.5
    done
) &
GUARD_PID=$!

# --- the VM driver (foreground, in the namespace). ---
mock_log "starting VM driver (run_batch.sh vm, DRYRUN_VM=1)"
DRYRUN_VM=1 "$M8_DIR/o_tests_v13/run_batch.sh" vm > "$MOCK_DIR/vm_driver.log" 2>&1
VM_RC=$?
mock_log "VM driver exited rc=$VM_RC"

# Stop the background helpers now that the driver is done.
kill "$TIMER_PID" "$GUARD_PID" 2>/dev/null || true
wait "$TIMER_PID" "$GUARD_PID" 2>/dev/null || true

# --- the mock external controller: at the controller deadline,
# terminate the mock instance through the mock OCI layer, poll
# until TERMINATED, and write the run record (the exact command +
# run_start/run_end/observed state) for the host's O13 to read.
_now=$(date -u +%s)
_ctrl_wait=$((CONTROLLER_EPOCH - _now))
if [ "$_ctrl_wait" -gt 0 ]; then
    mock_log "waiting ${_ctrl_wait}s until the controller deadline"
    sleep "$_ctrl_wait"
fi
CTRL_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CTRL_CMD="oci compute instance terminate --instance-id $INSTANCE_OCID --force --preserve-boot-volume false"
mock_log "controller terminating instance (job=$CONTROLLER_JOB_ID)"
"$OCI_CLI" compute instance terminate --instance-id "$INSTANCE_OCID" --force --preserve-boot-volume false >/dev/null 2>&1
CTRL_RC=$?
_ctrl_state=""
_i=0
while [ "$_i" -lt 60 ]; do
    _ctrl_state=$("$OCI_CLI" compute instance get --instance-id "$INSTANCE_OCID" --query 'data."lifecycle-state"' --raw-output 2>/dev/null) || _ctrl_state="QUERY_FAILED"
    if [ "$_ctrl_state" = "TERMINATED" ]; then break; fi
    sleep 2
    _i=$((_i + 1))
done
CTRL_END=$(date -u +%Y-%m-%dT%H:%M:%SZ)
python3 - "$WATCHDOG_RUN_RECORD" "$CONTROLLER_JOB_ID" "$CTRL_CMD" "$CTRL_START" "$CTRL_END" "$CTRL_RC" "$_ctrl_state" "$INSTANCE_OCID" <<'PYEOF'
import json, sys
path, job, cmd, start, end, rc, state, ocid = sys.argv[1:9]
doc = {"job_id": job, "command": cmd, "run_start": start,
       "run_end": end, "exit_code": int(rc),
       "observed_state": state, "instance_ocid": ocid}
json.dump(doc, open(path, "w"), indent=2)
PYEOF
mock_log "controller run record written: exit=$CTRL_RC observed_state=$_ctrl_state (record=$WATCHDOG_RUN_RECORD)"

# --- cleanup: kill any leftover mock VM processes (proxy, results
# server, orphaned case children) so nothing survives the namespace.
pkill -KILL -u 1000 -f results_server.py 2>/dev/null || true
pkill -KILL -u 1002 -f egress-proxy.py 2>/dev/null || true
pkill -KILL -u 1001 2>/dev/null || true
mock_log "mock VM cleanup done (vm driver rc=$VM_RC)"
exit "$VM_RC"
INNEREOF
chmod +x "$INNER"
mock_log "namespace inner script written"

# --- enter the namespace and run it. ---
# Export everything the inner script needs (it runs as a separate
# process inside the namespace; TIMER_EPOCH / CONTROLLER_EPOCH are
# computed here, not passed in).
export BATCH_DIR M8_DIR MOCK_OCI_STATE INSTANCE_OCID TIMER_MINUTES CONTROLLER_MINUTES WATCHDOG_RUN_RECORD CONTROLLER_JOB_ID OCI_CLI TIMER_EPOCH CONTROLLER_EPOCH
mock_log "entering private mount namespace"
unshare --mount --fork sh "$INNER"
MOCK_RC=$?
mock_log "namespace exited rc=$MOCK_RC"

# --- remove the host mount-point dirs created here (only if empty). ---
while IFS= read -r _d; do
    [ -n "$_d" ] && rmdir "$_d" 2>/dev/null || true
done < "$CREATED_DIRS_FILE"
mock_log "mock VM done rc=$MOCK_RC"
exit "$MOCK_RC"
