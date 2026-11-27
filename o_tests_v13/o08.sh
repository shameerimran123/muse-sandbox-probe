#!/bin/sh
# O8 - Disk exhaustion (threat T6)
# Spec: O_TESTS_SPEC_V8.md, O8. Environment: M8_PROPOSAL_V9.md Sec. 7.1, Sec. 7.2.
# Runs as UID 1001 inside the sandbox. The harness invokes it via the
# Sec. 4.2 sandbox command. NOT YET EXECUTED - written for review only.
#
# Purpose: verify the disk limits are enforced (loopback image size and
# I/O rate).
#
# PASS: writes fail with ENOSPC at 20 GB (the loopback image is full);
# the boot volume still has free space (at least 10 GB free after the
# run); the VM survives; write throughput does not exceed ~50 MB/s
# (io.max, on both the boot-volume device and the loopback device).
# FAIL: writes succeed past 20 GB; the boot volume runs out of free
# space; the VM does not survive; throughput exceeds 60 MB/s on either
# device.
# INCONCLUSIVE (exit 2): the script errors, times out, or the boot-volume
# free space cannot be verified. ALSO INCONCLUSIVE (spec V4 rule 10):
# either harness device file is missing or unreadable, or either device
# is missing from io.stat before or after the run, or its wbytes cannot
# be parsed - the per-device rate is never silently skipped.
#
# Exit: 0 = PASS, 1 = FAIL, 2 = error/inconclusive.
# Result line: O8_RESULT=PASS | FAIL | INCONCLUSIVE
#
# Measurement notes (documented, not assumed):
# - Writes use oflag=direct so they bypass the page cache and are
#   throttled by io.max at the device. Without it, dd would report the
#   page-cache speed, not the device rate.
# - The rate bound is 60 MB/s (50 MB/s cap + 20% measurement headroom).
#   Both the wall-clock rate and the per-device io.stat rate must be
#   within it, for BOTH expected devices.
# - ALL rate calculations use python3 float arithmetic rounded UP to
#   2 decimal places (ceiling) - spec V4 blocker H. Integer-floor
#   division can understate a rate near the cap and is NOT used
#   anywhere in this script. Rates are therefore decimal strings
#   (e.g. 49.07) and are compared with awk, not with shell -gt.
# - The wall-clock rate uses the ACTUAL bytes on disk (blocker H,
#   2026-11-25 ~22:39 PKT): the final dd that hits ENOSPC writes a
#   PARTIAL chunk (whatever fit before the disk filled), and counting
#   only full 1 GiB chunks omits those bytes and understates the
#   rate. The byte total is counted by a Python walk of the fill
#   directory (blocker H, 2026-11-25 ~23:04 PKT) - NOT by
#   find | stat | awk, which hides traversal and stat failures (find
#   errors go to /dev/null, a failed stat inside -exec is silent,
#   awk sums whatever it got) and can report a partial byte total as
#   if it were complete. The walk makes every failure an explicit
#   error: a traversal error, a stat failure, a symlink in the fill
#   directory, a non-regular file, a file larger than one chunk, or
#   a file count other than (full chunks + the partial chunk, if
#   ENOSPC) is INCONCLUSIVE, never a silent partial total. The
#   per-device io.stat rate already uses exact wbytes deltas and is
#   unchanged.
# - Runtime: 20 GB at the 50 MB/s cap takes at least ~410 s, longer if
#   the underlying device is slower than the cap. THE HARNESS RUNS THIS
#   TEST UNDER A DEDICATED TIMEOUT OF AT LEAST 900 s (the 600 s
#   per-case timeout is not enough if the device runs below the cap).
#   See O_TESTS_README.md.
# - The harness provides the expected device identifiers as FILES,
#   not environment variables (runner defect found in V8, 2026-11-26
#   ~00:15 PKT): /opt/harness/boot_device.txt and
#   /opt/harness/loop_dev.txt, each containing one "major:minor"
#   line (e.g. 8:0 and 7:0), recorded at setup from io.max. The V7
#   script read BOOT_DEV / LOOP_DEV from the environment, but the
#   sandbox runs with --clearenv and exactly 7 variables (spec
#   rule 19), none of which is a device identifier, and the runner
#   never exported them - so V7 o08.sh ALWAYS exited INCONCLUSIVE
#   ("required variable unset") and could never pass. The files are
#   written by the harness as root (vm_setup writes boot_device.txt;
#   prepare_workdir writes loop_dev.txt alongside loop_device.txt),
#   are bound read-only into the sandbox, and are readable by UID
#   1001. A missing or unreadable file is INCONCLUSIVE, never a
#   pass and never a silent skip.
# - The fill directory is removed after the measurements, so the next
#   test starts with a clean /work. The harness recreates the loopback
#   image per case in any event.
set -u

FAIL=0
INCONCLUSIVE=0
CG=/sys/fs/cgroup
FILLDIR=/work/o8_fill
CHUNK_MIB=1024
RATE_LIMIT_MBS=60
BOOT_FREE_MIN_BYTES=10737418240

# Sanity: this test is only meaningful as the workload user.
if [ "$(id -u 2>/dev/null)" != "1001" ]; then
    echo "O8_ERROR=not running as UID 1001 (got $(id -u 2>/dev/null || echo unknown))"
    echo "O8_RESULT=INCONCLUSIVE"
    exit 2
fi

# Both expected devices are REQUIRED (spec V4 rule 10). They come
# from the harness-written files /opt/harness/boot_device.txt and
# /opt/harness/loop_dev.txt (see the header note) - NOT from the
# environment, which the sandbox clears (spec rule 19). If either
# file is missing, unreadable, or empty, the per-device measurement
# cannot be performed - INCONCLUSIVE, never silently skipped.
BOOT_DEV=$(cat /opt/harness/boot_device.txt 2>/dev/null | tr -d ' \t\r\n')
if [ -z "$BOOT_DEV" ]; then
    echo "O8_ERROR=harness device file missing or empty: /opt/harness/boot_device.txt"
    echo "O8_RESULT=INCONCLUSIVE"
    exit 2
fi
LOOP_DEV=$(cat /opt/harness/loop_dev.txt 2>/dev/null | tr -d ' \t\r\n')
if [ -z "$LOOP_DEV" ]; then
    echo "O8_ERROR=harness device file missing or empty: /opt/harness/loop_dev.txt"
    echo "O8_RESULT=INCONCLUSIVE"
    exit 2
fi
# The files must contain exactly one major:minor token - anything
# else (a path, extra text) is a harness defect, not a device.
case "$BOOT_DEV" in
    [0-9]*:[0-9]*) ;;
    *) echo "O8_ERROR=boot_device.txt malformed: [$BOOT_DEV]"; echo "O8_RESULT=INCONCLUSIVE"; exit 2 ;;
esac
case "$LOOP_DEV" in
    [0-9]*:[0-9]*) ;;
    *) echo "O8_ERROR=loop_dev.txt malformed: [$LOOP_DEV]"; echo "O8_RESULT=INCONCLUSIVE"; exit 2 ;;
esac
echo "O8_DEVICES boot=$BOOT_DEV loop=$LOOP_DEV"

if ! _v=$(cat "$CG/io.stat" 2>/dev/null) || [ -z "$_v" ]; then
    echo "O8_ERROR=cannot read $CG/io.stat"
    echo "O8_RESULT=INCONCLUSIVE"
    exit 2
fi

# wbytes_of <io.stat-file> <dev>
# Prints the numeric wbytes for the device, or nothing if the device
# is missing or its wbytes cannot be parsed.
wbytes_of() {
    awk -v dev="$2" '$1 == dev {for (i=2;i<=NF;i++) if ($i ~ /^wbytes=[0-9]+$/) {sub(/^wbytes=/, "", $i); print $i}}' "$1"
}

mkdir -p "$FILLDIR" || {
    echo "O8_ERROR=cannot create $FILLDIR"
    echo "O8_RESULT=INCONCLUSIVE"
    exit 2
}

# io.stat before: "major:minor rbytes=N wbytes=N ..." per device.
# Both expected devices must be present with parseable wbytes.
cp "$CG/io.stat" /tmp/o8_iostat_before
for _dev in "$BOOT_DEV" "$LOOP_DEV"; do
    _w=$(wbytes_of /tmp/o8_iostat_before "$_dev")
    if [ -z "$_w" ]; then
        echo "O8_ERROR=device $_dev missing or wbytes unparseable in io.stat before run"
        rm -rf "$FILLDIR" /tmp/o8_iostat_before
        echo "O8_RESULT=INCONCLUSIVE"
        exit 2
    fi
    echo "O8_IO_BEFORE dev=$_dev wbytes=$_w"
done

_start=$(date +%s)
_chunks=0
_enospc=0
while true; do
    _n=$(printf '%04d' "$_chunks")
    if dd if=/dev/zero of="$FILLDIR/fill_$_n" bs=1M count=$CHUNK_MIB oflag=direct >/dev/null 2>/tmp/o8_dd.err; then
        _chunks=$((_chunks + 1))
    else
        if grep -q 'No space left on device' /tmp/o8_dd.err; then
            _enospc=1
        else
            echo "O8_DD_ERROR unexpected failure:"
            sed 's/^/O8_DD_ERROR /' /tmp/o8_dd.err
            rm -rf "$FILLDIR" /tmp/o8_iostat_before /tmp/o8_dd.err
            echo "O8_RESULT=INCONCLUSIVE"
            exit 2
        fi
        break
    fi
done
_end=$(date +%s)
_elapsed=$((_end - _start))
if [ "$_elapsed" -le 0 ]; then
    _elapsed=1
fi
# Actual bytes on disk (blocker H, 2026-11-25 ~22:39 PKT; corrected
# 2026-11-25 ~23:04 PKT): the final dd that hit ENOSPC wrote a
# partial chunk. Count only full chunks and the rate is understated
# by up to ~1 GiB / elapsed. Sum the real file sizes with a Python
# walk - NOT find | stat | awk, which can hide traversal/stat
# failures and report a partial total as complete. The walk below
# makes every failure explicit: a traversal error, a stat failure,
# a symlink or non-regular file in the fill directory, a file larger
# than one chunk, an unexpected subdirectory, or a file count other
# than (full chunks + the partial chunk, if ENOSPC) is INCONCLUSIVE,
# never silently skipped (rule 10).
_o8_count_out=$(python3 - "$FILLDIR" "$_chunks" "$_enospc" "$CHUNK_MIB" <<'PYEOF' 2>/tmp/o8_count.err
import os, stat as statmod, sys
filldir, chunks, enospc, chunk_mib = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
chunk_bytes = chunk_mib * 1048576
total = 0
n = 0
def _onerror(e):
    raise e
try:
    for root, dirs, names in os.walk(filldir, onerror=_onerror):
        if dirs:
            print("O8_BYTE_COUNT unexpected_subdir dir=%s" % os.path.join(root, dirs[0]))
            sys.exit(2)
        for name in names:
            p = os.path.join(root, name)
            if os.path.islink(p):
                print("O8_BYTE_COUNT symlink_file path=%s" % p)
                sys.exit(2)
            try:
                st = os.stat(p)
            except OSError as e:
                print("O8_BYTE_COUNT stat_failed path=%s error=%s" % (p, e))
                sys.exit(2)
            if not statmod.S_ISREG(st.st_mode):
                print("O8_BYTE_COUNT non_regular_file path=%s" % p)
                sys.exit(2)
            if st.st_size > chunk_bytes:
                print("O8_BYTE_COUNT file_too_large path=%s bytes=%d chunk_bytes=%d" % (p, st.st_size, chunk_bytes))
                sys.exit(2)
            total += st.st_size
            n += 1
except OSError as e:
    print("O8_BYTE_COUNT walk_failed error=%s" % e)
    sys.exit(2)
want = chunks + (1 if enospc else 0)
if n != want:
    print("O8_BYTE_COUNT file_count_mismatch files=%d want=%d" % (n, want))
    sys.exit(2)
print("bytes=%d" % total)
print("files=%d" % n)
sys.exit(0)
PYEOF
)
_o8_count_rc=$?
if [ "$_o8_count_rc" -ne 0 ]; then
    echo "O8_BYTE_COUNT result=error rc=$_o8_count_rc"
    sed 's/^/O8_BYTE_COUNT_ERR /' /tmp/o8_count.err 2>/dev/null | head -n 5
    rm -rf "$FILLDIR" /tmp/o8_iostat_before /tmp/o8_dd.err /tmp/o8_count.err
    echo "O8_RESULT=INCONCLUSIVE"
    exit 2
fi
rm -f /tmp/o8_count.err
_actual_bytes=$(printf '%s
' "$_o8_count_out" | awk -F= '/^bytes=/ {print $2}')
_o8_file_n=$(printf '%s
' "$_o8_count_out" | awk -F= '/^files=/ {print $2}')
echo "O8_FILL_FILES=${_o8_file_n:-unknown}"
if [ -z "$_actual_bytes" ]; then
    echo "O8_ERROR=cannot count fill files in $FILLDIR"
    rm -rf "$FILLDIR" /tmp/o8_iostat_before /tmp/o8_dd.err
    echo "O8_RESULT=INCONCLUSIVE"
    exit 2
fi
_full_bytes=$((_chunks * CHUNK_MIB * 1048576))
echo "O8_FILL_ACTUAL_BYTES=$_actual_bytes full_chunks_bytes=$_full_bytes"
if [ "$_actual_bytes" -eq 0 ]; then
    # ENOSPC was reached but no byte was written by this test: the
    # disk was already full before the fill started (a setup defect),
    # so no write rate was measured at all. INCONCLUSIVE, never a pass.
    echo "O8_ERROR=enospc_reached_but_zero_bytes_written"
    rm -rf "$FILLDIR" /tmp/o8_iostat_before /tmp/o8_dd.err
    echo "O8_RESULT=INCONCLUSIVE"
    exit 2
fi
_total_bytes=$_actual_bytes
# Ceiling to 2 decimals: ceil(bytes / elapsed / 1048576 * 100) / 100.
_rate_mbs=$(python3 -c 'import math, sys; print("%.2f" % (math.ceil(float(sys.argv[1]) / float(sys.argv[2]) / 1048576.0 * 100.0) / 100.0))' "$_total_bytes" "$_elapsed")
echo "O8_FILL chunks=$_chunks total_bytes=$_total_bytes elapsed_s=$_elapsed rate_mbs=$_rate_mbs enospc=$_enospc"

if [ "$_enospc" -ne 1 ]; then
    echo "O8_ENOSPC result=not_reached"
    FAIL=1
else
    echo "O8_ENOSPC result=reached"
fi

# The work filesystem must now be (nearly) full.
_work_avail=$(df -B1 /work 2>/dev/null | awk 'NR==2 {print $4}')
if [ -z "$_work_avail" ]; then
    echo "O8_ERROR=cannot read df /work"
    INCONCLUSIVE=1
else
    echo "O8_WORK_AVAIL_BYTES=$_work_avail"
    if [ "$_work_avail" -gt 1073741824 ]; then
        echo "O8_WORK_FULL result=not_full avail_bytes=$_work_avail"
        FAIL=1
    else
        echo "O8_WORK_FULL result=full"
    fi
fi

# The boot volume must still have at least 10 GB free.
_boot_avail=$(df -B1 / 2>/dev/null | awk 'NR==2 {print $4}')
if [ -z "$_boot_avail" ]; then
    echo "O8_ERROR=cannot read df /"
    INCONCLUSIVE=1
else
    echo "O8_BOOT_AVAIL_BYTES=$_boot_avail"
    if [ "$_boot_avail" -lt "$BOOT_FREE_MIN_BYTES" ]; then
        echo "O8_BOOT_FREE result=too_low"
        FAIL=1
    else
        echo "O8_BOOT_FREE result=ok"
    fi
fi

# Wall-clock write rate must not exceed the cap (+ headroom).
# _rate_mbs is a decimal string (ceiling, 2 places), so compare with awk.
if awk -v r="$_rate_mbs" -v lim="$RATE_LIMIT_MBS" 'BEGIN {exit (r > lim) ? 0 : 1}'; then
    echo "O8_RATE result=exceeded rate_mbs=$_rate_mbs limit_mbs=$RATE_LIMIT_MBS"
    FAIL=1
else
    echo "O8_RATE result=within_limit rate_mbs=$_rate_mbs"
fi

# Per-device write rate from io.stat (the authoritative device-level
# measurement). BOTH expected devices must be present after the run
# with parseable wbytes, and each device's rate must be within the cap.
cp "$CG/io.stat" /tmp/o8_iostat_after
for _dev in "$BOOT_DEV" "$LOOP_DEV"; do
    _w_before=$(wbytes_of /tmp/o8_iostat_before "$_dev")
    _w_after=$(wbytes_of /tmp/o8_iostat_after "$_dev")
    if [ -z "$_w_before" ] || [ -z "$_w_after" ]; then
        echo "O8_ERROR=device $_dev missing or wbytes unparseable in io.stat after run"
        INCONCLUSIVE=1
        continue
    fi
    _dw=$((_w_after - _w_before))
    # Ceiling to 2 decimals (spec V4 blocker H), same formula as above.
    _drate=$(python3 -c 'import math, sys; print("%.2f" % (math.ceil(float(sys.argv[1]) / float(sys.argv[2]) / 1048576.0 * 100.0) / 100.0))' "$_dw" "$_elapsed")
    echo "O8_IO_DEVICE dev=$_dev wbytes_delta=$_dw rate_mbs=$_drate"
    if awk -v r="$_drate" -v lim="$RATE_LIMIT_MBS" 'BEGIN {exit (r > lim) ? 0 : 1}'; then
        echo "O8_IO_RATE result=exceeded dev=$_dev rate_mbs=$_drate"
        FAIL=1
    fi
done
rm -f /tmp/o8_iostat_before /tmp/o8_iostat_after /tmp/o8_dd.err

# Clean up the fill files so the next test starts with a clean /work.
rm -rf "$FILLDIR"

if [ "$INCONCLUSIVE" -gt 0 ]; then
    echo "O8_RESULT=INCONCLUSIVE"
    exit 2
fi
if [ "$FAIL" -gt 0 ]; then
    echo "O8_RESULT=FAIL"
    exit 1
fi
echo "O8_RESULT=PASS"
exit 0
