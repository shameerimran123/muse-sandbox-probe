#!/bin/sh
# O13 - Teardown + independent watchdog (global)
# Spec: O_TESTS_SPEC_V8.md, O13. Environment: M8_PROPOSAL_V9.md Sec. 7.1, Sec. 10.2, Sec. 11.2.
#
# *** HOST-SIDE SCRIPT. It does NOT run on the VM and NOT as UID 1001. ***
# It runs on the host (the coordinator machine) after the batch, using the
# OCI API, to verify the instance was terminated, the network resources
# were deleted, the results endpoint is closed, and the billing is $0.
# NOT YET EXECUTED - written for review only.
#
# Required environment variables (set by the harness; all are recorded
# in the run manifest before the VM is created):
#   INSTANCE_OCID       OCID of the batch VM.
#   VCN_OCID            OCID of the per-batch VCN.
#   SUBNET_OCID         OCID of the per-batch subnet.
#   SECLIST_OCID        OCID of the per-batch security list.
#   VM_PUBLIC_IP        The VM's former public IP.
#   COMPARTMENT_OCID    Compartment OCID.
#   TENANCY_OCID        Tenancy OCID.
#   BATCH_START         Batch start time, ISO 8601 UTC (e.g. 2026-11-25T15:00:00Z).
#   ROUTETABLE_OCID     OCID of the per-batch route table.
#   IGW_OCID            OCID of the per-batch internet gateway.
#   WATCHDOG_RUN_RECORD Path to the external controller's structured run
#                       record, JSON (job_id, run_start, run_end,
#                       instance_ocid, command, exit_code, observed_state).
#   EXPECTED_CONTROLLER_JOB_ID
#                       The Muse cron job ID of the pre-authorized
#                       external controller, recorded in the run
#                       manifest BEFORE the VM was created (proposal
#                       Sec. 11.4). The run record's job_id must match
#                       it exactly (blocker L, 2026-11-25 ~22:39 PKT).
#   EXPECTED_TERMINATE_COMMAND
#                       The exact pre-authorized terminate command
#                       string, recorded in the run manifest BEFORE the
#                       batch ran (proposal Sec. 11.4): "oci compute
#                       instance terminate --instance-id <INSTANCE_OCID>
#                       --force --preserve-boot-volume false". The run
#                       record's command must match it exactly.
#   DONE_MARKER         Path to the downloaded DONE marker file. Its
#                       existence proves the host retrieved the final
#                       marker - i.e. the results server was still
#                       running when DONE was written (blocker L: the
#                       V4 teardown stopped the server BEFORE DONE was
#                       written, so the host could never retrieve it).
#                       If DONE is absent, the teardown order was
#                       wrong and the test is INCONCLUSIVE.
#   JOURNAL_SNAPSHOT    Path to the VM journal snapshot retrieved with
#                       the results - REQUIRED, not optional. The snapshot
#                       must show the VM-side timer unit m8-watchdog.timer
#                       armed. (The journal cannot be read after poweroff,
#                       so the snapshot is retrieved with the results.)
#                       Its HMAC sidecar (JOURNAL_SNAPSHOT.hmac) is
#                       verified with the per-batch secret BEFORE any
#                       line of the snapshot is trusted (blocker L,
#                       2026-11-25 ~23:04 PKT - the snapshot is served
#                       over plain HTTP and is untrusted data like any
#                       other manifest).
#   INSTANCE_STATE_LOG  Path to the host's polling record of the
#                       instance's lifecycle-state transitions. Lines are
#                       "ISO_TIMESTAMP STATE". Written ONLY by the
#                       implemented poller o13_poller.sh (proposal Sec.
#                       11.4), started by the harness at VM creation;
#                       the controller does NOT write to this log.
#   TIMER_DEADLINE      The test-mode timer deadline, ISO 8601 UTC.
#   BATCH_MANIFEST      Path to the downloaded batch.json.
#   RESULTS_SHA256      Path to the downloaded results.sha256 (the hash
#                       list - itself HMAC-signed, spec V4 rule 15).
#   HMAC_SECRET_FILE    Path to the host's copy of the per-batch HMAC
#                       secret (a file holding the hex-encoded 32-byte
#                       per-batch secret).
# Optional:
#   OCI_CLI             OCI CLI to use (default: oci).
#
# Test-mode deadlines (spec V4 O13): for the first bounded isolation
# test, the VM-side systemd timer powers off the VM at creation + 90
# minutes, and the host-side cron job (the external controller)
# terminates the instance at creation + 120 minutes. The batch (O1-O12)
# completes before the 90-minute mark. Production (benchmark) deadlines
# remain 24 hours; the test-mode values are recorded in the run manifest
# and are not presented as production values.
#
# PASS: instance TERMINATED (within 10 minutes of the terminate call);
# the controller's run record job_id matches EXPECTED_CONTROLLER_JOB_ID
# and its command matches EXPECTED_TERMINATE_COMMAND exactly; the
# downloaded DONE marker exists (the host retrieved the final marker);
# network resources deleted (VCN, subnet, security list, route table,
# internet gateway); only the declared results remain (on the host); the
# endpoint is unreachable after termination; the post-batch billing check
# passes ($0, inside allowance, no second VM, no extra volume) with a
# validated non-empty usage response; the journal snapshot shows the
# timer armed (ActiveState=active, NEXT within 60 s of the deadline);
# the state log shows the STOPPED transition at the timer deadline; the
# controller's run record proves its execution terminated this instance
# (exit 0, matching OCID, observed TERMINATED, and a TERMINATED entry
# in the state log inside the run window); the batch manifest's and the
# hash list's HMACs verify and the binding field matches.
# FAIL: the instance is not TERMINATED within 10 minutes of the terminate
# call; any network resource remains; the endpoint remains reachable after
# termination; the post-batch billing check fails (any charge, usage
# outside the allowance, a second VM, or an extra volume); the journal
# snapshot does not show the timer armed; no STOPPED transition is
# recorded at the timer deadline; the controller's run record is missing,
# malformed, shows a non-zero exit, a mismatched OCID, a job_id that
# does not match EXPECTED_CONTROLLER_JOB_ID, a command that does not
# match EXPECTED_TERMINATE_COMMAND exactly, or a non-TERMINATED
# observed state; no TERMINATED entry in the state log inside the
# controller run window; the DONE marker was not retrieved; or either
# HMAC fails / the binding mismatches.
# INCONCLUSIVE (exit 2): the script errors, times out, or the
# termination / closure / billing state cannot be verified. In
# particular: the journal snapshot or the state log or the run record is
# missing or malformed; the NEXT timestamp cannot be parsed from the
# snapshot; or the usage response is empty or structurally incomplete.
#
# REMOVED in V3 (spec V4 rule 16): the time-terminated cross-check.
# There is NO time-terminated field in the OCI Instance resource
# (verified against OCI Python SDK 2.192.0: the only time fields are
# time_created and time_maintenance_reboot_due). The controller-execution
# evidence is instead the run record PLUS the state log TERMINATED
# entry inside the run window (e4 below). This script never queries
# data."time-terminated".
#
# List-output parsing (spec V4 rule 17): every OCI list call in this
# script treats empty/whitespace-only stdout as an empty list (exit 0,
# no results), not as a parse error. Verified live 2026-11-25: empty
# list calls print 0 bytes. Applies to the instance list, the
# boot-volume list, the VNIC-attachment list, and the public-IP list.
#
# Deletion checks (b): a get must fail with the OCI 404 error shape -
# stderr JSON containing "status": 404 and code NotAuthorizedOrNotFound
# (verified live 2026-11-25, OCI_RESPONSE_SHAPES.md section 6). A get
# that succeeds means the resource still exists (FAIL); a failure with
# any other shape is INCONCLUSIVE.
#
# Exit: 0 = PASS, 1 = FAIL, 2 = error/inconclusive.
# Result line: O13_RESULT=PASS | FAIL | INCONCLUSIVE
#
# NOTE on the poll loop below: it is a BOUNDED WAIT (600 s) for an
# asynchronous state change (termination), not a retry that masks a
# failure. If TERMINATED is not reached within 600 s, it is FAIL.
# No other step in this script retries.
set -u

FAIL=0
INCONCLUSIVE=0
OCI_CLI=${OCI_CLI:-oci}
export OCI_CLI

for _v in INSTANCE_OCID VCN_OCID SUBNET_OCID SECLIST_OCID ROUTETABLE_OCID \
    IGW_OCID VM_PUBLIC_IP COMPARTMENT_OCID TENANCY_OCID BATCH_START \
    WATCHDOG_RUN_RECORD JOURNAL_SNAPSHOT INSTANCE_STATE_LOG \
    TIMER_DEADLINE BATCH_MANIFEST RESULTS_SHA256 HMAC_SECRET_FILE \
    EXPECTED_CONTROLLER_JOB_ID EXPECTED_TERMINATE_COMMAND DONE_MARKER; do
    eval "_val=\${$_v:-}"
    if [ -z "$_val" ]; then
        echo "O13_ERROR=required variable unset: $_v"
        echo "O13_RESULT=INCONCLUSIVE"
        exit 2
    fi
done

for _tool in "$OCI_CLI" curl python3; do
    if ! command -v "$_tool" >/dev/null 2>&1; then
        echo "O13_ERROR=required tool missing: $_tool"
        echo "O13_RESULT=INCONCLUSIVE"
        exit 2
    fi
done

_tmpdir=$(mktemp -d) || {
    echo "O13_ERROR=cannot create temp dir"
    echo "O13_RESULT=INCONCLUSIVE"
    exit 2
}
trap 'rm -rf "$_tmpdir"' EXIT

# --- (f) HMAC of the downloaded batch.json AND of results.sha256,
# verified BEFORE either is trusted for any teardown or billing
# conclusion (spec V4 rule 15), plus the results_sha256 binding check
# (batch.json's results_sha256 field must equal the SHA-256 of the
# downloaded results.sha256 file). A failed or missing HMAC, or a
# binding mismatch, is FAIL; a secret that cannot be read/parsed is
# INCONCLUSIVE. ---
python3 - "$BATCH_MANIFEST" "$RESULTS_SHA256" "$HMAC_SECRET_FILE" <<'PYEOF'
import hashlib, hmac, json, sys
manifest, hash_list, secret_file = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    secret_hex = open(secret_file).read().strip()
    key = bytes.fromhex(secret_hex)
    if len(key) != 32:
        print("O13_BATCH_HMAC secret_bytes=%d want=32" % len(key))
        sys.exit(2)
except Exception as e:
    print("O13_BATCH_HMAC secret_unreadable error=%s" % e)
    sys.exit(2)
def verify_hmac(path, label):
    sidecar = path + ".hmac"
    try:
        expect = open(sidecar).read().strip()
    except OSError:
        print("O13_%s missing_sidecar path=%s" % (label, path))
        return False
    try:
        got = hmac.new(key, open(path, "rb").read(), hashlib.sha256).hexdigest()
    except OSError as e:
        print("O13_%s unreadable path=%s error=%s" % (label, path, e))
        return None
    if hmac.compare_digest(got, expect):
        print("O13_%s verified path=%s" % (label, path))
        return True
    print("O13_%s mismatch path=%s" % (label, path))
    return False
ok = verify_hmac(manifest, "BATCH_HMAC")
if ok is None:
    sys.exit(2)
if not ok:
    sys.exit(1)
ok = verify_hmac(hash_list, "HASHLIST_HMAC")
if ok is None:
    sys.exit(2)
if not ok:
    sys.exit(1)
try:
    batch = json.load(open(manifest))
    actual = hashlib.sha256(open(hash_list, "rb").read()).hexdigest()
except Exception as e:
    print("O13_BINDING unreadable error=%s" % e)
    sys.exit(2)
if not isinstance(batch, dict) or "results_sha256" not in batch:
    print("O13_BINDING missing_field results_sha256")
    sys.exit(1)
if batch["results_sha256"] == actual:
    print("O13_BINDING results_sha256 match sha256=%s" % actual)
    sys.exit(0)
print("O13_BINDING mismatch batch_field=%s actual_sha256=%s" % (batch["results_sha256"], actual))
sys.exit(1)
PYEOF
_hmac_rc=$?
if [ "$_hmac_rc" -eq 1 ]; then
    FAIL=1
elif [ "$_hmac_rc" -ne 0 ]; then
    INCONCLUSIVE=1
fi

# --- (a) Instance TERMINATED (poll up to 600 s) ---
_state=""
_i=0
while [ "$_i" -lt 20 ]; do
    if _state=$("$OCI_CLI" compute instance get --instance-id "$INSTANCE_OCID" \
        --query 'data."lifecycle-state"' --raw-output 2>"$_tmpdir/inst.err"); then
        if [ "$_state" = "TERMINATED" ]; then
            break
        fi
        # Get succeeded but the instance is not terminated yet - wait
        # and poll again.
    elif grep -qi '404\|NotFound\|not found' "$_tmpdir/inst.err"; then
        echo "O13_INSTANCE result=not_found"
        INCONCLUSIVE=1
        break
    else
        echo "O13_INSTANCE result=query_failed"
        sed 's/^/O13_INSTANCE_ERR /' "$_tmpdir/inst.err" | head -n 3
        INCONCLUSIVE=1
        break
    fi
    _i=$((_i + 1))
    sleep 30
done
echo "O13_INSTANCE state=${_state:-unknown} polls=$_i"
if [ "$_state" != "TERMINATED" ] && [ "$INCONCLUSIVE" -eq 0 ]; then
    echo "O13_INSTANCE result=not_terminated"
    FAIL=1
elif [ "$_state" = "TERMINATED" ]; then
    echo "O13_INSTANCE result=terminated"
fi

# Availability domain (from the instance record) for the boot-volume check.
_ad=$(python3 -c '
import json, subprocess, sys, os
out = subprocess.run([os.environ.get("OCI_CLI", "oci"), "compute", "instance", "get",
    "--instance-id", os.environ["INSTANCE_OCID"]],
    capture_output=True, text=True)
try:
    print(json.loads(out.stdout)["data"]["availability-domain"])
except Exception:
    sys.exit(1)
' 2>/dev/null) || _ad=""
echo "O13_AVAILABILITY_DOMAIN=${_ad:-unknown}"

# --- (b) Network resources deleted: a get must fail with 404. ---
# check_deleted <label> <oci args...>
check_deleted() {
    _label=$1
    shift
    if "$OCI_CLI" "$@" >"$_tmpdir/get.out" 2>"$_tmpdir/get.err"; then
        echo "O13_DELETED label=$_label result=still_exists"
        FAIL=1
    elif grep -qE '"status"[[:space:]]*:[[:space:]]*404' "$_tmpdir/get.err" \
        && grep -q 'NotAuthorizedOrNotFound' "$_tmpdir/get.err"; then
        echo "O13_DELETED label=$_label result=deleted"
    else
        echo "O13_DELETED label=$_label result=inconclusive"
        sed 's/^/O13_DELETED_ERR /' "$_tmpdir/get.err" | head -n 3
        INCONCLUSIVE=1
    fi
}

check_deleted vcn network vcn get --vcn-id "$VCN_OCID"
check_deleted subnet network subnet get --subnet-id "$SUBNET_OCID"
check_deleted security-list network security-list get --security-list-id "$SECLIST_OCID"
check_deleted route-table network route-table get --rt-id "$ROUTETABLE_OCID"
check_deleted internet-gateway network internet-gateway get --ig-id "$IGW_OCID"

# --- (c) Endpoint closed, no VNIC, public IP released. ---
if curl -s -m 10 -o /dev/null -w '%{http_code}' "http://$VM_PUBLIC_IP:8080/" >/dev/null 2>&1; then
    echo "O13_ENDPOINT result=reachable"
    FAIL=1
else
    _rc=$?
    echo "O13_ENDPOINT result=unreachable rc=$_rc"
fi

if ! "$OCI_CLI" compute vnic-attachment list --compartment-id "$COMPARTMENT_OCID" \
    --instance-id "$INSTANCE_OCID" --all >"$_tmpdir/vnic.json" 2>"$_tmpdir/vnic.err"; then
    echo "O13_VNIC result=list_failed"
    sed 's/^/O13_VNIC_ERR /' "$_tmpdir/vnic.err" | head -n 3
    _vnic_n="ERR"
else
    # Empty/whitespace-only stdout is an empty list (spec V4 rule 17).
    _vnic_n=$(python3 - "$_tmpdir/vnic.json" <<'PYEOF' 2>/dev/null || echo ERR
import json, sys
try:
    raw = open(sys.argv[1]).read()
except OSError:
    print("ERR")
    sys.exit(0)
if not raw.strip():
    print(0)
    sys.exit(0)
try:
    print(len(json.loads(raw)["data"]))
except Exception:
    print("ERR")
PYEOF
)
fi
echo "O13_VNIC_ATTACHMENTS=${_vnic_n:-unknown}"
if [ "$_vnic_n" = "ERR" ] || [ -z "$_vnic_n" ]; then
    INCONCLUSIVE=1
elif [ "$_vnic_n" != "0" ]; then
    echo "O13_VNIC result=remaining"
    FAIL=1
else
    echo "O13_VNIC result=none"
fi

if ! "$OCI_CLI" network public-ip list --scope REGION \
    --compartment-id "$COMPARTMENT_OCID" --all >"$_tmpdir/pubip.json" 2>"$_tmpdir/pubip.err"; then
    echo "O13_PUBLIC_IP result=list_failed"
    sed 's/^/O13_PUBLIC_IP_ERR /' "$_tmpdir/pubip.err" | head -n 3
    _ip_n="ERR"
else
    # Empty/whitespace-only stdout is an empty list (spec V4 rule 17).
    _ip_n=$(python3 - "$_tmpdir/pubip.json" <<'PYEOF' 2>/dev/null || echo ERR
import json, sys, os
try:
    raw = open(sys.argv[1]).read()
except OSError:
    print("ERR")
    sys.exit(0)
if not raw.strip():
    print(0)
    sys.exit(0)
try:
    data = json.loads(raw)["data"]
    print(sum(1 for x in data if x.get("ip-address") == os.environ["VM_PUBLIC_IP"]))
except Exception:
    print("ERR")
PYEOF
)
fi
echo "O13_PUBLIC_IP_PRESENT=${_ip_n:-unknown}"
if [ "$_ip_n" = "ERR" ] || [ -z "$_ip_n" ]; then
    INCONCLUSIVE=1
elif [ "$_ip_n" != "0" ]; then
    echo "O13_PUBLIC_IP result=not_released"
    FAIL=1
else
    echo "O13_PUBLIC_IP result=released"
fi

# --- (d) Billing: $0 charged, no second A1 VM, no extra block volume. ---
# The usage-summary response must be validated as non-empty and
# structurally complete BEFORE zero cost can pass (spec V4 rule 18,
# corrected per the live response shape, OCI_RESPONSE_SHAPES.md
# section 2): the response is a JSON object whose "data" holds an
# "items" NON-EMPTY list (an empty list is INCONCLUSIVE - it proves no
# usage was recorded, not that the cost was zero); every item must have
# computed-amount (a number, not bool), time-usage-started, and
# time-usage-ended present. service and resource-name are null in the
# real response and are NOT required - they are recorded if present
# but never required to be strings. Only then is the summed
# computed-amount checked: it must be exactly 0.
_now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if ! "$OCI_CLI" usage-api usage-summary request-summarized-usages \
    --tenant-id "$TENANCY_OCID" \
    --time-usage-started "$BATCH_START" --time-usage-ended "$_now" \
    --granularity DAILY --query-type COST >"$_tmpdir/usage.json" 2>"$_tmpdir/usage.err"; then
    echo "O13_USAGE result=query_failed"
    sed 's/^/O13_USAGE_ERR /' "$_tmpdir/usage.err" | head -n 3
    INCONCLUSIVE=1
else
    python3 - "$_tmpdir/usage.json" <<'PYEOF'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception as e:
    print("O13_USAGE result=unparseable error=%s" % e)
    sys.exit(2)
# Real shape (verified live): {"data": {"items": [...]}}. A top-level
# "items" list is also accepted, so a differently-wrapped response is
# still validated the same way; any other shape is INCONCLUSIVE.
items = None
if isinstance(data, dict) and isinstance(data.get("items"), list):
    items = data["items"]
elif isinstance(data, dict) and isinstance(data.get("data"), dict) \
        and isinstance(data["data"].get("items"), list):
    items = data["data"]["items"]
if items is None:
    print("O13_USAGE result=unexpected_shape")
    sys.exit(2)
if len(items) == 0:
    print("O13_USAGE result=empty_items")
    sys.exit(2)
total = 0
for i, it in enumerate(items):
    if not isinstance(it, dict):
        print("O13_USAGE result=item_not_object index=%d" % i)
        sys.exit(2)
    for field in ("computed-amount", "time-usage-started", "time-usage-ended"):
        if field not in it:
            print("O13_USAGE result=missing_field item=%d field=%s" % (i, field))
            sys.exit(2)
    v = it["computed-amount"]
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        print("O13_USAGE result=bad_type item=%d field=computed-amount" % i)
        sys.exit(2)
    # service and resource-name are null in the real response: recorded
    # if present, never required to be strings (spec V4 rule 18).
    print("O13_USAGE_ITEM index=%d service=%s resource_name=%s" % (
        i, it.get("service"), it.get("resource-name")))
    total += v
print("O13_USAGE_COST_TOTAL=%s" % total)
print("O13_USAGE_ITEMS=%d" % len(items))
if total != 0:
    print("O13_USAGE result=charged")
    sys.exit(1)
print("O13_USAGE result=zero")
sys.exit(0)
PYEOF
    _usage_rc=$?
    if [ "$_usage_rc" -eq 1 ]; then
        FAIL=1
    elif [ "$_usage_rc" -ne 0 ]; then
        INCONCLUSIVE=1
    fi
fi

if ! "$OCI_CLI" compute instance list --compartment-id "$COMPARTMENT_OCID" \
    --all >"$_tmpdir/instlist.json" 2>"$_tmpdir/instlist.err"; then
    echo "O13_SECOND_A1 result=list_failed"
    sed 's/^/O13_SECOND_A1_ERR /' "$_tmpdir/instlist.err" | head -n 3
    _a1_n="ERR"
else
    # Empty/whitespace-only stdout is an empty list (spec V4 rule 17).
    _a1_n=$(python3 - "$_tmpdir/instlist.json" <<'PYEOF' 2>/dev/null || echo ERR
import json, sys
try:
    raw = open(sys.argv[1]).read()
except OSError:
    print("ERR")
    sys.exit(0)
if not raw.strip():
    print(0)
    sys.exit(0)
try:
    data = json.loads(raw)["data"]
    print(sum(1 for x in data
        if x.get("shape") == "VM.Standard.A1.Flex"
        and x.get("lifecycle-state") not in ("TERMINATED", "TERMINATING")))
except Exception:
    print("ERR")
PYEOF
)
fi
echo "O13_OTHER_A1_VMS=${_a1_n:-unknown}"
if [ "$_a1_n" = "ERR" ] || [ -z "$_a1_n" ]; then
    INCONCLUSIVE=1
elif [ "$_a1_n" != "0" ]; then
    echo "O13_SECOND_A1 result=exists"
    FAIL=1
else
    echo "O13_SECOND_A1 result=none"
fi

if [ -n "$_ad" ]; then
    # The OCI output goes to a temp file first: the Python program below
    # comes from a heredoc (stdin), so the JSON cannot also come from a
    # pipe - it must be a file argument.
    if ! "$OCI_CLI" bv boot-volume list --compartment-id "$COMPARTMENT_OCID" \
        --availability-domain "$_ad" --all >"$_tmpdir/vols.json" 2>/dev/null; then
        echo "O13_EXTRA_VOLUME result=list_failed"
        INCONCLUSIVE=1
        _vol_n="ERR"
    else
        _vol_n=$(python3 - "$_tmpdir/vols.json" "$BATCH_START" <<'PYEOF' 2>/dev/null || echo ERR
import json, sys
from datetime import datetime
def parse(t):
    return datetime.fromisoformat(t.replace("Z", "+00:00"))
try:
    raw = open(sys.argv[1]).read()
except OSError:
    print("ERR")
    sys.exit(0)
# Empty/whitespace-only stdout is an empty list (spec V4 rule 17).
if not raw.strip():
    print(0)
    sys.exit(0)
try:
    data = json.loads(raw)["data"]
    start = parse(sys.argv[2])
    print(sum(1 for x in data
        if x.get("time-created") and parse(x["time-created"]) > start))
except Exception:
    print("ERR")
PYEOF
)
    fi
    echo "O13_NEW_BOOT_VOLUMES=${_vol_n:-unknown}"
    if [ "$_vol_n" = "ERR" ] || [ -z "$_vol_n" ]; then
        INCONCLUSIVE=1
    elif [ "$_vol_n" != "0" ]; then
        echo "O13_EXTRA_VOLUME result=exists"
        FAIL=1
    else
        echo "O13_EXTRA_VOLUME result=none"
    fi
else
    echo "O13_EXTRA_VOLUME result=skipped_no_ad"
    INCONCLUSIVE=1
fi

# --- (e) Watchdog evidence (mandatory, based on actual execution records). ---
# (e1) Journal snapshot: REQUIRED (not optional). The harness captures
# it during VM-side teardown step 5 (proposal Sec. 11.2), after O1-O12
# complete and before the 90-minute timer fires, as exactly three
# sections in order: (1) systemctl show m8-watchdog.timer -p
# ActiveState -p SubState; (2) systemctl list-timers m8-watchdog.timer;
# (3) journalctl -u m8-watchdog.timer -u m8-watchdog.service -o
# short-iso. This check verifies: the file exists and is non-empty;
# section (1) contains ActiveState=active; section (2) contains a NEXT
# timestamp within 60 s of TIMER_DEADLINE. The NEXT timestamp is read
# from a systemctl list-timers output line, which starts with a weekday
# date-time (e.g. "Tue 2026-11-25 17:30:00 UTC") - journalctl lines use
# ISO timestamps and are NOT used for the NEXT check. The old heuristic
# (grep for a bare "active" anywhere, or a "Trigger:" line) is withdrawn
# and is NOT used here. Missing/empty snapshot, or a NEXT timestamp
# that cannot be parsed, is INCONCLUSIVE; timer not armed, or NEXT
# outside 60 s of the deadline, is FAIL.
if [ ! -f "$JOURNAL_SNAPSHOT" ]; then
    echo "O13_JOURNAL_SNAPSHOT result=missing"
    INCONCLUSIVE=1
elif [ ! -s "$JOURNAL_SNAPSHOT" ]; then
    echo "O13_JOURNAL_SNAPSHOT result=empty"
    INCONCLUSIVE=1
elif [ ! -f "$JOURNAL_SNAPSHOT.hmac" ]; then
    echo "O13_JOURNAL_SNAPSHOT result=missing_hmac_sidecar"
    FAIL=1
else
    # Snapshot HMAC (blocker L, 2026-11-25 ~23:04 PKT): the snapshot
    # is untrusted data served over plain HTTP, like any manifest.
    # Its HMAC is verified with the per-batch secret BEFORE any line
    # of it is trusted. A failed HMAC means the snapshot is
    # untrusted - FAIL, and the snapshot is NOT parsed (parsing an
    # untrusted snapshot proves nothing). An unreadable secret is
    # INCONCLUSIVE.
    python3 - "$JOURNAL_SNAPSHOT" "$HMAC_SECRET_FILE" <<'PYEOF'
import hashlib, hmac, sys
try:
    secret_hex = open(sys.argv[2]).read().strip()
    key = bytes.fromhex(secret_hex)
    if len(key) != 32:
        print("O13_JOURNAL_HMAC secret_bytes=%d want=32" % len(key))
        sys.exit(2)
except Exception as e:
    print("O13_JOURNAL_HMAC secret_unreadable error=%s" % e)
    sys.exit(2)
try:
    expect = open(sys.argv[1] + ".hmac").read().strip()
    got = hmac.new(key, open(sys.argv[1], "rb").read(), hashlib.sha256).hexdigest()
except OSError as e:
    print("O13_JOURNAL_HMAC unreadable error=%s" % e)
    sys.exit(2)
if hmac.compare_digest(got, expect):
    print("O13_JOURNAL_HMAC verified")
    sys.exit(0)
print("O13_JOURNAL_HMAC mismatch")
sys.exit(1)
PYEOF
    _jh_rc=$?
    if [ "$_jh_rc" -eq 1 ]; then
        echo "O13_JOURNAL_SNAPSHOT result=untrusted_hmac_failed"
        FAIL=1
    elif [ "$_jh_rc" -ne 0 ]; then
        echo "O13_JOURNAL_SNAPSHOT result=hmac_unverifiable"
        INCONCLUSIVE=1
    else
    python3 - "$JOURNAL_SNAPSHOT" "$TIMER_DEADLINE" <<'PYEOF'
import re, sys
from datetime import datetime, timedelta, timezone
def parse_iso(t):
    return datetime.fromisoformat(t.replace("Z", "+00:00"))
try:
    deadline = parse_iso(sys.argv[2])
except Exception:
    print("O13_JOURNAL_TIMER result=bad_deadline")
    sys.exit(2)
try:
    text = open(sys.argv[1]).read()
except OSError:
    print("O13_JOURNAL_TIMER result=unreadable")
    sys.exit(2)
if "m8-watchdog.timer" not in text:
    print("O13_JOURNAL_TIMER result=timer_not_shown")
    sys.exit(1)
if "ActiveState=active" not in text:
    print("O13_JOURNAL_TIMER result=not_armed")
    sys.exit(1)
# NEXT timestamp: a systemctl list-timers line starts with a weekday
# date-time; take the first such line in the snapshot. The timezone
# token (e.g. UTC) is ignored - the VM clock is UTC and the deadline
# is ISO 8601 UTC, so the bare date-time is read as UTC.
m = re.search(r"^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
              text, re.MULTILINE)
if not m:
    print("O13_JOURNAL_TIMER result=next_timestamp_not_found")
    sys.exit(2)
try:
    nxt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
except Exception:
    print("O13_JOURNAL_TIMER result=next_timestamp_unparseable")
    sys.exit(2)
diff = abs((nxt - deadline).total_seconds())
print("O13_JOURNAL_TIMER next=%s deadline=%s diff_s=%.0f" % (
    m.group(1), sys.argv[2], diff))
if diff <= 60:
    print("O13_JOURNAL_TIMER result=armed")
    sys.exit(0)
print("O13_JOURNAL_TIMER result=next_outside_60s")
sys.exit(1)
PYEOF
    _jt_rc=$?
    if [ "$_jt_rc" -eq 1 ]; then
        FAIL=1
    elif [ "$_jt_rc" -ne 0 ]; then
        INCONCLUSIVE=1
    fi
    fi
fi

# (e2) Instance-state log: must contain a STOPPED entry with a timestamp
# within [TIMER_DEADLINE - 600 s, TIMER_DEADLINE + 600 s]. Missing log
# = INCONCLUSIVE; no STOPPED entry in the window = FAIL - UNLESS the
# log does not show the poller alive through the deadline (no
# SUCCESSFUL entry at or after TIMER_DEADLINE), in which case it is
# INCONCLUSIVE (the poller was dead during the window, so the log
# cannot prove the VM was not STOPPED - blocker L, 2026-11-25
# ~23:04 PKT). Successful observations ONLY (blocker L, 2026-11-25
# ~23:30 PKT): QUERY_FAILED entries never count as deadline coverage
# - they prove the poller ran, not that it observed a state.
if [ ! -f "$INSTANCE_STATE_LOG" ]; then
    echo "O13_STATE_LOG result=missing"
    INCONCLUSIVE=1
else
    python3 - "$INSTANCE_STATE_LOG" "$TIMER_DEADLINE" <<'PYEOF'
import sys
from datetime import datetime, timedelta
def parse(t):
    return datetime.fromisoformat(t.replace("Z", "+00:00"))
try:
    deadline = parse(sys.argv[2])
except Exception:
    print("O13_STATE_LOG result=bad_deadline")
    sys.exit(2)
lo, hi = deadline - timedelta(seconds=600), deadline + timedelta(seconds=600)
print("O13_STATE_LOG window=%s..%s" % (lo.isoformat(), hi.isoformat()))
try:
    lines = open(sys.argv[1]).read().splitlines()
except OSError:
    print("O13_STATE_LOG result=unreadable")
    sys.exit(2)
entries = []
for line in lines:
    parts = line.split(None, 1)
    if len(parts) != 2:
        continue
    try:
        ts = parse(parts[0])
    except Exception:
        continue
    entries.append((ts, parts[1].strip()))
if not entries:
    print("O13_STATE_LOG result=no_parseable_entries")
    sys.exit(2)
# Coverage (blocker L, 2026-11-25 ~23:04 PKT; successful-only,
# 2026-11-25 ~23:30 PKT): the log must show the poller was alive
# THROUGH the timer deadline (at least one SUCCESSFUL observation
# at or after TIMER_DEADLINE) for a missing STOPPED to count as
# FAIL. If the poller stopped before the deadline, the log cannot
# prove the VM was not STOPPED in the window - INCONCLUSIVE (a dead
# poller is a harness failure, not a VM failure). QUERY_FAILED
# entries never count: a log whose only entries at or after the
# deadline are QUERY_FAILED proves nothing about the VM state.
VALID = {"PROVISIONING", "RUNNING", "STOPPING", "STOPPED",
         "TERMINATING", "TERMINATED"}
successful = [(ts, st) for ts, st in entries if st in VALID]
print("O13_STATE_LOG successful_observations=%d total_entries=%d"
      % (len(successful), len(entries)))
if not successful:
    print("O13_STATE_LOG result=no_successful_observations")
    sys.exit(2)
observed_through = any(ts >= deadline for ts, _st in successful)
stopped_at = None
for ts, st in successful:
    if st == "STOPPED" and lo <= ts <= hi:
        stopped_at = ts
        break
if stopped_at is not None:
    print("O13_STATE_LOG stopped_at=%s" % stopped_at.isoformat())
    print("O13_STATE_LOG result=stopped_in_window")
    sys.exit(0)
if not observed_through:
    print("O13_STATE_LOG result=poller_did_not_observe_through_deadline last_successful=%s" % max(ts for ts, _st in successful).isoformat())
    sys.exit(2)
print("O13_STATE_LOG result=no_stopped_in_window")
sys.exit(1)
PYEOF
    _sl_rc=$?
    if [ "$_sl_rc" -eq 1 ]; then
        FAIL=1
    elif [ "$_sl_rc" -ne 0 ]; then
        INCONCLUSIVE=1
    fi
fi

# (e3) Controller run record: valid JSON with job_id, run_start,
# run_end, instance_ocid, command, exit_code, observed_state.
# Malformed/missing = INCONCLUSIVE. exit_code != 0, instance_ocid
# mismatch, or observed_state != TERMINATED = FAIL.
_run_out=$(python3 - "$WATCHDOG_RUN_RECORD" <<'PYEOF' 2>/dev/null || echo PARSE_ERROR
import json, sys
try:
    r = json.load(open(sys.argv[1]))
except Exception as e:
    print("PARSE_ERROR %s" % e)
    sys.exit(2)
if not isinstance(r, dict):
    print("PARSE_ERROR not_object")
    sys.exit(2)
for f in ("job_id", "run_start", "run_end", "instance_ocid", "command",
          "exit_code", "observed_state"):
    if f not in r:
        print("PARSE_ERROR missing_field %s" % f)
        sys.exit(2)
print("exit_code=%s" % r["exit_code"])
print("instance_ocid=%s" % r["instance_ocid"])
print("observed_state=%s" % r["observed_state"])
print("run_start=%s" % r["run_start"])
print("run_end=%s" % r["run_end"])
print("job_id=%s" % r["job_id"])
print("command=%s" % r["command"])
PYEOF
)
case "$_run_out" in
    PARSE_ERROR*)
        echo "O13_RUN_RECORD $_run_out"
        INCONCLUSIVE=1
        ;;
    *)
        printf '%s\n' "$_run_out" | sed 's/^/O13_RUN_RECORD /'
        _rr_exit=$(printf '%s\n' "$_run_out" | awk -F= '/^exit_code=/ {print $2}')
        _rr_ocid=$(printf '%s\n' "$_run_out" | awk -F= '/^instance_ocid=/ {print $2}')
        _rr_state=$(printf '%s\n' "$_run_out" | awk -F= '/^observed_state=/ {print $2}')
        _rr_start=$(printf '%s\n' "$_run_out" | awk -F= '/^run_start=/ {print $2}')
        _rr_end=$(printf '%s\n' "$_run_out" | awk -F= '/^run_end=/ {print $2}')
        _rr_job=$(printf '%s\n' "$_run_out" | awk -F= '/^job_id=/ {print $2}')
        _rr_cmd=$(printf '%s\n' "$_run_out" | awk -F= '/^command=/ {print $2}')
        # Exact-match checks (blocker L, 2026-11-25 ~22:39 PKT): the
        # run record must prove THIS pre-authorized controller ran
        # THIS pre-authorized command. Checking only that the fields
        # exist does not prove that - any job running any terminate
        # command would pass. The expected values come from the run
        # manifest, recorded before the VM was created / the batch ran.
        if [ "$_rr_exit" != "0" ]; then
            echo "O13_RUN_RECORD result=exit_nonzero exit_code=$_rr_exit"
            FAIL=1
        elif [ "$_rr_ocid" != "$INSTANCE_OCID" ]; then
            echo "O13_RUN_RECORD result=ocid_mismatch"
            FAIL=1
        elif [ "$_rr_job" != "$EXPECTED_CONTROLLER_JOB_ID" ]; then
            echo "O13_RUN_RECORD result=job_id_mismatch job_id=$_rr_job expected=$EXPECTED_CONTROLLER_JOB_ID"
            FAIL=1
        elif [ "$_rr_cmd" != "$EXPECTED_TERMINATE_COMMAND" ]; then
            echo "O13_RUN_RECORD result=command_mismatch"
            echo "O13_RUN_RECORD command_recorded=$_rr_cmd"
            echo "O13_RUN_RECORD command_expected=$EXPECTED_TERMINATE_COMMAND"
            FAIL=1
        elif [ "$_rr_state" != "TERMINATED" ]; then
            echo "O13_RUN_RECORD result=state_not_terminated observed_state=$_rr_state"
            FAIL=1
        else
            echo "O13_RUN_RECORD result=valid"
        fi
        ;;
esac

# (e4) Controller-execution evidence (spec V4 rule 16): the
# instance-state log must contain a TERMINATED entry with a timestamp
# inside [run_start, run_end + 600 s] - the host observed the
# transition during the controller's run, proving the controller's
# execution caused the termination. No TERMINATED entry in the window
# is FAIL - UNLESS the log's last SUCCESSFUL entry is before
# run_start (the poller was dead during the controller run), in
# which case it is INCONCLUSIVE (blocker L, 2026-11-25 ~23:04
# PKT). Successful observations ONLY (blocker L, 2026-11-25
# ~23:30 PKT): QUERY_FAILED entries never count as coverage. A
# missing/unparseable run window or state log is INCONCLUSIVE. There
# is no time-terminated field to read from the OCI API, and this
# script does not query one. (e4b) below then checks liveness AFTER
# the termination observation.
if [ -n "${_rr_start:-}" ] && [ -n "${_rr_end:-}" ] && [ -f "$INSTANCE_STATE_LOG" ]; then
    python3 - "$INSTANCE_STATE_LOG" "$_rr_start" "$_rr_end" <<'PYEOF'
import sys
from datetime import datetime, timedelta
def parse(t):
    return datetime.fromisoformat(t.replace("Z", "+00:00"))
try:
    start = parse(sys.argv[2])
    end = parse(sys.argv[3]) + timedelta(seconds=600)
except Exception:
    print("O13_TERMINATED_IN_WINDOW result=unparseable_window")
    sys.exit(2)
print("O13_TERMINATED_IN_WINDOW window=%s..%s" % (sys.argv[2], end.isoformat()))
try:
    lines = open(sys.argv[1]).read().splitlines()
except OSError:
    print("O13_TERMINATED_IN_WINDOW result=unreadable")
    sys.exit(2)
entries = []
for line in lines:
    parts = line.split(None, 1)
    if len(parts) != 2:
        continue
    try:
        ts = parse(parts[0])
    except Exception:
        continue
    entries.append((ts, parts[1].strip()))
if not entries:
    print("O13_TERMINATED_IN_WINDOW result=no_parseable_entries")
    sys.exit(2)
# Coverage (blocker L, 2026-11-25 ~23:04 PKT; successful-only,
# 2026-11-25 ~23:30 PKT): the log must show the poller was alive
# during the controller run (its last SUCCESSFUL observation at or
# after run_start). If the last successful observation is before
# the run started, the poller was dead during the run -
# INCONCLUSIVE (a dead poller is a harness failure, not a VM
# failure). QUERY_FAILED entries never count.
VALID = {"PROVISIONING", "RUNNING", "STOPPING", "STOPPED",
         "TERMINATING", "TERMINATED"}
successful = [(ts, st) for ts, st in entries if st in VALID]
print("O13_TERMINATED_IN_WINDOW successful_observations=%d total_entries=%d"
      % (len(successful), len(entries)))
if not successful:
    print("O13_TERMINATED_IN_WINDOW result=no_successful_observations")
    sys.exit(2)
if max(ts for ts, _st in successful) < start:
    print("O13_TERMINATED_IN_WINDOW result=poller_dead_before_controller_run last_successful=%s" % max(ts for ts, _st in successful).isoformat())
    sys.exit(2)
found = False
for ts, st in successful:
    if st == "TERMINATED" and start <= ts <= end:
        print("O13_TERMINATED_IN_WINDOW terminated_at=%s" % ts.isoformat())
        found = True
        break
if found:
    print("O13_TERMINATED_IN_WINDOW result=in_controller_window")
    sys.exit(0)
print("O13_TERMINATED_IN_WINDOW result=no_terminated_in_window")
sys.exit(1)
PYEOF
    _tw_rc=$?
    if [ "$_tw_rc" -eq 1 ]; then
        FAIL=1
    elif [ "$_tw_rc" -ne 0 ]; then
        INCONCLUSIVE=1
    fi
elif [ -z "${_rr_start:-}" ] || [ -z "${_rr_end:-}" ]; then
    echo "O13_TERMINATED_IN_WINDOW result=skipped_no_run_record_window"
    INCONCLUSIVE=1
else
    echo "O13_TERMINATED_IN_WINDOW result=skipped_no_state_log"
    INCONCLUSIVE=1
fi

# (e4b) Liveness after termination (blocker L, 2026-11-25 ~23:30
# PKT; count corrected to THREE, 2026-11-26 ~00:15 PKT): the log
# must contain THREE TERMINATED observations with timestamps
# strictly after the first TERMINATED entry inside the controller
# window. This is the poller's liveness check after termination
# (o13_poller.sh performs THREE liveness queries, one POLL_INTERVAL
# apart, after observing TERMINATED, and appends each observation):
# it proves the poller was still alive and the instance still
# TERMINATED after the termination observation. The V7 rule said
# "a second observation" while the V7 spec rule 26 said three -
# the spec was internally inconsistent, and the V7 poller exited
# after ONE. V8 makes poller, spec rule 26, spec rule 27, (e4b),
# and proposal Sec. 11.4 all agree on exactly THREE. The three
# observations are NOT bounded by the (e4) window - they only have
# to be after the first, whenever they happened. A log with fewer
# than three TERMINATED entries after the first is INCONCLUSIVE
# (the poller may have died during its liveness window).
# QUERY_FAILED entries after the first TERMINATED do not count -
# only successful TERMINATED observations count. If (e4) found no
# TERMINATED in the window, this check is skipped (exit 0): (e4)
# already decided the verdict for that case, and (e4b) must not
# add a second one.
# REGRESSION CHECK (rule 26, enforced in code in V8): any valid
# non-TERMINATED state observed AFTER the first TERMINATED entry
# is a state regression - the lifecycle-state observation is
# inconsistent and the batch is INVALID (FAIL here). In V7 this
# check existed only in the spec's FAIL line; the poller exited 2
# on a regression but o13.sh never re-checked the log, so a
# regression the poller logged but did not catch would have
# passed (e4) silently. V8 checks the log itself.
if [ -n "${_rr_start:-}" ] && [ -n "${_rr_end:-}" ] && [ -f "$INSTANCE_STATE_LOG" ]; then
    # (V11, rule 39) Bounded wait for the poller's liveness
    # evidence. The poller writes its three liveness observations
    # one POLL_INTERVAL apart AFTER its own TERMINATED observation,
    # but this check used to read the state log exactly once, the
    # moment o13.sh reached it. If o13.sh reached the liveness
    # check before the poller wrote its third entry, the count was
    # 2 and the batch went INCONCLUSIVE although the poller later
    # confirmed all three - a scheduling race, not a failed test.
    # The V11 driver caught it twice: the batch-id and allpass runs
    # both have o13_exit in the SAME second as the poller's third
    # liveness write (03:23:10Z and 03:32:42Z), while the three
    # passing runs have o13_exit 5-6 s after it. The wait below
    # re-reads the log every 2 s until the program reports
    # confirmed (exit 0) or a decisive outcome (exit 1 regression
    # FAIL, exit 2 any other INCONCLUSIVE), or the bound expires.
    # Exit 3 means "fewer than three liveness observations so far"
    # and is the ONLY retryable outcome. The bound defaults to
    # 180 s: the liveness loop spans at most 3 x POLL_INTERVAL
    # (30 s in production = 90 s, 5 s in dry-run = 15 s) after the
    # poller's TERMINATED observation, and o13.sh can observe
    # TERMINATED up to one poll interval before the poller does,
    # so 180 s covers the worst case with margin. On expiry the
    # count as read decides (INCONCLUSIVE) - exactly the old
    # behaviour, never a pass. O13_LIVENESS_WAIT_MAX_S overrides
    # the bound (test use); an unset or non-numeric value falls
    # back to 180.
    _lb_wait_max=${O13_LIVENESS_WAIT_MAX_S:-180}
    case "$_lb_wait_max" in ''|*[!0-9]*) _lb_wait_max=180 ;; esac
    _lb_waited=0
    _lb_rc=3
    _lb_out=""
    while true; do
        _lb_out=$(python3 - "$INSTANCE_STATE_LOG" "$_rr_start" "$_rr_end" <<'PYEOF'
import sys
from datetime import datetime, timedelta
def parse(t):
    return datetime.fromisoformat(t.replace("Z", "+00:00"))
try:
    start = parse(sys.argv[2])
    end = parse(sys.argv[3]) + timedelta(seconds=600)
except Exception:
    print("O13_LIVENESS_AFTER_TERMINATION result=unparseable_window")
    sys.exit(2)
try:
    lines = open(sys.argv[1]).read().splitlines()
except OSError:
    print("O13_LIVENESS_AFTER_TERMINATION result=unreadable")
    sys.exit(2)
VALID = {"PROVISIONING", "RUNNING", "STOPPING", "STOPPED",
         "TERMINATING", "TERMINATED"}
entries = []
for line in lines:
    parts = line.split(None, 1)
    if len(parts) != 2:
        continue
    try:
        ts = parse(parts[0])
    except Exception:
        continue
    entries.append((ts, parts[1].strip()))
if not entries:
    print("O13_LIVENESS_AFTER_TERMINATION result=no_parseable_entries")
    sys.exit(2)
first = None
for ts, st in entries:
    if st == "TERMINATED" and start <= ts <= end:
        first = ts
        break
if first is None:
    print("O13_LIVENESS_AFTER_TERMINATION result=skipped_no_terminated_in_window")
    sys.exit(0)
# Regression: any valid non-TERMINATED state after the first
# TERMINATED observation is inconsistent - FAIL (batch INVALID).
for ts, st in entries:
    if ts > first and st in VALID and st != "TERMINATED":
        print("O13_LIVENESS_AFTER_TERMINATION first_terminated_at=%s regressed_state=%s regressed_at=%s result=state_regressed_after_termination" % (first.isoformat(), st, ts.isoformat()))
        sys.exit(1)
after = [ts for ts, st in entries if st == "TERMINATED" and ts > first]
if len(after) < 3:
    print("O13_LIVENESS_AFTER_TERMINATION first_terminated_at=%s liveness_observations=%d result=no_liveness_observation_after_termination" % (first.isoformat(), len(after)))
    sys.exit(3)
print("O13_LIVENESS_AFTER_TERMINATION first_terminated_at=%s liveness_observed_at=%s liveness_observations=3" % (first.isoformat(), after[2].isoformat()))
print("O13_LIVENESS_AFTER_TERMINATION result=liveness_confirmed")
sys.exit(0)
PYEOF
)
        _lb_rc=$?
        if [ "$_lb_rc" -ne 3 ]; then break; fi
        if [ "$_lb_waited" -ge "$_lb_wait_max" ]; then break; fi
        sleep 2
        _lb_waited=$((_lb_waited + 2))
    done
    if [ "$_lb_waited" -gt 0 ]; then
        echo "O13_LIVENESS_AFTER_TERMINATION waited_s=$_lb_waited"
    fi
    printf '%s\n' "$_lb_out"
    if [ "$_lb_rc" -eq 3 ]; then
        _lb_rc=2
    fi
    if [ "$_lb_rc" -eq 1 ]; then
        FAIL=1
    elif [ "$_lb_rc" -ne 0 ]; then
        INCONCLUSIVE=1
    fi
elif [ -z "${_rr_start:-}" ] || [ -z "${_rr_end:-}" ]; then
    echo "O13_LIVENESS_AFTER_TERMINATION result=skipped_no_run_record_window"
    INCONCLUSIVE=1
else
    echo "O13_LIVENESS_AFTER_TERMINATION result=skipped_no_state_log"
    INCONCLUSIVE=1
fi

# (e5) DONE marker retrieved (blocker L, 2026-11-25 ~22:39 PKT): the
# host must have retrieved the final DONE marker. In V4 the VM-side
# teardown stopped the results server BEFORE DONE was written, so the
# host could never retrieve it - the teardown order is fixed in
# proposal Sec. 11.2 (DONE is written before the server stops, and the
# server stays up until the host downloads). If DONE is absent here,
# the fixed order did not hold: INCONCLUSIVE, never a pass. (The
# marker's content is empty by design; only its presence is checked.
# Its authenticity is covered by the batch manifest HMAC in (f).)
if [ ! -f "$DONE_MARKER" ]; then
    echo "O13_DONE_MARKER result=missing"
    INCONCLUSIVE=1
else
    echo "O13_DONE_MARKER result=retrieved"
fi

if [ "$INCONCLUSIVE" -gt 0 ]; then
    echo "O13_RESULT=INCONCLUSIVE"
    exit 2
fi
if [ "$FAIL" -gt 0 ]; then
    echo "O13_RESULT=FAIL"
    exit 1
fi
echo "O13_RESULT=PASS"
exit 0
