#!/bin/sh
# mock_oci.sh - mock OCI CLI for the M8 --dry-run mode (Revision 8).
# Spec: O_TESTS_SPEC_V7.md rule 29; proposal M8_PROPOSAL_V8.md Sec. 11.5.
#
# *** DRY-RUN ONLY. It never contacts Oracle, creates no cloud
# resource, and spends nothing. It answers the exact OCI CLI calls
# the runner and the O-test scripts make, with the RECORDED REAL
# response shapes from m8/OCI_RESPONSE_SHAPES.md (never invented
# shapes): empty list calls print 0 bytes; the usage-summary shape
# is the live shape (service/resource-name null, computed-amount a
# JSON number); the 404 error shape is the live ServiceError JSON
# (status 404, code NotAuthorizedOrNotFound); instance get uses the
# kebab-case lifecycle-state key; the Instance model has no
# time-terminated field (so no such field is ever returned).
#
# The mock is STATEFUL: its state lives in $MOCK_OCI_STATE (a host
# directory created by the dry-run driver). The instance lifecycle
# is computed from timestamps in instance.json, so the poller
# observes the real sequence PROVISIONING -> RUNNING -> STOPPED
# (VM-side timer) -> TERMINATING -> TERMINATED (controller), with
# the same 30 s / 5 s polling the real scripts use.
#
# Supported --query expressions (exactly the ones the runner and
# the O-test scripts use; anything else is an error, exit 2):
#   data.id, data."home-region-key", data."available",
#   data."lifecycle-state", data[0].id, data[0]."public-ip",
#   length(data).
# With --raw-output a string/number is printed bare (no quotes).
#
# Usage: MOCK_OCI_STATE=<dir> mock_oci.sh <service> <resource> <action> [flags...]
# Exit: 0 on success; 1 on a 404 (resource deleted/nonexistent,
#   stderr carries the live 404 shape); 2 on a mock error
#   (unsupported command/query, missing state).
set -u

[ -n "${MOCK_OCI_STATE:-}" ] || { echo "mock_oci: MOCK_OCI_STATE is not set" >&2; exit 2; }
STATE="$MOCK_OCI_STATE"
[ -d "$STATE" ] || { echo "mock_oci: state dir missing: $STATE" >&2; exit 2; }
# (V11, rule 37) Invocation counter: every mock OCI call appends one
# line to $STATE/calls.log, so a regression can assert that a replay
# invocation made ZERO OCI calls. The file is created lazily on the
# first call and is never read by the mock itself; it is batch
# evidence, not mock state.
printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown-time)" "${*:-none}" >> "$STATE/calls.log" 2>/dev/null || true

TENANCY_OCID="ocid1.tenancy.oc1..aaaaaaaaarofozkiqhscb55mmn5ugszaxbeuo53bymesuzxvhomqcvs62vfq"
AD="JJYF:ME-DUBAI-1-AD-1"

# flag_value NAME [args...] - print the value of --NAME (or --NAME=VALUE).
flag_value() {
    _name=$1; shift
    while [ $# -gt 0 ]; do
        case "$1" in
            "$_name") printf '%s\n' "${2:-}"; return 0 ;;
            "$_name="*) printf '%s\n' "${1#*=}"; return 0 ;;
        esac
        shift
    done
    return 1
}

# has_flag NAME [args...] - true if --NAME is present.
has_flag() {
    _name=$1; shift
    while [ $# -gt 0 ]; do
        case "$1" in "$_name"|"$_name="*) return 0 ;; esac
        shift
    done
    return 1
}

# emit_404 OPERATION SERVICE - print the live 404 ServiceError JSON
# (OCI_RESPONSE_SHAPES.md section 6) to stderr and exit 1.
emit_404() {
    _op=$1; _svc=$2
    _ts=$(date -u +%Y-%m-%dT%H:%M:%S.000000+00:00)
    cat >&2 <<EOF
{
    "client_version": "Oracle-PythonSDK/2.192.0, Oracle-PythonCLI/3.96.3",
    "code": "NotAuthorizedOrNotFound",
    "message": "Authorization failed or requested resource not found.",
    "operation_name": "$_op",
    "status": 404,
    "target_service": "$_svc",
    "timestamp": "$_ts"
}
EOF
    exit 1
}

# apply_query JSON QUERY RAW - evaluate one of the supported --query
# expressions against the JSON (passed as $1). With RAW=1, print a
# string/number bare; otherwise print the JSON value.
apply_query() {
    _json=$1; _query=$2; _raw=$3
    python3 - "$_query" "$_raw" "$_json" <<'PYEOF'
import json, sys
q, raw = sys.argv[1], sys.argv[2] == "1"
try:
    doc = json.loads(sys.argv[3])
except Exception as e:
    print("mock_oci: cannot parse JSON for --query: %s" % e, file=sys.stderr)
    sys.exit(2)
# Supported expressions only (the ones the runner / O-test scripts use).
if q == "data.id":
    v = doc["data"]["id"]
elif q == 'data."home-region-key"':
    v = doc["data"]["home-region-key"]
elif q == 'data."available"':
    v = doc["data"]["available"]
elif q == 'data."lifecycle-state"':
    v = doc["data"]["lifecycle-state"]
elif q == "data[0].id":
    v = doc["data"][0]["id"]
elif q == 'data[0]."public-ip"':
    v = doc["data"][0]["public-ip"]
elif q == "length(data)":
    v = len(doc["data"])
else:
    print("mock_oci: unsupported --query: %s" % q, file=sys.stderr)
    sys.exit(2)
if raw:
    if v is None:
        print("null")
    elif isinstance(v, bool):
        print("true" if v else "false")
    else:
        print(v)
else:
    print(json.dumps(v))
PYEOF
}

# output_json JSON [QUERY] [RAW] - print the response, applying
# --query/--raw-output if given (the flags are parsed by the caller
# into $QUERY / $RAW).
output_json() {
    _json=$1
    if [ -n "${QUERY:-}" ]; then
        apply_query "$_json" "$QUERY" "${RAW:-0}"
    else
        printf '%s\n' "$_json"
    fi
}

# instance_state - compute the mock instance's effective lifecycle
# state from instance.json timestamps (see the header). Prints the
# bare state token. Exits 2 if no instance exists.
instance_state() {
    python3 - "$STATE/instance.json" <<'PYEOF'
import json, sys, time
try:
    inst = json.load(open(sys.argv[1]))
except Exception:
    print("PROVISIONING")
    sys.exit(0)
now = time.time()
term = inst.get("terminate_epoch")
if term is not None:
    if now >= term + 2:
        print("TERMINATED")
    else:
        print("TERMINATING")
    sys.exit(0)
timer = inst.get("timer_epoch")
if timer is not None and now >= timer:
    print("STOPPED")
    sys.exit(0)
run = inst.get("running_epoch")
if run is not None and now >= run:
    print("RUNNING")
    sys.exit(0)
print("PROVISIONING")
PYEOF
}

# instance_exists - true if instance.json exists and has an id.
instance_exists() {
    [ -f "$STATE/instance.json" ] && python3 -c "import json,sys; json.load(open('$STATE/instance.json'))['id']" 2>/dev/null >/dev/null
}

# instance_json - the full instance-get response JSON (data + etag).
instance_json() {
    _state=$(instance_state)
    python3 - "$STATE/instance.json" "$_state" <<'PYEOF'
import json, sys
inst = json.load(open(sys.argv[1]))
state = sys.argv[2]
doc = {"data": {
    "availability-domain": inst.get("availability_domain", "JJYF:ME-DUBAI-1-AD-1"),
    "compartment-id": inst.get("compartment_id", ""),
    "display-name": inst.get("display_name", "m8-batch-dryrun"),
    "id": inst["id"],
    "image-id": inst.get("image_id", ""),
    "lifecycle-state": state,
    "shape": "VM.Standard.A1.Flex",
    "time-created": inst.get("time_created", ""),
}, "etag": "mock-etag"}
print(json.dumps(doc))
PYEOF
}

# network_json KIND - the full get-response JSON for a network
# resource of kind KIND (vcn/subnet/seclist/rt/igw), or empty if it
# does not exist. Deleted resources are handled by the caller.
network_json() {
    _kind=$1
    python3 - "$STATE/network.json" "$_kind" <<'PYEOF'
import json, sys
try:
    net = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
kind = sys.argv[2]
res = net.get(kind)
if not res:
    sys.exit(1)
print(json.dumps({"data": res, "etag": "mock-etag"}))
PYEOF
}

# network_deleted KIND - true if the network resource is deleted.
network_deleted() {
    _kind=$1
    python3 - "$STATE/network.json" "$_kind" <<'PYEOF'
import json, sys
try:
    net = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
res = net.get(sys.argv[2])
if res and res.get("deleted"):
    sys.exit(0)
sys.exit(1)
PYEOF
}

# usage_json - the usage-summary fixture in the RECORDED REAL shape
# (OCI_RESPONSE_SHAPES.md section 2): {"data": {"items": [...]}},
# one item per day from the batch start to now, computed-amount 0.0
# (a JSON number), service/resource-name null.
usage_json() {
    python3 - "$STATE/batch.json" <<'PYEOF'
import json, sys
from datetime import datetime, timedelta, timezone
try:
    batch = json.load(open(sys.argv[1]))
    start = datetime.fromisoformat(batch["creation_time"].replace("Z", "+00:00"))
except Exception:
    start = datetime.now(timezone.utc) - timedelta(days=1)
now = datetime.now(timezone.utc)
items = []
day = start.replace(hour=0, minute=0, second=0, microsecond=0)
while day <= now:
    nxt = day + timedelta(days=1)
    items.append({
        "ad": None,
        "attributed-cost": "0",
        "attributed-usage": "0.585398808617",
        "compartment-id": None,
        "compartment-name": None,
        "computed-amount": 0.0,
        "computed-quantity": 0.585398808617,
        "currency": "SGD",
        "discount": None,
        "is-forecast": False,
        "list-rate": None,
        "platform": None,
        "region": None,
        "resource-id": None,
        "resource-name": None,
        "service": None,
        "shape": None,
        "sku-name": None,
        "tags": [{"key": None, "namespace": None, "value": None}],
        "tenant-id": None,
        "time-usage-ended": nxt.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "time-usage-started": day.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "unit": None,
        "unit-price": None,
    })
    day = nxt
# A batch that starts and ends on the same day still yields one item
# (the day containing the batch start); an empty items list would
# make o13 (d) INCONCLUSIVE, so never return an empty list.
if not items:
    day = start.replace(hour=0, minute=0, second=0, microsecond=0)
    nxt = day + timedelta(days=1)
    items.append({
        "ad": None,
        "attributed-cost": "0",
        "attributed-usage": "0.585398808617",
        "compartment-id": None,
        "compartment-name": None,
        "computed-amount": 0.0,
        "computed-quantity": 0.585398808617,
        "currency": "SGD",
        "discount": None,
        "is-forecast": False,
        "list-rate": None,
        "platform": None,
        "region": None,
        "resource-id": None,
        "resource-name": None,
        "service": None,
        "shape": None,
        "sku-name": None,
        "tags": [{"key": None, "namespace": None, "value": None}],
        "tenant-id": None,
        "time-usage-ended": nxt.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "time-usage-started": day.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "unit": None,
        "unit-price": None,
    })
print(json.dumps({"data": {"items": items}}))
PYEOF
}

# --- argument parsing: service, resource, action, then flags. ---
if [ $# -lt 3 ]; then
    echo "mock_oci: need <service> <resource> <action>" >&2
    exit 2
fi
SERVICE=$1; RESOURCE=$2; ACTION=$3; shift 3
QUERY=""
RAW=0
# Scan the remaining flags for --query / --raw-output WITHOUT shifting
# or rebuilding $@: the security-list create passes a JSON document as
# ONE argument, and word-splitting it (REST="$REST $1"; set -- $REST)
# would destroy it. $@ stays intact for flag_value and for the create
# handlers, which only look for the flag names they need.
_prev=""
for _a in "$@"; do
    if [ "$_prev" = "--query" ]; then
        QUERY=$_a; _prev=""; continue
    fi
    case "$_a" in
        --query) _prev="--query" ;;
        --query=*) QUERY=${_a#--query=} ;;
        --raw-output) RAW=1 ;;
        *) : ;;
    esac
done

case "$SERVICE $RESOURCE $ACTION" in
    "iam tenancy get")
        _json=$(python3 -c "import json; print(json.dumps({'data': {'id': '$TENANCY_OCID', 'home-region-key': 'DXB', 'name': 'mock-tenancy'}}))")
        output_json "$_json"
        ;;
    "compute instance list")
        # Empty list prints 0 bytes (live shape, section 1) unless
        # a live (non-TERMINATED) instance exists.
        if instance_exists && [ "$(instance_state)" != "TERMINATED" ]; then
            output_json "$(instance_json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps({"data": [d["data"]]}))')"
        else
            if [ -n "$QUERY" ]; then
                # length(data) on an empty list is 0.
                [ "$QUERY" = "length(data)" ] || { echo "mock_oci: unsupported --query on empty list: $QUERY" >&2; exit 2; }
                printf '0\n'
            else
                printf ''
            fi
        fi
        ;;
    "compute instance launch")
        _now=$(date -u +%s)
        _created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        _id="ocid1.instance.oc1.me-dubai-1.aaaaaaaamockdryrun"
        _img=$(flag_value --image-id "$@" 2>/dev/null || echo "ocid1.image.oc1.me-dubai-1.aaaaaaaamockimage")
        python3 - "$STATE/instance.json" "$_id" "$_img" "$_created" "$_now" <<'PYEOF'
import json, sys
out, iid, img, created, now = sys.argv[1:6]
now = int(now)
doc = {"id": iid, "image_id": img, "time_created": created,
       "created_epoch": now, "running_epoch": now + 30,
       "timer_epoch": None, "terminate_epoch": None,
       "availability_domain": "JJYF:ME-DUBAI-1-AD-1",
       "compartment_id": "ocid1.tenancy.oc1..aaaaaaaaarofozkiqhscb55mmn5ugszaxbeuo53bymesuzxvhomqcvs62vfq",
       "display_name": "m8-batch-dryrun", "public_ip": "127.0.0.1"}
json.dump(doc, open(out, "w"))
PYEOF
        _json=$(python3 -c "import json; print(json.dumps({'data': {'id': '$_id'}}))")
        output_json "$_json"
        ;;
    "compute instance get")
        instance_exists || emit_404 get_instance compute
        output_json "$(instance_json)"
        ;;
    "compute instance terminate")
        _id=$(flag_value --instance-id "$@" 2>/dev/null || echo "")
        instance_exists || emit_404 terminate_instance compute
        python3 - "$STATE/instance.json" <<'PYEOF'
import json, sys, time
p = sys.argv[1]
doc = json.load(open(p))
doc["terminate_epoch"] = int(time.time())
json.dump(doc, open(p, "w"))
PYEOF
        printf ''
        ;;
    "compute instance list-vnics")
        if instance_exists && [ "$(instance_state)" != "TERMINATED" ]; then
            _json=$(python3 -c "import json; print(json.dumps({'data': [{'public-ip': '127.0.0.1', 'display-name': 'mock-vnic'}]}))")
            output_json "$_json"
        else
            printf ''
        fi
        ;;
    "compute image list")
        _json=$(python3 -c "import json; print(json.dumps({'data': [{'id': 'ocid1.image.oc1.me-dubai-1.aaaaaaaamockimage', 'display-name': 'Oracle-Linux-9-mock', 'time-created': '2026-11-26T00:00:00Z'}]}))")
        output_json "$_json"
        ;;
    "compute vnic-attachment list")
        if instance_exists && [ "$(instance_state)" != "TERMINATED" ]; then
            printf '%s\n' '{"data": [{"id": "ocid1.vnicattachment.oc1.me-dubai-1.aaaaaaaamockvnic", "lifecycle-state": "ATTACHED"}]}'
        else
            printf ''
        fi
        ;;
    "bv boot-volume list")
        printf ''
        ;;
    "limits resource-availability get")
        _limit=$(flag_value --limit-name "$@" 2>/dev/null || echo "")
        case "$_limit" in
            standard-a1-core-count) _avail=41 ;;
            standard-a1-memory-count) _avail=277 ;;
            *) echo "mock_oci: unknown limit: $_limit" >&2; exit 2 ;;
        esac
        _json=$(python3 -c "import json; print(json.dumps({'data': {'available': $_avail}}))")
        output_json "$_json"
        ;;
    "network vcn create"|"network subnet create"|"network route-table create"|"network internet-gateway create"|"network security-list create")
        case "$RESOURCE" in
            vcn) _kind=vcn; _prefix="ocid1.vcn.oc1.me-dubai-1.aaaaaaaamockvcn" ;;
            subnet) _kind=subnet; _prefix="ocid1.subnet.oc1.me-dubai-1.aaaaaaaamocksubnet" ;;
            route-table) _kind=rt; _prefix="ocid1.routetable.oc1.me-dubai-1.aaaaaaaamockrt" ;;
            internet-gateway) _kind=igw; _prefix="ocid1.internetgateway.oc1.me-dubai-1.aaaaaaaamockigw" ;;
            security-list) _kind=seclist; _prefix="ocid1.securitylist.oc1.me-dubai-1.aaaaaaaamockseclist" ;;
        esac
        python3 - "$STATE/network.json" "$_kind" "$_prefix" "${HOST_EGRESS_IP:-}" "$@" <<'PYEOF'
import json, sys
path, kind, prefix, host_ip = sys.argv[1:5]
args = sys.argv[5:]
try:
    net = json.load(open(path))
except Exception:
    net = {}
res = {"id": prefix, "display-name": "m8-batch-dryrun",
       "compartment-id": "ocid1.tenancy.oc1..aaaaaaaaarofozkiqhscb55mmn5ugszaxbeuo53bymesuzxvhomqcvs62vfq",
       "lifecycle-state": "AVAILABLE", "deleted": False}
if kind == "vcn":
    res["cidr-block"] = "10.0.0.0/16"
elif kind == "subnet":
    res["cidr-block"] = "10.0.0.0/24"
elif kind == "rt":
    res["route-rules"] = [{"cidr-block": None, "description": None,
        "destination": "0.0.0.0/0", "destination-type": "CIDR_BLOCK",
        "network-entity-id": "ocid1.internetgateway.oc1.me-dubai-1.aaaaaaaamockigw",
        "route-type": "STATIC"}]
elif kind == "seclist":
    # Parse the ingress/egress rules the runner passed, so the get
    # returns the same rules o11 (e) audits (host-IP-only ingress).
    ingress = []
    egress = []
    i = 0
    while i < len(args):
        if args[i] == "--ingress-security-rules" and i + 1 < len(args):
            try:
                ingress = json.loads(args[i + 1])
            except Exception:
                ingress = []
        if args[i] == "--egress-security-rules" and i + 1 < len(args):
            try:
                egress = json.loads(args[i + 1])
            except Exception:
                egress = []
        i += 1
    # Normalise to the live get shape: kebab-case keys.
    def norm(rules):
        out = []
        for r in rules:
            n = dict(r)
            if "source" in n:
                n["source-type"] = "CIDR_BLOCK"
            n["protocol"] = str(n.get("protocol", "6"))
            if "tcpOptions" in n:
                n["tcp-options"] = {"destination-port-range": n.pop("tcpOptions").get("destinationPortRange", {})}
            if "udpOptions" in n:
                n["udp-options"] = {"destination-port-range": n.pop("udpOptions").get("destinationPortRange", {})}
            n["is-stateless"] = False
            out.append(n)
        return out
    res["ingress-security-rules"] = norm(ingress)
    res["egress-security-rules"] = norm(egress)
net[kind] = res
json.dump(net, open(path, "w"))
PYEOF
        _id=$(python3 -c "import json; print(json.load(open('$STATE/network.json'))['$_kind']['id'])")
        _json=$(python3 -c "import json; print(json.dumps({'data': {'id': '$_id'}}))")
        output_json "$_json"
        ;;
    "network vcn get"|"network subnet get"|"network security-list get"|"network route-table get"|"network internet-gateway get")
        case "$RESOURCE" in
            vcn) _kind=vcn; _op=get_vcn; _svc=network ;;
            subnet) _kind=subnet; _op=get_subnet; _svc=network ;;
            security-list) _kind=seclist; _op=get_security_list; _svc=network ;;
            route-table) _kind=rt; _op=get_route_table; _svc=network ;;
            internet-gateway) _kind=igw; _op=get_internet_gateway; _svc=network ;;
        esac
        if network_deleted "$_kind"; then
            emit_404 "$_op" "$_svc"
        fi
        _json=$(network_json "$_kind") || emit_404 "$_op" "$_svc"
        output_json "$_json"
        ;;
    "network vcn delete"|"network subnet delete"|"network security-list delete"|"network route-table delete"|"network internet-gateway delete")
        case "$RESOURCE" in
            vcn) _kind=vcn ;;
            subnet) _kind=subnet ;;
            security-list) _kind=seclist ;;
            route-table) _kind=rt ;;
            internet-gateway) _kind=igw ;;
        esac
        python3 - "$STATE/network.json" "$_kind" <<'PYEOF'
import json, sys
path, kind = sys.argv[1:3]
try:
    net = json.load(open(path))
except Exception:
    net = {}
if kind in net:
    net[kind]["deleted"] = True
json.dump(net, open(path, "w"))
PYEOF
        printf ''
        ;;
    "network public-ip list")
        if instance_exists && [ "$(instance_state)" != "TERMINATED" ]; then
            printf '%s\n' '{"data": [{"id": "ocid1.publicip.oc1.me-dubai-1.aaaaaaaamockip", "ip-address": "127.0.0.1", "lifecycle-state": "ASSIGNED"}]}'
        else
            printf ''
        fi
        ;;
    "usage-api usage-summary request-summarized-usages")
        printf '%s\n' "$(usage_json)"
        ;;
    *)
        echo "mock_oci: unsupported command: $SERVICE $RESOURCE $ACTION" >&2
        exit 2
        ;;
esac
exit 0
