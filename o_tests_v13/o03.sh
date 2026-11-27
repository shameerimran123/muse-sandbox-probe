#!/bin/sh
# O3 - Credential boundary (threats T2, T9)
# Spec: O_TESTS_SPEC_V8.md, O3. Environment: M8_PROPOSAL_V9.md Sec. 5.3, Sec. 5.4, Sec. 6.
# Runs as UID 1001 inside the sandbox. The harness invokes it via the
# Sec. 4.2 sandbox command. NOT YET EXECUTED - written for review only.
#
# Purpose: verify no host credential, token, or secret is reachable by the
# workload, and that the metadata service (169.254.169.254) is unreachable
# by ALL FOUR routes: direct, proxy, DNS, IPv6.
#
# Two modes (spec V4 O3, blocker F):
#   o03.sh           (default, workload mode) - runs as UID 1001.
#   o03.sh positive  (harness mode) - runs as root on the VM and drops
#                    to the proxy UID (1002) to perform the DNS positive
#                    control. It is an IMPLEMENTED TEST, not a described
#                    harness step: the harness runs it BEFORE the workload
#                    mode and includes its output in the O3 evidence.
#                    Prints O3_POSITIVE_CONTROL result=resolved (with the
#                    resolved address) on success, result=failed on
#                    failure; exits 0 on success, 2 on failure. It never
#                    prints an O3_RESULT line.
#
# PASS: no host credential/token/secret is present; no environment
# variable NAME matches SECRET/TOKEN/KEY/PASS; (c) direct metadata fails
# with EXACTLY curl exit code 28; (d) proxy metadata is refused with
# EXACTLY HTTP 403; (e) DNS fails by TIMEOUT on both UDP and TCP;
# (f) the IPv6 attempt fails (IPv6 is disabled); (g) the user-data file
# exists and is not readable by UID 1001; (h) the HMAC secret file
# exists and is not readable by UID 1001.
# FAIL: any credential/token/secret is found; any environment variable
# NAME matches; the metadata service responds by ANY route; a DNS
# RESPONSE is received by the workload UID; the user-data file or the
# HMAC secret file is readable by UID 1001.
# INCONCLUSIVE (exit 2): the script errors, times out, or any route's
# result is not recorded. In particular: a direct request with any curl
# exit code other than 28 is INCONCLUSIVE; a proxy request with any HTTP
# status other than exactly 403 (and not 2xx) is INCONCLUSIVE; a DNS
# refused/unreachable error is INCONCLUSIVE; a protected file that must
# exist is ABSENT (spec V4 rule 11).
#
# Exit: 0 = PASS, 1 = FAIL, 2 = error/inconclusive.
# Result line: O3_RESULT=PASS | FAIL | INCONCLUSIVE
#
# Exact-response rule (spec V4 rule 8): for a request THROUGH the proxy,
# the specified denial is exactly HTTP 403. Any other 4xx/5xx is
# INCONCLUSIVE; a transport failure (curl non-zero, HTTP 000) is
# INCONCLUSIVE; a 2xx is FAIL. For a DIRECT request, the specified block
# is the iptables DROP, whose exact observable is curl exit code 28.
# Any other curl exit code is INCONCLUSIVE; any HTTP response is FAIL.
#
# DNS rule (spec V4 rule 9): the workload's DNS query must fail by
# TIMEOUT (no response - the packets are DROPped). A DNS RESPONSE (even
# NXDOMAIN) is FAIL. A refused/unreachable error is INCONCLUSIVE. The
# queries below are RAW UDP and TCP queries to 169.254.169.254:53 with a
# 5 s timeout - not getaddrinfo, which cannot distinguish these cases.
#
# The proxy port comes from $PROXY_PORT (set by the harness); default 3128
# (egress-proxy.py LISTEN_PORT). The script never prints environment
# VALUES - only variable names - so a leaked secret is never written into
# the evidence.
set -u

# Positive-control mode (spec V4 O3): run as root, drop to UID 1002
# with setpriv, resolve registry.npmjs.org with socket.getaddrinfo.
# A successful resolution proves DNS itself works, so a workload
# timeout is specifically a firewall block. Dispatch BEFORE the UID
# 1001 sanity check below (this mode must NOT run as UID 1001).
if [ "${1:-}" = "positive" ]; then
    if [ "$(id -u 2>/dev/null)" != "0" ]; then
        echo "O3_POSITIVE_CONTROL result=failed detail=not_root"
        exit 2
    fi
    for _tool in setpriv python3; do
        if ! command -v "$_tool" >/dev/null 2>&1; then
            echo "O3_POSITIVE_CONTROL result=failed detail=missing_tool_$_tool"
            exit 2
        fi
    done
    _addr=$(setpriv --reuid=1002 --regid=1002 --clear-groups -- python3 -c 'import socket; print(socket.getaddrinfo("registry.npmjs.org", 443)[0][4][0])' 2>/dev/null)
    if [ -n "$_addr" ]; then
        echo "O3_POSITIVE_CONTROL result=resolved address=$_addr"
        exit 0
    else
        echo "O3_POSITIVE_CONTROL result=failed detail=no_address_resolved"
        exit 2
    fi
fi

# Sandbox-environment guard (blocker 1, 2026-11-25 ~22:39 PKT): the
# Sec. 4.2 sandbox command sets HOME explicitly (--setenv HOME
# /home/workload) after --clearenv. If HOME is unset here, the promised
# environment was not set up: do NOT abort under set -u at the first
# bare $HOME reference below - record it and end
# INCONCLUSIVE. The default below is only so the credential-path
# checks have a defined home to test; an unset HOME never passes.
if [ -z "${HOME:-}" ]; then
    echo "O3_HOME result=unset expected=/home/workload"
    echo "O3_RESULT=INCONCLUSIVE"
    exit 2
fi

FAIL=0
INCONCLUSIVE=0
PROXY_PORT=${PROXY_PORT:-3128}

# Sanity: this test is only meaningful as the workload user.
if [ "$(id -u 2>/dev/null)" != "1001" ]; then
    echo "O3_ERROR=not running as UID 1001 (got $(id -u 2>/dev/null || echo unknown))"
    echo "O3_RESULT=INCONCLUSIVE"
    exit 2
fi

for _tool in curl python3; do
    if ! command -v "$_tool" >/dev/null 2>&1; then
        echo "O3_ERROR=required tool missing: $_tool"
        echo "O3_RESULT=INCONCLUSIVE"
        exit 2
    fi
done

# (a) Environment variable NAMES: none may match SECRET/TOKEN/KEY/PASS.
# Only names are checked (and only names are printed); values are never
# read or printed.
_leaks=$(env | cut -d= -f1 | grep -iE 'SECRET|TOKEN|KEY|PASS' | tr '\n' ' ')
if [ -n "$_leaks" ]; then
    echo "O3_ENV_LEAK vars=$_leaks"
    FAIL=1
else
    echo "O3_ENV_LEAK none"
fi

# (b) Credential paths: none may be readable. Absence counts as not
# reachable - these are credential locations that must not exist.
attempt_read() {
    _path=$1
    if [ -d "$_path" ]; then
        if ls "$_path" >/dev/null 2>&1; then
            echo "O3_CRED path=$_path result=readable"
            FAIL=1
        else
            echo "O3_CRED path=$_path result=denied"
        fi
    elif [ -e "$_path" ]; then
        if cat "$_path" >/dev/null 2>&1; then
            echo "O3_CRED path=$_path result=readable"
            FAIL=1
        else
            echo "O3_CRED path=$_path result=denied"
        fi
    else
        echo "O3_CRED path=$_path result=absent"
    fi
}

attempt_read "$HOME/.ssh"
attempt_read "$HOME/.aws"
attempt_read "$HOME/.config"
attempt_read "$HOME/.oci"
attempt_read /etc/oci
attempt_read /var/run/secrets

# (c) Metadata, DIRECT route (no proxy). Exactly curl exit code 28 is
# the DROP timeout (PASS). Any HTTP response is FAIL. Any other curl
# exit code is INCONCLUSIVE.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
direct_metadata() {
    _url=$1
    _code=$(curl -s -m 5 --noproxy '*' -o /dev/null -w '%{http_code}' "$_url" 2>/dev/null)
    _rc=$?
    if [ "$_rc" -eq 28 ]; then
        echo "O3_META_DIRECT url=$_url result=blocked rc=28"
    elif [ "$_rc" -eq 0 ]; then
        echo "O3_META_DIRECT url=$_url result=responded code=$_code"
        FAIL=1
    else
        echo "O3_META_DIRECT url=$_url result=inconclusive rc=$_rc code=$_code"
        INCONCLUSIVE=1
    fi
}

direct_metadata http://169.254.169.254/
direct_metadata http://169.254.169.254/latest/

# (d) Metadata, PROXY route. The proxy must refuse with EXACTLY HTTP 403.
proxy_check() {
    _url=$1
    _label=$2
    _code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' \
        -x "http://127.0.0.1:${PROXY_PORT}" "$_url" 2>/dev/null)
    _rc=$?
    if [ "$_rc" -ne 0 ] || [ "$_code" = "000" ]; then
        echo "O3_META_PROXY label=$_label result=inconclusive rc=$_rc code=$_code"
        INCONCLUSIVE=1
    elif [ "$_code" = "403" ]; then
        echo "O3_META_PROXY label=$_label result=denied code=403"
    elif [ "${_code#2}" != "$_code" ]; then
        echo "O3_META_PROXY label=$_label result=allowed code=$_code"
        FAIL=1
    else
        echo "O3_META_PROXY label=$_label result=inconclusive code=$_code"
        INCONCLUSIVE=1
    fi
}

proxy_check http://169.254.169.254/ metadata-root
proxy_check http://169.254.169.254/latest/ metadata-latest

# (e) DNS query from the workload UID, RAW UDP and TCP to
# 169.254.169.254:53 with a 5 s timeout. Timeout = blocked (PASS).
# A response received (even NXDOMAIN) = FAIL. Refused/unreachable =
# INCONCLUSIVE. The Python probe exits 0 = timeout, 1 = response,
# 2 = refused/unreachable/other error.
dns_check() {
    _proto=$1
    _qname=$2
    _label=$3
    _out=$(python3 - "$_proto" "$_qname" <<'PYEOF'
import socket, struct, sys
proto = sys.argv[1]
qname = sys.argv[2]
host = "169.254.169.254"
port = 53
def build(qname):
    hdr = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b""
    for label in qname.split("."):
        b = label.encode()
        q += bytes([len(b)]) + b
    q += b"\x00" + struct.pack(">HH", 1, 1)
    return hdr + q
pkt = build(qname)
try:
    if proto == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.sendto(pkt, (host, port))
        try:
            data, _ = s.recvfrom(2048)
        except socket.timeout:
            print("timeout")
            sys.exit(0)
        print("response bytes=%d" % len(data))
        sys.exit(1)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((host, port))
        except socket.timeout:
            print("timeout")
            sys.exit(0)
        # Connected: a DNS path exists, whether or not a reply follows.
        print("connected")
        sys.exit(1)
except socket.timeout:
    print("timeout")
    sys.exit(0)
except OSError as e:
    print("error errno=%s %s" % (e.errno, e))
    sys.exit(2)
PYEOF
)
    _rc=$?
    if [ "$_rc" -eq 0 ]; then
        echo "O3_DNS label=$_label proto=$_proto result=blocked_timeout detail=$_out"
    elif [ "$_rc" -eq 1 ]; then
        echo "O3_DNS label=$_label proto=$_proto result=response detail=$_out"
        FAIL=1
    else
        echo "O3_DNS label=$_label proto=$_proto result=inconclusive detail=$_out"
        INCONCLUSIVE=1
    fi
}

dns_check udp example.com metadata-dns
dns_check tcp example.com metadata-dns

# (f) IPv6 route. Two checks: no IPv6 interfaces may exist, and an IPv6
# connection attempt must fail.
if [ -s /proc/net/if_inet6 ]; then
    echo "O3_IPV6_INTERFACES present"
    FAIL=1
else
    echo "O3_IPV6_INTERFACES none"
fi
if timeout 10 python3 -c 'import socket; s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); s.settimeout(5); s.connect(("2606:4700:4700::1111", 80))' >/dev/null 2>&1; then
    echo "O3_IPV6_CONNECT result=connected"
    FAIL=1
else
    echo "O3_IPV6_CONNECT result=failed"
fi

# (g) Cloud-init user-data file: must EXIST (absence is INCONCLUSIVE,
# spec V4 rule 11) and must not be readable by UID 1001.
if [ ! -e /var/lib/cloud/instance/user-data.txt ]; then
    echo "O3_USERDATA result=absent"
    INCONCLUSIVE=1
elif cat /var/lib/cloud/instance/user-data.txt >/dev/null 2>&1; then
    echo "O3_USERDATA result=readable"
    FAIL=1
else
    echo "O3_USERDATA result=denied"
fi

# (h) HMAC secret file: must EXIST (absence is INCONCLUSIVE, spec V2
# rule 11) and must not be readable by UID 1001.
if [ ! -e /opt/harness/hmac.key ]; then
    echo "O3_HMAC_KEY result=absent"
    INCONCLUSIVE=1
elif cat /opt/harness/hmac.key >/dev/null 2>&1; then
    echo "O3_HMAC_KEY result=readable"
    FAIL=1
else
    echo "O3_HMAC_KEY result=denied"
fi

if [ "$INCONCLUSIVE" -gt 0 ]; then
    echo "O3_RESULT=INCONCLUSIVE"
    exit 2
fi
if [ "$FAIL" -gt 0 ]; then
    echo "O3_RESULT=FAIL"
    exit 1
fi
echo "O3_RESULT=PASS"
exit 0
