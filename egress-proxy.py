#!/usr/bin/env python3
"""egress-proxy.py - M8 CONNECT-only egress proxy (Revision 5).

Runs as UID 1002 (proxy). Listens on 127.0.0.1:3128.

For each CONNECT host:port request:
  1. exact-host allow-list check (anchored regexes, read from the filter
     file on EVERY request, so a test-only entry can be added and removed
     without a restart)
  2. resolve the host itself (getaddrinfo) - DNS is only available to
     this UID (iptables allows UID 1002 DNS to 169.254.169.254 only)
  3. check EVERY resolved IP against the deny ranges; if ANY resolved IP
     is denied, refuse with exactly HTTP 403 and log it - the proxy never
     connects to a denied IP
  4. connect to the first allowed resolved IP (TCP 443 only) and tunnel
     bytes
  5. log every CONNECT with host, resolved IPs, allow/deny decision

Only CONNECT is accepted; every other method is refused with HTTP 403.
No redirect following: a CONNECT proxy only tunnels bytes. It never
issues a request of its own, so it cannot follow a redirect - the client
issues each new request, and each is checked independently.

Revision 5 (2026-11-26) - BOUNDED CONCURRENCY (ChatGPT V11 NO-GO,
blocker 1): the Revision 4 accept loop spawned one daemon thread per
connection with no cap, and the proxy runs as UID 1002 OUTSIDE the
workload UID 1001 cgroup, so a hostile workload could exhaust the VM
by opening connections until the proxy ran out of threads/memory.
Revision 5 bounds the proxy in two independent layers:
  (a) IN-PROCESS HARD CAP: at most MAX_WORKERS (16) concurrent
      tunnels. The accept loop takes a semaphore slot NON-BLOCKING
      before spawning a worker; when no slot is free the connection
      is refused immediately with exactly HTTP 503 and logged with
      reason=concurrency-cap - it is never queued, never left
      half-open, and never allowed to grow the thread count. A
      worker releases its slot in a finally block when it exits, so
      a slot is held at most for the life of one tunnel (client
      socket timeout 30 s bounds a slow client). The listen backlog
      equals MAX_WORKERS, so the kernel cannot queue more pending
      connections than the proxy can serve.
  (b) PROXY CGROUP (enforced by the harness, not by this file):
      the proxy runs inside /sys/fs/cgroup/proxy/ with memory.max
      512 MiB, cpu.max 0.5 CPU and pids.max 64 (proposal Sec. 7.1,
      setup check Sec. 7.4 item 21). pids.max bounds the thread
      count at the kernel level even if the semaphore logic ever
      failed, and memory.max bounds the proxy's total footprint.
      The cap in (a) is the primary bound (16 workers, proven by
      the O5(h) concurrency test and the dry-run regression); the
      cgroup is defence in depth.
Thread stacks are bounded explicitly (2 MiB each) so 16 workers
cannot reserve more than 32 MiB of stack.

Environment overrides (test use ONLY - the production start command
sets none of them, so the defaults below always apply on the VM):
  EGRESS_PROXY_FILTER, EGRESS_PROXY_LOG, EGRESS_PROXY_HOST,
  EGRESS_PROXY_PORT, EGRESS_PROXY_MAX_WORKERS.

Python 3 standard library only. No third-party dependency.
"""

import ipaddress
import logging
import os
import re
import select
import socket
import sys
import threading

LISTEN_HOST = os.environ.get("EGRESS_PROXY_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("EGRESS_PROXY_PORT", "3128"))
FILTER_FILE = os.environ.get("EGRESS_PROXY_FILTER", "/opt/proxy/filter")
LOG_FILE = os.environ.get("EGRESS_PROXY_LOG", "/var/log/m8-proxy.log")
CONNECT_TIMEOUT = 10.0
ALLOWED_PORT = 443

# Hard cap on concurrent tunnels (Revision 5). A workload that opens
# more connections than this is refused, never queued.
MAX_WORKERS = int(os.environ.get("EGRESS_PROXY_MAX_WORKERS", "16"))

# Bound per-thread stack (Revision 5): 2 MiB x MAX_WORKERS = 32 MiB
# worst case, inside the proxy cgroup's 512 MiB memory.max.
try:
    threading.stack_size(2 * 1024 * 1024)
except (ValueError, RuntimeError):
    pass  # platform default stands; the semaphore + cgroup still bound

# Deny ranges (IPv4 + IPv6). Any resolved IP inside one of these is denied.
DENY_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918
    ipaddress.ip_network("169.254.0.0/16"),    # link-local (incl. OCI metadata 169.254.169.254)
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("0.0.0.0/8"),         # "this network"
    ipaddress.ip_network("224.0.0.0/4"),       # multicast
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique-local
    ipaddress.ip_network("::/128"),            # IPv6 unspecified
]

LOG = logging.getLogger("egress-proxy")


def _denied(ip):
    """True if ip (str) is inside any deny range (incl. IPv4-mapped IPv6)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable address: deny
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return any(addr in net for net in DENY_NETWORKS)


def load_filter():
    """Read the allow-list file; return a list of compiled anchored regexes."""
    patterns = []
    with open(FILTER_FILE, "r", encoding="ascii") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(re.compile(line))
    return patterns


def is_allowed_host(host, patterns):
    """Exact-host match: the host must match one anchored pattern fully."""
    return any(p.fullmatch(host) for p in patterns)


def handle(client, client_addr):
    try:
        client.settimeout(30.0)
        request_line = b""
        while not request_line.endswith(b"\r\n"):
            chunk = client.recv(1)
            if not chunk:
                return
            request_line += chunk
            if len(request_line) > 8192:
                return
        # Discard headers until the blank line.
        buf = b""
        while not buf.endswith(b"\r\n\r\n"):
            chunk = client.recv(1)
            if not chunk:
                return
            buf += chunk
            if len(buf) > 8192:
                return
        parts = request_line.decode("ascii", "replace").split()
        if len(parts) < 3 or parts[0] != "CONNECT":
            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            LOG.info("CONNECT %s decision=deny reason=not-connect", client_addr)
            return
        target = parts[1]
        if ":" not in target:
            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            LOG.info("CONNECT %s decision=deny reason=no-port", target)
            return
        host, _, port_s = target.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            LOG.info("CONNECT %s decision=deny reason=bad-port", target)
            return
        if port != ALLOWED_PORT:
            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            LOG.info("CONNECT %s decision=deny reason=port-not-443", target)
            return
        # 1. Allow-list check FIRST, before any DNS resolution (so a
        # non-allow-listed host is never resolved at all).
        try:
            patterns = load_filter()
        except OSError as exc:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            LOG.error("CONNECT %s decision=deny reason=filter-unreadable %s", target, exc)
            return
        if not is_allowed_host(host, patterns):
            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            LOG.info("CONNECT %s decision=deny reason=not-allow-listed", target)
            return
        # 2. Resolve the host ourselves.
        try:
            infos = socket.getaddrinfo(host, ALLOWED_PORT, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            LOG.info("CONNECT %s decision=deny reason=dns-failed %s", target, exc)
            return
        resolved = sorted({info[4][0] for info in infos})
        # 3. Check EVERY resolved IP. If ANY is denied, refuse.
        denied = [ip for ip in resolved if _denied(ip)]
        if denied:
            client.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            LOG.info("CONNECT %s resolved=%s decision=deny reason=resolved-private-ip denied=%s",
                     target, resolved, denied)
            return
        # 4. Connect to the first allowed resolved IP and tunnel.
        upstream = None
        for ip in resolved:
            try:
                upstream = socket.create_connection((ip, ALLOWED_PORT),
                                                    timeout=CONNECT_TIMEOUT)
                break
            except OSError:
                continue
        if upstream is None:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            LOG.info("CONNECT %s resolved=%s decision=deny reason=upstream-unreachable",
                     target, resolved)
            return
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        LOG.info("CONNECT %s resolved=%s decision=allow", target, resolved)
        # 5. Tunnel bytes until either side closes.
        client.setblocking(False)
        upstream.setblocking(False)
        sockets = [client, upstream]
        while True:
            readable, _, _ = select.select(sockets, [], [], 60.0)
            if not readable:
                break
            for src in readable:
                dst = upstream if src is client else client
                try:
                    data = src.recv(65536)
                except OSError:
                    data = b""
                if not data:
                    return
                try:
                    dst.sendall(data)
                except OSError:
                    return
    except OSError:
        return
    finally:
        try:
            client.close()
        except OSError:
            pass


def _handle_and_release(client, client_addr, slots):
    """Run handle() and always release the concurrency slot (Revision 5)."""
    try:
        handle(client, client_addr)
    finally:
        slots.release()


def main():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    # Backlog equals the worker cap (Revision 5): the kernel cannot
    # queue more pending connections than the proxy can serve.
    server.listen(MAX_WORKERS)
    # The concurrency semaphore (Revision 5): one slot per worker.
    slots = threading.Semaphore(MAX_WORKERS)
    LOG.info("listening on %s:%d as uid 1002 max_workers=%d", LISTEN_HOST, LISTEN_PORT, MAX_WORKERS)
    try:
        while True:
            client, addr = server.accept()
            # Non-blocking acquire: when the cap is reached the
            # connection is refused immediately with 503 - never
            # queued, never left half-open, never allowed to grow
            # the thread count past MAX_WORKERS.
            if not slots.acquire(blocking=False):
                try:
                    client.sendall(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
                except OSError:
                    pass
                try:
                    client.close()
                except OSError:
                    pass
                LOG.info("CONNECT %s decision=deny reason=concurrency-cap", addr)
                continue
            thread = threading.Thread(target=_handle_and_release,
                                      args=(client, addr, slots), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()


if __name__ == "__main__":
    sys.exit(main())
