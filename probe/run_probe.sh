#!/usr/bin/env bash
# Muse sandbox probe — main probe (specs, N1-N8 read-only, N11 setup).
# Inert, human-reviewed. No AI-generated code, no product code, no real bugs.
# REVISED per ChatGPT review (2026-11-25): all exhaustion loops removed.
# N6/N7/N8 are READ-ONLY inspections of limits and capacity — nothing is
# driven toward OOM, fork exhaustion, or disk fill. N5 does NOT touch the
# firewall — it records the egress baseline only. N10 (sentinel) removed: a second
# dispatch runs on a new VM by design, so sentinel absence cannot prove
# teardown. Every test prints its result to stdout AND to
# probe-results/results.txt. A test that cannot run prints MECHANISM
# UNAVAILABLE instead of guessing.
set -u
RESULTS_DIR="probe-results"
mkdir -p "$RESULTS_DIR"
OUT="$RESULTS_DIR/results.txt"
exec > >(tee "$OUT") 2>&1

echo "=== MUSE SANDBOX PROBE (REVISED) ==="
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "runner: $(uname -a)"
echo "--- specs ---"
echo "cpus: $(nproc)"
echo "mem_total_MB: $(free -m | awk '/^Mem:/ {print $2}')"
echo "mem_available_MB: $(free -m | awk '/^Mem:/ {print $7}')"
echo "disk_root: $(df -h / | tail -1)"
echo "disk_tmp: $(df -h /tmp | tail -1)"
echo "user: $(id)"
echo "github_repo: ${GITHUB_REPOSITORY:-unset}"
echo "github_run_id: ${GITHUB_RUN_ID:-unset}"

echo "--- N1 filesystem read boundary ---"
for p in /etc/shadow /root "$HOME/.ssh/id_rsa" "$HOME/.aws/credentials"; do
  if [ -e "$p" ]; then
    if [ -r "$p" ]; then echo "N1 READABLE (sensitive): $p"; else echo "N1 BLOCKED (exists, unreadable): $p"; fi
  else
    echo "N1 ABSENT: $p"
  fi
done

echo "--- N2 filesystem write boundary ---"
USR_TEST="/usr/muse-probe-write-test-${GITHUB_RUN_ID:-local}"
if echo test > "$USR_TEST" 2>/dev/null; then
  echo "N2 WRITABLE (unexpected): /usr"
  rm -f "$USR_TEST"
else
  echo "N2 BLOCKED: /usr"
fi
TMP_TEST="/tmp/muse-probe-write-test-${GITHUB_RUN_ID:-local}"
if echo test > "$TMP_TEST" 2>/dev/null; then
  echo "N2 WRITABLE (expected, destroyed with runner): /tmp"
  rm -f "$TMP_TEST"
else
  echo "N2 BLOCKED: /tmp"
fi

echo "--- N3 credential boundary (names only, NEVER values) ---"
echo "env var names matching SECRET/TOKEN/KEY/PASS (values NOT printed):"
env | cut -d= -f1 | grep -i -E 'secret|token|key|pass|credential' || echo "N3 none found"
for d in "$HOME/.ssh" "$HOME/.aws" "$HOME/.config"; do
  if [ -d "$d" ]; then echo "N3 EXISTS: $d"; else echo "N3 ABSENT: $d"; fi
done
echo "N3 note: token scope is set by the workflow permissions (contents: read); no runtime token-permissions test is run."

echo "--- N4 privilege boundary (OBSERVATIONS, not pass/fail) ---"
echo "sudo available: $(sudo -n true 2>/dev/null && echo yes || echo no) (sudo inside a disposable VM does not by itself prove host escape)"
echo "su available: $(su -c true root 2>/dev/null && echo yes || echo no)"
if [ -r /proc/1/cmdline ]; then echo "/proc/1 readable (contents NOT disclosed)"; else echo "/proc/1 BLOCKED"; fi
if [ -S /var/run/docker.sock ]; then echo "DOCKER SOCKET PRESENT"; else echo "DOCKER SOCKET ABSENT"; fi
if [ -r /proc/self/uid_map ]; then echo "uid_map: $(cat /proc/self/uid_map)"; else echo "uid_map BLOCKED"; fi
echo "capabilities: $(grep CapEff /proc/self/status 2>/dev/null || echo unavailable)"
echo "namespaces: $(ls /proc/self/ns/ 2>/dev/null | tr '\n' ' ' || echo unavailable)"

echo "--- N5 network boundary (baseline only — no firewall changes) ---"
echo "This records what is reachable by default on this standard runner configuration."
for u in https://example.com https://pypi.org https://github.com; do
  code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "$u" 2>/dev/null || echo "000")
  echo "N5 baseline $u -> HTTP $code"
done
echo "N5 finding: this standard GitHub-hosted runner configuration has no job-level platform egress allow-list configured or tested. The observed baseline is not proof of a universal GitHub Actions network limitation."

echo "--- N6 memory limits (READ-ONLY) ---"
echo "meminfo: $(grep -E 'MemTotal|MemAvailable' /proc/meminfo | tr '\n' ' ')"
for f in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.high; do
  if [ -r "$f" ]; then echo "N6 $f: $(cat "$f")"; else echo "N6 $f: unavailable"; fi
done
echo "N6 ulimit -v: $(ulimit -v)"

echo "--- N7 process limits (READ-ONLY) ---"
echo "N7 ulimit -u: $(ulimit -u)"
for f in /sys/fs/cgroup/pids.max /sys/fs/cgroup/pids.current; do
  if [ -r "$f" ]; then echo "N7 $f: $(cat "$f")"; else echo "N7 $f: unavailable"; fi
done
echo "N7 pid_max: $(cat /proc/sys/kernel/pid_max 2>/dev/null || echo unavailable)"
echo "N7 loadavg: $(cat /proc/loadavg)"

echo "--- N8 disk capacity (READ-ONLY + small bounded write) ---"
echo "N8 df root: $(df -h / | tail -1)"
echo "N8 df tmp: $(df -h /tmp | tail -1)"
echo "N8 inodes root: $(df -i / | tail -1)"
echo "N8 filesystem: $(df -T / | tail -1)"
if dd if=/dev/zero of=/tmp/muse-probe-small-write bs=1M count=10 status=none 2>/dev/null; then
  echo "N8 small write: 10 MB write SUCCEEDED (writability confirmed, not a fill test)"
  rm -f /tmp/muse-probe-small-write
else
  echo "N8 small write: 10 MB write FAILED"
fi

echo "--- N11 evidence setup (narrow demonstration) ---"
echo '{"probe": "sandbox-probe", "run_id": "'"${GITHUB_RUN_ID:-unknown}"'", "date": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}' > "$RESULTS_DIR/results.json"
sha256sum "$RESULTS_DIR/results.json" > "$RESULTS_DIR/results.sha256"
echo "N11: results.json written, hash recorded. The workflow tamper step tests basic checksum-mismatch detection only; this is NOT tamper-proofing."

echo "=== PROBE DONE ==="
