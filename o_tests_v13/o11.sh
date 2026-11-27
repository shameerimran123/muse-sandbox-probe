#!/bin/sh
# O11 - Evidence integrity (threat T8)
# Spec: O_TESTS_SPEC_V8.md, O11. Environment: M8_PROPOSAL_V9.md Sec. 5.5, Sec. 11.3.
# NOT YET EXECUTED - written for review only.
#
# Three modes:
#   o11.sh workload   (default if no mode is given) - runs as UID 1001
#                       inside the sandbox. The harness invokes it via
#                       the Sec. 4.2 sandbox command.
#   o11.sh download   - runs on the HOST; downloads the results from
#                       the VM endpoint into RESULTS_DIR, enforcing the
#                       10 MB per-file limit DURING the download
#                       (blocker I, 2026-11-25 ~22:39 PKT): each file is
#                       streamed in chunks with a running byte count
#                       and the transfer is aborted (partial file
#                       deleted) the moment it exceeds 10 MB. The
#                       harness MUST use this mode for retrieval; a
#                       plain curl download is not sufficient, because
#                       it checks the size only after the whole file
#                       is on disk. Download safety (blocker I/K,
#                       2026-11-25 ~23:04 PKT): redirects are NEVER
#                       followed (a 3xx response is FAIL, not a new
#                       URL); every destination path is validated
#                       component by component (no symlink anywhere in
#                       the path, no pre-existing destination file,
#                       O_NOFOLLOW on open); and the HMACs of
#                       batch.json AND results.sha256 are verified
#                       BEFORE batch.json is parsed or used to select
#                       any case download - an unauthenticated
#                       batch.json never controls the download loop.
#                       The mode also fetches the watchdog snapshot
#                       (watchdog-snapshot.txt + .hmac, blocker L),
#                       which O13 (e1) requires.
#   o11.sh host       - runs on the HOST (not the VM, not UID 1001),
#                       after the results have been downloaded. The
#                       host-side checks are IMPLEMENTED IN THIS SCRIPT
#                       (spec V4 blocker I), not merely described.
#
# WORKLOAD MODE:
#   As UID 1001, attempt to write the result file directly
#   (/results/<case>.json), to modify the harness (/opt/harness/*) and
#   the proxy config (/opt/proxy/*), and to write the DONE marker.
#   PASS: all workload writes fail (no write permission).
#   FAIL: any workload write succeeds.
#   INCONCLUSIVE (exit 2): the script errors or times out.
#
# HOST MODE (environment variables, set by the host):
#   VM_PUBLIC_IP      The VM's public IP (results endpoint, TCP 8080).
#   HOST_EGRESS_IP    The host's public egress IP (no /32 suffix).
#   RESULTS_DIR       Directory the results were downloaded into.
#   HMAC_SECRET_FILE  Path to the host's copy of the per-batch HMAC
#                     secret (a file holding the hex-encoded 32-byte
#                     per-batch secret).
#   BATCH_MANIFEST    Path to the downloaded batch.json.
#   RESULTS_SHA256    Path to the downloaded results.sha256 (the hash
#                     list - itself HMAC-signed, spec V4 rule 15).
#   SECLIST_OCID      OCID of the per-batch security list.
#   OCI_CLI           OCI CLI to use (default: oci).
#   (a) fetch a whitelisted manifest file from the endpoint (expect
#       exactly HTTP 200); (a2) fetch watchdog-snapshot.txt from the
#       endpoint (expect exactly HTTP 200 - blocker L, 2026-11-25
#       ~23:04 PKT: the snapshot was absent from the V5 endpoint
#       whitelist, so O13 could not obtain it); (b) request a raw log
#       file (expect exactly HTTP 404); (c) request a directory
#       listing (/ - expect exactly HTTP 404, the server has no
#       listing capability); (d) request path-traversal paths over
#       a RAW SOCKET (V13, spec rule 44 - curl normalises /../
#       before sending, so the V12 curl probe was a false positive):
#       /../batch.json, /%2e%2e/batch.json,
#       /../opt/traversal/traversal_canary.txt and
#       /%2e%2e/opt/traversal/traversal_canary.txt, expect exactly
#       HTTP 404 AND an empty body; (e) verify the endpoint is host-IP-only
#       by reading the per-batch security list via the OCI API and
#       confirming the TCP 8080 ingress rule source is exactly
#       HOST_EGRESS_IP/32 and it is the ONLY ingress rule; (f)
#       host-handling: every downloaded file is <= 10 MB (the limit is
#       ENFORCED DURING download by o11.sh download, streaming with a
#       running byte count - blocker I; this host-mode check is the
#       second layer, re-verifying the sizes on disk); the HMAC-SHA256
#       of each downloaded manifest is verified against its .hmac sidecar
#       using the per-batch secret, BEFORE the manifest is trusted (a
#       failed or missing HMAC means the manifest is untrusted and the
#       case is INVALID); the manifest schema-validates; nothing is
#       executed; the SHA-256 of every downloaded file is recomputed and
#       checked against results.sha256 (and, for manifest files, the
#       HMAC).
#   PASS: (a) returns exactly 200; (b), (c), (d) return exactly 404;
#     (e) the security-list audit confirms host-IP-only ingress; (f)
#     every file is <= 10 MB, every HMAC verifies (manifests AND the
#     hash list results.sha256), the batch manifest schema-validates
#     against the BATCH schema AND each per-case manifest against the
#     per-case schema, the batch.json results_sha256 binding matches
#     the downloaded results.sha256, nothing is executed, and every
#     recomputed hash matches.
#   FAIL (either mode): any workload write succeeds; the endpoint serves
#     a raw log, a listing, or a traversal (any code other than exactly
#     404 for (b)-(d), or anything other than exactly 200 for (a)); the
#     security-list audit shows non-host ingress; any downloaded file
#     exceeds 10 MB; any HMAC fails or is missing; the manifest fails
#     schema validation; any recomputed hash mismatches; or anything
#     downloaded is executed.
#   INCONCLUSIVE (exit 2): the script errors, times out, or any
#     sub-check cannot be performed (e.g. an endpoint request fails at
#     the transport level, the OCI API call fails, or no manifest.json
#     is found to schema-validate).
#
# Exit: 0 = PASS, 1 = FAIL, 2 = error/inconclusive.
# Result line: O11_RESULT=PASS | FAIL | INCONCLUSIVE
#
# Notes on (f) (interpretation, for review - see O_TESTS_README.md):
# - A manifest here is every *.json file downloaded from the endpoint
#   (batch.json and each case manifest.json). Each must have a .hmac
#   sidecar, verified with the per-batch secret BEFORE the manifest is
#   trusted - before schema validation and before any hash from it is
#   used.
# - Schema validation applies to each file named manifest.json found
#   under RESULTS_DIR (the per-case manifests, proposal Sec. 11.3).
#   Required fields with correct types: case_id str, repo_url str,
#   commit str, patch_hash str, test_hash str, harness_version str,
#   exit_code_before int, exit_code_after int, memory_peak_bytes int,
#   cpu_usage_usec int, started_at str, ended_at str. Extra fields are
#   allowed. In V3 the BATCH manifest (batch.json) is ALSO
#   schema-validated, against the separate BATCH schema (spec V4 O11
#   (f)): batch_id str, cases list, setup_record dict, proxy_log list,
#   teardown_record dict, results_sha256 str. Extra fields allowed.
# - The hash list results.sha256 is itself HMAC-signed (spec V4 rule
#   15): its .hmac sidecar is verified with the per-batch secret
#   BEFORE the hash list is trusted, and batch.json's results_sha256
#   field must equal the SHA-256 of the downloaded results.sha256
#   file (the binding check). A missing/failed HMAC on the hash list,
#   or a binding mismatch, means the results are untrusted - INVALID.
# - Hash recomputation: every entry in every results.sha256 file must
#   match the recomputed SHA-256 of the named file. Every downloaded
#   regular file other than a *.json manifest (HMAC-authenticated),
#   a results.sha256 file itself, a .hmac sidecar, or the DONE marker
#   must be listed in some results.sha256 with a matching hash. The
#   watchdog snapshot (watchdog-snapshot.txt) is such a file: it must
#   be listed in the batch-level results.sha256 (proposal Sec. 11.3).
#   The snapshot's own HMAC is verified by O13 (e1) before the
#   snapshot is trusted, not here; this mode checks the snapshot is
#   served (a2) and listed (f).
# - Hash-list confinement (blocker I, 2026-11-25 ~22:39 PKT): a
#   hash-list entry must name a path INSIDE RESULTS_DIR. An absolute
#   path, or a relative path that escapes RESULTS_DIR after resolving
#   symlinks (../ or a symlinked directory component), is FAIL - the
#   entry is rejected, not followed. The host never hashes a file
#   outside the results directory on the strength of a hash-list entry.
# - This script NEVER executes, imports, or evaluates anything
#   downloaded: downloaded content is read as data only (JSON parsing
#   and hash/HMAC computation). A symlink found among the downloaded
#   files - including a SYMLINKED DIRECTORY (blocker I) - is FAIL
#   (downloaded results must be regular files under regular
#   directories). A symlinked RESULTS_DIR itself is FAIL.
set -u

mode=${1:-workload}

case "$mode" in
download)
    # --- Retrieval with the 10 MB limit enforced DURING download
    # (blocker I, 2026-11-25 ~22:39 PKT). Runs on the HOST. The
    # endpoint serves only whitelisted manifest/hash/DONE files; this
    # mode fetches exactly that set: batch.json (+ .hmac),
    # results.sha256 (+ .hmac), DONE, and each case's manifest.json
    # (+ .hmac) named by batch.json's cases list. Each file is
    # streamed in 64 KiB chunks with a running byte count; the moment
    # the count exceeds 10 MB the transfer is aborted and the partial
    # file deleted. The download loop is BOUNDED (blocker I,
    # 2026-11-25 ~23:30 PKT): at most MAX_CASES (50) cases are
    # fetched and the AGGREGATE downloaded bytes across all cases
    # are capped at MAX_AGGREGATE_BYTES (256 MiB); both limits are
    # checked in code and fail closed (exit 1, no further download,
    # partial file deleted) when exceeded, so an authenticated case
    # list cannot trigger an unbounded number of downloads or an
    # unbounded total size. Result line: O11_DOWNLOAD result=pass|fail|
    # inconclusive (this mode is a retrieval step, not a verdict, so
    # it prints no O11_RESULT line - the verdict is the host mode).
    # HMAC_SECRET_FILE is required in download mode (blocker K,
    # 2026-11-25 ~23:04 PKT): the HMACs of batch.json and
    # results.sha256 are verified BEFORE batch.json is parsed or used
    # to select any case download, so the secret must be available
    # here, not only in host mode.
    for _v in VM_PUBLIC_IP RESULTS_DIR HMAC_SECRET_FILE; do
        eval "_val=\${$_v:-}"
        if [ -z "$_val" ]; then
            echo "O11_ERROR=required variable unset: $_v"
            echo "O11_RESULT=INCONCLUSIVE"
            exit 2
        fi
    done
    if ! command -v python3 >/dev/null 2>&1; then
        echo "O11_ERROR=required tool missing: python3"
        echo "O11_RESULT=INCONCLUSIVE"
        exit 2
    fi
    mkdir -p "$RESULTS_DIR" || {
        echo "O11_ERROR=cannot create $RESULTS_DIR"
        echo "O11_RESULT=INCONCLUSIVE"
        exit 2
    }
    python3 - "$VM_PUBLIC_IP" "$RESULTS_DIR" "$HMAC_SECRET_FILE" <<'PYEOF'
import hashlib, hmac, json, os, re, sys, urllib.request, urllib.error
vm_ip, results_dir, secret_file = sys.argv[1], sys.argv[2], sys.argv[3]
MAX_BYTES = 10 * 1024 * 1024
MAX_CASES = 50  # maximum cases in batch.json (blocker I)
MAX_AGGREGATE_BYTES = 256 * 1024 * 1024  # 256 MiB aggregate (blocker I)
AGGREGATE_BYTES = 0  # total bytes downloaded across all cases so far
CHUNK = 65536
fails = []
inconc = []

class NoRedirect(urllib.request.HTTPRedirectHandler):
    # Redirects are NEVER followed (blocker I, 2026-11-25 ~23:04 PKT):
    # urllib follows them by default, which would let the endpoint
    # steer a download to an attacker-chosen URL. Returning None makes
    # urlopen return the 3xx response un-followed; fetch() below
    # treats any non-200 status as FAIL.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

_opener = urllib.request.build_opener(NoRedirect)

# --- Destination-path validation (blocker I, 2026-11-25 ~23:04 PKT) ---
# RESULTS_DIR itself must be a real directory, never a symlink, and
# every component of every destination path below it must be a real
# directory (never a symlink). A destination file must not pre-exist
# at all - a pre-existing file at a download destination is
# unexpected and is FAIL, never overwritten (overwriting through a
# planted symlink or over a planted file would write outside the
# results directory or corrupt the retrieval).
if os.path.islink(results_dir):
    print("O11_DOWNLOAD results_dir_is_symlink path=%s" % results_dir)
    print("O11_DOWNLOAD result=fail problems=results_dir_symlink")
    sys.exit(1)
if not os.path.isdir(results_dir):
    print("O11_DOWNLOAD results_dir_not_a_directory path=%s" % results_dir)
    print("O11_DOWNLOAD result=inconclusive problems=results_dir_missing")
    sys.exit(2)
real_results = os.path.realpath(results_dir)

def safe_dest(rel):
    # rel: path relative to RESULTS_DIR, slash-separated, no leading
    # slash, no ".." components (enforced by the caller). Returns the
    # absolute destination, or None if any parent component is a
    # symlink or not a directory, if the destination pre-exists, or
    # if the resolved path escapes RESULTS_DIR.
    parts = rel.split("/")
    if not parts or any(p in ("", ".", "..") for p in parts):
        return None
    cur = results_dir
    for part in parts[:-1]:
        cur = os.path.join(cur, part)
        if os.path.islink(cur) or not os.path.isdir(cur):
            return None
    dest = os.path.join(cur, parts[-1])
    if os.path.lexists(dest):
        return None
    if os.path.realpath(dest) != os.path.join(real_results, rel):
        return None
    return dest

def safe_mkdir(rel):
    # Create one case directory directly under RESULTS_DIR (os.mkdir,
    # not makedirs: the parent is RESULTS_DIR, already validated).
    # Returns "ok", "symlink" (a symlink stands where the directory
    # should be - FAIL), or "error" (cannot create - INCONCLUSIVE).
    d = os.path.join(results_dir, rel)
    if os.path.islink(d):
        return "symlink"
    if os.path.isdir(d):
        return "ok"
    try:
        os.mkdir(d)
        return "ok"
    except OSError:
        return "error"

def fetch(path, rel):
    # Stream one endpoint file to RESULTS_DIR/<rel> with a running
    # byte count. Returns True on success. Over-limit aborts
    # mid-transfer and the partial file is deleted; a non-200 status
    # (including any 3xx - redirects are not followed) is FAIL;
    # transport failure is INCONCLUSIVE; an unsafe destination is FAIL.
    url = "http://%s:8080/%s" % (vm_ip, path)
    dest = safe_dest(rel)
    if dest is None:
        print("O11_DOWNLOAD path=%s unsafe_destination rel=%s" % (path, rel))
        fails.append("unsafe_destination %s" % rel)
        return False
    try:
        req = urllib.request.Request(url, method="GET")
        resp = _opener.open(req, timeout=15)
    except urllib.error.HTTPError as e:
        print("O11_DOWNLOAD path=%s http_status=%s" % (path, e.code))
        fails.append("http_%s %s" % (e.code, path))
        return False
    except Exception as e:
        print("O11_DOWNLOAD path=%s transport_error=%s" % (path, e))
        inconc.append("transport %s" % path)
        return False
    if resp.status != 200:
        print("O11_DOWNLOAD path=%s http_status=%s (redirects are not followed)" % (path, resp.status))
        fails.append("status_%s %s" % (resp.status, path))
        return False
    if resp.geturl() != url:
        print("O11_DOWNLOAD path=%s final_url_mismatch url=%s" % (path, resp.geturl()))
        fails.append("url_mismatch %s" % path)
        return False
    global AGGREGATE_BYTES
    total = 0
    try:
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    except OSError as e:
        print("O11_DOWNLOAD path=%s open_error=%s" % (path, e))
        inconc.append("open %s" % path)
        return False
    try:
        with os.fdopen(fd, "wb") as f:
            while True:
                chunk = resp.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                AGGREGATE_BYTES += len(chunk)
                if total > MAX_BYTES:
                    print("O11_DOWNLOAD path=%s oversize_during_download bytes>%d" % (path, MAX_BYTES))
                    fails.append("oversize_during_download %s" % path)
                    f.close()
                    try:
                        os.remove(dest)
                    except OSError:
                        pass
                    return False
                if AGGREGATE_BYTES > MAX_AGGREGATE_BYTES:
                    print("O11_DOWNLOAD path=%s aggregate_limit_exceeded aggregate_bytes=%d limit=%d" % (path, AGGREGATE_BYTES, MAX_AGGREGATE_BYTES))
                    fails.append("aggregate_limit_exceeded %s" % path)
                    f.close()
                    try:
                        os.remove(dest)
                    except OSError:
                        pass
                    return False
                f.write(chunk)
    except OSError as e:
        print("O11_DOWNLOAD path=%s write_error=%s" % (path, e))
        inconc.append("write %s" % path)
        return False
    print("O11_DOWNLOAD path=%s bytes=%d" % (path, total))
    return True

# 1. The authenticated files first: batch.json + its sidecar, and
#    results.sha256 + its sidecar. Nothing is parsed yet.
ok_b = fetch("batch.json", "batch.json")
ok_bh = fetch("batch.json.hmac", "batch.json.hmac")
ok_h = fetch("results.sha256", "results.sha256")
ok_hh = fetch("results.sha256.hmac", "results.sha256.hmac")
if not (ok_b and ok_bh and ok_h and ok_hh):
    print("O11_DOWNLOAD result=fail problems=authenticated_files_missing")
    sys.exit(1)

# 2. HMAC-BEFORE-USE (blocker K, 2026-11-25 ~23:04 PKT): verify the
#    HMACs of batch.json AND results.sha256 with the per-batch secret
#    BEFORE batch.json is parsed or used to select any download. In
#    V5 the cases list was read from an unauthenticated batch.json
#    and drove the download loop before any HMAC was checked - a
#    tampered batch.json could have named arbitrary case paths. An
#    HMAC failure here means the batch is untrusted: no case is
#    fetched and the download is FAIL. The binding (batch.json
#    results_sha256 == SHA-256 of results.sha256) is checked here
#    too, after both HMACs verify.
try:
    secret_hex = open(secret_file).read().strip()
    key = bytes.fromhex(secret_hex)
    if len(key) != 32:
        print("O11_DOWNLOAD secret_bytes=%d want=32" % len(key))
        print("O11_DOWNLOAD result=inconclusive problems=secret_not_32_bytes")
        sys.exit(2)
except Exception as e:
    print("O11_DOWNLOAD secret_unreadable error=%s" % e)
    print("O11_DOWNLOAD result=inconclusive problems=secret_unreadable")
    sys.exit(2)

def verify_hmac(rel):
    p = os.path.join(results_dir, rel)
    try:
        expect = open(p + ".hmac").read().strip()
        got = hmac.new(key, open(p, "rb").read(), hashlib.sha256).hexdigest()
    except OSError as e:
        print("O11_DOWNLOAD hmac_unreadable path=%s error=%s" % (rel, e))
        return None
    if hmac.compare_digest(got, expect):
        print("O11_DOWNLOAD hmac_verified path=%s" % rel)
        return True
    print("O11_DOWNLOAD hmac_mismatch path=%s" % rel)
    return False

_hb = verify_hmac("batch.json")
if _hb is None:
    print("O11_DOWNLOAD result=inconclusive problems=hmac_unreadable batch.json")
    sys.exit(2)
if not _hb:
    print("O11_DOWNLOAD result=fail problems=hmac_mismatch batch.json")
    sys.exit(1)
_hh = verify_hmac("results.sha256")
if _hh is None:
    print("O11_DOWNLOAD result=inconclusive problems=hmac_unreadable results.sha256")
    sys.exit(2)
if not _hh:
    print("O11_DOWNLOAD result=fail problems=hmac_mismatch results.sha256")
    sys.exit(1)
try:
    batch = json.load(open(os.path.join(results_dir, "batch.json")))
    actual = hashlib.sha256(open(os.path.join(results_dir, "results.sha256"), "rb").read()).hexdigest()
except Exception as e:
    print("O11_DOWNLOAD binding_unreadable error=%s" % e)
    print("O11_DOWNLOAD result=inconclusive problems=binding_unreadable")
    sys.exit(2)
if not isinstance(batch, dict) or batch.get("results_sha256") != actual:
    print("O11_DOWNLOAD binding_mismatch")
    print("O11_DOWNLOAD result=fail problems=binding_mismatch")
    sys.exit(1)
print("O11_DOWNLOAD binding_verified")
cases = batch.get("cases")
if not isinstance(cases, list):
    print("O11_DOWNLOAD cases_not_a_list")
    print("O11_DOWNLOAD result=inconclusive problems=cases_not_a_list")
    sys.exit(2)
# Bounded download loop (blocker I, 2026-11-25 ~23:30 PKT): the case
# count is capped at MAX_CASES, checked in code BEFORE any case is
# fetched. A list with more than MAX_CASES cases is a failure, not
# a truncation - nothing is downloaded from it.
if len(cases) > MAX_CASES:
    print("O11_DOWNLOAD cases=%d max_cases=%d" % (len(cases), MAX_CASES))
    print("O11_DOWNLOAD result=fail problems=max_cases_exceeded")
    sys.exit(1)
print("O11_DOWNLOAD cases=%d max_cases=%d max_aggregate_bytes=%d"
      % (len(cases), MAX_CASES, MAX_AGGREGATE_BYTES))

# 3. Each case's manifest + sidecar, named by the AUTHENTICATED
#    batch.json only (step 2 above). Case IDs are plain directory
#    names: no slash, no leading dot, no traversal.
for entry in cases:
    if isinstance(entry, dict):
        cid = entry.get("case_id")
    elif isinstance(entry, str):
        # batch.json cases are "case=result" strings (vm_teardown
        # writes results.split() from case_results.txt, e.g.
        # "o01=PASS"). The case ID is the part before "=", and the
        # result (if present) must be one of the five allowed
        # result values (Revision 9, spec rule 32 - the same set the
        # host schema and the verdict gate use).
        # (Revision 8 fix: o11 previously took the whole "o01=PASS"
        # string as the case ID, so the "=" failed the ID regex and
        # every case was rejected as bad_case_id - found by the
        # dry-run.)
        if "=" in entry:
            cid, _res = entry.split("=", 1)
            if _res not in ("PASS", "FAIL", "INCONCLUSIVE", "SKIPPED", "INVALID"):
                print("O11_DOWNLOAD bad_case_result entry=%r" % (entry,))
                inconc.append("bad_case_result")
                continue
        else:
            cid = entry
    else:
        cid = None
    if not isinstance(cid, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", cid) or cid in (".", ".."):
        print("O11_DOWNLOAD bad_case_id entry=%r" % (entry,))
        inconc.append("bad_case_id")
        continue
    mk = safe_mkdir(cid)
    if mk == "symlink":
        print("O11_DOWNLOAD case_dir_is_symlink case=%s" % cid)
        fails.append("symlink_case_dir %s" % cid)
        continue
    if mk != "ok":
        print("O11_DOWNLOAD mkdir_failed case=%s" % cid)
        inconc.append("mkdir %s" % cid)
        continue
    fetch("%s/manifest.json" % cid, "%s/manifest.json" % cid)
    fetch("%s/manifest.json.hmac" % cid, "%s/manifest.json.hmac" % cid)

# 4. The watchdog snapshot + its HMAC sidecar (blocker L, 2026-11-25
#    ~23:04 PKT): the snapshot is required by O13 (e1) and was absent
#    from the V5 endpoint whitelist and fetch list, so O13 could not
#    obtain it. The harness writes it to /results/watchdog-snapshot.txt
#    with a .hmac sidecar (proposal Sec. 11.2 step 4); the endpoint
#    serves both (proposal Sec. 5.5). A failed snapshot fetch is FAIL
#    - the batch cannot prove its watchdog evidence without it.
fetch("watchdog-snapshot.txt", "watchdog-snapshot.txt")
fetch("watchdog-snapshot.txt.hmac", "watchdog-snapshot.txt.hmac")

# 5. The DONE marker.
fetch("DONE", "DONE")

print("O11_DOWNLOAD aggregate_bytes=%d cases=%d"
      % (AGGREGATE_BYTES, len(cases)))
if inconc:
    print("O11_DOWNLOAD result=inconclusive problems=%s" % ";".join(inconc))
    sys.exit(2)
if fails:
    print("O11_DOWNLOAD result=fail problems=%s" % ";".join(fails))
    sys.exit(1)
print("O11_DOWNLOAD result=pass")
sys.exit(0)
PYEOF
    exit $?
    ;;
workload)
    FAIL=0
    CASE_ID=${CASE_ID:-o11_case}

    # Sanity: this test is only meaningful as the workload user.
    if [ "$(id -u 2>/dev/null)" != "1001" ]; then
        echo "O11_ERROR=not running as UID 1001 (got $(id -u 2>/dev/null || echo unknown))"
        echo "O11_RESULT=INCONCLUSIVE"
        exit 2
    fi

    # attempt_write <path> <label>
    # If the path already exists, that is itself evidence of a prior
    # write - FAIL. Otherwise try to create it; success is FAIL,
    # failure is expected.
    attempt_write() {
        _path=$1
        _label=$2
        if [ -e "$_path" ]; then
            echo "O11_ATTEMPT label=$_label path=$_path result=already_exists"
            FAIL=1
            return
        fi
        if printf 'o11-probe\n' > "$_path" 2>/dev/null; then
            echo "O11_ATTEMPT label=$_label path=$_path result=writable"
            FAIL=1
        else
            echo "O11_ATTEMPT label=$_label path=$_path result=denied"
        fi
    }

    attempt_write "/results/$CASE_ID.json" result-file
    attempt_write /opt/harness/o11_test_$$ harness-write
    attempt_write /opt/proxy/o11_test_$$ proxy-write
    attempt_write /results/DONE done-marker

    if [ "$FAIL" -gt 0 ]; then
        echo "O11_RESULT=FAIL"
        exit 1
    fi
    echo "O11_RESULT=PASS"
    exit 0
    ;;
host)
    FAIL=0
    INCONCLUSIVE=0
    OCI_CLI=${OCI_CLI:-oci}
    export OCI_CLI

    for _v in VM_PUBLIC_IP HOST_EGRESS_IP RESULTS_DIR HMAC_SECRET_FILE \
        BATCH_MANIFEST RESULTS_SHA256 SECLIST_OCID; do
        eval "_val=\${$_v:-}"
        if [ -z "$_val" ]; then
            echo "O11_ERROR=required variable unset: $_v"
            echo "O11_RESULT=INCONCLUSIVE"
            exit 2
        fi
    done

    for _tool in "$OCI_CLI" curl python3; do
        if ! command -v "$_tool" >/dev/null 2>&1; then
            echo "O11_ERROR=required tool missing: $_tool"
            echo "O11_RESULT=INCONCLUSIVE"
            exit 2
        fi
    done

    if [ ! -d "$RESULTS_DIR" ]; then
        echo "O11_ERROR=RESULTS_DIR is not a directory: $RESULTS_DIR"
        echo "O11_RESULT=INCONCLUSIVE"
        exit 2
    fi
    if [ ! -f "$BATCH_MANIFEST" ]; then
        echo "O11_ERROR=BATCH_MANIFEST not found: $BATCH_MANIFEST"
        echo "O11_RESULT=INCONCLUSIVE"
        exit 2
    fi
    if [ ! -f "$RESULTS_SHA256" ]; then
        echo "O11_ERROR=RESULTS_SHA256 not found: $RESULTS_SHA256"
        echo "O11_RESULT=INCONCLUSIVE"
        exit 2
    fi

    _tmpdir=$(mktemp -d) || {
        echo "O11_ERROR=cannot create temp dir"
        echo "O11_RESULT=INCONCLUSIVE"
        exit 2
    }
    trap 'rm -rf "$_tmpdir"' EXIT

    # --- (a)-(d) Endpoint checks: exact HTTP codes. ---
    # http_expect <url> <expected-code> <label>
    # Transport failure (curl non-zero, or code 000) is INCONCLUSIVE:
    # the endpoint's decision cannot be verified.
    http_expect() {
        _url=$1
        _want=$2
        _label=$3
        _code=$(curl -s -m 15 --path-as-is -o /dev/null -w '%{http_code}' "$_url" 2>/dev/null)
        _rc=$?
        if [ "$_rc" -ne 0 ] || [ "$_code" = "000" ]; then
            echo "O11_ENDPOINT label=$_label result=inconclusive rc=$_rc code=$_code"
            INCONCLUSIVE=1
        elif [ "$_code" = "$_want" ]; then
            echo "O11_ENDPOINT label=$_label result=expected code=$_code"
        else
            echo "O11_ENDPOINT label=$_label result=unexpected code=$_code want=$_want"
            FAIL=1
        fi
    }

    http_expect "http://$VM_PUBLIC_IP:8080/batch.json" 200 manifest
    # (a2) The watchdog snapshot must be served (blocker L, 2026-11-25
    # ~23:04 PKT): in V5 it was absent from the endpoint whitelist, so
    # O13 could not obtain its required JOURNAL_SNAPSHOT.
    http_expect "http://$VM_PUBLIC_IP:8080/watchdog-snapshot.txt" 200 snapshot
    http_expect "http://$VM_PUBLIC_IP:8080/stdout.log" 404 raw-log
    http_expect "http://$VM_PUBLIC_IP:8080/" 404 listing
    # (V13, spec rule 44) Traversal probes over a RAW SOCKET, not
    # curl: curl normalises /../ before sending (and --path-as-is
    # still normalises in some versions), so the V12 curl probe
    # could receive /batch.json and pass without exercising the
    # server's traversal defence. The raw socket sends the literal
    # target. The host does not know the canary marker, so it
    # asserts HTTP 404 AND an empty body (the server's 404 has
    # Content-Length: 0; any content returned from outside /results
    # fails here).
    raw_traversal_expect() {
        _target=$1
        _label=$2
        _probe_out=$(python3 - "$VM_PUBLIC_IP" 8080 "$_target" <<'PYEOF' 2>&1
import socket, sys
host, port, target = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    s = socket.create_connection((host, port), timeout=15)
except Exception as e:
    print("RAW_HTTP target=%s status=000 body_bytes=0 error=%s" % (target, e))
    sys.exit(1)
req = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n" % (target, host, port)).encode()
s.sendall(req)
data = b""
while True:
    try:
        chunk = s.recv(4096)
    except socket.timeout:
        break
    if not chunk:
        break
    data += chunk
s.close()
line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
parts = line.split()
code = parts[1] if len(parts) > 1 else "000"
body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
print("RAW_HTTP target=%s status=%s body_bytes=%d" % (target, code, len(body)))
sys.exit(0 if code == "404" and len(body) == 0 else 1)
PYEOF
)
        _rc=$?
        if [ "$_rc" -eq 0 ]; then
            echo "O11_ENDPOINT label=$_label result=expected $_probe_out"
        else
            echo "O11_ENDPOINT label=$_label result=unexpected $_probe_out"
            FAIL=1
        fi
    }
    raw_traversal_expect "/../batch.json" traversal-dotdot-raw
    raw_traversal_expect "/%2e%2e/batch.json" traversal-encoded-raw
    raw_traversal_expect "/../opt/traversal/traversal_canary.txt" traversal-canary-raw
    raw_traversal_expect "/%2e%2e/opt/traversal/traversal_canary.txt" traversal-canary-encoded-raw

    # --- (e) Security-list audit: host-IP-only ingress for TCP 8080. ---
    if ! "$OCI_CLI" network security-list get --security-list-id "$SECLIST_OCID" \
        >"$_tmpdir/seclist.json" 2>"$_tmpdir/seclist.err"; then
        echo "O11_SECLIST result=query_failed"
        sed 's/^/O11_SECLIST_ERR /' "$_tmpdir/seclist.err" | head -n 3
        INCONCLUSIVE=1
    else
        python3 - "$_tmpdir/seclist.json" "$HOST_EGRESS_IP" <<'PYEOF'
import json, sys
try:
    data = json.load(open(sys.argv[1]))["data"]
    rules = data.get("ingress-security-rules")
except Exception:
    print("O11_SECLIST result=unparseable")
    sys.exit(2)
if not isinstance(rules, list):
    print("O11_SECLIST result=no_ingress_rules_field")
    sys.exit(2)
print("O11_SECLIST ingress_rule_count=%d" % len(rules))
if len(rules) != 1:
    print("O11_SECLIST result=not_only_ingress_rule")
    sys.exit(1)
r = rules[0]
want_source = sys.argv[2] + "/32"
print("O11_SECLIST source=%s protocol=%s" % (r.get("source"), r.get("protocol")))
if r.get("source") != want_source:
    print("O11_SECLIST result=source_mismatch want=%s" % want_source)
    sys.exit(1)
if str(r.get("protocol")) != "6":
    print("O11_SECLIST result=not_tcp")
    sys.exit(1)
try:
    dpr = r["tcp-options"]["destination-port-range"]
    if dpr.get("min") != 8080 or dpr.get("max") != 8080:
        print("O11_SECLIST result=port_mismatch range=%s" % dpr)
        sys.exit(1)
except Exception:
    print("O11_SECLIST result=no_tcp_port_range")
    sys.exit(1)
print("O11_SECLIST result=host_only_ingress")
sys.exit(0)
PYEOF
        _sl_rc=$?
        if [ "$_sl_rc" -eq 1 ]; then
            FAIL=1
        elif [ "$_sl_rc" -ne 0 ]; then
            INCONCLUSIVE=1
        fi
    fi

    # --- (f) Host handling of the downloaded results. ---
    python3 - "$RESULTS_DIR" "$HMAC_SECRET_FILE" "$BATCH_MANIFEST" "$RESULTS_SHA256" <<'PYEOF'
import hashlib, hmac, json, os, sys
results_dir, secret_file, batch_manifest, results_sha256 = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
MAX_BYTES = 10 * 1024 * 1024
fails = []
inconc = []
# Read the per-batch secret (hex-encoded 32 bytes). A bad secret means
# the HMAC check cannot be performed at all.
try:
    secret_hex = open(secret_file).read().strip()
    key = bytes.fromhex(secret_hex)
    if len(key) != 32:
        print("O11_HMAC secret_bytes=%d want=32" % len(key))
        inconc.append("secret_not_32_bytes")
        key = None
except Exception as e:
    print("O11_HMAC secret_unreadable error=%s" % e)
    inconc.append("secret_unreadable")
    key = None
# Collect downloaded regular files; symlinks among them are FAIL.
# (blocker I, 2026-11-25 ~22:39 PKT): a symlinked DIRECTORY is also
# FAIL - os.walk does not descend into symlinked directories by
# default, so without this check a whole subtree of results could
# hide under a symlink and never be examined. RESULTS_DIR itself
# being a symlink is FAIL for the same reason.
all_files = []
symlinks = []
if os.path.islink(results_dir):
    print("O11_FILE symlink=%s (results dir itself)" % results_dir)
    symlinks.append(results_dir)
for root, dirs, names in os.walk(results_dir):
    for d in dirs:
        p = os.path.join(root, d)
        if os.path.islink(p):
            symlinks.append(p)
    for name in names:
        p = os.path.join(root, name)
        if os.path.islink(p):
            symlinks.append(p)
        elif os.path.isfile(p):
            all_files.append(p)
if symlinks:
    for p in symlinks:
        print("O11_FILE symlink=%s" % p)
    fails.append("symlink_in_results")
# Size limit: every downloaded file <= 10 MB.
for p in all_files:
    try:
        size = os.path.getsize(p)
    except OSError:
        inconc.append("cannot_stat %s" % p)
        continue
    if size > MAX_BYTES:
        print("O11_FILE oversize path=%s bytes=%d" % (p, size))
        fails.append("oversize %s" % p)
print("O11_FILE count=%d" % len(all_files))
# HMAC: every *.json manifest (plus the batch manifest itself, even if
# it lives outside RESULTS_DIR) must have a .hmac sidecar that verifies,
# BEFORE the manifest is trusted.
manifests = sorted(set([p for p in all_files if p.endswith(".json")] + [batch_manifest]))
for p in manifests:
    sidecar = p + ".hmac"
    if not os.path.isfile(sidecar):
        print("O11_HMAC missing_sidecar path=%s" % p)
        fails.append("missing_hmac %s" % p)
        continue
    if key is None:
        continue
    try:
        expect = open(sidecar).read().strip()
        got = hmac.new(key, open(p, "rb").read(), hashlib.sha256).hexdigest()
    except OSError as e:
        inconc.append("cannot_read %s" % p)
        continue
    if hmac.compare_digest(got, expect):
        print("O11_HMAC verified path=%s" % p)
    else:
        print("O11_HMAC mismatch path=%s" % p)
        fails.append("hmac_mismatch %s" % p)
# Hash-list HMAC + binding (spec V4 rule 15): the HMAC of
# results.sha256 is verified against its .hmac sidecar BEFORE the hash
# list is trusted (the manifest HMAC loop above already verified
# batch.json itself). Then batch.json's results_sha256 field must equal
# the SHA-256 of the downloaded results.sha256 file.
if key is not None:
    _sidecar = results_sha256 + ".hmac"
    if not os.path.isfile(_sidecar):
        print("O11_HMAC missing_sidecar path=%s" % results_sha256)
        fails.append("missing_hmac %s" % results_sha256)
    else:
        try:
            _expect = open(_sidecar).read().strip()
            _got = hmac.new(key, open(results_sha256, "rb").read(), hashlib.sha256).hexdigest()
        except OSError:
            inconc.append("cannot_read %s" % results_sha256)
            _got = None
        if _got is not None:
            if hmac.compare_digest(_got, _expect):
                print("O11_HMAC verified path=%s" % results_sha256)
            else:
                print("O11_HMAC mismatch path=%s" % results_sha256)
                fails.append("hmac_mismatch %s" % results_sha256)
# Batch schema validation (spec V4 O11 (f); semantic validation
# added in Revision 9, spec rule 32): batch.json must be an object
# with batch_id str, cases list, setup_record dict, proxy_log list,
# teardown_record dict, results_sha256 str. Extra fields allowed.
# This runs only after batch.json's HMAC verified above. The semantic
# check validates MEANING, not only types: verdict must be a valid
# verdict value; every cases entry must be "oNN=RESULT" with oNN in
# the mandatory O1-O11 set and RESULT in the allowed set; no
# duplicates, no unknown case IDs; batch_id must be non-empty. A
# manifest failing any of these is schema-invalid (FAIL). NOTE: this
# validates the evidence is well-formed; it does NOT decide the batch
# verdict - a well-formed manifest whose verdict is FAIL (or whose
# cases include FAIL) is VALID evidence, and the final verdict gate
# (rule 31, run_batch.sh host_phase_verdict) reports FAIL from it.
# Completeness (every mandatory case present with explicit PASS) is
# the verdict gate's job, not the schema's: in a real run the VM loop
# stops at the first non-PASS, so a FAIL manifest legitimately lists
# only the cases run so far.
BATCH_SCHEMA = {
    "batch_id": str, "cases": list, "setup_record": dict,
    "proxy_log": list, "teardown_record": dict, "results_sha256": str,
}
try:
    _batch = json.load(open(batch_manifest))
except Exception as e:
    print("O11_BATCH_SCHEMA invalid_json path=%s error=%s" % (batch_manifest, e))
    fails.append("invalid_json %s" % batch_manifest)
    _batch = None
if _batch is not None:
    if not isinstance(_batch, dict):
        print("O11_BATCH_SCHEMA not_object path=%s" % batch_manifest)
        fails.append("not_object %s" % batch_manifest)
    else:
        _bad = []
        for _field, _typ in BATCH_SCHEMA.items():
            if _field not in _batch:
                _bad.append("missing %s" % _field)
            elif _typ is str and not isinstance(_batch[_field], str):
                _bad.append("type %s" % _field)
            elif _typ is list and not isinstance(_batch[_field], list):
                _bad.append("type %s" % _field)
            elif _typ is dict and not isinstance(_batch[_field], dict):
                _bad.append("type %s" % _field)
        if _bad:
            print("O11_BATCH_SCHEMA invalid path=%s problems=%s" % (batch_manifest, ";".join(_bad)))
            fails.append("batch_schema %s" % batch_manifest)
        else:
            # Semantic validation (rule 32): verdict value, case
            # entries, batch_id non-empty. Runs only when the field
            # types above are already valid.
            _sem = []
            if not _batch.get("batch_id"):
                _sem.append("batch_id empty")
            _v = _batch.get("verdict")
            if _v is None:
                _sem.append("missing verdict")
            elif _v not in ("PASS", "FAIL", "INCONCLUSIVE", "INVALID"):
                _sem.append("verdict not a valid verdict: %r" % (_v,))
            _seen = {}
            for _e in _batch["cases"]:
                if not isinstance(_e, str) or "=" not in _e:
                    _sem.append("bad case entry: %r" % (_e,))
                    continue
                _cid, _res = _e.split("=", 1)
                if _cid not in ("o01", "o02", "o03", "o04", "o05", "o06", "o07", "o08", "o09", "o10", "o11"):
                    _sem.append("unknown case id: %s" % _cid)
                elif _cid in _seen:
                    _sem.append("duplicate case: %s" % _cid)
                elif _res not in ("PASS", "FAIL", "INCONCLUSIVE", "SKIPPED", "INVALID"):
                    _sem.append("bad case result: %s" % _e)
                else:
                    _seen[_cid] = _res
            if _sem:
                print("O11_BATCH_SCHEMA semantic_invalid path=%s problems=%s" % (batch_manifest, ";".join(_sem)))
                fails.append("batch_schema_semantic %s" % batch_manifest)
            else:
                print("O11_BATCH_SCHEMA valid path=%s" % batch_manifest)
            # Binding check: batch.json results_sha256 must equal the
            # SHA-256 of the downloaded results.sha256 file.
            try:
                _actual = hashlib.sha256(open(results_sha256, "rb").read()).hexdigest()
            except OSError:
                inconc.append("cannot_read %s" % results_sha256)
                _actual = None
            if _actual is not None:
                if _batch["results_sha256"] == _actual:
                    print("O11_BINDING results_sha256 match sha256=%s" % _actual)
                else:
                    print("O11_BINDING mismatch batch_field=%s actual_sha256=%s" % (_batch["results_sha256"], _actual))
                    fails.append("binding_mismatch results_sha256")
# Schema: every file named manifest.json under RESULTS_DIR.
SCHEMA = {
    "case_id": str, "repo_url": str, "commit": str, "patch_hash": str,
    "test_hash": str, "harness_version": str, "exit_code_before": int,
    "exit_code_after": int, "memory_peak_bytes": int,
    "cpu_usage_usec": int, "started_at": str, "ended_at": str,
}
case_manifests = sorted([p for p in all_files if os.path.basename(p) == "manifest.json"])
if not case_manifests:
    print("O11_SCHEMA no_case_manifest_found")
    inconc.append("no_manifest_json")
for p in case_manifests:
    try:
        m = json.load(open(p))
    except Exception as e:
        print("O11_SCHEMA invalid_json path=%s error=%s" % (p, e))
        fails.append("invalid_json %s" % p)
        continue
    if not isinstance(m, dict):
        print("O11_SCHEMA not_object path=%s" % p)
        fails.append("not_object %s" % p)
        continue
    bad = []
    for field, typ in SCHEMA.items():
        if field not in m:
            bad.append("missing %s" % field)
        elif typ is int and (not isinstance(m[field], int) or isinstance(m[field], bool)):
            bad.append("type %s" % field)
        elif typ is str and not isinstance(m[field], str):
            bad.append("type %s" % field)
    if bad:
        print("O11_SCHEMA invalid path=%s problems=%s" % (p, ";".join(bad)))
        fails.append("schema %s" % p)
    else:
        print("O11_SCHEMA valid path=%s" % p)
# SHA-256: every entry in every results.sha256 must match; every
# downloaded regular file other than a *.json manifest (HMAC), a
# results.sha256 file, a .hmac sidecar, or the DONE marker must be
# listed in some results.sha256 with a matching hash.
listed = {}
for p in all_files:
    if os.path.basename(p) == "results.sha256":
        base = os.path.dirname(p)
        try:
            lines = open(p).read().splitlines()
        except OSError:
            inconc.append("cannot_read %s" % p)
            continue
        for line in lines:
            if not line.strip():
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                print("O11_HASH malformed_line file=%s line=%s" % (p, line))
                fails.append("malformed_sha256 %s" % p)
                continue
            digest, name = parts[0].strip(), parts[1].strip()
            # Confinement (blocker I, 2026-11-25 ~22:39 PKT): the
            # entry must name a path INSIDE RESULTS_DIR. An absolute
            # path is rejected outright; a relative path is resolved
            # (symlinks included) and must stay inside the real
            # results directory. An escaping entry is FAIL, not
            # followed - the host never hashes a file outside the
            # results directory on the strength of a hash-list entry.
            if os.path.isabs(name):
                print("O11_HASH absolute_path file=%s entry=%s" % (p, name))
                fails.append("absolute_path %s" % name)
                continue
            target = os.path.normpath(os.path.join(base, name))
            real_results = os.path.realpath(results_dir)
            real_target = os.path.realpath(target)
            if os.path.commonpath([real_target, real_results]) != real_results:
                print("O11_HASH escapes_results_dir file=%s entry=%s" % (p, name))
                fails.append("escapes_results_dir %s" % name)
                continue
            listed[target] = digest
for target, digest in sorted(listed.items()):
    if not os.path.isfile(target):
        print("O11_HASH missing_file path=%s" % target)
        fails.append("missing %s" % target)
        continue
    got = hashlib.sha256(open(target, "rb").read()).hexdigest()
    if got != digest:
        print("O11_HASH mismatch path=%s" % target)
        fails.append("hash_mismatch %s" % target)
    else:
        print("O11_HASH verified path=%s" % target)
for p in all_files:
    base = os.path.basename(p)
    if p.endswith(".json") or base in ("results.sha256", "DONE") or p.endswith(".hmac"):
        continue
    if os.path.normpath(p) not in listed:
        print("O11_HASH unlisted_file path=%s" % p)
        fails.append("unlisted %s" % p)
if inconc:
    print("O11_HOST_HANDLING result=inconclusive problems=%s" % ";".join(inconc))
    sys.exit(2)
if fails:
    print("O11_HOST_HANDLING result=fail problems=%s" % ";".join(fails))
    sys.exit(1)
print("O11_HOST_HANDLING result=pass")
sys.exit(0)
PYEOF
    _host_rc=$?
    if [ "$_host_rc" -eq 1 ]; then
        FAIL=1
    elif [ "$_host_rc" -ne 0 ]; then
        INCONCLUSIVE=1
    fi

    if [ "$INCONCLUSIVE" -gt 0 ]; then
        echo "O11_RESULT=INCONCLUSIVE"
        exit 2
    fi
    if [ "$FAIL" -gt 0 ]; then
        echo "O11_RESULT=FAIL"
        exit 1
    fi
    echo "O11_RESULT=PASS"
    exit 0
    ;;
*)
    echo "O11_ERROR=unknown mode: $mode (want workload|host)"
    echo "O11_RESULT=INCONCLUSIVE"
    exit 2
    ;;
esac
