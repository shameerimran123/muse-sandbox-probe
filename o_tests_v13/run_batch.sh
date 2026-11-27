#!/bin/sh
# run_batch.sh - M8 batch orchestration runner (Revision 13)
# Spec: O_TESTS_SPEC_V13.md; proposal M8_PROPOSAL_V13.md Sec. 11.1-11.5.
# EXECUTED in --dry-run mode only (no VM is authorized yet): the
# dry-run exercises the full host + VM lifecycle locally against a
# mock OCI layer (mock_oci.sh) and a mock VM (mock_vm.sh); its
# evidence log is o_tests_v13/dry_run_evidence.log. The real (cloud)
# path has NOT been executed.
#
# Revision 13 (spec rules 43-44, ChatGPT V12 verdict 2026-11-27
# ~00:54 PKT - NO-GO, blocker (c) NOT CLEARED): the V12 defects ARE
# fixed (proxy cap + proxy cgroup, secret never in user-data - rules
# 40-42 retained). The TWO new defects: (A) the secret delivery is
# unauthenticated - RSA-OAEP encrypts but does not authenticate who
# created the ciphertext; the host fetches hmac_secret.enc over
# plain HTTP and anyone with the host public key can encrypt an
# arbitrary 64-char secret, so a substituted ciphertext could make
# the host accept an attacker-known secret and then forge HMACs for
# forged manifests; (B) the O11 traversal check is a false positive
# - check 9 and o11.sh fetch /../batch.json with curl, but curl
# normalises the path before sending, so the server receives
# /batch.json and the check passes without exercising the server's
# traversal defence. Revision 13 fixes both: (rule 43) the VM signs
# the delivery with its OCI instance-identity private key (fetched
# from the IMDS identity endpoints at setup, deleted after signing)
# over batch_id + a fresh per-batch challenge + the ciphertext
# SHA-256, and publishes the signature + leaf + intermediate
# certificates; the host verifies the chain against the pinned OCI
# root CA, the cert's instance OCID and tenancy OCID, the dates,
# and the signature over the host's own recorded challenge before
# decrypting; the driver proves a substituted ciphertext, a
# wrong-sender certificate, a wrong-CA certificate, and a replayed
# (old-challenge) signature all fail closed; (rule 44) the
# traversal probes use a raw socket that sends the literal
# unnormalised request target - literal and percent-encoded forms,
# plus a planted canary file outside /results - and require HTTP
# 404 with no canary content returned; the driver proves the same
# probes DETECT a deliberately vulnerable server. Rules 31-42 are
# preserved unchanged.
#
# Revision 12 (spec rules 40-42, ChatGPT V11 verdict 2026-11-26
# ~06:49 PKT - NO-GO, blocker (c) NOT CLEARED): (rule 37) the
# stored verdict is replayed in host_main() immediately after
# batch_id_resolve, before any phase, and the stored exit= is
# validated against verdict= on replay; (rule 38) a case-level
# FAIL dominates the overall verdict field in the gate; (rule 39)
# o13.sh (e4b) waits a bounded 180 s for the poller's three
# liveness observations before judging the state log (the V11
# driver caught a scheduling race: o13.sh could read the log
# before the poller's third liveness write and report
# INCONCLUSIVE although all three were later confirmed). The
# driver adds gate-precedence checks, early-marker-loss replay
# checks, and liveness-wait checks (positive + timeout).
#
# Revision 12 (spec rules 40-42, ChatGPT V11 verdict 2026-11-26
# ~21:27 PKT - NO-GO, blocker (c) NOT CLEARED): the V11 defects ARE
# fixed (early replay, FAIL precedence, exit= validation, liveness
# wait - rules 37-39 retained). The TWO new defects: (1) the egress
# proxy spawns one thread per connection with no cap and runs as UID
# 1002 outside the workload UID 1001 cgroup, so the workload can
# exhaust the VM outside the claimed limits; (2) the per-batch HMAC
# secret transits inside cloud-init user-data, contradicting the
# spec's no-secrets-in-user-data rule, and scrubbing only
# user-data.txt is insufficient evidence. Revision 12 fixes both:
# (rule 40) the proxy has a hard MAX_WORKERS=16 concurrency cap
# (excess connections refused immediately with HTTP 503, never
# queued) plus its own cgroup (/sys/fs/cgroup/proxy: memory.max
# 512 MiB, cpu.max 0.5 CPU, pids.max 64); O5(h) tests the cap on
# the VM and the driver runs an adversarial concurrency regression
# against the real proxy; (rule 41) the secret is generated INSIDE
# the VM by the harness and never enters user-data - the host
# generates a per-batch RSA keypair, puts only the PUBLIC key in
# user-data, and the VM encrypts the secret with it (RSA-OAEP
# SHA-256) and publishes the ciphertext as /results/hmac_secret.enc
# for the host to pull and decrypt; the host verifies the user-data
# contains no secret and the secret appears only in the two allowed
# files; (rule 42) the driver adds the proxy concurrency regression
# and the secret-delivery verification (round-trip, sweep, tamper
# and wrong-key fail-closed). Rules 31-39 are preserved unchanged.
#
# Revision 10 (spec rules 35-36, ChatGPT V9 verdict 2026-11-26
# ~05:05 PKT - NO-GO, blocker (c) NOT CLEARED): the V9 verdict
# phase wrote its verdict.done marker unconditionally and returned
# 0 whenever the marker existed, so a later invocation reported a
# successful exit for a FAIL/INCONCLUSIVE batch. The V10 verdict
# phase (host_phase_verdict) persists the final verdict + exit code
# in verdict.txt and REPLAYS the stored result on a later
# invocation (PASS -> exit 0, FAIL -> exit 1, INCONCLUSIVE/INVALID
# -> exit 2); the verdict.done marker is written ONLY when the
# verdict is PASS. A batch dir with completed phase markers but no
# batch_id.txt is now rejected even without --resume (rule 36).
# Regression dry-runs (rule 34, extended) prove the replay: resume
# after INCONCLUSIVE -> exit 2, resume after FAIL -> exit 1, resume
# after PASS -> exit 0, plus a full all-pass run and missing/empty
# batch_id.txt rejections. The V9 closed verdict gate (rule 31),
# stable BATCH_ID (rule 33), split lifecycle/security outcomes
# (rule 34) and the V8 lifecycle corrections (poller 3 liveness
# queries, H12 order) are retained.
#
# Revision 9 (spec rules 31-34, ChatGPT V8 verdict 2026-11-26
# ~02:49 PKT - NO-GO, blocker (c) NOT CLEARED): the V8 final verdict
# gate was FAIL-OPEN - it read only O13_RESULT, O11_RESULT (host)
# and O12_RESULT, so a batch whose VM-side O1-O11 tests were
# INCONCLUSIVE was declared PASS. The V9 gate (host_phase_verdict)
# authenticates and inspects the VM's batch manifest and requires
# the VM verdict exactly PASS + every mandatory O1-O11 case explicit
# PASS + the manifest batch_id equal to the persisted BATCH_ID.
# BATCH_ID is now stable (persisted in batch_id.txt on first
# invocation, reused afterwards, mismatch rejected - rule 33). The
# dry-run reports lifecycle and security outcomes SEPARATELY (rule
# 34) and three regression dry-runs prove the gate blocks PASS for
# an injected FAIL, an injected INCONCLUSIVE, and a mismatched
# BATCH_ID. The V8 lifecycle corrections are retained (poller 3
# liveness queries, H12 order).
#
# This is the ACTUAL orchestration runner (blocker K, 2026-11-25
# ~23:30 PKT), not a described procedure: it drives the O1-O13
# sequence in order, starts the lifecycle poller, installs the O5
# whole-sequence cleanup trap in code, records the O9/O10/O12
# outcomes that have no result line of their own, and passes
# HMAC_SECRET_FILE to the download flow explicitly. Every step is
# recorded in a plain-text batch record (one line per event), and
# every phase writes a marker file on success so a later invocation
# with --resume continues from where the previous one stopped.
#
# Three modes:
#   run_batch.sh host --batch-dir DIR [--resume]
#       Host-side orchestration (the coordinator machine). Validates
#       inputs, re-verifies the M1-M7 freeze, verifies the repo +
#       commit, runs the OCI pre-creation checks, generates the
#       per-batch host RSA keypair (the HMAC secret is generated
#       inside the VM - rule 41), creates the per-batch network,
#       checks the controller checkpoint, generates the user-data
#       (the bootstrap script + the host's per-batch PUBLIC key -
#       no secret; the reviewed egress-proxy.py comes from the
#       verified repo clone, not from the user-data), creates ONE A1
#       VM, starts the lifecycle poller, waits for DONE, fetches the
#       encrypted per-batch secret (hmac_secret.enc), decrypts it and
#       verifies the secret delivery, downloads the results with
#       o11.sh download (HMAC_SECRET_FILE passed explicitly), runs
#       the o11 host checks + o12 verify, terminates the VM, runs
#       o13, records the verdict, and destroys the host's copy of
#       the per-batch secret and the host private key.
#       The host mode runs in TWO invocations by design: the first
#       invocation stops at the controller checkpoint (exit 3) after
#       creating the VM, because the controller cron job must be
#       UPDATED with the real instance OCID and re-verified via
#       cron.list by the OPERATOR (this script cannot call the Muse
#       cron API). The operator updates the cron, verifies it, writes
#       the updated controller_verified file, and re-runs this script
#       with --resume. The VM-side case loop waits up to 20 minutes
#       after setup verification for that to happen; if the operator
#       has not completed it within 20 minutes of VM creation, the
#       --resume invocation marks the batch INVALID and terminates
#       the VM (the VM-side sequence may have started before the
#       controller was verified).
#   run_batch.sh vm
#       VM-side driver (run as root on the VM by the cloud-init
#       bootstrap). Performs vm_setup (packages, users, cgroup,
#       iptables, proxy, results server, watchdogs, HMAC secret),
#       runs the 20 setup-verification checks (Sec. 7.4), drives
#       O1-O11 in order through the Sec. 4.2 sandbox command (O12
#       and O13 are host-side and are recorded by the host mode),
#       and performs the VM-side teardown (Sec. 11.2 steps 1-6).
#       The VM mode never contacts the host and never executes
#       anything downloaded from the VM - it only writes results.
#       In a dry-run (DRYRUN_VM=1, set by mock_vm.sh) it runs the
#       dry-run branches: vm_setup_dryrun (no packages, no iptables,
#       no loopback image, no systemd - the fake cgroup / fake /etc /
#       fake /tmp are already in place from the mock VM), the
#       20-check subset vm_setup_verify_dryrun, the 120 s per-case
#       timeout, and the O9 dry-run branch (90 s timeout, the
#       systemd-watchdog sub-check skipped with its reason recorded).
#   run_batch.sh dryrun --batch-dir DIR
#       Local dry-run driver (Revision 8, spec rule 29; Revision 9
#       rules 31-34). Runs the
#       FULL lifecycle locally with NO VM and NO cloud change: it
#       sets up the mock OCI state, runs host_main invocation 1
#       (H0-H6, which starts the mock VM), performs the mock
#       operator step (writes controller_verified with the exact
#       mock terminate command), runs host_main --resume
#       (invocation 2, H7-H12 to verdict), waits for the mock VM
#       to finish, and writes the evidence log to
#       o_tests_v13/dry_run_evidence.log. The dry-run deadlines are
#       compressed (timer 8 min, controller 9 min, poller 10 min,
#       DONE wait 7 min, poll interval 5 s) and every bound that
#       differs from the real run is recorded in the evidence log
#       and in the proposal (Sec. 11.5) - a mock run proves the
#       runner's logic, the poller's 3-query liveness window, the
#       trap, the HMAC-before-use flow and the download bounds; it
#       does NOT prove a real VM boots, a real cgroup enforces, or
#       real OCI accepts the calls. Only a real VM run proves those.
#       The dry-run reports TWO outcomes (rule 34): lifecycle_verdict
#       (orchestration) and security_verdict (the rule-31 gate over
#       the VM's O1-O11 evidence). The overall dry-run verdict is
#       PASS only if BOTH are PASS; in practice the main dry-run is
#       INCONCLUSIVE (mock cases O3/O5-O9 are INCONCLUSIVE-by-design)
#       with lifecycle PASS - and the evidence log says so plainly.
#   run_batch.sh dryrun-regressions --batch-dir DIR
#       Regression dry-runs (Revision 9, spec rule 34). Runs the main
#       dry-run plus four injected-defect dry-runs, each in its own
#       subdir with its own evidence log: (a) DRYRUN_INJECT_FAIL=o07
#       (a security test forced FAIL), (b)
#       DRYRUN_INJECT_INCONCLUSIVE=o05 (a security test forced
#       INCONCLUSIVE), (c) DRYRUN_INJECT_BATCH_ID_MISMATCH=1 (the VM
#       writes a tampered batch_id into batch.json, HMAC still valid).
#       Each regression must NOT produce an overall PASS; the driver
#       verifies the verdict files and prints a summary table. Exit 0
#       only if the main run behaves as expected (lifecycle PASS,
#       security INCONCLUSIVE) and all three regressions block PASS.
#       A fourth check runs the host with a mismatched BATCH_ID env
#       var against the main run's batch dir and requires exit 1.
#
# Required environment (host mode):
#   REPO_URL            Public git URL of the benchmark repo. The repo
#                       must contain o_tests_v13/ (the scripts + the
#                       manifest) and egress-proxy.py at its root.
#                       The repo does not exist yet - the operator
#                       supplies its URL when it is created. This
#                       script never guesses a URL.
#   COMMIT              Full 40-hex commit to run (recorded in the
#                       batch manifest; the clone is verified against
#                       it byte-for-byte).
#   HOST_EGRESS_IP      The host's public egress IP (no /32 suffix).
#                       The results endpoint is host-IP-only; if it
#                       cannot be determined, the batch does not start.
#   CONTROLLER_JOB_ID   The Muse cron job ID of the external
#                       controller (created by the operator BEFORE the
#                       VM, per Sec. 11.1 step 3).
#   EXPECTED_TERMINATE_COMMAND
#                       The exact terminate command the controller runs:
#                       oci compute instance terminate --instance-id
#                       <INSTANCE_OCID> --force --preserve-boot-volume
#                       false (with the real OCID, after creation).
#   WATCHDOG_RUN_RECORD Path (on the host) where the controller writes
#                       its JSON run record (Sec. 11.4).
# Optional (host mode):
#   HMAC_SECRET_FILE    Path to the host's per-batch secret file. If
#                       unset, the runner generates one (32 random
#                       bytes, hex, mode 600) in the batch dir.
#   TEST_MODE           1 (default): test deadlines (VM timer 90 min,
#                       controller 120 min, poller 150 min, DONE 85
#                       min). 0: production deadlines (24 h / 24 h /
#                       25 h / 23 h).
#   OCI_CLI             OCI CLI to use (default: oci).
#   M8_DIR              The m8 directory (default: derived from this
#                       script's location - the host runs it from the
#                       m8/o_tests_v13/ tree).
#
# Required environment (vm mode; written by the bootstrap to
# /opt/harness/batch.env, mode 600, root-only):
#   BATCH_ID, REPO_URL, COMMIT, TIMER_MINUTES, HMAC_SECRET (hex).
# The vm mode reads nothing else from the environment.
#
# Exit codes (both modes): 0 = batch verdict PASS (host) / all cases
# PASS (vm); 1 = a test FAILed; 2 = INCONCLUSIVE or INVALID or a
# harness error; 3 = controller checkpoint (host only - the operator
# must update + verify the controller cron, then re-run with
# --resume). A timeout or an inconclusive result is a failure, never
# a pass.
#
# What this runner does NOT do: it does not create the controller
# cron job (the operator does, via the Muse cron API); it does not
# write the controller's run record (the controller does); it does
# not execute any file downloaded from the VM; it does not run a
# benchmark case (only the O1-O13 isolation tests, with synthetic
# human-reviewed scripts); it does not weaken any limit to pass.
set -u

# ------------------------------------------------------------------
# Common helpers
# ------------------------------------------------------------------

# log MSG - timestamped line to stdout (and, once BATCH_RECORD is
# set, appended to the batch record as well).
log() {
    _ts=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown-time)
    printf '%s %s\n' "$_ts" "$1"
    if [ -n "${BATCH_RECORD:-}" ]; then
        printf '%s %s\n' "$_ts" "$1" >> "$BATCH_RECORD" 2>/dev/null || true
    fi
}

# die CODE MSG - log and exit.
die() {
    _code=$1; shift
    log "RUNNER_FATAL $*"
    exit "$_code"
}

# require_var NAME - fail closed (exit 2) if the variable is unset/empty.
require_var() {
    eval "_v=\${$1:-}"
    if [ -z "$_v" ]; then
        die 2 "required variable unset: $1"
    fi
}

# require_tool NAME - fail closed (exit 2) if the tool is missing.
require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        die 2 "required tool missing: $1"
    fi
}

# phase_done NAME / phase_mark NAME - marker files in BATCH_DIR
# recording that a host phase completed. --resume skips completed
# phases. A marker is written only after the phase's own
# verification succeeded.
phase_done() {
    [ -f "$BATCH_DIR/$1.done" ]
}
phase_mark() {
    printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown-time)" > "$BATCH_DIR/$1.done"
}

# record_event KEY=VALUE - one line in the batch record (via log).
record_event() {
    log "RUNNER $1"
}

# iso_now - current UTC time in ISO 8601.
iso_now() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}

# epoch_of ISO - seconds since epoch (UTC); empty on failure.
epoch_of() {
    date -u -d "$1" +%s 2>/dev/null || echo ""
}

# ------------------------------------------------------------------
# Dry-run mode (Revision 8, spec rule 29)
# ------------------------------------------------------------------

# dryrun_main --batch-dir DIR - the local dry-run driver. Runs the
# FULL lifecycle locally with NO VM and NO cloud change: it sets up
# the mock OCI state, runs host_main invocation 1 (H0-H6, which
# starts the mock VM and stops at the controller checkpoint, exit
# 3), performs the mock operator step (writes controller_verified
# with the exact mock terminate command), runs host_main --resume
# (invocation 2, H7-H12 to verdict), waits for the mock VM to
# finish (its controller step runs after the VM driver exits), and
# writes the evidence log to o_tests_v13/dry_run_evidence.log.
# The batch dir is a scratch dir: it is removed and recreated.
# Exit: invocation 2's exit code (0 = PASS, 1 = FAIL, 2 =
# INCONCLUSIVE/INVALID). The evidence log is written even on
# failure, so a failed dry-run is still recorded.
dryrun_main() {
    BATCH_DIR=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --batch-dir) BATCH_DIR=$2; shift 2 ;;
            *) die 2 "dryrun: unknown argument: $1" ;;
        esac
    done
    [ -n "$BATCH_DIR" ] || die 2 "dryrun: --batch-dir is required"
    rm -rf "$BATCH_DIR"
    mkdir -p "$BATCH_DIR" || die 2 "cannot create batch dir: $BATCH_DIR"
    BATCH_RECORD="$BATCH_DIR/batch_record.txt"
    touch "$BATCH_RECORD" || die 2 "cannot write batch record: $BATCH_RECORD"
    SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    M8_DIR=${M8_DIR:-$(dirname "$SCRIPT_DIR")}
    [ -f "$M8_DIR/step0_verify_freeze.py" ] || die 2 "M8_DIR does not contain step0_verify_freeze.py: $M8_DIR"
    [ -f "$M8_DIR/o_tests_v13/o_tests_manifest.json" ] || die 2 "M8_DIR does not contain o_tests_v13/o_tests_manifest.json"
    [ -f "$M8_DIR/o_tests_v13/mock_oci.sh" ] || die 2 "M8_DIR does not contain o_tests_v13/mock_oci.sh"
    [ -f "$M8_DIR/o_tests_v13/mock_vm.sh" ] || die 2 "M8_DIR does not contain o_tests_v13/mock_vm.sh"
    # Dry-run environment (exported to both host invocations).
    export DRYRUN=1
    export MOCK_OCI_STATE="$BATCH_DIR/mock_oci_state"
    mkdir -p "$MOCK_OCI_STATE" || die 2 "cannot create mock OCI state dir"
    printf '{}\n' > "$MOCK_OCI_STATE/network.json"
    printf '{"creation_time":""}\n' > "$MOCK_OCI_STATE/batch.json"
    export OCI_CLI="$M8_DIR/o_tests_v13/mock_oci.sh"
    export REPO_URL="dry-run:local-tree"
    # COMMIT is the first 40 hex characters of the local manifest
    # SHA-256 (there is no git repo in a dry-run).
    export COMMIT=$(sha256sum "$M8_DIR/o_tests_v13/o_tests_manifest.json" | awk '{print $1}' | cut -c1-40)
    export HOST_EGRESS_IP="127.0.0.1"
    export CONTROLLER_JOB_ID="dryrun-controller"
    export WATCHDOG_RUN_RECORD="$BATCH_DIR/mock_controller_run_record.json"
    export DRYRUN_TIMER_MINUTES=8 DRYRUN_CONTROLLER_MINUTES=9 DRYRUN_POLLER_MINUTES=10 DRYRUN_DONE_MINUTES=7
    # Regression injection (Revision 9, spec rule 34; Revision 10,
    # spec rules 35-36; Revision 11, spec rules 37-39): inherited from the dryrun-regressions
    # driver (or set by the operator when invoking dryrun directly).
    # DRYRUN_INJECT_FAIL=<case> forces one case's recorded outcome
    # to FAIL; DRYRUN_INJECT_INCONCLUSIVE=<case> forces
    # INCONCLUSIVE; DRYRUN_INJECT_BATCH_ID_MISMATCH=1 makes the VM
    # write a tampered batch_id into its manifest; DRYRUN_INJECT_
    # ALL_PASS=1 forces EVERY case's recorded outcome to PASS, so
    # the full PASS path (overall PASS, exit 0, verdict.done
    # written, resume replaying exit 0) can be exercised. All four
    # are dry-run-only and are recorded in the evidence log.
    export DRYRUN_INJECT_FAIL=${DRYRUN_INJECT_FAIL:-}
    export DRYRUN_INJECT_INCONCLUSIVE=${DRYRUN_INJECT_INCONCLUSIVE:-}
    export DRYRUN_INJECT_BATCH_ID_MISMATCH=${DRYRUN_INJECT_BATCH_ID_MISMATCH:-0}
    export DRYRUN_INJECT_ALL_PASS=${DRYRUN_INJECT_ALL_PASS:-0}
    export M8_DIR
    log "DRYRUN start batch_dir=$BATCH_DIR commit_is_manifest_prefix=$COMMIT timer=8 controller=9 poller=10 done=7"
    # The controller_verified placeholder (job_id + run_record +
    # a placeholder command - no instance OCID yet). The mock
    # operator step replaces the command with the exact one after
    # invocation 1 creates the mock instance.
    printf 'job_id=%s\ncommand=%s\nrun_record=%s\n' "$CONTROLLER_JOB_ID" "oci compute instance terminate --instance-id PLACEHOLDER --force --preserve-boot-volume false" "$WATCHDOG_RUN_RECORD" > "$BATCH_DIR/controller_verified"
    # Invocation 1 (H0-H6): freeze, snapshot, repo, preflight,
    # secret, network, controller checkpoint, mock VM create.
    # Stops at the controller checkpoint (exit 3).
    "$0" host --batch-dir "$BATCH_DIR" > "$BATCH_DIR/invocation1.log" 2>&1
    _rc1=$?
    cat "$BATCH_DIR/invocation1.log" >> "$BATCH_DIR/batch_record.txt" 2>/dev/null || true
    if [ "$_rc1" -ne 3 ]; then
        log "DRYRUN invocation 1 exited $_rc1 (want 3) - dry-run FAILED (see invocation1.log)"
        dryrun_write_evidence "$BATCH_DIR" "invocation1_failed"
        exit 1
    fi
    log "DRYRUN invocation 1 done (exit 3, controller checkpoint)"
    # Mock operator step: read the mock instance OCID and write
    # the EXACT terminate command into controller_verified (the
    # same step the operator performs with cron.list in the real
    # flow, here simulated with the mock OCID).
    _inst=$(cat "$BATCH_DIR/instance_ocid.txt" 2>/dev/null || echo "")
    [ -n "$_inst" ] || { log "DRYRUN no instance OCID after invocation 1"; dryrun_write_evidence "$BATCH_DIR" "no_instance_ocid"; exit 1; }
    printf 'job_id=%s\ncommand=oci compute instance terminate --instance-id %s --force --preserve-boot-volume false\nrun_record=%s\n' "$CONTROLLER_JOB_ID" "$_inst" "$WATCHDOG_RUN_RECORD" > "$BATCH_DIR/controller_verified"
    log "DRYRUN mock operator step done (controller_verified updated with the real OCID $_inst)"
    # Invocation 2 (H7-H12): controller verify, poller, DONE wait,
    # download, verify+terminate+o13, verdict.
    "$0" host --batch-dir "$BATCH_DIR" --resume > "$BATCH_DIR/invocation2.log" 2>&1
    _rc2=$?
    cat "$BATCH_DIR/invocation2.log" >> "$BATCH_DIR/batch_record.txt" 2>/dev/null || true
    log "DRYRUN invocation 2 done (exit $_rc2)"
    # Revision 9 (rule 34): the main dry-run's EXPECTED outcome is
    # exit 2 with lifecycle PASS and security INCONCLUSIVE - the mock
    # VM cannot exercise the real controls (O3/O5-O9 INCONCLUSIVE),
    # so the closed gate must refuse an overall PASS. An overall PASS
    # here would mean the V8 fail-open defect is still present.
    _v=$(cat "$BATCH_DIR/verdict.txt" 2>/dev/null || echo "")
    _lv=$(printf '%s\n' "$_v" | sed -n 's/^lifecycle_verdict=//p')
    _sv=$(printf '%s\n' "$_v" | sed -n 's/^security_verdict=//p')
    _ov=$(printf '%s\n' "$_v" | sed -n 's/^verdict=//p')
    # (V11) The expected outcome depends on the injection: the
    # all-pass run expects PASS/PASS/PASS, the FAIL and batch_id
    # runs expect FAIL, the INCONCLUSIVE run and the plain main run
    # expect INCONCLUSIVE. The old line stated the plain-main
    # expectation unconditionally, so it was wrong for the all-pass
    # run (V10 open item 6, cosmetic).
    if [ "${DRYRUN_INJECT_ALL_PASS:-0}" = "1" ]; then
        _exp="expected: overall=PASS lifecycle=PASS security=PASS (all-pass injection)"
    elif [ -n "${DRYRUN_INJECT_FAIL:-}" ] || [ "${DRYRUN_INJECT_BATCH_ID_MISMATCH:-0}" = "1" ]; then
        _exp="expected: overall=FAIL lifecycle=PASS security=FAIL (injected defect)"
    else
        _exp="expected: overall=INCONCLUSIVE lifecycle=PASS security=INCONCLUSIVE"
    fi
    log "DRYRUN main-run outcomes: overall=$_ov lifecycle=$_lv security=$_sv ($_exp)"
    # Wait for the mock VM to finish (its controller step runs
    # after the VM driver exits; the mock VM exits after the
    # controller writes its run record).
    _mock_pid=$(cat "$BATCH_DIR/mock_vm.pid" 2>/dev/null || echo "")
    if [ -n "$_mock_pid" ]; then
        _waited=0
        while kill -0 "$_mock_pid" 2>/dev/null && [ "$_waited" -lt 600 ]; do
            sleep 5
            _waited=$((_waited + 5))
        done
        if kill -0 "$_mock_pid" 2>/dev/null; then
            log "DRYRUN mock VM still running after 600 s - killing it"
            kill "$_mock_pid" 2>/dev/null || true
            sleep 2
            kill -9 "$_mock_pid" 2>/dev/null || true
        else
            log "DRYRUN mock VM finished after ${_waited}s"
        fi
    fi
    # Orphan backstop: kill any leftover mock VM processes (the
    # O7 fork-bomb children sleep 600 s; the mock VM's cleanup
    # should have killed them, but do not leave them behind).
    pkill -KILL -u 1001 2>/dev/null || true
    pkill -KILL -u 1002 -f egress-proxy.py 2>/dev/null || true
    pkill -KILL -u 1000 -f results_server.py 2>/dev/null || true
    # Remove the proxy/results log files created on the host's real
    # /var/log by the mock VM (they are host-side artefacts of the
    # dry-run, not batch evidence - the batch evidence is in the
    # batch dir).
    rm -f /var/log/m8-proxy.log /var/log/m8-proxy.out /var/log/m8-results.out
    dryrun_write_evidence "$BATCH_DIR" "invocation2_exit=$_rc2"
    log "DRYRUN done (invocation 2 exit $_rc2)"
    exit "$_rc2"
}

# dryrun_write_evidence BATCH_DIR TAG - assemble the dry-run
# evidence log (the deliverable) from the batch record + the key
# files, with a header stating the dry-run parameters, the bounds
# that differ from a real run, and what the mock proves vs what
# only a real VM run can prove. Written to
# o_tests_v13/dry_run_evidence.log (and a copy in the batch dir).
dryrun_write_evidence() {
    _bd=$1; _tag=$2
    _ev="$M8_DIR/o_tests_v13/dry_run_evidence.log"
    {
        printf 'M8 DRY-RUN EVIDENCE LOG (Revision 12, spec rules 29-42)\n'
        printf 'generated: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'tag: %s\n' "$_tag"
        printf 'batch_dir: %s\n' "$_bd"
        printf 'commit (manifest SHA-256 prefix): %s\n' "$COMMIT"
        printf 'deadlines (minutes): timer=%s controller=%s poller=%s done=%s\n' "$DRYRUN_TIMER_MINUTES" "$DRYRUN_CONTROLLER_MINUTES" "$DRYRUN_POLLER_MINUTES" "$DRYRUN_DONE_MINUTES"
        printf 'mock oci: %s\n' "$OCI_CLI"
        printf 'mock vm: %s\n' "$M8_DIR/o_tests_v13/mock_vm.sh"
        printf '\n'
        printf 'WHAT THIS DRY-RUN PROVES (mock, local, $0):\n'
        printf '  - the runner logic: host H0-H12 in order, the two-invocation\n'
        printf '    split at the controller checkpoint (exit 3), the H12 reorder\n'
        printf '    (network deleted BEFORE o13; o13 BEFORE host_terminate_vm;\n'
        printf '    host_terminate_vm conditional on not-TERMINATED).\n'
        printf '  - the poller: 3 successful post-TERMINATED liveness queries\n'
        printf '    before exit 0 (blocker 1), and the o13 (e4b) three-observation\n'
        printf '    check against the poller log.\n'
        printf '  - the O5 whole-sequence cleanup trap (setup/pre/workload/post\n'
        printf '    in a subshell with trap ... EXIT).\n'
        printf '  - the HMAC-before-use flow (secret generated, copied to the\n'
        printf '    mock VM, used to HMAC the results, verified on download).\n'
        printf '  - the download bounds (10 MB per file, MAX_CASES 50, 256 MiB\n'
        printf '    aggregate) via the o11 download.\n'
        printf '  - the O-test scripts execute (each case produces a result\n'
        printf '    line + manifest) under the Sec. 4.2 sandbox command.\n'
        printf '  - the CLOSED verdict gate (rule 31): the host verdict\n'
        printf '    authenticates the VM batch manifest (HMAC) and requires\n'
        printf '    the VM verdict exactly PASS + every mandatory O1-O11 case\n'
        printf '    explicit PASS + the manifest batch_id equal to the\n'
        printf '    persisted BATCH_ID. A VM-side FAIL or INCONCLUSIVE can\n'
        printf '    no longer produce an overall PASS.\n'
        printf '  - stable batch identity (rule 33): one BATCH_ID persisted\n'
        printf '    in batch_id.txt, reused by both host invocations and\n'
        printf '    written into the VM manifest.\n'
        printf '\n'
        printf 'SPLIT OUTCOMES (rule 34): the verdict file reports\n'
        printf 'lifecycle_verdict (orchestration) and security_verdict (the\n'
        printf 'rule-31 gate over the VM O1-O11 evidence) separately. The\n'
        printf 'overall verdict is PASS only if BOTH are PASS. This main\n'
        printf 'run is EXPECTED to be overall INCONCLUSIVE with lifecycle\n'
        printf 'PASS and security INCONCLUSIVE - the mock cannot exercise\n'
        printf 'the real controls, so an overall PASS here would be the\n'
        printf 'V8 fail-open defect. See dryrun-regressions for the four\n'
        printf 'injected-defect runs that prove the gate blocks PASS,\n'
        printf 'plus the verdict-replay runs (rule 35) and the\n'
        printf 'batch-identity runs (rule 36).\n'
        if [ "${DRYRUN_INJECT_ALL_PASS:-0}" = "1" ]; then
            printf 'ALL-PASS RUN: DRYRUN_INJECT_ALL_PASS=1 forced every\n'
            printf 'case outcome to PASS at the recording layer, so this\n'
            printf 'run is EXPECTED to be overall PASS (exit 0) with\n'
            printf 'verdict.done written. It exercises the full PASS path\n'
            printf 'and the verdict replay on resume. It does NOT prove\n'
            printf 'the real controls - the mock still cannot exercise\n'
            printf 'them; the outcomes are forced, not measured.\n'
        fi
        printf '\n'
        printf 'WHAT IT DOES NOT PROVE (only a real VM run can):\n'
        printf '  - a real A1 VM boots, cloud-init runs, and the real OCI API\n'
        printf '    accepts the calls (the mock returns recorded shapes).\n'
        printf '  - a real cgroup v2 enforces memory.max / pids.max / cpu.max\n'
        printf '    (the fake cgroup is static fixture text; O6/O7/O9 outcomes\n'
        printf '    are INCONCLUSIVE-by-design in the dry-run, not passes).\n'
        printf '  - real iptables UID rules + the metadata DROP (no iptables\n'
        printf '    in the mock VM; O2/O3/O5 network outcomes are bounded by\n'
        printf '    the proxy only).\n'
        printf '  - the systemd watchdog kill (no systemd in the mock VM;\n'
        printf '    O9 sub-check 2 is DRYRUN_SKIP).\n'
        printf '  - the 20 GB loopback workdir + io.max throttling (no\n'
        printf '    /dev/loop* on this host; O8 is INCONCLUSIVE-by-design).\n'
        printf '  - the VM-side timer powering off a real VM, or the real\n'
        printf '    Muse cron controller terminating a real instance.\n'
        printf '\n'
        printf 'DRY-RUN BOUNDS (differ from the real run):\n'
        printf '  - per-case timeout 120 s (real 600 s; O8 900 s); O9 sub-check 1\n'
        printf '    timeout 90 s (real 600 s).\n'
        printf '  - O6 RLIMIT_AS 192 MB (ulimit, not a cgroup); O7 RLIMIT_NPROC 600.\n'
        printf '  - O8 disk guard: the fill is killed at 256 MiB of /work.\n'
        printf '  - poll interval 5 s (real 30 s); DONE poll 5 s (real 60 s).\n'
        printf '  - vm_run_cases records ALL cases (does not stop at the first\n'
        printf '    non-PASS, so every case is exercised).\n'
        printf '  - setup checks 1, 2, 4, 6, 8, 11 are DRYRUN_SKIP; check 5 is\n'
        printf '    deferred; check 12 is partial (/proc/1/root skipped).\n'
        printf '\n'
        printf '=== BATCH RECORD ===\n'
        cat "$_bd/batch_record.txt" 2>/dev/null || printf '(no batch record)\n'
        printf '\n=== VERDICT ===\n'
        cat "$_bd/verdict.txt" 2>/dev/null || printf '(no verdict file)\n'
        printf '\n=== VM BATCH MANIFEST (downloaded results/batch.json) ===\n'
        cat "$_bd/results/batch.json" 2>/dev/null || printf '(no downloaded batch.json)\n'
        printf '\n=== O13 LOG ===\n'
        cat "$_bd/o13.log" 2>/dev/null || printf '(no o13 log)\n'
        printf '\n=== O11 HOST LOG ===\n'
        cat "$_bd/o11_host.log" 2>/dev/null || printf '(no o11 host log)\n'
        printf '\n=== O12 VERIFY LOG ===\n'
        cat "$_bd/o12_verify.log" 2>/dev/null || printf '(no o12 verify log)\n'
        printf '\n=== DOWNLOAD LOG ===\n'
        cat "$_bd/download.log" 2>/dev/null || printf '(no download log)\n'
        printf '\n=== POLLER LOG (instance_state.log) ===\n'
        cat "$_bd/instance_state.log" 2>/dev/null || printf '(no instance state log)\n'
        printf '\n=== POLLER OUT ===\n'
        cat "$_bd/poller.out" 2>/dev/null || printf '(no poller out)\n'
        printf '\n=== CASE RESULTS ===\n'
        cat "$_bd/results/case_results.txt" 2>/dev/null || printf '(no case results)\n'
        printf '\n=== MOCK VM LOG ===\n'
        cat "$_bd/mock_vm.log" 2>/dev/null || printf '(no mock VM log)\n'
        printf '\n=== MOCK CONTROLLER RUN RECORD ===\n'
        cat "$_bd/mock_controller_run_record.json" 2>/dev/null || printf '(no controller run record)\n'
        printf '\n=== VM DRIVER LOG (last 100 lines) ===\n'
        tail -n 100 "$_bd/mock_vm/vm_driver.log" 2>/dev/null || printf '(no VM driver log)\n'
    } > "$_ev" 2>&1 || { log "DRYRUN cannot write evidence log $_ev"; return 1; }
    cp "$_ev" "$_bd/dry_run_evidence.log" 2>/dev/null || true
    log "DRYRUN evidence log written: $_ev ($(wc -c < "$_ev") bytes)"
    return 0
}

# ------------------------------------------------------------------
# Regression dry-runs (Revision 9, spec rule 34)
# ------------------------------------------------------------------

# dryrun_regressions --batch-dir DIR - run the main dry-run plus
# four injected-defect dry-runs, each in its own subdir with its own
# evidence log, and verify the verdict gate blocks an overall PASS in
# the three negative regressions and that the all-pass run reaches
# PASS. Also verifies the verdict replay (rule 35: re-invoking the
# host against a completed batch dir replays the stored verdict) and
# the batch_id_resolve path (rule 36: a mismatched BATCH_ID env var,
# and a missing/empty batch_id.txt in a dir with phase markers, are
# rejected). Exit 0 only if every run behaves as expected; otherwise
# exit 1 with the failing checks listed in the summary. Each run
# takes ~10 minutes (the compressed dry-run deadlines), so the full
# set takes ~50-60 minutes. $0 cost, no VM, no cloud change.
dryrun_regressions() {
    _base=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --batch-dir) _base=$2; shift 2 ;;
            *) die 2 "dryrun-regressions: unknown argument: $1" ;;
        esac
    done
    [ -n "$_base" ] || die 2 "dryrun-regressions: --batch-dir is required"
    mkdir -p "$_base" || die 2 "cannot create batch dir: $_base"
    SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    M8_DIR=${M8_DIR:-$(dirname "$SCRIPT_DIR")}
    _summary="$_base/regressions_summary.txt"
    : > "$_summary" || die 2 "cannot write summary: $_summary"
    log "REGRESSIONS start base=$_base (main + 4 injected-defect runs)"
    _failures=0
    # _run_one NAME VAR=VALUE... - one dry-run with the given
    # injection env vars; preserves its evidence log under a distinct
    # name and records its exit code. The fixed-path evidence log is
    # overwritten by each run, so it is copied immediately.
    _run_one() {
        _name=$1; shift
        _dir="$_base/$_name"
        log "REGRESSIONS run=$_name dir=$_dir"
        env "$@" "$0" dryrun --batch-dir "$_dir" > "$_base/$_name.driver.log" 2>&1
        _rc=$?
        cp "$M8_DIR/o_tests_v13/dry_run_evidence.log" "$M8_DIR/o_tests_v13/dry_run_evidence_$_name.log" 2>/dev/null || true
        cp "$M8_DIR/o_tests_v13/dry_run_evidence.log" "$_base/$_name.evidence.log" 2>/dev/null || true
        printf '%s exit=%s\n' "$_name" "$_rc" >> "$_summary"
        log "REGRESSIONS run=$_name done (exit $_rc)"
        return 0
    }
    # _expect FILE KEY VALUE - one verdict-file expectation; records
    # PASS/FAIL in the summary and counts failures.
    _expect() {
        _f=$1; _k=$2; _want=$3; _label=$4
        _got=$(sed -n "s/^$_k=//p" "$_f" 2>/dev/null | head -1)
        if [ "$_got" = "$_want" ]; then
            printf 'EXPECT-PASS %s: %s=%s\n' "$_label" "$_k" "$_got" >> "$_summary"
        else
            printf 'EXPECT-FAIL %s: %s=%s (want %s)\n' "$_label" "$_k" "$_got" "$_want" >> "$_summary"
            _failures=$((_failures + 1))
        fi
    }
    _expect_contains() {
        _f=$1; _k=$2; _want=$3; _label=$4
        _got=$(sed -n "s/^$_k=//p" "$_f" 2>/dev/null | head -1)
        case "$_got" in
            *"$_want"*) printf 'EXPECT-PASS %s: %s contains %s\n' "$_label" "$_k" "$_want" >> "$_summary" ;;
            *) printf 'EXPECT-FAIL %s: %s=%s (want it to contain %s)\n' "$_label" "$_k" "$_got" "$_want" >> "$_summary"
               _failures=$((_failures + 1)) ;;
        esac
    }
    _expect_file_exists() {
        _f=$1; _label=$2
        if [ -f "$_f" ]; then
            printf 'EXPECT-PASS %s: file exists: %s\n' "$_label" "$_f" >> "$_summary"
        else
            printf 'EXPECT-FAIL %s: file missing: %s\n' "$_label" "$_f" >> "$_summary"
            _failures=$((_failures + 1))
        fi
    }
    _expect_file_absent() {
        _f=$1; _label=$2
        if [ ! -e "$_f" ]; then
            printf 'EXPECT-PASS %s: file absent: %s\n' "$_label" "$_f" >> "$_summary"
        else
            printf 'EXPECT-FAIL %s: file present but must be absent: %s\n' "$_label" "$_f" >> "$_summary"
            _failures=$((_failures + 1))
        fi
    }
    _run_one main
    _run_one regression_fail DRYRUN_INJECT_FAIL=o07
    _run_one regression_inconclusive DRYRUN_INJECT_INCONCLUSIVE=o05
    _run_one regression_batch_id DRYRUN_INJECT_BATCH_ID_MISMATCH=1
    _run_one regression_allpass DRYRUN_INJECT_ALL_PASS=1
    # Expectations. Main run: overall INCONCLUSIVE (mock cannot prove
    # the real controls), lifecycle PASS, security INCONCLUSIVE.
    _expect "$_base/main/verdict.txt" verdict INCONCLUSIVE main-overall
    _expect "$_base/main/verdict.txt" lifecycle_verdict PASS main-lifecycle
    _expect "$_base/main/verdict.txt" security_verdict INCONCLUSIVE main-security
    _expect "$_base/main/verdict.txt" vm_gate INCONCLUSIVE main-vm-gate
    # Regression (a): an injected FAIL must produce overall FAIL, the
    # gate must report FAIL with the failing case recorded, and the
    # lifecycle must still PASS (the orchestration itself worked).
    _expect "$_base/regression_fail/verdict.txt" verdict FAIL regression-fail-overall
    _expect "$_base/regression_fail/verdict.txt" vm_gate FAIL regression-fail-gate
    _expect "$_base/regression_fail/verdict.txt" lifecycle_verdict PASS regression-fail-lifecycle
    _expect_contains "$_base/regression_fail/verdict.txt" vm_cases "o07=FAIL" regression-fail-case
    # Regression (b): an injected INCONCLUSIVE must not produce PASS.
    _expect "$_base/regression_inconclusive/verdict.txt" verdict INCONCLUSIVE regression-inconclusive-overall
    _expect "$_base/regression_inconclusive/verdict.txt" vm_gate INCONCLUSIVE regression-inconclusive-gate
    _expect "$_base/regression_inconclusive/verdict.txt" lifecycle_verdict PASS regression-inconclusive-lifecycle
    _expect_contains "$_base/regression_inconclusive/verdict.txt" vm_cases "o05=INCONCLUSIVE" regression-inconclusive-case
    # Regression (c): a tampered batch_id (HMAC still valid) must be
    # rejected by value comparison - overall FAIL, gate FAIL with the
    # batch_id_mismatch reason, lifecycle still PASS.
    _expect "$_base/regression_batch_id/verdict.txt" verdict FAIL regression-batch-id-overall
    _expect "$_base/regression_batch_id/verdict.txt" vm_gate FAIL regression-batch-id-gate
    _expect "$_base/regression_batch_id/verdict.txt" vm_gate_reason batch_id_mismatch regression-batch-id-reason
    _expect "$_base/regression_batch_id/verdict.txt" lifecycle_verdict PASS regression-batch-id-lifecycle
    # Regression (d): the all-pass run forces every case to PASS at
    # the recording layer, so the full PASS path must work: overall
    # PASS, gate PASS, lifecycle PASS, security PASS, exit 0, and
    # the verdict.done marker written (it is written ONLY on PASS,
    # rule 35). This is the one run where an overall PASS is the
    # expected outcome - it proves the gate can pass a batch, not
    # only block one.
    _expect "$_base/regression_allpass/verdict.txt" verdict PASS regression-allpass-overall
    _expect "$_base/regression_allpass/verdict.txt" vm_gate PASS regression-allpass-gate
    _expect "$_base/regression_allpass/verdict.txt" lifecycle_verdict PASS regression-allpass-lifecycle
    _expect "$_base/regression_allpass/verdict.txt" security_verdict PASS regression-allpass-security
    _expect "$_base/regression_allpass/verdict.txt" exit 0 regression-allpass-exit
    _expect_file_exists "$_base/regression_allpass/verdict.done" regression-allpass-marker
    # The other runs must NOT have a verdict.done marker: their
    # verdicts are not PASS, so the phase was not successful.
    _expect_file_absent "$_base/main/verdict.done" main-no-marker
    _expect_file_absent "$_base/regression_fail/verdict.done" regression-fail-no-marker
    _expect_file_absent "$_base/regression_inconclusive/verdict.done" regression-inconclusive-no-marker
    _expect_file_absent "$_base/regression_batch_id/verdict.done" regression-batch-id-no-marker
    # Fourth check: the resolve path. Running the host with a
    # mismatched BATCH_ID env var against the main run's batch dir
    # must exit 1 with a batch_id mismatch error, before any phase.
    # The check runs with the same dry-run environment the host
    # invocations get (mock OCI + the required vars), so it reaches
    # batch_id_resolve instead of dying at the tool check: the plain
    # invocation died exit 2 "required tool missing: oci" (2026-11-26
    # re-run), because the real oci CLI is not on PATH on the
    # coordinator. That was a driver bug, not a runner bug - the
    # resolve path itself was never reached.
    DRYRUN=1 \
    OCI_CLI="$SCRIPT_DIR/mock_oci.sh" \
    MOCK_OCI_STATE="$_base/main/mock_oci_state" \
    REPO_URL="dry-run:local-tree" \
    COMMIT="$(sha256sum "$SCRIPT_DIR/o_tests_manifest.json" | awk '{print $1}' | cut -c1-40)" \
    HOST_EGRESS_IP="127.0.0.1" \
    CONTROLLER_JOB_ID="dryrun-controller" \
    WATCHDOG_RUN_RECORD="$_base/main/mock_controller_run_record.json" \
    BATCH_ID="wrong-batch-id-for-resolve-check" "$0" host --batch-dir "$_base/main" --resume > "$_base/resolve_mismatch.log" 2>&1
    _rrc=$?
    if [ "$_rrc" -eq 1 ] && grep -q "batch_id mismatch" "$_base/resolve_mismatch.log"; then
        printf 'EXPECT-PASS resolve-mismatch: exit=1 batch_id mismatch reported\n' >> "$_summary"
    else
        printf 'EXPECT-FAIL resolve-mismatch: exit=%s (want 1 with batch_id mismatch)\n' "$_rrc" >> "$_summary"
        _failures=$((_failures + 1))
    fi
    # Verdict replay (rule 35): re-invoking the host against a
    # COMPLETED batch dir must replay the stored verdict, never
    # return 0 for a non-PASS batch. The resume runs use the same
    # dry-run environment as the resolve check above (mock OCI +
    # required vars), with BATCH_ID unset so batch_id_resolve reuses
    # the persisted identity. The mock VM is already dead by then;
    # every earlier phase is skipped via its marker, so the resume
    # reaches host_phase_verdict and replays verdict.txt.
    _resume_check() {
        _rd=$1; _want_rc=$2; _want_v=$3; _label=$4
        env -u BATCH_ID DRYRUN=1 \
        OCI_CLI="$SCRIPT_DIR/mock_oci.sh" \
        MOCK_OCI_STATE="$_rd/mock_oci_state" \
        REPO_URL="dry-run:local-tree" \
        COMMIT="$(sha256sum "$SCRIPT_DIR/o_tests_manifest.json" | awk '{print $1}' | cut -c1-40)" \
        HOST_EGRESS_IP="127.0.0.1" \
        CONTROLLER_JOB_ID="dryrun-controller" \
        WATCHDOG_RUN_RECORD="$_rd/mock_controller_run_record.json" \
        "$0" host --batch-dir "$_rd" --resume > "$_base/$_label.resume.log" 2>&1
        _rrc=$?
        _rv=$(sed -n 's/^verdict=//p' "$_rd/verdict.txt" 2>/dev/null | head -1)
        if [ "$_rrc" -eq "$_want_rc" ] && [ "$_rv" = "$_want_v" ]; then
            printf 'EXPECT-PASS %s: resume exit=%s verdict=%s\n' "$_label" "$_rrc" "$_rv" >> "$_summary"
        else
            printf 'EXPECT-FAIL %s: resume exit=%s (want %s) verdict=%s (want %s)\n' "$_label" "$_rrc" "$_want_rc" "$_rv" "$_want_v" >> "$_summary"
            _failures=$((_failures + 1))
        fi
    }
    _resume_check "$_base/main" 2 INCONCLUSIVE resume-inconclusive
    _resume_check "$_base/regression_fail" 1 FAIL resume-fail
    _resume_check "$_base/regression_allpass" 0 PASS resume-pass
    # The resume must not create a verdict.done marker for a
    # non-PASS batch, and must not delete the one a PASS batch has.
    _expect_file_absent "$_base/main/verdict.done" resume-inconclusive-marker
    _expect_file_absent "$_base/regression_fail/verdict.done" resume-fail-marker
    _expect_file_exists "$_base/regression_allpass/verdict.done" resume-pass-marker
    # Batch identity with existing phase markers (rule 36): a batch
    # dir with completed phase markers but no batch_id.txt must be
    # rejected, with AND without --resume. Same for an empty
    # batch_id.txt. Each case gets a COPY of the main run's batch
    # dir (markers present, verdict INCONCLUSIVE) with the identity
    # removed or emptied.
    _identity_check() {
        _src=$1; _mode=$2; _use_resume=$3; _label=$4
        _id_dir="$_base/$_label"
        rm -rf "$_id_dir"
        cp -r "$_src" "$_id_dir" || { printf 'EXPECT-FAIL %s: cannot copy batch dir\n' "$_label" >> "$_summary"; _failures=$((_failures + 1)); return 0; }
        if [ "$_mode" = "missing" ]; then
            rm -f "$_id_dir/batch_id.txt"
        else
            : > "$_id_dir/batch_id.txt"
        fi
        if [ "$_use_resume" = "resume" ]; then
            _id_args="--resume"
        else
            _id_args=""
        fi
        env -u BATCH_ID DRYRUN=1 \
        OCI_CLI="$SCRIPT_DIR/mock_oci.sh" \
        MOCK_OCI_STATE="$_id_dir/mock_oci_state" \
        REPO_URL="dry-run:local-tree" \
        COMMIT="$(sha256sum "$SCRIPT_DIR/o_tests_manifest.json" | awk '{print $1}' | cut -c1-40)" \
        HOST_EGRESS_IP="127.0.0.1" \
        CONTROLLER_JOB_ID="dryrun-controller" \
        WATCHDOG_RUN_RECORD="$_id_dir/mock_controller_run_record.json" \
        "$0" host --batch-dir "$_id_dir" $_id_args > "$_base/$_label.host.log" 2>&1
        _irc=$?
        if [ "$_irc" -eq 2 ] && grep -q "batch_id" "$_base/$_label.host.log"; then
            printf 'EXPECT-PASS %s: exit=2 batch_id rejected\n' "$_label" >> "$_summary"
        else
            printf 'EXPECT-FAIL %s: exit=%s (want 2 with a batch_id error)\n' "$_label" "$_irc" >> "$_summary"
            _failures=$((_failures + 1))
        fi
    }
    _identity_check "$_base/main" missing resume identity-missing-resume
    _identity_check "$_base/main" missing fresh identity-missing-fresh
    _identity_check "$_base/main" empty resume identity-empty-resume
    _identity_check "$_base/main" empty fresh identity-empty-fresh
    # Gate-precedence checks (V11, rule 38): extract the verdict-gate
    # program verbatim from this file (the python3 heredoc inside
    # host_phase_verdict) and run it against crafted, HMAC-valid
    # manifests. The extraction is verified: the file must be
    # non-empty and contain the MANDATORY list. Each check crafts a
    # batch.json with a chosen overall verdict and case outcomes,
    # signs it with a fresh per-check secret, and asserts the gate
    # value the rule requires. The gate program is run exactly as
    # host_phase_verdict runs it (same four argv: manifest, sidecar,
    # secret file, expected batch_id).
    _gate_py="$_base/gate_program.py"
    awk 'f && /^PYEOF$/{exit} /^    _gate_out=/{f=1;next} f' "$SCRIPT_DIR/run_batch.sh" > "$_gate_py" 2>/dev/null || true
    if [ ! -s "$_gate_py" ] || ! grep -q "MANDATORY" "$_gate_py"; then
        printf 'EXPECT-FAIL gate-extract: cannot extract gate program from run_batch.sh\n' >> "$_summary"
        _failures=$((_failures + 1))
    fi
    _gate_check() {
        _label=$1; _verdict=$2; _cases=$3; _want_gate=$4
        _gd="$_base/gate_$_label"
        mkdir -p "$_gd" || { printf 'EXPECT-FAIL %s: cannot create gate dir\n' "$_label" >> "$_summary"; _failures=$((_failures + 1)); return 0; }
        python3 - "$_gd" "$_verdict" "$_cases" <<'PYEOF'
import hashlib, hmac, json, os, sys
d, verdict, cases = sys.argv[1], sys.argv[2], sys.argv[3]
secret = os.urandom(32)
manifest = {"verdict": verdict, "batch_id": "gate-test-batch", "cases": cases.split()}
data = json.dumps(manifest).encode()
open(os.path.join(d, "batch.json"), "wb").write(data)
open(os.path.join(d, "batch.json.hmac"), "w").write(hmac.new(secret, data, hashlib.sha256).hexdigest())
open(os.path.join(d, "hmac_secret"), "w").write(secret.hex())
PYEOF
        _gout=$(python3 "$_gate_py" "$_gd/batch.json" "$_gd/batch.json.hmac" "$_gd/hmac_secret" "gate-test-batch" 2>/dev/null)
        _ggate=$(printf '%s\n' "$_gout" | sed -n 's/^gate=//p')
        if [ "$_ggate" = "$_want_gate" ]; then
            printf 'EXPECT-PASS %s: gate=%s\n' "$_label" "$_ggate" >> "$_summary"
        else
            printf 'EXPECT-FAIL %s: gate=%s (want %s)\n' "$_label" "$_ggate" "$_want_gate" >> "$_summary"
            _failures=$((_failures + 1))
        fi
    }
    _fail_o03="o01=PASS o02=PASS o03=FAIL o04=PASS o05=PASS o06=PASS o07=PASS o08=PASS o09=PASS o10=PASS o11=PASS"
    _inc_o05="o01=PASS o02=PASS o03=PASS o04=PASS o05=INCONCLUSIVE o06=PASS o07=PASS o08=PASS o09=PASS o10=PASS o11=PASS"
    _gate_check gate-inconclusive-case-fail INCONCLUSIVE "$_fail_o03" FAIL
    _gate_check gate-invalid-case-fail INVALID "$_fail_o03" FAIL
    _gate_check gate-pass-case-fail PASS "$_fail_o03" FAIL
    _gate_check gate-inconclusive-no-fail INCONCLUSIVE "$_inc_o05" INCONCLUSIVE
    # Early-marker-loss replay checks (V11, rule 37): copy a
    # COMPLETED batch dir, remove an EARLY phase marker (freeze.done,
    # H0), and re-invoke the host WITHOUT --resume. The early replay
    # in host_main() must exit with the stored verdict WITHOUT
    # running any phase (no "RUNNER phase=" lines in the log) and
    # WITHOUT any OCI call (mock OCI call count, from
    # mock_oci_state/calls.log, unchanged), and verdict.txt must be
    # byte-identical afterwards. The removed marker must stay absent
    # (no phase re-ran to recreate it). This is the scenario the V10
    # 37/37 regressions did NOT cover: the completed dirs retained
    # their expected state, so replay happened only inside
    # host_phase_verdict() after all phases had already run.
    _early_marker_replay_check() {
        _src=$1; _want_rc=$2; _want_v=$3; _label=$4
        _em_dir="$_base/$_label"
        rm -rf "$_em_dir"
        cp -r "$_src" "$_em_dir" || { printf 'EXPECT-FAIL %s: cannot copy batch dir\n' "$_label" >> "$_summary"; _failures=$((_failures + 1)); return 0; }
        rm -f "$_em_dir/freeze.done"
        _calls_before=$(wc -l < "$_em_dir/mock_oci_state/calls.log" 2>/dev/null || echo 0)
        _calls_before=$(printf '%s' "$_calls_before" | tr -d '[:space:]')
        _verdict_before=$(sha256sum "$_em_dir/verdict.txt" 2>/dev/null | awk '{print $1}')
        env -u BATCH_ID DRYRUN=1 \
        OCI_CLI="$SCRIPT_DIR/mock_oci.sh" \
        MOCK_OCI_STATE="$_em_dir/mock_oci_state" \
        REPO_URL="dry-run:local-tree" \
        COMMIT="$(sha256sum "$SCRIPT_DIR/o_tests_manifest.json" | awk '{print $1}' | cut -c1-40)" \
        HOST_EGRESS_IP="127.0.0.1" \
        CONTROLLER_JOB_ID="dryrun-controller" \
        WATCHDOG_RUN_RECORD="$_em_dir/mock_controller_run_record.json" \
        "$0" host --batch-dir "$_em_dir" > "$_base/$_label.host.log" 2>&1
        _emrc=$?
        _calls_after=$(wc -l < "$_em_dir/mock_oci_state/calls.log" 2>/dev/null || echo 0)
        _calls_after=$(printf '%s' "$_calls_after" | tr -d '[:space:]')
        _verdict_after=$(sha256sum "$_em_dir/verdict.txt" 2>/dev/null | awk '{print $1}')
        _ok=1
        [ "$_emrc" -eq "$_want_rc" ] || _ok=0
        grep -q "verdict replay" "$_base/$_label.host.log" || _ok=0
        if grep -q "RUNNER phase=" "$_base/$_label.host.log"; then _ok=0; fi
        [ "$_calls_after" = "$_calls_before" ] || _ok=0
        [ "$_verdict_after" = "$_verdict_before" ] || _ok=0
        [ -f "$_em_dir/freeze.done" ] && _ok=0
        if [ "$_ok" -eq 1 ]; then
            printf 'EXPECT-PASS %s: replay exit=%s verdict=%s, 0 phases, 0 OCI calls (calls %s->%s), verdict.txt unchanged\n' "$_label" "$_emrc" "$_want_v" "$_calls_before" "$_calls_after" >> "$_summary"
        else
            printf 'EXPECT-FAIL %s: exit=%s (want %s), oci_calls %s->%s, verdict_changed=%s, freeze_marker_recreated=%s\n' "$_label" "$_emrc" "$_want_rc" "$_calls_before" "$_calls_after" "$([ "$_verdict_after" = "$_verdict_before" ] && echo no || echo yes)" "$([ -f "$_em_dir/freeze.done" ] && echo yes || echo no)" >> "$_summary"
            _failures=$((_failures + 1))
        fi
    }
    _early_marker_replay_check "$_base/main" 2 INCONCLUSIVE replay-early-marker-inconclusive
    _early_marker_replay_check "$_base/regression_fail" 1 FAIL replay-early-marker-fail
    # Liveness-wait checks (V11, rule 39): run the REAL o13.sh
    # against a copy of the completed allpass batch whose
    # instance_state.log is truncated to first TERMINATED + TWO
    # liveness entries (the third entry dropped). The HMAC secret
    # was destroyed by the verdict phase, so the HMAC checks in
    # this copy go INCONCLUSIVE and the overall O13_RESULT is
    # INCONCLUSIVE in both modes - the assertions below are on the
    # LIVENESS lines only, which need no secret. Positive mode
    # ("wait"): a background appender adds the dropped third entry
    # after 20 s (later than o13.sh's ~2 s of pre-liveness checks,
    # so the first liveness read sees 2 and the wait must be
    # exercised); the check passes only if the output contains
    # liveness_confirmed AND waited_s >= 2. Negative mode
    # ("timeout"): no appender and O13_LIVENESS_WAIT_MAX_S=4; the
    # check passes only if the output contains
    # no_liveness_observation_after_termination with
    # liveness_observations=2 and the run finishes in under 60 s
    # (the timeout path is fail-closed and does not hang to the
    # 180 s default). Both modes copy the batch dir, so the
    # completed allpass evidence is untouched.
    _liveness_wait_check() {
        _label=$1; _mode=$2
        _lw_dir="$_base/$_label"
        rm -rf "$_lw_dir"
        cp -r "$_base/regression_allpass" "$_lw_dir" || { printf 'EXPECT-FAIL %s: cannot copy batch dir\n' "$_label" >> "$_summary"; _failures=$((_failures + 1)); return 0; }
        _lw_last=$(tail -1 "$_lw_dir/instance_state.log")
        head -n -1 "$_lw_dir/instance_state.log" > "$_lw_dir/instance_state.log.tmp" && mv "$_lw_dir/instance_state.log.tmp" "$_lw_dir/instance_state.log"
        _lw_creation=$(cat "$_lw_dir/creation_time.txt")
        _lw_timer=$(date -u -d "$_lw_creation + 8 minutes" +%Y-%m-%dT%H:%M:%SZ)
        _lw_appender=""
        if [ "$_mode" = "wait" ]; then
            ( sleep 20; printf '%s\n' "$_lw_last" >> "$_lw_dir/instance_state.log" ) &
            _lw_appender=$!
        fi
        _lw_start=$(date +%s)
        if [ "$_mode" = "timeout" ]; then _lw_extra="O13_LIVENESS_WAIT_MAX_S=4"; else _lw_extra=""; fi
        # shellcheck disable=SC2086
        env $_lw_extra \
        INSTANCE_OCID="$(cat "$_lw_dir/instance_ocid.txt")" \
        VCN_OCID="$(cat "$_lw_dir/vcn_ocid.txt")" \
        SUBNET_OCID="$(cat "$_lw_dir/subnet_ocid.txt")" \
        SECLIST_OCID="$(cat "$_lw_dir/seclist_ocid.txt")" \
        ROUTETABLE_OCID="$(cat "$_lw_dir/rt_ocid.txt")" \
        IGW_OCID="$(cat "$_lw_dir/igw_ocid.txt")" \
        VM_PUBLIC_IP="$(cat "$_lw_dir/vm_public_ip.txt")" \
        COMPARTMENT_OCID="$(cat "$_lw_dir/tenancy_ocid.txt")" \
        TENANCY_OCID="$(cat "$_lw_dir/tenancy_ocid.txt")" \
        BATCH_START="$_lw_creation" \
        WATCHDOG_RUN_RECORD="$_lw_dir/mock_controller_run_record.json" \
        JOURNAL_SNAPSHOT="$_lw_dir/results/watchdog-snapshot.txt" \
        INSTANCE_STATE_LOG="$_lw_dir/instance_state.log" \
        TIMER_DEADLINE="$_lw_timer" \
        BATCH_MANIFEST="$_lw_dir/results/batch.json" \
        RESULTS_SHA256="$_lw_dir/results/results.sha256" \
        HMAC_SECRET_FILE="$_lw_dir/hmac_secret" \
        EXPECTED_CONTROLLER_JOB_ID="dryrun-controller" \
        EXPECTED_TERMINATE_COMMAND="$(cat "$_lw_dir/expected_terminate_command.txt")" \
        DONE_MARKER="$_lw_dir/results/DONE" \
        OCI_CLI="$SCRIPT_DIR/mock_oci.sh" \
        MOCK_OCI_STATE="$_lw_dir/mock_oci_state" \
        "$SCRIPT_DIR/o13.sh" > "$_base/$_label.o13.log" 2>&1
        _lw_end=$(date +%s)
        [ -n "$_lw_appender" ] && wait "$_lw_appender" 2>/dev/null
        _lw_elapsed=$((_lw_end - _lw_start))
        _lw_waited=$(sed -n 's/.*waited_s=\([0-9]*\).*/\1/p' "$_base/$_label.o13.log" | head -1)
        [ -z "$_lw_waited" ] && _lw_waited=0
        if [ "$_mode" = "wait" ]; then
            if grep -q "result=liveness_confirmed" "$_base/$_label.o13.log" && [ "$_lw_waited" -ge 2 ]; then
                printf 'EXPECT-PASS %s: liveness_confirmed after wait (waited_s=%s, elapsed=%ss)\n' "$_label" "$_lw_waited" "$_lw_elapsed" >> "$_summary"
            else
                printf 'EXPECT-FAIL %s: no liveness_confirmed with wait (waited_s=%s, elapsed=%ss)\n' "$_label" "$_lw_waited" "$_lw_elapsed" >> "$_summary"
                _failures=$((_failures + 1))
            fi
        else
            if grep -q "result=no_liveness_observation_after_termination" "$_base/$_label.o13.log" && grep -q "liveness_observations=2" "$_base/$_label.o13.log" && [ "$_lw_elapsed" -lt 60 ]; then
                printf 'EXPECT-PASS %s: timeout is fail-closed (2 observations, waited_s=%s, elapsed=%ss)\n' "$_label" "$_lw_waited" "$_lw_elapsed" >> "$_summary"
            else
                printf 'EXPECT-FAIL %s: timeout path wrong (waited_s=%s, elapsed=%ss)\n' "$_label" "$_lw_waited" "$_lw_elapsed" >> "$_summary"
                _failures=$((_failures + 1))
            fi
        fi
    }
    _liveness_wait_check liveness-wait-positive wait
    _liveness_wait_check liveness-wait-timeout timeout
    # Proxy concurrency regression (Revision 12, rule 40): run the
    # REAL egress-proxy.py (the reviewed source in $M8_DIR) with
    # test env overrides (filter/port/log under the regressions base
    # dir - never /tmp), open 48 concurrent connections holding
    # partial request lines, and assert the hard cap holds: at most
    # 16 held, at least 30 refused with exactly 503, proxy threads
    # <= 18, and the proxy still answers a non-allow-listed CONNECT
    # with exactly 403 after the load drains. Two expectations:
    # proxy-cap-holds (the cap numbers) and proxy-cap-survives
    # (drain + post-drain 403).
    _proxy_cap_check() {
        _pc_dir="$_base/proxy-cap"
        mkdir -p "$_pc_dir" || { printf 'EXPECT-FAIL proxy-cap-holds: cannot create proxy-cap dir\n' >> "$_summary"; _failures=$((_failures + 1)); return 0; }
        printf '%s\n' '^github\.com$' '^pypi\.org$' > "$_pc_dir/filter" || { printf 'EXPECT-FAIL proxy-cap-holds: cannot write filter\n' >> "$_summary"; _failures=$((_failures + 1)); return 0; }
        _pc_log="$_base/proxy-cap-check.log"
        : > "$_pc_log" || true
        EGRESS_PROXY_FILTER="$_pc_dir/filter" EGRESS_PROXY_LOG="$_pc_dir/proxy.log" EGRESS_PROXY_PORT=13128 EGRESS_PROXY_HOST=127.0.0.1 python3 "$M8_DIR/egress-proxy.py" > "$_pc_dir/proxy.out" 2>&1 &
        _pc_pid=$!
        sleep 2
        if ! kill -0 "$_pc_pid" 2>/dev/null; then
            printf 'EXPECT-FAIL proxy-cap-holds: proxy did not start\n' >> "$_summary"
            _failures=$((_failures + 1))
            return 0
        fi
        python3 - "$_pc_pid" "$_pc_log" <<'PYEOF'
import socket, sys, threading, time
pid, logpath = int(sys.argv[1]), sys.argv[2]
N = 48
outcomes = {}
socks = []
lock = threading.Lock()
def threads_of(p):
    try:
        for line in open("/proc/%d/status" % p):
            if line.startswith("Threads:"):
                return int(line.split()[1])
    except OSError:
        return -1
    return -1
def worker(i):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4.0)
    try:
        s.connect(("127.0.0.1", 13128))
        s.sendall(b"CONNECT github.com:443 HTTP/1.1\r\n")
        try:
            data = s.recv(4096)
        except socket.timeout:
            data = b""
        if data.startswith(b"HTTP/1.1 503"):
            res = "refused503"
        elif data == b"":
            res = "held"
        else:
            res = "other:%r" % data[:40]
    except (ConnectionRefusedError, OSError):
        res = "refused-conn"
        s = None
    with lock:
        outcomes[i] = res
        if s is not None:
            socks.append(s)
ts = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
for t in ts:
    t.start()
for t in ts:
    t.join(10)
refused = sum(1 for v in outcomes.values() if v == "refused503" or v == "refused-conn")
other = sum(1 for v in outcomes.values() if v.startswith("other"))
held = N - refused - other
thr = threads_of(pid)
for s in socks:
    try:
        s.close()
    except OSError:
        pass
time.sleep(1)
drained = threads_of(pid)
post = "none"
try:
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.settimeout(5.0)
    s2.connect(("127.0.0.1", 13128))
    s2.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
    try:
        d2 = s2.recv(4096)
    except socket.timeout:
        d2 = b""
    if d2.startswith(b"HTTP/1.1 403"):
        post = "403"
    elif d2 == b"":
        post = "timeout"
    else:
        post = "other:%r" % d2[:40]
    s2.close()
except OSError as e:
    post = "error:%s" % e
ok = held <= 16 and refused >= 30 and 0 < thr <= 18 and 0 < drained <= 2 and post == "403"
with open(logpath, "a") as f:
    f.write("PROXY_CAP attempted=%d refused=%d held=%d other=%d proxy_threads=%d drained_threads=%d post_drain=%s\n" % (N, refused, held, other, thr, drained, post))
    f.write("PROXY_CAP RESULT: %s\n" % ("PASS" if ok else "FAIL"))
sys.exit(0 if ok else 1)
PYEOF
        _pc_rc=$?
        kill "$_pc_pid" 2>/dev/null || true
        wait "$_pc_pid" 2>/dev/null || true
        cp "$_pc_dir/proxy.log" "$_base/proxy-cap-proxy.log" 2>/dev/null || true
        if [ "$_pc_rc" -eq 0 ] && grep -q "PROXY_CAP RESULT: PASS" "$_pc_log"; then
            printf 'EXPECT-PASS proxy-cap-holds: %s\n' "$(grep 'PROXY_CAP attempted=' "$_pc_log" | head -1)" >> "$_summary"
            printf 'EXPECT-PASS proxy-cap-survives: %s\n' "$(grep 'PROXY_CAP attempted=' "$_pc_log" | head -1)" >> "$_summary"
        else
            printf 'EXPECT-FAIL proxy-cap-holds: proxy cap regression failed (see %s)\n' "$_pc_log" >> "$_summary"
            printf 'EXPECT-FAIL proxy-cap-survives: proxy cap regression failed (see %s)\n' "$_pc_log" >> "$_summary"
            _failures=$((_failures + 2))
        fi
    }
    _proxy_cap_check
    # Secret-delivery verification (Revision 12, rule 41): the main
    # run's secret_delivery.log must show all six delivery checks
    # PASS (decrypt, user-data has no secret value, public key
    # present, no private key, no secret assignment, sweep clean),
    # and the download log must show the HMAC of batch.json verified
    # with the decrypted secret (the round-trip: the VM-generated
    # secret, encrypted with the host public key, decrypted on the
    # host, and used to authenticate the manifest).
    _secret_expect() {
        _sl=$1; _file=$2; _pat=$3
        if grep -q "$_pat" "$_file" 2>/dev/null; then
            printf 'EXPECT-PASS %s\n' "$_sl" >> "$_summary"
        else
            printf 'EXPECT-FAIL %s: pattern not found in %s\n' "$_sl" "$_file" >> "$_summary"
            _failures=$((_failures + 1))
        fi
    }
    _secret_expect secret-decrypt "$_base/main/secret_delivery.log" "SECRET_DELIVERY decrypt=PASS"
    _secret_expect secret-userdata-clean "$_base/main/secret_delivery.log" "SECRET_DELIVERY user_data_no_secret=PASS"
    _secret_expect secret-public-key-present "$_base/main/secret_delivery.log" "SECRET_DELIVERY public_key_present=PASS"
    _secret_expect secret-private-key-absent "$_base/main/secret_delivery.log" "SECRET_DELIVERY private_key_absent=PASS"
    _secret_expect secret-no-secret-assignment "$_base/main/secret_delivery.log" "SECRET_DELIVERY no_secret_assignment=PASS"
    _secret_expect secret-sweep-clean "$_base/main/secret_delivery.log" "SECRET_DELIVERY sweep=PASS"
    _secret_expect secret-roundtrip "$_base/main/download.log" "O11_DOWNLOAD hmac_verified path=batch.json"
    # Tamper / wrong-key fail-closed checks (Revision 12, rule 41):
    # self-contained (fresh keypairs, no batch state): a ciphertext
    # with one byte flipped must fail to decrypt, and a ciphertext
    # encrypted under key A must fail to decrypt under key B. Both
    # failures are openssl non-zero exits - the decrypt step fails
    # closed, never produces a garbage secret. The test keypairs and
    # the test secret are deleted afterwards; only the check log
    # remains.
    _secret_tamper_check() {
        _st_dir="$_base/secret-tamper"
        mkdir -p "$_st_dir" || { printf 'EXPECT-FAIL secret-tamper-failclosed: cannot create dir\n' >> "$_summary"; _failures=$((_failures + 1)); printf 'EXPECT-FAIL secret-wrongkey-failclosed: cannot create dir\n' >> "$_summary"; _failures=$((_failures + 1)); return 0; }
        _st_log="$_base/secret-tamper-check.log"
        {
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$_st_dir/key_a.pem" 2>/dev/null
        openssl pkey -in "$_st_dir/key_a.pem" -pubout -out "$_st_dir/key_a.pub" 2>/dev/null
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$_st_dir/key_b.pem" 2>/dev/null
        python3 -c "import secrets; print(secrets.token_hex(32))" > "$_st_dir/secret.txt"
        openssl pkeyutl -encrypt -pubin -inkey "$_st_dir/key_a.pub" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in "$_st_dir/secret.txt" -out "$_st_dir/secret.enc" 2>/dev/null
        cp "$_st_dir/secret.enc" "$_st_dir/secret_tampered.enc"
        printf 'X' | dd of="$_st_dir/secret_tampered.enc" bs=1 seek=100 conv=notrunc 2>/dev/null
        if openssl pkeyutl -decrypt -inkey "$_st_dir/key_a.pem" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in "$_st_dir/secret_tampered.enc" -out "$_st_dir/tampered.dec" 2>/dev/null; then
            echo "SECRET_TAMPER tampered_ciphertext: DECRYPTED (fail-open)"
        else
            echo "SECRET_TAMPER tampered_ciphertext: decrypt failed (fail-closed)"
        fi
        if openssl pkeyutl -decrypt -inkey "$_st_dir/key_b.pem" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in "$_st_dir/secret.enc" -out "$_st_dir/wrongkey.dec" 2>/dev/null; then
            echo "SECRET_TAMPER wrong_key: DECRYPTED (fail-open)"
        else
            echo "SECRET_TAMPER wrong_key: decrypt failed (fail-closed)"
        fi
        } > "$_st_log" 2>&1
        if grep -q "tampered_ciphertext: decrypt failed (fail-closed)" "$_st_log"; then
            printf 'EXPECT-PASS secret-tamper-failclosed: tampered ciphertext fails to decrypt\n' >> "$_summary"
        else
            printf 'EXPECT-FAIL secret-tamper-failclosed: tampered ciphertext decrypted\n' >> "$_summary"
            _failures=$((_failures + 1))
        fi
        if grep -q "wrong_key: decrypt failed (fail-closed)" "$_st_log"; then
            printf 'EXPECT-PASS secret-wrongkey-failclosed: ciphertext under key A fails under key B\n' >> "$_summary"
        else
            printf 'EXPECT-FAIL secret-wrongkey-failclosed: ciphertext under key A decrypted under key B\n' >> "$_summary"
            _failures=$((_failures + 1))
        fi
        rm -rf "$_st_dir"
    }
    _secret_tamper_check
    # Secret-authenticity verification (Revision 13, rule 43): the
    # main run's secret_delivery.log must show authenticity=PASS
    # (chain + OCID + tenancy + dates + signature + challenge all
    # passed on the host before the ciphertext was decrypted).
    _secret_expect secret-authenticity "$_base/main/secret_delivery.log" "SECRET_DELIVERY authenticity=PASS"
    # Authenticated-delivery fail-closed checks (Revision 13,
    # rule 43): self-contained regressions against the main run's
    # artifacts (genuine ciphertext/signature/certificates, pinned
    # mock root CA, recorded batch id + challenge + OCIDs). Each
    # case must be REJECTED by host_verify_secret_auth, and the
    # rejection must come from the specific defence named:
    # (a) a substituted ciphertext (attacker-known secret, encrypted
    # with the host public key, paired with the GENUINE signature)
    # must fail on the signature (the signature is over the genuine
    # ciphertext's hash); (b) a certificate for a DIFFERENT instance
    # (the mock attacker identity issued in host_phase_vm_create_
    # dryrun, same CA) signing the genuine delivery data must fail
    # on the OCID check; (c) a certificate from a DIFFERENT CA
    # (fresh attacker CA, genuine instance OCID in the CN) signing
    # the genuine delivery data must fail on the chain check;
    # (d) the genuine signature verified against a WRONG challenge
    # (a replay from another batch) must fail on the signature /
    # challenge check. The fixtures are deleted afterwards; only
    # the check log remains.
    _secret_auth_check() {
        _sa_dir="$_base/secret-auth"
        mkdir -p "$_sa_dir" || { printf 'EXPECT-FAIL secret-auth-substituted: cannot create dir\n' >> "$_summary"; _failures=$((_failures + 1)); printf 'EXPECT-FAIL secret-auth-wrong-sender: cannot create dir\n' >> "$_summary"; _failures=$((_failures + 1)); printf 'EXPECT-FAIL secret-auth-wrong-ca: cannot create dir\n' >> "$_summary"; _failures=$((_failures + 1)); printf 'EXPECT-FAIL secret-auth-replay: cannot create dir\n' >> "$_summary"; _failures=$((_failures + 1)); return 0; }
        _sa_log="$_base/secret-auth-check.log"
        {
        _sa_main="$_base/main"
        _sa_bid=$(cat "$_sa_main/batch_id.txt" 2>/dev/null | tr -d '[:space:]')
        _sa_chal=$(cat "$_sa_main/batch_challenge.txt" 2>/dev/null | tr -d '[:space:]')
        _sa_ocid=$(cat "$_sa_main/instance_ocid.txt" 2>/dev/null | tr -d '[:space:]')
        _sa_ten=$(cat "$_sa_main/tenancy_ocid.txt" 2>/dev/null | tr -d '[:space:]')
        _sa_root="$_sa_main/oci_root_ca.pem"
        _sa_enc_sha=$(sha256sum "$_sa_main/hmac_secret.enc" 2>/dev/null | awk '{print $1}')
        printf 'BATCH_ID=%s\nCHALLENGE=%s\nCIPHERTEXT_SHA256=%s\n' "$_sa_bid" "$_sa_chal" "$_sa_enc_sha" > "$_sa_dir/delivery_data.txt"
        # (a) Substituted ciphertext + genuine signature.
        python3 -c "import secrets; print(secrets.token_hex(32))" > "$_sa_dir/attacker_secret.txt"
        openssl pkeyutl -encrypt -pubin -inkey "$_sa_main/hmac_host_key.pub" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in "$_sa_dir/attacker_secret.txt" -out "$_sa_dir/substituted.enc" 2>/dev/null
        if host_verify_secret_auth "$_sa_dir/substituted.enc" "$_sa_main/hmac_secret.sig" "$_sa_main/hmac_secret.cert.pem" "$_sa_main/hmac_secret.intermediate.pem" "$_sa_root" "$_sa_ocid" "$_sa_ten" "$_sa_bid" "$_sa_chal" "$_sa_dir/substituted.log"; then
            echo "SECRET_AUTH substituted_ciphertext: ACCEPTED (fail-open)"
        else
            echo "SECRET_AUTH substituted_ciphertext: rejected (fail-closed)"
        fi
        # (b) Wrong-sender certificate (different instance OCID, same CA).
        if [ -f "$_sa_main/mock_identity/attacker_cert.pem" ] && [ -f "$_sa_main/mock_identity/attacker_key.pem" ]; then
            openssl dgst -sha256 -sign "$_sa_main/mock_identity/attacker_key.pem" -out "$_sa_dir/wrong_sender.sig" "$_sa_dir/delivery_data.txt" 2>/dev/null
            if host_verify_secret_auth "$_sa_main/hmac_secret.enc" "$_sa_dir/wrong_sender.sig" "$_sa_main/mock_identity/attacker_cert.pem" "$_sa_main/hmac_secret.intermediate.pem" "$_sa_root" "$_sa_ocid" "$_sa_ten" "$_sa_bid" "$_sa_chal" "$_sa_dir/wrong_sender.log"; then
                echo "SECRET_AUTH wrong_sender: ACCEPTED (fail-open)"
            else
                echo "SECRET_AUTH wrong_sender: rejected (fail-closed)"
            fi
        else
            echo "SECRET_AUTH wrong_sender: attacker identity fixture missing"
        fi
        # (c) Wrong-CA certificate (fresh attacker CA, genuine OCID in the CN).
        openssl req -x509 -newkey rsa:2048 -keyout "$_sa_dir/attacker_root_key.pem" -out "$_sa_dir/attacker_root.pem" -days 2 -nodes -subj "/CN=M8-ATTACKER-ROOT-CA/O=M8-ATTACKER" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
        openssl req -newkey rsa:2048 -keyout "$_sa_dir/attacker_inter_key.pem" -out "$_sa_dir/attacker_inter.csr" -nodes -subj "/CN=M8-ATTACKER-INTERMEDIATE-CA/O=M8-ATTACKER" 2>/dev/null
        printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$_sa_dir/attacker_inter.ext"
        openssl x509 -req -in "$_sa_dir/attacker_inter.csr" -CA "$_sa_dir/attacker_root.pem" -CAkey "$_sa_dir/attacker_root_key.pem" -CAcreateserial -out "$_sa_dir/attacker_inter.pem" -days 2 -extfile "$_sa_dir/attacker_inter.ext" 2>/dev/null
        openssl req -newkey rsa:2048 -keyout "$_sa_dir/attacker_leaf_key.pem" -out "$_sa_dir/attacker_leaf.csr" -nodes -subj "/CN=M8-ATTACKER-LEAF/O=M8-ATTACKER" 2>/dev/null
        printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n1.3.6.1.4.1.99999.1=ASN1:UTF8:opc-identity:%s\n1.3.6.1.4.1.99999.2=ASN1:UTF8:opc-tenant:%s\n' "$_sa_ocid" "$_sa_ten" > "$_sa_dir/attacker_leaf.ext"
        openssl x509 -req -in "$_sa_dir/attacker_leaf.csr" -CA "$_sa_dir/attacker_inter.pem" -CAkey "$_sa_dir/attacker_inter_key.pem" -CAcreateserial -out "$_sa_dir/attacker_leaf.pem" -days 2 -extfile "$_sa_dir/attacker_leaf.ext" 2>/dev/null
        openssl dgst -sha256 -sign "$_sa_dir/attacker_leaf_key.pem" -out "$_sa_dir/wrong_ca.sig" "$_sa_dir/delivery_data.txt" 2>/dev/null
        if host_verify_secret_auth "$_sa_main/hmac_secret.enc" "$_sa_dir/wrong_ca.sig" "$_sa_dir/attacker_leaf.pem" "$_sa_dir/attacker_inter.pem" "$_sa_root" "$_sa_ocid" "$_sa_ten" "$_sa_bid" "$_sa_chal" "$_sa_dir/wrong_ca.log"; then
            echo "SECRET_AUTH wrong_ca: ACCEPTED (fail-open)"
        else
            echo "SECRET_AUTH wrong_ca: rejected (fail-closed)"
        fi
        # (d) Replay: genuine signature, wrong challenge.
        _sa_wrong_chal="00000000000000000000000000000000"
        if host_verify_secret_auth "$_sa_main/hmac_secret.enc" "$_sa_main/hmac_secret.sig" "$_sa_main/hmac_secret.cert.pem" "$_sa_main/hmac_secret.intermediate.pem" "$_sa_root" "$_sa_ocid" "$_sa_ten" "$_sa_bid" "$_sa_wrong_chal" "$_sa_dir/replay.log"; then
            echo "SECRET_AUTH replay: ACCEPTED (fail-open)"
        else
            echo "SECRET_AUTH replay: rejected (fail-closed)"
        fi
        } > "$_sa_log" 2>&1
        if grep -q "substituted_ciphertext: rejected (fail-closed)" "$_sa_log" && grep -q "SECRET_DELIVERY auth_signature=FAIL" "$_sa_dir/substituted.log" 2>/dev/null; then
            printf 'EXPECT-PASS secret-auth-substituted: substituted ciphertext rejected on the signature check\n' >> "$_summary"
        else
            printf 'EXPECT-FAIL secret-auth-substituted: substituted ciphertext was accepted or rejected by the wrong check (see %s)\n' "$_sa_log" >> "$_summary"
            _failures=$((_failures + 1))
        fi
        if grep -q "wrong_sender: rejected (fail-closed)" "$_sa_log" && grep -q "SECRET_DELIVERY auth_ocid=FAIL" "$_sa_dir/wrong_sender.log" 2>/dev/null; then
            printf 'EXPECT-PASS secret-auth-wrong-sender: certificate for another instance rejected on the OCID check\n' >> "$_summary"
        else
            printf 'EXPECT-FAIL secret-auth-wrong-sender: wrong-sender certificate was accepted or rejected by the wrong check (see %s)\n' "$_sa_log" >> "$_summary"
            _failures=$((_failures + 1))
        fi
        if grep -q "wrong_ca: rejected (fail-closed)" "$_sa_log" && grep -q "SECRET_DELIVERY auth_chain=FAIL" "$_sa_dir/wrong_ca.log" 2>/dev/null; then
            printf 'EXPECT-PASS secret-auth-wrong-ca: certificate from another CA rejected on the chain check\n' >> "$_summary"
        else
            printf 'EXPECT-FAIL secret-auth-wrong-ca: wrong-CA certificate was accepted or rejected by the wrong check (see %s)\n' "$_sa_log" >> "$_summary"
            _failures=$((_failures + 1))
        fi
        if grep -q "replay: rejected (fail-closed)" "$_sa_log" && grep -q "SECRET_DELIVERY auth_signature=FAIL" "$_sa_dir/replay.log" 2>/dev/null; then
            printf 'EXPECT-PASS secret-auth-replay: genuine signature over a wrong challenge rejected on the signature check\n' >> "$_summary"
        else
            printf 'EXPECT-FAIL secret-auth-replay: replayed signature was accepted or rejected by the wrong check (see %s)\n' "$_sa_log" >> "$_summary"
            _failures=$((_failures + 1))
        fi
        rm -rf "$_sa_dir"
    }
    _secret_auth_check
    # Traversal checks (Revision 13, rule 44): self-contained
    # regressions against the REAL results server source (extracted
    # from run_batch.sh, only RESULTS_DIR/PORT patched for the test
    # - the shipped source is untouched). The real server must
    # return 404 with no canary leak for every literal and encoded
    # traversal probe; the same probes must DETECT a deliberately
    # vulnerable server (a naive join with no checks), proving the
    # probes are not vacuous.
    _traversal_check() {
        _tr_dir="$_base/traversal"
        mkdir -p "$_tr_dir/results" "$_tr_dir/opt/traversal" || { printf 'EXPECT-FAIL traversal-real-server: cannot create dir\n' >> "$_summary"; _failures=$((_failures + 1)); printf 'EXPECT-FAIL traversal-vulnerable-server: cannot create dir\n' >> "$_summary"; _failures=$((_failures + 1)); return 0; }
        _tr_log="$_base/traversal-check.log"
        {
        printf 'TRAVERSAL-CANARY-driver-test\n' > "$_tr_dir/opt/traversal/traversal_canary.txt"
        printf 'BATCH_ID=driver-test\n' > "$_tr_dir/results/batch.json"
        sed -n "/cat > \/opt\/harness\/results_server.py <<'PYEOF'/,/^PYEOF$/{p;/^PYEOF$/q}" "$M8_DIR/o_tests_v13/run_batch.sh" | sed -e '1d' -e '$d' > "$_tr_dir/real_server.py" || echo "TRAVERSAL extract failed"
        sed -i -e "s|^RESULTS_DIR = \"/results\"|RESULTS_DIR = \"$_tr_dir/results\"|" -e "s|^PORT = 8080|PORT = 18080|" "$_tr_dir/real_server.py"
        grep -q "RESULTS_DIR = \"$_tr_dir/results\"" "$_tr_dir/real_server.py" && grep -q "PORT = 18080" "$_tr_dir/real_server.py" || echo "TRAVERSAL patch failed"
        python3 -c "compile(open(\"$_tr_dir/real_server.py\").read(), 'real_server.py', 'exec')" || echo "TRAVERSAL real-server.py does not compile"
        python3 "$_tr_dir/real_server.py" > "$_tr_dir/real_server.out" 2>&1 &
        _tr_pid=$!
        sleep 2
        _tr_marker="TRAVERSAL-CANARY-driver-test"
        _tr_fail=0
        if ! kill -0 "$_tr_pid" 2>/dev/null; then
            echo "TRAVERSAL real-server: server process died on start; server output:"
            cat "$_tr_dir/real_server.out" 2>/dev/null || echo "(no server output)"
            _tr_fail=1
        fi
        if [ "$_tr_fail" -eq 0 ]; then
        for _t in "/../batch.json" "/../opt/traversal/traversal_canary.txt" "/%2e%2e/opt/traversal/traversal_canary.txt" "/..%2fopt/traversal/traversal_canary.txt" "/%252e%252e/opt/traversal/traversal_canary.txt"; do
            _probe_out=$(raw_traversal_probe 127.0.0.1 18080 "$_t" "$_tr_marker" 2>&1)
            _probe_rc=$?
            echo "TRAVERSAL real-server probe: $_probe_out"
            [ "$_probe_rc" -eq 0 ] || _tr_fail=1
        done
        fi
        kill "$_tr_pid" 2>/dev/null || true
        wait "$_tr_pid" 2>/dev/null || true
        if [ "$_tr_fail" -eq 0 ]; then echo "TRAVERSAL real-server: all probes 404, no canary leak"; else echo "TRAVERSAL real-server: a probe failed"; fi
        cat > "$_tr_dir/vuln_server.py" <<'VPYEOF'
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
ROOT = os.environ.get("VULN_ROOT", "/tmp")
class H(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        from urllib.parse import unquote
        p = unquote(self.path.split("?", 1)[0].lstrip("/"))
        target = os.path.join(ROOT, p)
        if not os.path.isfile(target):
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
        data = open(target, "rb").read()
        self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
HTTPServer(("0.0.0.0", 18081), H).serve_forever()
VPYEOF
        VULN_ROOT="$_tr_dir/results" python3 "$_tr_dir/vuln_server.py" > "$_tr_dir/vuln_server.out" 2>&1 &
        _vuln_pid=$!
        sleep 2
        _vuln_out=$(raw_traversal_probe 127.0.0.1 18081 "/../opt/traversal/traversal_canary.txt" "$_tr_marker" 2>&1)
        echo "TRAVERSAL vulnerable-server probe: $_vuln_out"
        if raw_traversal_probe 127.0.0.1 18081 "/../opt/traversal/traversal_canary.txt" "$_tr_marker" >/dev/null 2>&1; then
            echo "TRAVERSAL vulnerable-server: probe did NOT detect the leak (vacuous)"
        else
            echo "TRAVERSAL vulnerable-server: probe DETECTED the leak"
        fi
        kill "$_vuln_pid" 2>/dev/null || true
        wait "$_vuln_pid" 2>/dev/null || true
        } > "$_tr_log" 2>&1
        if grep -q "TRAVERSAL real-server: all probes 404, no canary leak" "$_tr_log"; then
            printf 'EXPECT-PASS traversal-real-server: raw-socket literal+encoded probes return 404 with no canary leak on the real server\n' >> "$_summary"
        else
            printf 'EXPECT-FAIL traversal-real-server: a raw-socket probe failed on the real server (see %s)\n' "$_tr_log" >> "$_summary"
            _failures=$((_failures + 1))
        fi
        if grep -q "TRAVERSAL vulnerable-server: probe DETECTED the leak" "$_tr_log"; then
            printf 'EXPECT-PASS traversal-vulnerable-server: the same probes DETECT a deliberately vulnerable server (not vacuous)\n' >> "$_summary"
        else
            printf 'EXPECT-FAIL traversal-vulnerable-server: the probes did not detect the vulnerable server\n' >> "$_summary"
            _failures=$((_failures + 1))
        fi
        rm -rf "$_tr_dir"
    }
    _traversal_check
    # O11 host-mode traversal: the main run's o11_host.log must show
    # the raw-socket traversal probe passing (label
    # traversal-dotdot-raw, result=expected).
    _secret_expect o11-traversal-raw "$_base/main/o11_host.log" "O11_ENDPOINT label=traversal-dotdot-raw result=expected"
    cp "$_summary" "$M8_DIR/o_tests_v13/dry_run_regressions_summary.txt" 2>/dev/null || true
    log "REGRESSIONS summary written: $_summary (failures=$_failures)"
    if [ "$_failures" -eq 0 ]; then
        log "REGRESSIONS all expectations met - the verdict gate blocks PASS in the negative regressions, the all-pass run reaches PASS, the verdict replay + batch-identity checks hold, the liveness wait confirms a late third observation while its timeout stays fail-closed, the proxy concurrency cap holds under adversarial load, the secret delivery verifies end to end (round-trip, sweep, tamper and wrong-key fail-closed) and authenticates (substituted ciphertext, wrong-sender, wrong-CA and replay all rejected), and the traversal defence holds under raw-socket literal+encoded probes that also detect a deliberately vulnerable server"
        exit 0
    else
        log "REGRESSIONS $_failures expectation(s) FAILED - see $_summary"
        exit 1
    fi
}

# ------------------------------------------------------------------
# Host mode
# ------------------------------------------------------------------

# replay_stored_verdict - (V11, rule 37) Replay a stored final
# verdict and exit with its exit code. If no verdict.txt exists,
# return 1 (the caller proceeds normally). The stored `exit=` field
# is VALIDATED against the stored `verdict=` field: PASS -> 0,
# FAIL -> 1, INCONCLUSIVE/INVALID -> 2. A missing or mismatched
# exit= line, or an unreadable verdict= line, is INCONCLUSIVE
# (exit 2) - never PASS, never exit 0. The replay is read-only:
# verdict.txt is not rewritten and no phase is run. Called from
# host_main() immediately after batch_id_resolve() (rule 37: the
# replay happens BEFORE any phase, so a missing phase marker in an
# already-finalized batch cannot cause a phase to re-run) and from
# host_phase_verdict() as defence-in-depth (there it is normally
# unreachable, because host_main already replayed).
replay_stored_verdict() {
    [ -f "$BATCH_DIR/verdict.txt" ] || return 1
    _stored=$(sed -n 's/^verdict=//p' "$BATCH_DIR/verdict.txt" 2>/dev/null | head -1)
    _stored_exit=$(sed -n 's/^exit=//p' "$BATCH_DIR/verdict.txt" 2>/dev/null | head -1)
    case "$_stored" in
        PASS) _want_exit=0 ;;
        FAIL) _want_exit=1 ;;
        INCONCLUSIVE|INVALID) _want_exit=2 ;;
        *) log "RUNNER verdict replay: verdict.txt unreadable (stored='$_stored') - INCONCLUSIVE, exit 2"; exit 2 ;;
    esac
    if [ "$_stored_exit" != "$_want_exit" ]; then
        log "RUNNER verdict replay: stored exit=$_stored_exit does not match verdict=$_stored (want $_want_exit) - INCONCLUSIVE, exit 2"
        exit 2
    fi
    log "RUNNER verdict replay: stored verdict $_stored - exit $_want_exit"
    exit "$_want_exit"
}

host_main() {
    BATCH_DIR=""
    RESUME=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --batch-dir) BATCH_DIR=$2; shift 2 ;;
            --resume) RESUME=1; shift ;;
            *) die 2 "host: unknown argument: $1" ;;
        esac
    done
    [ -n "$BATCH_DIR" ] || die 2 "host: --batch-dir is required"
    mkdir -p "$BATCH_DIR" || die 2 "cannot create batch dir: $BATCH_DIR"
    BATCH_RECORD="$BATCH_DIR/batch_record.txt"
    touch "$BATCH_RECORD" || die 2 "cannot write batch record: $BATCH_RECORD"
    OCI_CLI=${OCI_CLI:-oci}
    TEST_MODE=${TEST_MODE:-1}
    DRYRUN=${DRYRUN:-0}
    # Deadlines in minutes (test mode first, production second).
    if [ "$TEST_MODE" = "1" ]; then
        TIMER_MINUTES=90; CONTROLLER_MINUTES=120; POLLER_MINUTES=150; DONE_MINUTES=85
    else
        TIMER_MINUTES=1440; CONTROLLER_MINUTES=1440; POLLER_MINUTES=1500; DONE_MINUTES=1380
    fi
    # Dry-run deadlines (compressed, spec rule 29): the mock VM's
    # timer fires at creation + 8 min, the mock controller at + 9
    # min, the poller deadline is + 10 min, and the DONE wait is
    # + 7 min. These are the same values the dry-run driver sets in
    # the environment (DRYRUN_TIMER_MINUTES etc.); host_main uses
    # them so the host and the mock VM agree on the schedule.
    if [ "$DRYRUN" = "1" ]; then
        TIMER_MINUTES=${DRYRUN_TIMER_MINUTES:-8}; CONTROLLER_MINUTES=${DRYRUN_CONTROLLER_MINUTES:-9}
        POLLER_MINUTES=${DRYRUN_POLLER_MINUTES:-10}; DONE_MINUTES=${DRYRUN_DONE_MINUTES:-7}
    fi
    require_tool "$OCI_CLI"
    require_tool python3
    require_tool git
    require_tool curl
    require_tool sha256sum
    require_tool base64
    require_var REPO_URL
    require_var COMMIT
    require_var HOST_EGRESS_IP
    require_var CONTROLLER_JOB_ID
    require_var WATCHDOG_RUN_RECORD
    case "$COMMIT" in ''|*[!0-9a-f]*) die 2 "COMMIT must be lowercase hex" ;; esac
    if [ "${#COMMIT}" -ne 40 ]; then
        die 2 "COMMIT must be exactly 40 hex characters"
    fi
    # M8_DIR: the m8 directory (the host runs this script from the
    # m8/o_tests_v13/ tree). The freeze check and the manifest live there.
    SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    M8_DIR=${M8_DIR:-$(dirname "$SCRIPT_DIR")}
    [ -f "$M8_DIR/step0_verify_freeze.py" ] || die 2 "M8_DIR does not contain step0_verify_freeze.py: $M8_DIR"
    [ -f "$M8_DIR/o_tests_v13/o_tests_manifest.json" ] || die 2 "M8_DIR does not contain o_tests_v13/o_tests_manifest.json"
    [ -f "$M8_DIR/egress-proxy.py" ] || die 2 "M8_DIR does not contain egress-proxy.py"
    batch_id_resolve
    # (V11, rule 37) Early verdict replay: if this batch already has
    # a final verdict, replay it NOW, before any phase runs. The old
    # code only replayed inside host_phase_verdict(), after every
    # phase had run - so a missing phase marker in a finalized batch
    # could re-run a phase (including cloud-side phases) before the
    # stored verdict was replayed (ChatGPT V10 verdict, blocker 1).
    replay_stored_verdict
    record_event "batch_id=$BATCH_ID test_mode=$TEST_MODE timer_min=$TIMER_MINUTES controller_min=$CONTROLLER_MINUTES poller_min=$POLLER_MINUTES done_min=$DONE_MINUTES repo=$REPO_URL commit=$COMMIT"
    host_phase_freeze
    host_phase_o12_snapshot
    host_phase_repo
    host_phase_ocipreflight
    host_phase_secret
    host_phase_network
    host_phase_controller_checkpoint
    host_phase_vm_create
    host_phase_controller_verify
    host_phase_poller
    host_phase_done_wait
    host_phase_download
    host_phase_verify_terminate_o13
    host_phase_verdict
}

# batch_id_resolve - stable batch identity (Revision 9, spec rule
# 33). BATCH_ID is generated ONCE per batch and persisted in
# $BATCH_DIR/batch_id.txt (mode 600). Every later invocation of the
# same batch (including --resume and the dry-run's invocation 2)
# reuses the persisted value. If BATCH_ID is set in the environment
# AND differs from the persisted value, this is a hard FAIL (exit 1):
# a batch must retain one stable identity across the controller
# checkpoint, the VM results and the final verdict (ChatGPT V8
# verdict: V8 open item 1 NOT ACCEPTED). If there is no persisted
# value and this is a --resume invocation, the batch is INVALID
# (exit 2): a resume without an identity proves the batch dir is not
# a real first-invocation dir. Otherwise the ID is generated (or the
# operator-supplied env value is used) and persisted.
batch_id_resolve() {
    if [ -f "$BATCH_DIR/batch_id.txt" ]; then
        _persisted=$(cat "$BATCH_DIR/batch_id.txt" 2>/dev/null | tr -d '[:space:]')
        if [ -z "$_persisted" ]; then
            die 2 "batch_id.txt exists but is empty - batch INVALID"
        fi
        if [ -n "${BATCH_ID:-}" ] && [ "$BATCH_ID" != "$_persisted" ]; then
            die 1 "batch_id mismatch: environment BATCH_ID=$BATCH_ID but persisted batch_id=$_persisted - batch identity is stable, refusing to continue"
        fi
        BATCH_ID=$_persisted
        log "RUNNER batch_id reused from batch_id.txt: $BATCH_ID"
    else
        if [ "$RESUME" = "1" ]; then
            die 2 "no batch_id.txt in batch dir - cannot --resume a batch with no persisted identity"
        fi
        # (V10, rule 36) A batch dir that already contains completed
        # phase markers is a resumed batch, not a new one: its
        # identity must already exist. Generating a fresh BATCH_ID
        # here would silently re-identity a batch whose VM results
        # and verdict already carry the old one (ChatGPT V9 verdict,
        # open item 4). This applies even when --resume was omitted.
        _has_markers=0
        for _m in "$BATCH_DIR"/*.done; do
            [ -f "$_m" ] && _has_markers=1
        done
        if [ "$_has_markers" -eq 1 ]; then
            die 2 "no batch_id.txt in batch dir but completed phase markers exist - batch identity missing, refusing to continue"
        fi
        BATCH_ID=${BATCH_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
        printf '%s\n' "$BATCH_ID" > "$BATCH_DIR/batch_id.txt" || die 2 "cannot persist batch_id"
        chmod 600 "$BATCH_DIR/batch_id.txt" || die 2 "cannot chmod batch_id.txt"
        log "RUNNER batch_id generated and persisted: $BATCH_ID"
    fi
}

# H0: re-verify the M1-M7 freeze (Step 0). Any mismatch stops the batch.
host_phase_freeze() {
    phase_done freeze && return 0
    log "RUNNER phase=freeze"
    (cd "$M8_DIR" && python3 step0_verify_freeze.py) > "$BATCH_DIR/freeze_check.log" 2>&1 || {
        log "RUNNER freeze_check FAILED (see freeze_check.log)"
        die 2 "freeze check failed - M1-M7 manifests do not match; batch does not start"
    }
    grep -q "ALL MATCH" "$BATCH_DIR/freeze_check.log" || {
        log "RUNNER freeze_check output does not contain ALL MATCH"
        die 2 "freeze check output unexpected - batch does not start"
    }
    record_event "freeze=all_match"
    phase_mark freeze
}

# H0b: O12 snapshot (host-side, before the VM is created). Hashes the
# benchmark repo, the harness, and the M1-M7 frozen manifests (the
# m8 directory tree) so o12.sh verify can prove the run changed
# nothing on the host. The snapshot is taken AFTER the freeze check
# and BEFORE any cloud change; the runner writes nothing into M8_DIR
# during the batch (all batch files go to BATCH_DIR), so the
# snapshot must match at verify time.
host_phase_o12_snapshot() {
    phase_done o12_snapshot && return 0
    log "RUNNER phase=o12_snapshot"
    "$M8_DIR/o_tests_v13/o12.sh" snapshot "$BATCH_DIR/o12_snapshot.txt" "$M8_DIR" > "$BATCH_DIR/o12_snapshot.log" 2>&1 || {
        log "RUNNER o12 snapshot failed (see o12_snapshot.log)"
        die 2 "o12 snapshot failed - batch does not start"
    }
    record_event "o12_snapshot=1 manifest=$BATCH_DIR/o12_snapshot.txt"
    phase_mark o12_snapshot
}

# H1: verify the repo + commit. Clone to a scratch dir, check out the
# recorded commit, verify the manifest hash, then verify every listed
# file's hash against the manifest, and verify egress-proxy.py
# against its recorded hash. Any mismatch stops the batch.
host_phase_repo() {
    phase_done repo && return 0
    log "RUNNER phase=repo url=$REPO_URL commit=$COMMIT"
    REPO_SCRATCH="$BATCH_DIR/repo_scratch"
    rm -rf "$REPO_SCRATCH"
    if [ "${DRYRUN:-0}" = "1" ]; then
        # Dry-run (spec rule 29): there is no benchmark repo yet
        # (REPO_URL=dry-run:local-tree) and no git commit to check
        # out - COMMIT is the first 40 hex characters of the local
        # manifest SHA-256, recorded by the dry-run driver. Copy
        # the local tree instead of cloning, and skip the checkout;
        # the manifest + proxy hash checks below still run against
        # the copy, so the verification is the same.
        mkdir -p "$REPO_SCRATCH" || die 2 "cannot create repo scratch"
        cp -r "$M8_DIR/o_tests_v13" "$M8_DIR/egress-proxy.py" "$REPO_SCRATCH/" || die 2 "dry-run repo copy failed"
        printf 'dry-run: local tree copied (no clone, no checkout)\n' > "$BATCH_DIR/git_clone.log"
        printf 'dry-run: COMMIT is the manifest SHA-256 prefix, not a git commit\n' > "$BATCH_DIR/git_checkout.log"
        record_event "repo_dryrun local_tree_copied commit_is_manifest_prefix=$COMMIT"
    else
    git clone --quiet "$REPO_URL" "$REPO_SCRATCH" > "$BATCH_DIR/git_clone.log" 2>&1 || {
        log "RUNNER git clone failed (see git_clone.log)"
        die 2 "repo clone failed - batch does not start"
    }
    (cd "$REPO_SCRATCH" && git checkout --quiet "$COMMIT") > "$BATCH_DIR/git_checkout.log" 2>&1 || {
        log "RUNNER git checkout $COMMIT failed (see git_checkout.log)"
        die 2 "commit $COMMIT not found in repo - batch does not start"
    }
    fi
    [ -f "$REPO_SCRATCH/o_tests_v13/o_tests_manifest.json" ] || die 2 "repo has no o_tests_v13/o_tests_manifest.json at $COMMIT"
    [ -f "$REPO_SCRATCH/egress-proxy.py" ] || die 2 "repo has no egress-proxy.py at $COMMIT"
    MANIFEST_SHA256=$(sha256sum "$M8_DIR/o_tests_v13/o_tests_manifest.json" | awk '{print $1}')
    CLONE_MANIFEST_SHA256=$(sha256sum "$REPO_SCRATCH/o_tests_v13/o_tests_manifest.json" | awk '{print $1}')
    [ "$MANIFEST_SHA256" = "$CLONE_MANIFEST_SHA256" ] || die 2 "manifest hash mismatch: local=$MANIFEST_SHA256 clone=$CLONE_MANIFEST_SHA256"
    record_event "manifest_sha256=$MANIFEST_SHA256"
    EGRESS_PROXY_SHA256=$(sha256sum "$M8_DIR/egress-proxy.py" | awk '{print $1}')
    CLONE_PROXY_SHA256=$(sha256sum "$REPO_SCRATCH/egress-proxy.py" | awk '{print $1}')
    [ "$EGRESS_PROXY_SHA256" = "$CLONE_PROXY_SHA256" ] || die 2 "egress-proxy.py hash mismatch: local=$EGRESS_PROXY_SHA256 clone=$CLONE_PROXY_SHA256"
    record_event "egress_proxy_sha256=$EGRESS_PROXY_SHA256"
    # Every file listed in the manifest must match its recorded hash.
    (cd "$REPO_SCRATCH/o_tests_v13" && python3 - "$M8_DIR/o_tests_v13/o_tests_manifest.json" <<'PYEOF'
import hashlib, json, sys
manifest = json.load(open(sys.argv[1]))
bad = []
for name, want in manifest.items():
    try:
        got = hashlib.sha256(open(name, "rb").read()).hexdigest()
    except OSError as e:
        bad.append("%s unreadable %s" % (name, e))
        continue
    if got != want:
        bad.append("%s got=%s want=%s" % (name, got, want))
if bad:
    print("MANIFEST_MISMATCH")
    for b in bad:
        print(b)
    sys.exit(1)
print("MANIFEST_OK entries=%d" % len(manifest))
PYEOF
    ) > "$BATCH_DIR/manifest_check.log" 2>&1 || {
        log "RUNNER manifest file check failed (see manifest_check.log)"
        die 2 "repo files do not match the manifest - batch does not start"
    }
    grep -q "MANIFEST_OK" "$BATCH_DIR/manifest_check.log" || die 2 "manifest check output unexpected"
    record_event "repo_verified commit=$COMMIT manifest_entries=$(grep -o 'entries=[0-9]*' "$BATCH_DIR/manifest_check.log" | cut -d= -f2)"
    phase_mark repo
}

# H2: OCI pre-creation checks (read-only). Home region must be
# me-dubai-1; no other A1 VM may exist; A1 service-limit headroom
# must be available. (Service limits are headroom, NOT physical
# capacity - a launch failure is a STOP, not a retry.)
host_phase_ocipreflight() {
    phase_done ocipreflight && return 0
    log "RUNNER phase=ocipreflight"
    TENANCY_OCID=$("$OCI_CLI" iam tenancy get --query 'data.id' --raw-output 2>"$BATCH_DIR/tenancy.err") || {
        log "RUNNER tenancy get failed (see tenancy.err)"
        die 2 "cannot read tenancy OCID - batch does not start"
    }
    [ -n "$TENANCY_OCID" ] || die 2 "tenancy OCID empty"
    record_event "tenancy_ocid=$TENANCY_OCID"
    HOME_REGION=$("$OCI_CLI" iam tenancy get --query 'data."home-region-key"' --raw-output 2>/dev/null) || die 2 "cannot read home region"
    [ "$HOME_REGION" = "DXB" ] || die 2 "home region is $HOME_REGION, not DXB (me-dubai-1) - batch does not start"
    record_event "home_region=$HOME_REGION"
    EXISTING=$("$OCI_CLI" compute instance list --compartment-id "$TENANCY_OCID" --query 'length(data)' --raw-output 2>"$BATCH_DIR/instances.err") || {
        log "RUNNER instance list failed (see instances.err)"
        die 2 "cannot list instances - batch does not start"
    }
    [ "$EXISTING" = "0" ] || die 2 "$EXISTING instance(s) already exist - no other A1 VM may exist; batch does not start"
    record_event "existing_instances=0"
    # A1 service-limit headroom (AD JJYF:ME-DUBAI-1-AD-1).
    for _limit in standard-a1-core-count standard-a1-memory-count; do
        _avail=$("$OCI_CLI" limits resource-availability get --service-name compute --limit-name "$_limit" --compartment-id "$TENANCY_OCID" --availability-domain JJYF:ME-DUBAI-1-AD-1 --query 'data."available"' --raw-output 2>/dev/null) || die 2 "cannot read A1 limit $_limit"
        record_event "a1_limit_available $_limit=$_avail"
    done
    # Resolve the Oracle Linux 9 Arm64 platform image for A1.Flex at
    # run time (no hardcoded image OCID - the platform image OCID is
    # not a fact this script may guess). Latest by creation time.
    IMAGE_OCID=$("$OCI_CLI" compute image list --compartment-id "$TENANCY_OCID" --operating-system "Oracle Linux" --operating-system-version "9" --shape VM.Standard.A1.Flex --sort-by TIMECREATED --sort-order DESC --query 'data[0].id' --raw-output 2>"$BATCH_DIR/image.err") || {
        log "RUNNER image list failed (see image.err)"
        die 2 "cannot resolve the Oracle Linux 9 Arm64 image - batch does not start"
    }
    [ -n "$IMAGE_OCID" ] || die 2 "no Oracle Linux 9 Arm64 image found for VM.Standard.A1.Flex"
    record_event "image_ocid=$IMAGE_OCID"
    printf '%s\n' "$TENANCY_OCID" > "$BATCH_DIR/tenancy_ocid.txt"
    printf '%s\n' "$IMAGE_OCID" > "$BATCH_DIR/image_ocid.txt"
    phase_mark ocipreflight
}

# H3: per-batch host RSA keypair (Revision 12, spec rule 41).
# The host NO LONGER generates the per-batch HMAC secret: the
# secret is generated INSIDE the VM by the harness (bootstrap /
# vm_setup_dryrun) and never enters user-data, so the V11
# user-data-transit contradiction is closed. What the host
# generates here is a fresh per-batch RSA-2048 keypair: the PUBLIC
# key goes into user-data (a public key is not a secret), the
# PRIVATE key stays on the host (mode 600) and is used once, in
# the download phase, to decrypt the VM's encrypted secret
# (/results/hmac_secret.enc). The private key is destroyed after
# the verdict, with the secret (host_phase_verdict). A fresh
# keypair is generated for every batch and never reused. Only the
# SHA-256 of the public key file is recorded - never key material.
host_phase_secret() {
    phase_done secret && return 0
    log "RUNNER phase=secret"
    require_tool openssl || die 2 "openssl is required for the per-batch host keypair"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$BATCH_DIR/hmac_host_key.pem" 2>"$BATCH_DIR/hmac_host_key.err" || die 2 "cannot generate per-batch host RSA keypair (see hmac_host_key.err)"
    chmod 600 "$BATCH_DIR/hmac_host_key.pem"
    openssl pkey -in "$BATCH_DIR/hmac_host_key.pem" -pubout -out "$BATCH_DIR/hmac_host_key.pub" 2>/dev/null || die 2 "cannot extract per-batch host public key"
    chmod 600 "$BATCH_DIR/hmac_host_key.pub"
    grep -q "BEGIN PUBLIC KEY" "$BATCH_DIR/hmac_host_key.pub" || die 2 "generated host public key is not a PEM public key"
    if grep -q "PRIVATE KEY" "$BATCH_DIR/hmac_host_key.pub"; then die 2 "host public key file contains private key material"; fi
    record_event "hmac_host_pubkey_sha256=$(sha256sum "$BATCH_DIR/hmac_host_key.pub" | awk '{print $1}')"
    # (V13, spec rule 43) Fresh per-batch challenge. The challenge
    # is a PUBLIC nonce (32 hex chars, secrets.token_hex(16)) - it
    # is NOT a secret and NOT key material, so it may travel in
    # user-data and in batch.env. It binds the authenticated secret
    # delivery to this batch: the VM signs batch_id + challenge +
    # ciphertext SHA-256, and the host verifies the signature over
    # ITS OWN recorded challenge, so a signature made for any other
    # batch (or a replayed signature from an earlier batch) fails.
    python3 -c "import secrets; print(secrets.token_hex(16))" > "$BATCH_DIR/batch_challenge.txt" 2>/dev/null || die 2 "cannot generate per-batch challenge"
    chmod 600 "$BATCH_DIR/batch_challenge.txt"
    grep -Eq '^[0-9a-f]{32}$' "$BATCH_DIR/batch_challenge.txt" || die 2 "per-batch challenge is not 32 hex chars"
    record_event "batch_challenge_sha256=$(sha256sum "$BATCH_DIR/batch_challenge.txt" | awk '{print $1}')"
    # (V13, spec rule 43) Pin the OCI instance-principal root CA
    # for this batch. The root CA is the trust anchor the host
    # already trusts: it is fetched fresh per batch from Oracle's
    # auth endpoint for the home region (me-dubai-1, verified as
    # HOME_REGION=DXB in ocipreflight) and recorded by SHA-256.
    # Real path: `oci raw-request` (signed with the configured API
    # key) first; if the endpoint's response is not JSON-parseable
    # by raw-request, fall back to plain curl over HTTPS to the
    # same official endpoint. Either way the fetched material is
    # validated before use (must parse as an x509 CA certificate) -
    # the trust comes from TLS to Oracle's auth service plus the
    # chain/OCID/signature checks in the download phase, not from
    # the fetch transport alone. Dry-run path: generate a MOCK
    # root CA + mock intermediate CA as labelled fixtures (the
    # dry-run proves sign/verify/bind/reject logic, NOT real OCI
    # issuance - real issuance is proven by setup check 22 on the
    # real VM and by the host preflight root-CA fetch). The mock
    # root key is single-use (deleted after signing the
    # intermediate); the intermediate key is kept (mode 600) until
    # the leaf is issued in host_phase_vm_create_dryrun.
    if [ "$DRYRUN" = "1" ]; then
        mkdir -p "$BATCH_DIR/mock_identity" || die 2 "cannot create mock identity dir"
        chmod 700 "$BATCH_DIR/mock_identity"
        openssl req -x509 -newkey rsa:2048 -keyout "$BATCH_DIR/mock_identity/root_key.pem" -out "$BATCH_DIR/oci_root_ca.pem" -days 2 -nodes -subj "/CN=M8-MOCK-OCI-ROOT-CA/O=M8-MOCK" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>"$BATCH_DIR/mock_identity/root_ca.err" || die 2 "cannot generate mock OCI root CA (see mock_identity/root_ca.err)"
        chmod 600 "$BATCH_DIR/mock_identity/root_key.pem"
        chmod 644 "$BATCH_DIR/oci_root_ca.pem"
        openssl req -newkey rsa:2048 -keyout "$BATCH_DIR/mock_identity/intermediate_key.pem" -out "$BATCH_DIR/mock_identity/intermediate.csr" -nodes -subj "/CN=M8-MOCK-OCI-INTERMEDIATE-CA/O=M8-MOCK" 2>"$BATCH_DIR/mock_identity/intermediate_key.err" || die 2 "cannot generate mock intermediate key"
        chmod 600 "$BATCH_DIR/mock_identity/intermediate_key.pem"
        printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$BATCH_DIR/mock_identity/intermediate.ext"
        openssl x509 -req -in "$BATCH_DIR/mock_identity/intermediate.csr" -CA "$BATCH_DIR/oci_root_ca.pem" -CAkey "$BATCH_DIR/mock_identity/root_key.pem" -CAcreateserial -out "$BATCH_DIR/mock_identity/intermediate.pem" -days 2 -extfile "$BATCH_DIR/mock_identity/intermediate.ext" 2>"$BATCH_DIR/mock_identity/intermediate.err" || die 2 "cannot sign mock intermediate CA (see mock_identity/intermediate.err)"
        chmod 644 "$BATCH_DIR/mock_identity/intermediate.pem"
        rm -f "$BATCH_DIR/mock_identity/root_key.pem" "$BATCH_DIR/oci_root_ca.srl" "$BATCH_DIR/mock_identity/intermediate.csr" "$BATCH_DIR/mock_identity/intermediate.ext"
        openssl x509 -noout -text -in "$BATCH_DIR/oci_root_ca.pem" 2>/dev/null | grep -q "CA:TRUE" || die 2 "mock OCI root CA is not a CA certificate"
        record_event "oci_root_ca_sha256=$(sha256sum "$BATCH_DIR/oci_root_ca.pem" | awk '{print $1}') mock_identity=fixtures"
    else
        _root_raw="$BATCH_DIR/oci_root_ca.raw"
        _root_url="https://auth.me-dubai-1.oraclecloud.com/v1/instancePrincipalRootCACertificates"
        if ! "$OCI_CLI" raw-request --http-method GET --target-uri "$_root_url" > "$_root_raw" 2>"$BATCH_DIR/oci_root_ca.err"; then
            log "RUNNER oci raw-request for the instance-principal root CA failed (see oci_root_ca.err) - falling back to plain curl over HTTPS to the same official endpoint"
            curl -fsSL --max-time 30 "$_root_url" > "$_root_raw" 2>"$BATCH_DIR/oci_root_ca.err" || die 2 "cannot fetch the OCI instance-principal root CA (see oci_root_ca.err)"
        fi
        python3 - "$_root_raw" "$BATCH_DIR/oci_root_ca.pem" <<'PYEOF' || die 2 "cannot extract PEM blocks from the OCI root CA response"
import json, re, sys
raw = open(sys.argv[1], 'rb').read().decode('utf-8', 'replace')
texts = []
try:
    obj = json.loads(raw)
    data = obj.get('data', obj) if isinstance(obj, dict) else obj
    if isinstance(data, str):
        texts.append(data)
    elif isinstance(data, list):
        texts.extend(str(x) for x in data)
except Exception:
    texts.append(raw)
pems = []
for t in texts:
    pems.extend(re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', t, re.S))
if not pems:
    sys.exit('no PEM certificate block found in the OCI root CA response')
with open(sys.argv[2], 'w') as f:
    f.write('\n'.join(pems) + '\n')
PYEOF
        chmod 644 "$BATCH_DIR/oci_root_ca.pem"
        openssl x509 -noout -text -in "$BATCH_DIR/oci_root_ca.pem" 2>/dev/null | grep -q "CA:TRUE" || die 2 "fetched OCI root CA is not a CA certificate"
        record_event "oci_root_ca_sha256=$(sha256sum "$BATCH_DIR/oci_root_ca.pem" | awk '{print $1}')"
    fi
    phase_mark secret
}

# H4: per-batch network (OCI API, host-side), in creation order:
# VCN (10.0.0.0/16), internet gateway, route table (0.0.0.0/0 ->
# IGW), security list (ingress TCP 8080 from HOST_EGRESS_IP/32
# ONLY; egress TCP 443 to 0.0.0.0/0; egress UDP+TCP 53 to
# 169.254.169.254/32; NO IPv6 rules), subnet (10.0.0.0/24).
# Every OCID is recorded. Any creation failure stops the batch.
host_phase_network() {
    phase_done network && return 0
    log "RUNNER phase=network"
    TENANCY_OCID=$(cat "$BATCH_DIR/tenancy_ocid.txt")
    VCN_OCID=$("$OCI_CLI" network vcn create --compartment-id "$TENANCY_OCID" --cidr-block 10.0.0.0/16 --display-name "m8-batch-$BATCH_ID" --query 'data.id' --raw-output 2>"$BATCH_DIR/vcn.err") || {
        log "RUNNER VCN create failed (see vcn.err)"
        die 2 "VCN creation failed - batch does not start"
    }
    record_event "vcn_ocid=$VCN_OCID"
    IGW_OCID=$("$OCI_CLI" network internet-gateway create --compartment-id "$TENANCY_OCID" --vcn-id "$VCN_OCID" --is-enabled true --display-name "m8-batch-$BATCH_ID" --query 'data.id' --raw-output 2>"$BATCH_DIR/igw.err") || die 2 "internet gateway creation failed"
    record_event "igw_ocid=$IGW_OCID"
    RT_OCID=$("$OCI_CLI" network route-table create --compartment-id "$TENANCY_OCID" --vcn-id "$VCN_OCID" --display-name "m8-batch-$BATCH_ID" --route-rules '[{"cidrBlock":"0.0.0.0/0","networkEntityId":"'"$IGW_OCID"'"}]' --query 'data.id' --raw-output 2>"$BATCH_DIR/rt.err") || die 2 "route table creation failed"
    record_event "rt_ocid=$RT_OCID"
    SECLIST_OCID=$("$OCI_CLI" network security-list create --compartment-id "$TENANCY_OCID" --vcn-id "$VCN_OCID" --display-name "m8-batch-$BATCH_ID" --ingress-security-rules '[{"protocol":"6","source":"'"$HOST_EGRESS_IP"'/32","tcpOptions":{"destinationPortRange":{"min":8080,"max":8080}}}]' --egress-security-rules '[{"protocol":"6","destination":"0.0.0.0/0","tcpOptions":{"destinationPortRange":{"min":443,"max":443}}},{"protocol":"17","destination":"169.254.169.254/32","udpOptions":{"destinationPortRange":{"min":53,"max":53}}},{"protocol":"6","destination":"169.254.169.254/32","tcpOptions":{"destinationPortRange":{"min":53,"max":53}}}]' --query 'data.id' --raw-output 2>"$BATCH_DIR/seclist.err") || {
        log "RUNNER security list create failed (see seclist.err)"
        die 2 "security list creation failed - batch does not start"
    }
    record_event "seclist_ocid=$SECLIST_OCID host_egress_ip=$HOST_EGRESS_IP"
    SUBNET_OCID=$("$OCI_CLI" network subnet create --compartment-id "$TENANCY_OCID" --vcn-id "$VCN_OCID" --cidr-block 10.0.0.0/24 --route-table-id "$RT_OCID" --security-list-ids '["'"$SECLIST_OCID"'"]' --display-name "m8-batch-$BATCH_ID" --query 'data.id' --raw-output 2>"$BATCH_DIR/subnet.err") || die 2 "subnet creation failed"
    record_event "subnet_ocid=$SUBNET_OCID"
    printf '%s\n' "$VCN_OCID" > "$BATCH_DIR/vcn_ocid.txt"
    printf '%s\n' "$IGW_OCID" > "$BATCH_DIR/igw_ocid.txt"
    printf '%s\n' "$RT_OCID" > "$BATCH_DIR/rt_ocid.txt"
    printf '%s\n' "$SECLIST_OCID" > "$BATCH_DIR/seclist_ocid.txt"
    printf '%s\n' "$SUBNET_OCID" > "$BATCH_DIR/subnet_ocid.txt"
    phase_mark network
}

# H5 (controller checkpoint, before VM creation): the operator must
# have created the controller cron job BEFORE the VM (Sec. 11.1 step
# 3) and recorded its verification in
# $BATCH_DIR/controller_verified - a file containing exactly three
# lines: job_id=<CONTROLLER_JOB_ID>, command=<the command as stored
# in the cron job>, run_record=<WATCHDOG_RUN_RECORD>. At this stage
# the command is the PLACEHOLDER (no instance OCID yet); the runner
# checks the job id and the run-record path match, and records that
# the controller is armed. The exact-command check with the real
# OCID happens in host_phase_controller_verify, after creation.
# This script cannot call the Muse cron API - the operator's
# verification (via cron.list) is the evidence, recorded in the file.
host_phase_controller_checkpoint() {
    phase_done controller_checkpoint && return 0
    log "RUNNER phase=controller_checkpoint"
    _cv="$BATCH_DIR/controller_verified"
    [ -f "$_cv" ] || {
        log "RUNNER controller_verified missing: $BATCH_DIR/controller_verified"
        log "RUNNER the operator must create the controller cron job (Sec. 11.1 step 3), verify it via cron.list (exists, enabled), and write controller_verified with job_id=$CONTROLLER_JOB_ID, the stored command, and run_record=$WATCHDOG_RUN_RECORD - then re-run with --resume"
        die 2 "controller not verified before VM creation - batch does not start"
    }
    _job=$(grep '^job_id=' "$_cv" 2>/dev/null | cut -d= -f2-)
    _rr=$(grep '^run_record=' "$_cv" 2>/dev/null | cut -d= -f2-)
    [ "$_job" = "$CONTROLLER_JOB_ID" ] || die 2 "controller_verified job_id ($_job) != CONTROLLER_JOB_ID ($CONTROLLER_JOB_ID)"
    [ "$_rr" = "$WATCHDOG_RUN_RECORD" ] || die 2 "controller_verified run_record ($_rr) != WATCHDOG_RUN_RECORD ($WATCHDOG_RUN_RECORD)"
    grep -q '^command=' "$_cv" || die 2 "controller_verified has no command= line"
    record_event "controller_checkpoint job_id=$CONTROLLER_JOB_ID run_record=$WATCHDOG_RUN_RECORD"
    phase_mark controller_checkpoint
}

# generate_user_data - build the cloud-init user-data for the VM and
# write it to $1 (plain text, reviewed before creation). The
# user-data contains: (a) the bootstrap script (creates the users,
# installs git, clones the repo at COMMIT, verifies the manifest +
# hashes - including the egress-proxy.py hash against the recorded
# reviewed hash - installs the proxy from the verified clone, starts
# it inside its own cgroup, copies the tree to /opt/harness, writes
# batch.env, generates the per-batch HMAC secret INSIDE the VM and
# encrypts it for the host, signs the delivery with the VM's OCI
# instance-identity key (spec rule 43), then execs run_batch.sh
# vm); (b) the host per-batch PUBLIC key (not a secret); (c) the
# per-batch CHALLENGE (a public nonce, not a secret - it binds the
# signed delivery to this batch). NO secret and NO private key is
# in user-data (spec rules 41, 43).
# host's per-batch PUBLIC key (PEM) - a public key is not a secret,
# and it is the ONLY key material in user-data (Revision 12, spec
# rule 41: the per-batch HMAC secret NEVER enters user-data - the
# V11 transit + scrub design is withdrawn). The proxy source is NOT
# embedded in the user-data (that would add ~11 KB of base64 and
# risk the user-data size limit): it comes from the verified repo
# clone, and its hash is checked against the recorded reviewed hash
# before it is installed. Root egress is permitted during setup
# (Sec. 5.3), so dnf and git run directly - the proxy is only
# needed once the workload runs. The generated user-data is scanned
# for forbidden patterns (OCI OCIDs, private keys, tokens, secret
# assignments) before creation - any hit is a STOP.
generate_user_data() {
    _out=$1
    _pubkey="$BATCH_DIR/hmac_host_key.pub"
    [ -f "$_pubkey" ] || die 2 "per-batch host public key missing ($BATCH_DIR/hmac_host_key.pub) - the secret phase must run first"
    [ -f "$BATCH_DIR/batch_challenge.txt" ] || die 2 "per-batch challenge missing ($BATCH_DIR/batch_challenge.txt) - the secret phase must run first"
    _challenge=$(cat "$BATCH_DIR/batch_challenge.txt" | tr -d '[:space:]')
    _manifest_sha=$(sha256sum "$M8_DIR/o_tests_v13/o_tests_manifest.json" | awk '{print $1}')
    _proxy_sha=$(sha256sum "$M8_DIR/egress-proxy.py" | awk '{print $1}')
    {
        printf '#!/bin/sh\n'
        printf '# m8 batch bootstrap (generated by run_batch.sh host mode).\n'
        printf '# Runs as root via cloud-init at first boot. Creates the\n'
        printf '# users, installs git, clones the benchmark repo at the\n'
        printf '# recorded commit, verifies the manifest + hashes (including\n'
        printf '# the egress-proxy.py hash), installs the proxy from the\n'
        printf '# verified clone, starts it, copies the tree to /opt/harness,\n'
        printf '# writes batch.env, generates the per-batch HMAC secret\n'
        printf '# INSIDE the VM and encrypts it for the host (spec rule\n'
        printf '# 41), then execs run_batch.sh vm. Any failure exits\n'
        printf '# non-zero and the VM is terminated by the host (no case\n'
        printf '# runs).\n'
        printf 'set -u\n'
        printf 'BATCH_ID=%s\n' "$BATCH_ID"
        printf 'REPO_URL=%s\n' "$REPO_URL"
        printf 'COMMIT=%s\n' "$COMMIT"
        printf 'MANIFEST_SHA256=%s\n' "$_manifest_sha"
        printf 'EGRESS_PROXY_SHA256=%s\n' "$_proxy_sha"
        printf 'TIMER_MINUTES=%s\n' "$TIMER_MINUTES"
        printf 'BATCH_CHALLENGE=%s\n' "$_challenge"
        printf '# (V12, spec rule 41) No HMAC secret is in this file.\n'
        printf '# The host per-batch PUBLIC key is embedded below (after\n'
        printf '# the directories are created); the secret is generated\n'
        printf '# inside the VM and encrypted with that public key.\n'
        printf '%s\n' 'log() { printf "%s %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown-time)" "$1" >> /var/log/m8-bootstrap.log 2>/dev/null || true; printf "%s %s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown-time)" "$1"; }'
        printf '%s\n' 'die() { log "BOOTSTRAP_FATAL $1"; exit 1; }'
        printf '%s\n' 'mkdir -p /opt/proxy /opt/harness /var/log /results || die "cannot create dirs"'
        printf '%s\n' '# V12 (spec rule 41): the host per-batch PUBLIC key. A'
        printf '%s\n' '# public key is not a secret - it is the only key material'
        printf '%s\n' '# in user-data. The VM encrypts the per-batch secret with'
        printf '%s\n' '# it and publishes the ciphertext for the host to pull.'
        printf '%s\n' 'cat > /opt/harness/host_pubkey.pem <<'"'"'HOSTPUBEOF'"'"''
        while IFS= read -r _line; do printf '%s\n' "$_line"; done < "$_pubkey"
        printf '%s\n' 'HOSTPUBEOF'
        printf '%s\n' 'chmod 600 /opt/harness/host_pubkey.pem || die "cannot chmod host_pubkey.pem"'
        printf '%s\n' 'grep -q "BEGIN PUBLIC KEY" /opt/harness/host_pubkey.pem || die "host_pubkey.pem is not a PEM public key"'
        printf '%s\n' '# /opt/harness is mode 0710 root:harness (Revision 8 fix): the'
        printf '%s\n' '# results server runs as UID 1000 (harness) and its source'
        printf '%s\n' '# lives in /opt/harness, so the directory needs group-execute'
        printf '%s\n' '# for the harness group. Mode 0700 (V7) made it unreadable'
        printf '%s\n' '# by its own UID, so the results server could never start.'
        printf '%s\n' '# 0710 still bars the workload UID 1001 (not in group harness)'
        printf '%s\n' '# from reading or listing the directory, and the HMAC secret'
        printf '%s\n' '# stays mode 600 root (unreadable by UID 1000).'
        printf '%s\n' 'chown root:harness /opt/harness || die "cannot chown harness dir"'
        printf '%s\n' 'chmod 0710 /opt/harness || die "cannot chmod harness dir"'
        printf '%s\n' 'chown root:proxy /opt/proxy || die "cannot chown proxy dir"'
        printf '%s\n' 'chmod 0710 /opt/proxy || die "cannot chmod proxy dir"'
        printf '%s\n' 'id harness >/dev/null 2>&1 || useradd -u 1000 -m -s /sbin/nologin harness || die "cannot create harness user"'
        printf '%s\n' 'id workload >/dev/null 2>&1 || useradd -u 1001 -m -s /sbin/nologin workload || die "cannot create workload user"'
        printf '%s\n' 'id proxy >/dev/null 2>&1 || useradd -u 1002 -m -s /sbin/nologin proxy || die "cannot create proxy user"'
        printf '%s\n' '# Root egress is permitted during setup (Sec. 5.3: UID 0 outbound is'
        printf '%s\n' '# permitted during setup and denied only for the workload run, when'
        printf '%s\n' '# vm_setup applies the restrictive rules). So dnf and git run DIRECTLY'
        printf '%s\n' '# here - NOT through the proxy (the proxy allow-list has only the five'
        printf '%s\n' '# domains, and dnf needs the Oracle repos, which are not allow-listed).'
        printf '%s\n' 'command -v git >/dev/null 2>&1 || dnf install -y git || die "cannot install git"'
        printf '%s\n' 'command -v python3 >/dev/null 2>&1 || dnf install -y python3 || die "cannot install python3"'
        printf '%s\n' 'rm -rf /tmp/m8-repo && git clone --quiet "$REPO_URL" /tmp/m8-repo || die "git clone failed"'
        printf '%s\n' '(cd /tmp/m8-repo && git checkout --quiet "$COMMIT") || die "git checkout $COMMIT failed"'
        printf '%s\n' '[ -f /tmp/m8-repo/o_tests_v13/o_tests_manifest.json ] || die "repo has no manifest"'
        printf '%s\n' '[ -f /tmp/m8-repo/egress-proxy.py ] || die "repo has no egress-proxy.py"'
        printf '%s\n' '_cm=$(sha256sum /tmp/m8-repo/o_tests_v13/o_tests_manifest.json | awk "{print \$1}")'
        printf '%s\n' '[ "$_cm" = "$MANIFEST_SHA256" ] || die "cloned manifest hash mismatch"'
        printf '%s\n' '_cp=$(sha256sum /tmp/m8-repo/egress-proxy.py | awk "{print \$1}")'
        printf '%s\n' '[ "$_cp" = "$EGRESS_PROXY_SHA256" ] || die "cloned proxy hash mismatch"'
        printf '%s\n' '(cd /tmp/m8-repo/o_tests_v13 && python3 - /tmp/m8-repo/o_tests_v13/o_tests_manifest.json <<PYEOF2'
        printf '%s\n' 'import hashlib, json, sys'
        printf '%s\n' 'manifest = json.load(open(sys.argv[1]))'
        printf '%s\n' 'bad = []'
        printf '%s\n' 'for name, want in manifest.items():'
        printf '%s\n' '    try:'
        printf '%s\n' '        got = hashlib.sha256(open(name, "rb").read()).hexdigest()'
        printf '%s\n' '    except OSError as e:'
        printf '%s\n' '        bad.append("%s unreadable %s" % (name, e))'
        printf '%s\n' '        continue'
        printf '%s\n' '    if got != want:'
        printf '%s\n' '        bad.append("%s mismatch" % name)'
        printf '%s\n' 'if bad:'
        printf '%s\n' '    print("MANIFEST_MISMATCH")'
        printf '%s\n' '    sys.exit(1)'
        printf '%s\n' 'print("MANIFEST_OK")'
        printf '%s\n' 'PYEOF2'
        printf '%s\n' ') || die "cloned files do not match the manifest"'
        printf '%s\n' '# Install the proxy from the VERIFIED clone (its hash was checked'
        printf '%s\n' '# against EGRESS_PROXY_SHA256 above) and start it as UID 1002.'
        printf '%s\n' 'cp /tmp/m8-repo/egress-proxy.py /opt/proxy/egress-proxy.py || die "cannot install proxy"'
        printf '%s\n' '# The proxy runs as UID 1002 (proxy), so its source and its'
        printf '%s\n' '# filter must be READABLE by that UID: mode 640 root:proxy'
        printf '%s\n' '# (Revision 8 fix - V7 chmod 600 made the proxy unreadable'
        printf '%s\n' '# by its own UID, so it could never start; found by the'
        printf '%s\n' '# dry-run). The /opt/proxy DIRECTORY is mode 0710 root:proxy'
        printf '%s\n' '# (group-execute so UID 1002 can traverse it).'
        printf '%s\n' 'chown root:proxy /opt/proxy/egress-proxy.py || die "cannot chown proxy"'
        printf '%s\n' 'chmod 640 /opt/proxy/egress-proxy.py || die "cannot chmod proxy"'
        printf '%s\n' 'printf "%s\n" "^github\\.com$" "^objects\\.githubusercontent\\.com$" "^registry\\.npmjs\\.org$" "^pypi\\.org$" "^files\\.pythonhosted\\.org$" > /opt/proxy/filter || die "cannot write filter"'
        printf '%s\n' 'chown root:proxy /opt/proxy/filter || die "cannot chown filter"'
        printf '%s\n' 'chmod 640 /opt/proxy/filter || die "cannot chmod filter"'
        printf '%s\n' 'touch /var/log/m8-proxy.log || die "cannot create proxy log"'
        printf '%s\n' 'chown proxy:proxy /var/log/m8-proxy.log || die "cannot chown proxy log"'
        printf '%s\n' 'chmod 644 /var/log/m8-proxy.log || die "cannot chmod proxy log"'
        printf '%s\n' '# V12 (spec rule 40): the proxy runs inside its own cgroup'
        printf '%s\n' '# /sys/fs/cgroup/proxy (memory.max 512 MiB, cpu.max 0.5 CPU,'
        printf '%s\n' '# pids.max 64) - independent of the workload cgroup, so a'
        printf '%s\n' '# hostile workload cannot exhaust the VM through the proxy.'
        printf '%s\n' 'for _c in cpu memory pids; do grep -qw "$_c" /sys/fs/cgroup/cgroup.controllers || die "controller $_c not available for proxy cgroup"; done'
        printf '%s\n' 'mkdir -p /sys/fs/cgroup/proxy || die "cannot create proxy cgroup"'
        printf '%s\n' 'printf "+cpu +memory +pids " > /sys/fs/cgroup/cgroup.subtree_control || die "cannot enable proxy cgroup controllers"'
        printf '%s\n' 'printf "536870912" > /sys/fs/cgroup/proxy/memory.max || die "cannot set proxy memory.max"'
        printf '%s\n' 'printf "50000 100000" > /sys/fs/cgroup/proxy/cpu.max || die "cannot set proxy cpu.max"'
        printf '%s\n' 'printf "64" > /sys/fs/cgroup/proxy/pids.max || die "cannot set proxy pids.max"'
        printf '%s\n' 'nohup setpriv --reuid=1002 --regid=1002 --clear-groups --inh-caps=-all --ambient-caps=-all --no-new-privs python3 /opt/proxy/egress-proxy.py >/var/log/m8-proxy.out 2>&1 &'
        printf '%s\n' 'echo $! > /sys/fs/cgroup/proxy/cgroup.procs || die "cannot place proxy in proxy cgroup"'
        printf '%s\n' 'sleep 2'
        printf '%s\n' 'grep -q "^$!$" /sys/fs/cgroup/proxy/cgroup.procs || die "proxy not in proxy cgroup"'
        printf '%s\n' 'cp /tmp/m8-repo/o_tests_v13/*.sh /opt/harness/ || die "cannot copy scripts"'
        printf '%s\n' 'cp /tmp/m8-repo/o_tests_v13/o_tests_manifest.json /opt/harness/ || die "cannot copy manifest"'
        printf '%s\n' '# The O-test scripts run as the workload UID 1001 (run_sandbox'
        printf '%s\n' '# setprivs to 1001 and execs the script), so they must be'
        printf '%s\n' '# READABLE and EXECUTABLE by UID 1001: mode 755. Mode 700'
        printf '%s\n' '# (V7) made them root-only, so every case failed with'
        printf '%s\n' '# "Permission denied" and was INCONCLUSIVE. The scripts are'
        printf '%s\n' '# reviewed harness code, not secrets; the secrets (batch.env,'
        printf '%s\n' '# hmac.key) stay mode 600 root. (Revision 8 fix, found by'
        printf '%s\n' '# the dry-run.)'
        printf '%s\n' 'chmod 755 /opt/harness/*.sh || die "cannot chmod scripts"'
        printf '%s\n' '# V13 (spec rule 43): learn this instance'"'"'s OCID from IMDS'
        printf '%s\n' '# for batch.env - setup check 22 compares it against the'
        printf '%s\n' '# identity certificate'"'"'s OCID. (The host already knows the'
        printf '%s\n' '# OCID from the launch response; this is the VM'"'"'s'
        printf '%s\n' '# independent read of the same value.)'
        printf '%s\n' 'INSTANCE_OCID=$(curl -fsSL -H "Authorization: Bearer <redacted>" --max-time 10 http://169.254.169.254/opc/v2/instance/ 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('"'"'id'"'"','"'"''"'"'))" 2>/dev/null) || true'
        printf '%s\n' '[ -n "$INSTANCE_OCID" ] || INSTANCE_OCID=$(curl -fsSL --max-time 10 http://169.254.169.254/opc/v2/instance/ 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('"'"'id'"'"','"'"''"'"'))" 2>/dev/null) || true'
        printf '%s\n' '[ -n "$INSTANCE_OCID" ] || die "cannot read instance OCID from IMDS"'
        printf '%s\n' 'printf "BATCH_ID=%s\nREPO_URL=%s\nCOMMIT=%s\nTIMER_MINUTES=%s\nBATCH_CHALLENGE=%s\nINSTANCE_OCID=%s\n" "$BATCH_ID" "$REPO_URL" "$COMMIT" "$TIMER_MINUTES" "$BATCH_CHALLENGE" "$INSTANCE_OCID" > /opt/harness/batch.env || die "cannot write batch.env"'
        printf '%s\n' 'chmod 600 /opt/harness/batch.env || die "cannot chmod batch.env"'
        printf '%s\n' '# V12 (spec rule 41): the per-batch HMAC secret is generated'
        printf '%s\n' '# INSIDE the VM - it NEVER enters user-data. The host public'
        printf '%s\n' '# key (above) encrypts it for the host.'
        printf '%s\n' 'python3 -c "import sys, secrets; sys.stdout.write(secrets.token_hex(32))" > /opt/harness/hmac.key || die "cannot generate hmac.key"'
        printf '%s\n' 'chmod 600 /opt/harness/hmac.key || die "cannot chmod hmac.key"'
        printf '%s\n' 'chown root:root /opt/harness/hmac.key /opt/harness/batch.env || die "cannot chown secret files"'
        printf '%s\n' '# The secret must NOT appear in user-data (it was never written'
        printf '%s\n' '# there): verify by grep with the generated value. A hit is a'
        printf '%s\n' '# bootstrap failure - the VM is terminated, no case runs.'
        printf '%s\n' '_s=$(cat /opt/harness/hmac.key | tr -d "[:space:]")'
        printf '%s\n' 'if [ -f /var/lib/cloud/instance/user-data.txt ]; then if grep -qF "$_s" /var/lib/cloud/instance/user-data.txt; then die "secret present in user-data"; fi; log "BOOTSTRAP user-data contains no secret value"; fi'
        printf '%s\n' '# Encrypt the secret for the host (RSA-OAEP SHA-256) and publish'
        printf '%s\n' '# the ciphertext on the results endpoint for the host to pull.'
        printf '%s\n' '# The ciphertext is public-safe: it decrypts only with the host'
        printf '%s\n' '# private key, which never leaves the host.'
        printf '%s\n' 'command -v openssl >/dev/null 2>&1 || dnf install -y openssl || die "cannot install openssl"'
        printf '%s\n' 'openssl pkeyutl -encrypt -pubin -inkey /opt/harness/host_pubkey.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in /opt/harness/hmac.key -out /results/hmac_secret.enc || die "cannot encrypt hmac secret"'
        printf '%s\n' 'chmod 644 /results/hmac_secret.enc || die "cannot chmod hmac_secret.enc"'
        printf '%s\n' '# V13 (spec rule 43): authenticate the secret delivery. The'
        printf '%s\n' '# VM'"'"'s OCI instance-identity certificate + private key are'
        printf '%s\n' '# fetched from the IMDS identity endpoints. This bootstrap'
        printf '%s\n' '# runs BEFORE vm_setup applies the metadata TCP-80 DROP, so'
        printf '%s\n' '# the fetch works; the identity is Oracle-issued, unique per'
        printf '%s\n' '# instance, and signed by an Oracle-operated CA. The VM signs'
        printf '%s\n' '# batch_id + the per-batch challenge + the ciphertext SHA-256'
        printf '%s\n' '# with its instance private key, publishes the signature +'
        printf '%s\n' '# leaf + intermediate certificates on the results endpoint,'
        printf '%s\n' '# then DELETES the private key. The host verifies the chain'
        printf '%s\n' '# against the pinned OCI root CA, the cert'"'"'s instance OCID'
        printf '%s\n' '# and tenancy OCID, the dates, and the signature over ITS OWN'
        printf '%s\n' '# recorded challenge before decrypting.'
        printf '%s\n' '# Fetch the leaf certificate (with the bearer header; fall'
        printf '%s\n' '# back to no header - Oracle'"'"'s own verification doc fetches'
        printf '%s\n' '# it with plain curl).'
        printf '%s\n' 'curl -fsSL -H "Authorization: Bearer <redacted>" --max-time 10 http://169.254.169.254/opc/v2/identity/cert.pem -o /opt/harness/instance_cert.pem 2>/dev/null || curl -fsSL --max-time 10 http://169.254.169.254/opc/v2/identity/cert.pem -o /opt/harness/instance_cert.pem || die "cannot fetch instance identity certificate"'
        printf '%s\n' 'curl -fsSL -H "Authorization: Bearer <redacted>" --max-time 10 http://169.254.169.254/opc/v2/identity/intermediate.pem -o /opt/harness/instance_intermediate.pem 2>/dev/null || curl -fsSL --max-time 10 http://169.254.169.254/opc/v2/identity/intermediate.pem -o /opt/harness/instance_intermediate.pem || die "cannot fetch instance intermediate certificate"'
        printf '%s\n' '# The private key REQUIRES the bearer header - no fallback.'
        printf '%s\n' 'curl -fsSL -H "Authorization: Bearer <redacted>" --max-time 10 http://169.254.169.254/opc/v2/identity/key.pem -o /opt/harness/instance_key.pem || die "cannot fetch instance identity private key"'
        printf '%s\n' 'chmod 600 /opt/harness/instance_key.pem || die "cannot chmod instance_key.pem"'
        printf '%s\n' 'chmod 644 /opt/harness/instance_cert.pem /opt/harness/instance_intermediate.pem || die "cannot chmod identity certificates"'
        printf '%s\n' '# The key must match the certificate.'
        printf '%s\n' '_cert_pub=$(openssl x509 -noout -pubkey -in /opt/harness/instance_cert.pem 2>/dev/null) || die "instance certificate does not parse"'
        printf '%s\n' '_key_pub=$(openssl pkey -in /opt/harness/instance_key.pem -pubout 2>/dev/null) || die "instance private key does not parse"'
        printf '%s\n' '[ "$_cert_pub" = "$_key_pub" ] || die "instance key does not match instance certificate"'
        printf '%s\n' '# Build the delivery data: batch_id + challenge + ciphertext hash.'
        printf '%s\n' '_enc_sha=$(sha256sum /results/hmac_secret.enc | awk "{print \$1}")'
        printf '%s\n' 'printf "BATCH_ID=%s\nCHALLENGE=%s\nCIPHERTEXT_SHA256=%s\n" "$BATCH_ID" "$BATCH_CHALLENGE" "$_enc_sha" > /opt/harness/delivery_data.txt || die "cannot write delivery_data.txt"'
        printf '%s\n' 'chmod 600 /opt/harness/delivery_data.txt || die "cannot chmod delivery_data.txt"'
        printf '%s\n' '# Sign with the instance private key.'
        printf '%s\n' 'openssl dgst -sha256 -sign /opt/harness/instance_key.pem -out /results/hmac_secret.sig /opt/harness/delivery_data.txt || die "cannot sign secret delivery"'
        printf '%s\n' 'chmod 644 /results/hmac_secret.sig || die "cannot chmod hmac_secret.sig"'
        printf '%s\n' 'cp /opt/harness/instance_cert.pem /results/hmac_secret.cert.pem || die "cannot publish instance certificate"'
        printf '%s\n' 'cp /opt/harness/instance_intermediate.pem /results/hmac_secret.intermediate.pem || die "cannot publish instance intermediate certificate"'
        printf '%s\n' 'chmod 644 /results/hmac_secret.cert.pem /results/hmac_secret.intermediate.pem || die "cannot chmod identity certificates"'
        printf '%s\n' '# Delete the instance private key - it must not persist on the VM.'
        printf '%s\n' 'rm -f /opt/harness/instance_key.pem || die "cannot delete instance private key"'
        printf '%s\n' '[ ! -e /opt/harness/instance_key.pem ] || die "instance private key still present after delete"'
        printf '%s\n' 'log "BOOTSTRAP secret delivery signed with instance identity"'
        printf '%s\n' 'rm -rf /tmp/m8-repo || true'
        printf '%s\n' 'log "BOOTSTRAP complete, exec run_batch.sh vm"'
        printf '%s\n' 'exec /opt/harness/run_batch.sh vm'
    } > "$_out"
    # Scan the generated user-data for forbidden patterns (Correction 6):
    # OCI OCIDs, private keys, GitHub tokens, passwords, secret
    # assignments. (Revision 12, spec rule 41: NO secret is expected
    # in user-data any more - the per-batch HMAC secret is generated
    # inside the VM. A secret assignment here is a STOP.) The host
    # PUBLIC key IS expected (it is not a secret) - the scan rejects
    # private keys only, so the public key passes.
    if grep -qE 'ocid1\.|BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY|ghp_[A-Za-z0-9]|github_pat_|password[[:space:]]*=|HMAC_SECRET=' "$_out"; then
        log "RUNNER user-data contains a forbidden pattern (OCID/private key/token/password/secret assignment)"
        die 2 "user-data review failed - batch does not start"
    fi
    grep -q "BEGIN PUBLIC KEY" "$_out" || { log "RUNNER user-data has no host public key"; die 2 "user-data review failed - no host public key"; }
    record_event "user_data_bytes=$(wc -c < "$_out") user_data_sha256=$(sha256sum "$_out" | awk '{print $1}')"
}

# H6 (dry-run): create the MOCK instance through the mock OCI layer
# (spec rule 29) and start the mock VM in the background. Mirrors
# the real H6 step for step, except: no cloud-init user-data is
# consumed (it is still generated + scanned, so that code path is
# exercised), the mock launch returns a fake OCID, the public IP is
# 127.0.0.1, and the mock VM (mock_vm.sh) is started in the
# background instead of a real VM booting. The VM-side batch.env is
# written here (the mock VM copies it into the fake tree) with the
# mock values; HMAC_SECRET_FILE is the VM-side path
# /opt/harness/hmac.key (vm_setup_dryrun copies the host's secret
# there). The first invocation still stops here (exit 3) at the
# controller checkpoint, exactly as in the real flow.
host_phase_vm_create_dryrun() {
    log "RUNNER phase=vm_create (dry-run)"
    TENANCY_OCID=$(cat "$BATCH_DIR/tenancy_ocid.txt")
    IMAGE_OCID=$(cat "$BATCH_DIR/image_ocid.txt")
    SUBNET_OCID=$(cat "$BATCH_DIR/subnet_ocid.txt")
    generate_user_data "$BATCH_DIR/user-data.txt"
    CREATION_TIME=$(iso_now)
    printf '%s\n' "$CREATION_TIME" > "$BATCH_DIR/creation_time.txt"
    # The mock OCI layer's usage fixture reads the batch creation
    # time from its state dir.
    python3 - "$MOCK_OCI_STATE/batch.json" "$CREATION_TIME" <<'PYEOF'
import json, sys
json.dump({"creation_time": sys.argv[2]}, open(sys.argv[1], "w"))
PYEOF
    INSTANCE_OCID=$("$OCI_CLI" compute instance launch --availability-domain JJYF:ME-DUBAI-1-AD-1 --compartment-id "$TENANCY_OCID" --shape VM.Standard.A1.Flex --shape-config '{"ocpus": 2, "memoryInGBs": 12}' --image-id "$IMAGE_OCID" --subnet-id "$SUBNET_OCID" --assign-public-ip true --boot-volume-size-in-gbs 50 --display-name "m8-batch-$BATCH_ID" --metadata "{\"user_data\": \"dry-run\"}" --query 'data.id' --raw-output 2>"$BATCH_DIR/launch.err") || {
        log "RUNNER mock instance launch failed (see launch.err)"
        die 2 "mock VM launch failed - dry-run does not start"
    }
    [ -n "$INSTANCE_OCID" ] || die 2 "mock launch returned no instance OCID"
    record_event "instance_ocid=$INSTANCE_OCID creation_time=$CREATION_TIME (dry-run mock)"
    printf '%s\n' "$INSTANCE_OCID" > "$BATCH_DIR/instance_ocid.txt"
    # The mock returns 127.0.0.1 as soon as the instance exists.
    _tries=0
    VM_PUBLIC_IP=""
    while [ "$_tries" -lt 20 ]; do
        sleep 5
        VM_PUBLIC_IP=$("$OCI_CLI" compute instance list-vnics --instance-id "$INSTANCE_OCID" --query 'data[0]."public-ip"' --raw-output 2>/dev/null)
        if [ -n "$VM_PUBLIC_IP" ] && [ "$VM_PUBLIC_IP" != "null" ]; then
            break
        fi
        VM_PUBLIC_IP=""
        _tries=$((_tries + 1))
    done
    [ -n "$VM_PUBLIC_IP" ] || die 2 "no mock public IP after 100 s - dry-run does not start"
    record_event "vm_public_ip=$VM_PUBLIC_IP (dry-run mock)"
    printf '%s\n' "$VM_PUBLIC_IP" > "$BATCH_DIR/vm_public_ip.txt"
    # The VM-side batch.env (the mock VM copies it into the fake
    # tree; the VM driver sources it). DRYRUN_VM=1 is set by the
    # mock VM when it execs the VM driver.
    {
        printf 'BATCH_ID=%s\n' "$BATCH_ID"
        printf 'REPO_URL=%s\n' "$REPO_URL"
        printf 'COMMIT=%s\n' "$COMMIT"
        printf 'TIMER_MINUTES=%s\n' "$TIMER_MINUTES"
        printf 'CONTROLLER_MINUTES=%s\n' "$CONTROLLER_MINUTES"
        printf 'POLLER_MINUTES=%s\n' "$POLLER_MINUTES"
        printf 'DONE_MINUTES=%s\n' "$DONE_MINUTES"
        printf 'HOST_EGRESS_IP=%s\n' "$HOST_EGRESS_IP"
        printf 'VM_PUBLIC_IP=%s\n' "$VM_PUBLIC_IP"
        printf 'INSTANCE_OCID=%s\n' "$INSTANCE_OCID"
        printf 'BATCH_CHALLENGE=%s\n' "$(cat "$BATCH_DIR/batch_challenge.txt" | tr -d '[:space:]')"
        printf 'HMAC_SECRET_FILE=%s\n' "/opt/harness/hmac.key"
        printf 'DRYRUN=1\n'
    } > "$BATCH_DIR/batch.env" || die 2 "cannot write batch.env"
    chmod 600 "$BATCH_DIR/batch.env"
    record_event "batch_env_written"
    # (V13, spec rule 43) Mock instance-identity issuance (dry-run
    # only - the host plays the role of OCI here): issue the mock
    # leaf certificate for the mock instance OCID, signed by the
    # mock intermediate CA created in host_phase_secret. The leaf
    # carries the instance OCID (opc-identity:) and the tenancy
    # OCID (opc-tenant:) in custom-OID extensions under the
    # unassigned mock enterprise arc 1.3.6.1.4.1.99999 - the same
    # content the real OCI leaf carries in its subject (the OCI
    # Python SDK reads exactly those opc-identity:/opc-tenant:
    # prefixes from the leaf subject). The OCIDs ride in extensions,
    # NOT in the subject: DN attribute values are capped at 64
    # chars (openssl: maxsize=64) and the tenancy OCID is 89 chars,
    # so a subject O=/CN= carrying it cannot even be created. The
    # host's OCID checks search the full certificate text and do
    # not assume a field, so the same code path verifies the real
    # cert and the mock. The intermediate key is deleted after
    # issuing (single-use); the leaf private key goes to the mock
    # VM's fake IMDS (mock_vm.sh copies it in), where
    # vm_setup_dryrun signs with it and deletes it - mirroring the
    # real bootstrap.
    _ten_ocid=$(cat "$BATCH_DIR/tenancy_ocid.txt" | tr -d '[:space:]')
    openssl req -newkey rsa:2048 -keyout "$BATCH_DIR/mock_identity/key.pem" -out "$BATCH_DIR/mock_identity/cert.csr" -nodes -subj "/CN=M8-MOCK-INSTANCE/O=M8-MOCK" 2>"$BATCH_DIR/mock_identity/cert_key.err" || die 2 "cannot generate mock instance identity key"
    chmod 600 "$BATCH_DIR/mock_identity/key.pem"
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n1.3.6.1.4.1.99999.1=ASN1:UTF8:opc-identity:%s\n1.3.6.1.4.1.99999.2=ASN1:UTF8:opc-tenant:%s\n' "$INSTANCE_OCID" "$_ten_ocid" > "$BATCH_DIR/mock_identity/cert.ext"
    openssl x509 -req -in "$BATCH_DIR/mock_identity/cert.csr" -CA "$BATCH_DIR/mock_identity/intermediate.pem" -CAkey "$BATCH_DIR/mock_identity/intermediate_key.pem" -CAcreateserial -out "$BATCH_DIR/mock_identity/cert.pem" -days 2 -extfile "$BATCH_DIR/mock_identity/cert.ext" 2>"$BATCH_DIR/mock_identity/cert.err" || die 2 "cannot sign mock instance identity certificate (see mock_identity/cert.err)"
    chmod 644 "$BATCH_DIR/mock_identity/cert.pem"
    rm -f "$BATCH_DIR/mock_identity/intermediate.srl" "$BATCH_DIR/mock_identity/cert.csr" "$BATCH_DIR/mock_identity/cert.ext"
    openssl x509 -noout -text -in "$BATCH_DIR/mock_identity/cert.pem" 2>/dev/null | grep -qF "$INSTANCE_OCID" || die 2 "mock instance identity certificate does not contain the instance OCID"
    record_event "mock_identity_issued instance_ocid=$INSTANCE_OCID"
    # (V13, rule 43) Issue a SECOND mock leaf certificate for a
    # DIFFERENT instance OCID (driver fixture for the wrong-sender
    # regression): it chains to the same mock CA, so only the OCID
    # check can reject it. The attacker key is stored in the batch
    # dir as a labelled fixture (mode 600) and is NEVER placed in
    # the mock VM. The intermediate key is deleted after BOTH
    # issuances (single-use). The genuine mock leaf key
    # (mock_identity/key.pem) is likewise a dry-run fixture only -
    # the real instance key is deleted on the VM after signing; the
    # mock copy is retained in the batch dir as issuance evidence.
    _attacker_ocid="ocid1.instance.oc1.me-dubai-1.aaaaaaaattacker"
    openssl req -newkey rsa:2048 -keyout "$BATCH_DIR/mock_identity/attacker_key.pem" -out "$BATCH_DIR/mock_identity/attacker_cert.csr" -nodes -subj "/CN=M8-MOCK-ATTACKER/O=M8-MOCK" 2>"$BATCH_DIR/mock_identity/attacker_cert_key.err" || die 2 "cannot generate mock attacker identity key"
    chmod 600 "$BATCH_DIR/mock_identity/attacker_key.pem"
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n1.3.6.1.4.1.99999.1=ASN1:UTF8:opc-identity:%s\n1.3.6.1.4.1.99999.2=ASN1:UTF8:opc-tenant:%s\n' "$_attacker_ocid" "$_ten_ocid" > "$BATCH_DIR/mock_identity/attacker_cert.ext"
    openssl x509 -req -in "$BATCH_DIR/mock_identity/attacker_cert.csr" -CA "$BATCH_DIR/mock_identity/intermediate.pem" -CAkey "$BATCH_DIR/mock_identity/intermediate_key.pem" -CAcreateserial -out "$BATCH_DIR/mock_identity/attacker_cert.pem" -days 2 -extfile "$BATCH_DIR/mock_identity/attacker_cert.ext" 2>"$BATCH_DIR/mock_identity/attacker_cert.err" || die 2 "cannot sign mock attacker identity certificate (see mock_identity/attacker_cert.err)"
    chmod 644 "$BATCH_DIR/mock_identity/attacker_cert.pem"
    rm -f "$BATCH_DIR/mock_identity/intermediate_key.pem" "$BATCH_DIR/mock_identity/attacker_cert.csr" "$BATCH_DIR/mock_identity/attacker_cert.ext" "$BATCH_DIR/mock_identity/attacker_cert.srl"
    openssl x509 -noout -text -in "$BATCH_DIR/mock_identity/attacker_cert.pem" 2>/dev/null | grep -qF "$_attacker_ocid" || die 2 "mock attacker identity certificate does not contain the attacker OCID"
    record_event "mock_attacker_identity_issued ocid=$_attacker_ocid"
    # Start the mock VM in the background (it runs the VM driver in
    # its private mount namespace, then the mock controller). The
    # host waits for it in the dry-run driver (dryrun_main).
    BATCH_DIR="$BATCH_DIR" M8_DIR="$M8_DIR" MOCK_OCI_STATE="$MOCK_OCI_STATE" INSTANCE_OCID="$INSTANCE_OCID" TIMER_MINUTES="$TIMER_MINUTES" CONTROLLER_MINUTES="$CONTROLLER_MINUTES" WATCHDOG_RUN_RECORD="$WATCHDOG_RUN_RECORD" CONTROLLER_JOB_ID="$CONTROLLER_JOB_ID" OCI_CLI="$OCI_CLI" nohup "$M8_DIR/o_tests_v13/mock_vm.sh" > "$BATCH_DIR/mock_vm.out" 2>&1 &
    MOCK_VM_PID=$!
    printf '%s\n' "$MOCK_VM_PID" > "$BATCH_DIR/mock_vm.pid"
    record_event "mock_vm_started pid=$MOCK_VM_PID"
    phase_mark vm_create
    # FIRST INVOCATION STOPS HERE (exit 3), as in the real flow:
    # the dry-run driver performs the mock operator step (writes
    # controller_verified with the exact mock terminate command)
    # and re-runs with --resume.
    log "RUNNER CHECKPOINT (dry-run) instance=$INSTANCE_OCID ip=$VM_PUBLIC_IP mock_vm_pid=$MOCK_VM_PID"
    if [ "$RESUME" -eq 0 ]; then
        exit 3
    fi
}

# H6: create ONE A1 VM (OCI API, host-side). Shape VM.Standard.A1.Flex,
# 2 OCPU / 12 GB, the resolved Oracle Linux 9 Arm64 image, 50 GB boot
# volume, the per-batch subnet, an ephemeral public IP. User-data is
# generated, reviewed (forbidden-pattern scan inside
# generate_user_data), and base64-encoded. The instance OCID, image
# OCID, and public IP are recorded. A launch failure (e.g. out of
# capacity) is a STOP, not a retry.
host_phase_vm_create() {
    phase_done vm_create && return 0
    log "RUNNER phase=vm_create"
    if [ "${DRYRUN:-0}" = "1" ]; then
        host_phase_vm_create_dryrun
        return 0
    fi
    TENANCY_OCID=$(cat "$BATCH_DIR/tenancy_ocid.txt")
    IMAGE_OCID=$(cat "$BATCH_DIR/image_ocid.txt")
    SUBNET_OCID=$(cat "$BATCH_DIR/subnet_ocid.txt")
    generate_user_data "$BATCH_DIR/user-data.txt"
    USER_DATA_B64=$(base64 -w0 "$BATCH_DIR/user-data.txt")
    CREATION_TIME=$(iso_now)
    printf '%s\n' "$CREATION_TIME" > "$BATCH_DIR/creation_time.txt"
    INSTANCE_OCID=$("$OCI_CLI" compute instance launch --availability-domain JJYF:ME-DUBAI-1-AD-1 --compartment-id "$TENANCY_OCID" --shape VM.Standard.A1.Flex --shape-config '{"ocpus": 2, "memoryInGBs": 12}' --image-id "$IMAGE_OCID" --subnet-id "$SUBNET_OCID" --assign-public-ip true --boot-volume-size-in-gbs 50 --display-name "m8-batch-$BATCH_ID" --metadata "{\"user_data\": \"$USER_DATA_B64\"}" --query 'data.id' --raw-output 2>"$BATCH_DIR/launch.err") || {
        log "RUNNER instance launch failed (see launch.err)"
        die 2 "VM launch failed (capacity or API error) - STOP, no retry"
    }
    [ -n "$INSTANCE_OCID" ] || die 2 "launch returned no instance OCID"
    record_event "instance_ocid=$INSTANCE_OCID creation_time=$CREATION_TIME"
    printf '%s\n' "$INSTANCE_OCID" > "$BATCH_DIR/instance_ocid.txt"
    # The public IP appears once the instance is RUNNING; poll up to
    # 10 minutes (the IP is needed for the results endpoint).
    _tries=0
    VM_PUBLIC_IP=""
    _poll_sleep=30
    if [ "${DRYRUN:-0}" = "1" ]; then _poll_sleep=5; fi
    while [ "$_tries" -lt 20 ]; do
        sleep "$_poll_sleep"
        VM_PUBLIC_IP=$("$OCI_CLI" compute instance list-vnics --instance-id "$INSTANCE_OCID" --query 'data[0]."public-ip"' --raw-output 2>/dev/null)
        if [ -n "$VM_PUBLIC_IP" ] && [ "$VM_PUBLIC_IP" != "null" ]; then
            break
        fi
        VM_PUBLIC_IP=""
        _tries=$((_tries + 1))
    done
    [ -n "$VM_PUBLIC_IP" ] || die 2 "no public IP after 10 minutes - batch does not start"
    record_event "vm_public_ip=$VM_PUBLIC_IP"
    printf '%s\n' "$VM_PUBLIC_IP" > "$BATCH_DIR/vm_public_ip.txt"
    phase_mark vm_create
    # FIRST INVOCATION STOPS HERE (exit 3): the operator must update
    # the controller cron job with the real instance OCID and
    # re-verify it via cron.list, then re-run with --resume. The
    # VM-side case loop waits up to 20 minutes after setup
    # verification for that to happen.
    log "RUNNER CHECKPOINT instance=$INSTANCE_OCID ip=$VM_PUBLIC_IP"
    log "RUNNER CHECKPOINT the operator must now: (1) update the controller cron job ($CONTROLLER_JOB_ID) with the exact command: oci compute instance terminate --instance-id $INSTANCE_OCID --force --preserve-boot-volume false; (2) verify via cron.list that the job exists, is enabled, and its stored command matches exactly; (3) write $BATCH_DIR/controller_verified with job_id=$CONTROLLER_JOB_ID, command=<the exact command>, run_record=$WATCHDOG_RUN_RECORD; (4) re-run this script with --resume within 20 minutes of VM creation ($CREATION_TIME)"
    if [ "$RESUME" -eq 0 ]; then
        exit 3
    fi
}

# H6b: after creation, verify the controller was updated with the
# real OCID and re-verified by the operator (Sec. 11.1 step 3). The
# controller_verified file must now contain the EXACT terminate
# command with the real instance OCID, string-for-string, plus the
# job id and the run-record path. Also enforces the 20-minute
# window: if more than 20 minutes have passed since VM creation,
# the VM-side sequence may have started before the controller was
# verified, so the batch is INVALID (the VM is terminated below).
host_phase_controller_verify() {
    phase_done controller_verify && return 0
    log "RUNNER phase=controller_verify"
    INSTANCE_OCID=$(cat "$BATCH_DIR/instance_ocid.txt")
    CREATION_TIME=$(cat "$BATCH_DIR/creation_time.txt")
    EXPECTED_TERMINATE_COMMAND="oci compute instance terminate --instance-id $INSTANCE_OCID --force --preserve-boot-volume false"
    printf '%s\n' "$EXPECTED_TERMINATE_COMMAND" > "$BATCH_DIR/expected_terminate_command.txt"
    _cv="$BATCH_DIR/controller_verified"
    [ -f "$_cv" ] || die 2 "controller_verified missing after VM creation - batch INVALID"
    _job=$(grep '^job_id=' "$_cv" 2>/dev/null | cut -d= -f2-)
    _cmd=$(grep '^command=' "$_cv" 2>/dev/null | cut -d= -f2-)
    _rr=$(grep '^run_record=' "$_cv" 2>/dev/null | cut -d= -f2-)
    [ "$_job" = "$CONTROLLER_JOB_ID" ] || die 2 "controller job_id mismatch after creation"
    [ "$_cmd" = "$EXPECTED_TERMINATE_COMMAND" ] || {
        log "RUNNER controller command mismatch: recorded=[$_cmd] expected=[$EXPECTED_TERMINATE_COMMAND]"
        die 2 "controller command does not match exactly - batch INVALID"
    }
    [ "$_rr" = "$WATCHDOG_RUN_RECORD" ] || die 2 "controller run_record mismatch after creation"
    # 20-minute window (from VM creation): the VM-side case loop
    # waits up to 20 minutes after setup verification; if the
    # operator took longer, the sequence may have started before
    # the controller was verified.
    _now_epoch=$(date -u +%s)
    _creation_epoch=$(epoch_of "$CREATION_TIME")
    if [ -z "$_creation_epoch" ] || [ $((_now_epoch - _creation_epoch)) -gt 1200 ]; then
        log "RUNNER controller verified more than 20 minutes after VM creation - batch INVALID"
        host_terminate_vm
        die 2 "controller verification window exceeded - batch INVALID, VM terminated"
    fi
    record_event "controller_verified job_id=$CONTROLLER_JOB_ID command_exact=1 elapsed_s=$((_now_epoch - _creation_epoch))"
    phase_mark controller_verify
}

# host_terminate_vm - terminate the instance via the OCI API (used
# when a batch is INVALID before the normal teardown, and by the
# verify phase). Records the call; does not delete network resources
# (those are deleted by host_phase_verify_terminate_o13 / o13).
# host_terminate_vm - the host's terminate call. CONDITIONAL
# (Revision 8, blocker 2): it checks the instance state first and
# SKIPS the terminate call if the instance is already TERMINATED
# (the external controller already terminated it - the normal path
# in H12, where o13 verified the controller's window before this
# call). Calling terminate on an already-TERMINATED instance would
# fail on the real OCI API and would destroy the evidence that the
# controller did the termination. It only terminates when the
# instance is NOT TERMINATED - the safety net for a controller
# that failed to fire (the error paths in H6b/H8/H9 and the end of
# H12). A query failure is treated as "not TERMINATED" (terminate
# anyway - a missed terminate is worse than a redundant one).
host_terminate_vm() {
    INSTANCE_OCID=$(cat "$BATCH_DIR/instance_ocid.txt" 2>/dev/null)
    [ -n "$INSTANCE_OCID" ] || return 0
    _state=$("$OCI_CLI" compute instance get --instance-id "$INSTANCE_OCID" --query 'data."lifecycle-state"' --raw-output 2>/dev/null) || _state=""
    if [ "$_state" = "TERMINATED" ]; then
        log "RUNNER instance $INSTANCE_OCID already TERMINATED (controller) - host terminate skipped"
        record_event "terminate_skipped already_terminated_by_controller instance=$INSTANCE_OCID"
        return 0
    fi
    log "RUNNER terminating instance $INSTANCE_OCID (state=${_state:-unknown})"
    "$OCI_CLI" compute instance terminate --instance-id "$INSTANCE_OCID" --force --preserve-boot-volume false > "$BATCH_DIR/terminate.log" 2>&1 || log "RUNNER terminate call failed (see terminate.log)"
    record_event "terminate_called instance=$INSTANCE_OCID"
}

# H7: start the lifecycle poller (blocker L). The poller is the ONLY
# writer of INSTANCE_STATE_LOG. Liveness check (a) - at batch start:
# the poller PID must be alive immediately after starting, recorded
# with a timestamp. If the poller cannot be started, the batch does
# not start.
host_phase_poller() {
    phase_done poller && return 0
    log "RUNNER phase=poller"
    INSTANCE_OCID=$(cat "$BATCH_DIR/instance_ocid.txt")
    CREATION_TIME=$(cat "$BATCH_DIR/creation_time.txt")
    _creation_epoch=$(epoch_of "$CREATION_TIME")
    POLLER_DEADLINE=$(date -u -d "@$((_creation_epoch + POLLER_MINUTES * 60))" +%Y-%m-%dT%H:%M:%SZ)
    INSTANCE_STATE_LOG="$BATCH_DIR/instance_state.log"
    _poll_interval=30
    if [ "${DRYRUN:-0}" = "1" ]; then _poll_interval=5; fi
    INSTANCE_OCID="$INSTANCE_OCID" INSTANCE_STATE_LOG="$INSTANCE_STATE_LOG" POLLER_DEADLINE="$POLLER_DEADLINE" OCI_CLI="$OCI_CLI" POLL_INTERVAL="$_poll_interval" nohup "$M8_DIR/o_tests_v13/o13_poller.sh" > "$BATCH_DIR/poller.out" 2>&1 &
    POLLER_PID=$!
    printf '%s\n' "$POLLER_PID" > "$BATCH_DIR/poller.pid"
    printf '%s\n' "$POLLER_DEADLINE" > "$BATCH_DIR/poller_deadline.txt"
    sleep 2
    if kill -0 "$POLLER_PID" 2>/dev/null; then
        record_event "poller_started pid=$POLLER_PID deadline=$POLLER_DEADLINE liveness_a=alive_at_batch_start"
    else
        log "RUNNER poller died immediately after starting (see poller.out)"
        die 2 "poller could not be started - batch does not start"
    fi
    phase_mark poller
}

# H8: wait for the DONE marker on the results endpoint (poll every
# 60 s until creation + DONE_MINUTES). Liveness check (b) - just
# before the VM-side timer deadline: when DONE is observed (or at
# the DONE deadline, whichever comes first), check the poller PID
# is alive and record it with a timestamp. If DONE never appears,
# the batch is INVALID (the VM is terminated; o13 still runs on
# whatever evidence exists).
host_phase_done_wait() {
    phase_done done_wait && return 0
    log "RUNNER phase=done_wait"
    VM_PUBLIC_IP=$(cat "$BATCH_DIR/vm_public_ip.txt")
    CREATION_TIME=$(cat "$BATCH_DIR/creation_time.txt")
    _creation_epoch=$(epoch_of "$CREATION_TIME")
    _deadline_epoch=$((_creation_epoch + DONE_MINUTES * 60))
    POLLER_PID=$(cat "$BATCH_DIR/poller.pid")
    DONE_SEEN=0
    _done_sleep=60
    if [ "${DRYRUN:-0}" = "1" ]; then _done_sleep=5; fi
    while [ "$(date -u +%s)" -lt "$_deadline_epoch" ]; do
        _code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "http://$VM_PUBLIC_IP:8080/DONE" 2>/dev/null || echo 000)
        if [ "$_code" = "200" ]; then
            DONE_SEEN=1
            break
        fi
        sleep "$_done_sleep"
    done
    # Liveness check (b): the poller must be alive when DONE is
    # observed (or at the DONE deadline). Recorded with a timestamp.
    # A poller that already exited 0 with its liveness confirmation
    # (it observed TERMINATED and confirmed it) is not a dead poller
    # - it completed. Only a poller that died without that
    # confirmation is a liveness failure.
    if kill -0 "$POLLER_PID" 2>/dev/null; then
        record_event "poller_liveness_b=alive_at_done_or_deadline time=$(iso_now)"
    elif grep -q "terminated_liveness_confirmed" "$BATCH_DIR/poller.out" 2>/dev/null; then
        record_event "poller_liveness_b=exited_after_liveness_confirmation time=$(iso_now)"
    else
        record_event "poller_liveness_b=DEAD time=$(iso_now)"
        log "RUNNER poller liveness (b) FAILED - batch INVALID"
        host_terminate_vm
        die 2 "poller dead at DONE/deadline - batch INVALID, VM terminated"
    fi
    if [ "$DONE_SEEN" -eq 0 ]; then
        log "RUNNER DONE not seen by creation + $DONE_MINUTES minutes - batch INVALID"
        host_terminate_vm
        die 2 "DONE marker never appeared - batch INVALID, VM terminated"
    fi
    record_event "done_seen=1"
    phase_mark done_wait
}

# host_verify_secret_auth - (V13, spec rule 43) Verify the
# authenticated delivery of the per-batch HMAC secret. Arguments:
#   $1 enc file, $2 sig file, $3 cert file, $4 intermediate file,
#   $5 pinned root CA file, $6 expected instance OCID,
#   $7 expected tenancy OCID, $8 batch id, $9 challenge (hex),
#   $10 output log file (appended).
# Writes one SECRET_DELIVERY name=PASS/FAIL line per check plus a
# final authenticity=PASS/FAIL line. Returns 0 only if ALL checks
# pass; any failure is fail-closed (non-zero, batch INVALID).
# The verification is over the HOST's own recorded values (batch
# id, challenge, OCIDs, pinned root CA) - nothing the VM asserts is
# trusted: the chain is verified against the pinned root CA, the
# cert must contain the created instance's OCID and the tenancy
# OCID, the dates must be valid now, and the signature must verify
# over delivery data reconstructed from the host's recorded
# batch_id + challenge + the fetched ciphertext's SHA-256. A
# substituted ciphertext, a certificate for another instance, a
# certificate from another CA, or a signature over any other
# challenge all fail. The delivery data contains no secret (only
# batch id, challenge, ciphertext hash) and is deleted after use.
host_verify_secret_auth() {
    _v_enc=$1; _v_sig=$2; _v_cert=$3; _v_inter=$4; _v_root=$5
    _v_ocid=$6; _v_ten=$7; _v_bid=$8; _v_chal=$9; _v_log=${10}
    _v_ok=1
    # (1) chain against the pinned root CA.
    if openssl verify -CAfile "$_v_root" -untrusted "$_v_inter" "$_v_cert" >/dev/null 2>&1; then
        printf 'SECRET_DELIVERY auth_chain=PASS\n' >> "$_v_log"
    else
        printf 'SECRET_DELIVERY auth_chain=FAIL\n' >> "$_v_log"; _v_ok=0
    fi
    # (2) the cert contains the created instance's OCID (fixed-string
    # containment of the exact recorded value - the real and mock
    # OCID forms differ, so no regex is assumed).
    if openssl x509 -noout -text -in "$_v_cert" 2>/dev/null | grep -qF "$_v_ocid"; then
        printf 'SECRET_DELIVERY auth_ocid=PASS\n' >> "$_v_log"
    else
        printf 'SECRET_DELIVERY auth_ocid=FAIL (cert does not contain %s)\n' "$_v_ocid" >> "$_v_log"; _v_ok=0
    fi
    # (3) the cert contains the tenancy OCID.
    if openssl x509 -noout -text -in "$_v_cert" 2>/dev/null | grep -qF "$_v_ten"; then
        printf 'SECRET_DELIVERY auth_tenancy=PASS\n' >> "$_v_log"
    else
        printf 'SECRET_DELIVERY auth_tenancy=FAIL (cert does not contain %s)\n' "$_v_ten" >> "$_v_log"; _v_ok=0
    fi
    # (4) the cert is valid now.
    if openssl x509 -noout -checkend 0 -in "$_v_cert" >/dev/null 2>&1; then
        printf 'SECRET_DELIVERY auth_dates=PASS\n' >> "$_v_log"
    else
        printf 'SECRET_DELIVERY auth_dates=FAIL\n' >> "$_v_log"; _v_ok=0
    fi
    # (5) the signature verifies over delivery data reconstructed
    # from the HOST's recorded batch id + challenge + the fetched
    # ciphertext's SHA-256 (same byte format the VM signs:
    # BATCH_ID=<id>\nCHALLENGE=<hex>\nCIPHERTEXT_SHA256=<sha>\n).
    _v_enc_sha=$(sha256sum "$_v_enc" 2>/dev/null | awk '{print $1}')
    _v_data="$_v_log.delivery_data"
    printf 'BATCH_ID=%s\nCHALLENGE=%s\nCIPHERTEXT_SHA256=%s\n' "$_v_bid" "$_v_chal" "$_v_enc_sha" > "$_v_data" 2>/dev/null || { printf 'SECRET_DELIVERY auth_signature=FAIL (cannot write delivery data)\n' >> "$_v_log"; printf 'SECRET_DELIVERY auth_challenge=FAIL\n' >> "$_v_log"; printf 'SECRET_DELIVERY authenticity=FAIL\n' >> "$_v_log"; return 1; }
    _v_pub="$_v_log.delivery_pubkey"
    if openssl x509 -noout -pubkey -in "$_v_cert" -out "$_v_pub" 2>/dev/null && openssl dgst -sha256 -verify "$_v_pub" -signature "$_v_sig" "$_v_data" >/dev/null 2>&1; then
        printf 'SECRET_DELIVERY auth_signature=PASS\n' >> "$_v_log"
        printf 'SECRET_DELIVERY auth_challenge=PASS\n' >> "$_v_log"
    else
        printf 'SECRET_DELIVERY auth_signature=FAIL\n' >> "$_v_log"
        printf 'SECRET_DELIVERY auth_challenge=FAIL\n' >> "$_v_log"; _v_ok=0
    fi
    rm -f "$_v_data" "$_v_pub"
    if [ "$_v_ok" -eq 1 ]; then
        printf 'SECRET_DELIVERY authenticity=PASS\n' >> "$_v_log"
        return 0
    fi
    printf 'SECRET_DELIVERY authenticity=FAIL\n' >> "$_v_log"
    return 1
}

# H9: download the results with o11.sh download (blocker I/K).
# HMAC_SECRET_FILE is passed EXPLICITLY (blocker K, 2026-11-25
# ~23:30 PKT - the runner, not the environment, supplies it).
# The download enforces the 10 MB per-file limit DURING download,
# the MAX_CASES (50) cap, and the 256 MiB aggregate cap.
host_phase_download() {
    phase_done download && return 0
    log "RUNNER phase=download"
    VM_PUBLIC_IP=$(cat "$BATCH_DIR/vm_public_ip.txt")
    RESULTS_DIR="$BATCH_DIR/results"
    mkdir -p "$RESULTS_DIR" || die 2 "cannot create results dir"
    # V12 (spec rule 41): fetch the VM's encrypted per-batch secret
    # FIRST (before any HMAC verification - the secret is needed for
    # it), decrypt it with the per-batch host private key, and verify
    # the secret delivery: the user-data must contain no secret value,
    # must contain the host public key and no private key, and the
    # secret must appear only in the two allowed files. Any failure is
    # fail-closed: the batch is INVALID, no HMAC is attempted with a
    # bad or missing secret. The delivery checks are recorded in
    # secret_delivery.log (one SECRET_DELIVERY name=PASS line each);
    # the driver asserts all six PASS lines plus the HMAC round-trip
    # in download.log. The ciphertext is stored in the batch dir,
    # NOT in the results dir: o11's host-handling check requires
    # every file in the results dir to be listed in results.sha256,
    # and the ciphertext is a secret-delivery artifact, not a result.
    # V13 (spec rule 43): fetch the authenticated-delivery artifacts
    # (signature + leaf + intermediate certificates) WITH the
    # ciphertext and VERIFY the delivery BEFORE decrypting: the
    # chain against the pinned OCI root CA, the cert's instance OCID
    # and tenancy OCID, the dates, and the signature over the host's
    # own recorded batch id + challenge + the fetched ciphertext's
    # SHA-256. An unauthenticated ciphertext is never decrypted.
    _enc="$BATCH_DIR/hmac_secret.enc"
    _sig="$BATCH_DIR/hmac_secret.sig"
    _cert="$BATCH_DIR/hmac_secret.cert.pem"
    _inter="$BATCH_DIR/hmac_secret.intermediate.pem"
    : > "$BATCH_DIR/secret_delivery.log" || die 2 "cannot create secret_delivery.log"
    python3 - "$VM_PUBLIC_IP" "$BATCH_DIR" <<'PYEOF' >> "$BATCH_DIR/secret_delivery.log" 2>&1 || die 2 "cannot fetch the secret-delivery artifacts from the results endpoint (see secret_delivery.log)"
import sys, urllib.request
ip, outdir = sys.argv[1], sys.argv[2]
for name, limit in (("hmac_secret.enc", 4096), ("hmac_secret.sig", 4096), ("hmac_secret.cert.pem", 8192), ("hmac_secret.intermediate.pem", 8192)):
    try:
        req = urllib.request.Request("http://%s:8080/%s" % (ip, name))
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
    except Exception as e:
        print("SECRET_FETCH error: %s: %s" % (name, e))
        sys.exit(1)
    if len(data) > limit:
        print("SECRET_FETCH error: %s too large (%d bytes)" % (name, len(data)))
        sys.exit(1)
    open("%s/%s" % (outdir, name), "wb").write(data)
    print("SECRET_FETCH ok %s bytes=%d" % (name, len(data)))
PYEOF
    _root="$BATCH_DIR/oci_root_ca.pem"
    _inst_ocid=$(cat "$BATCH_DIR/instance_ocid.txt" 2>/dev/null | tr -d '[:space:]')
    _ten_ocid=$(cat "$BATCH_DIR/tenancy_ocid.txt" 2>/dev/null | tr -d '[:space:]')
    _chal=$(cat "$BATCH_DIR/batch_challenge.txt" 2>/dev/null | tr -d '[:space:]')
    [ -f "$_root" ] || die 2 "pinned OCI root CA missing ($BATCH_DIR/oci_root_ca.pem) - the secret phase must run first"
    [ -n "$_inst_ocid" ] || die 2 "instance OCID missing - batch INVALID"
    [ -n "$_ten_ocid" ] || die 2 "tenancy OCID missing - batch INVALID"
    [ -n "$_chal" ] || die 2 "per-batch challenge missing - batch INVALID"
    if ! host_verify_secret_auth "$_enc" "$_sig" "$_cert" "$_inter" "$_root" "$_inst_ocid" "$_ten_ocid" "$BATCH_ID" "$_chal" "$BATCH_DIR/secret_delivery.log"; then
        log "RUNNER secret delivery authentication failed (see secret_delivery.log)"
        die 2 "secret delivery not authenticated - batch INVALID"
    fi
    openssl pkeyutl -decrypt -inkey "$BATCH_DIR/hmac_host_key.pem" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in "$_enc" -out "$BATCH_DIR/hmac_secret" 2>"$BATCH_DIR/hmac_secret.decrypt.err" || { log "RUNNER hmac_secret.enc decryption failed (see hmac_secret.decrypt.err)"; die 2 "secret decryption failed - batch INVALID"; }
    chmod 600 "$BATCH_DIR/hmac_secret"
    _dec=$(cat "$BATCH_DIR/hmac_secret" 2>/dev/null | tr -d '[:space:]')
    case "$_dec" in ????????????????????????????????????????????????????????????????) : ;; *) log "RUNNER decrypted secret is not 64 lowercase hex"; die 2 "decrypted secret malformed - batch INVALID" ;; esac
    case "$_dec" in ''|*[!0-9a-f]*) log "RUNNER decrypted secret is not lowercase hex"; die 2 "decrypted secret malformed - batch INVALID" ;; esac
    printf 'SECRET_DELIVERY decrypt=PASS\n' >> "$BATCH_DIR/secret_delivery.log"
    if grep -qF "$_dec" "$BATCH_DIR/user-data.txt" 2>/dev/null; then log "RUNNER decrypted secret found in user-data"; die 2 "secret present in user-data - batch INVALID"; fi
    printf 'SECRET_DELIVERY user_data_no_secret=PASS\n' >> "$BATCH_DIR/secret_delivery.log"
    grep -q "BEGIN PUBLIC KEY" "$BATCH_DIR/user-data.txt" 2>/dev/null || { log "RUNNER user-data has no host public key"; die 2 "user-data has no host public key - batch INVALID"; }
    printf 'SECRET_DELIVERY public_key_present=PASS\n' >> "$BATCH_DIR/secret_delivery.log"
    if grep -q "PRIVATE KEY" "$BATCH_DIR/user-data.txt" 2>/dev/null; then log "RUNNER user-data contains a private key"; die 2 "user-data contains a private key - batch INVALID"; fi
    printf 'SECRET_DELIVERY private_key_absent=PASS\n' >> "$BATCH_DIR/secret_delivery.log"
    if grep -q "HMAC_SECRET=" "$BATCH_DIR/user-data.txt" 2>/dev/null; then log "RUNNER user-data contains a secret assignment"; die 2 "user-data contains a secret assignment - batch INVALID"; fi
    printf 'SECRET_DELIVERY no_secret_assignment=PASS\n' >> "$BATCH_DIR/secret_delivery.log"
    _sweep=$(grep -rlF -- "$_dec" "$BATCH_DIR" 2>/dev/null | sort)
    # grep normalises a trailing slash on the directory argument away, so
    # build the expected set from the same single-slash form (BATCH_DIR may
    # carry a trailing slash from --batch-dir DIR/; without this the two
    # strings differ by one '/' per path and the comparison always fails)
    _batch="${BATCH_DIR%/}"
    _expect_sweep="$_batch/hmac_secret"
    if [ -f "$_batch/mock_vm/root/opt/harness/hmac.key" ]; then _expect_sweep=$(printf '%s\n%s\n' "$_batch/hmac_secret" "$_batch/mock_vm/root/opt/harness/hmac.key" | sort); fi
    if [ "$_sweep" = "$_expect_sweep" ]; then
        printf 'SECRET_DELIVERY sweep=PASS\n' >> "$BATCH_DIR/secret_delivery.log"
    else
        log "RUNNER secret sweep found unexpected copies: $(printf '%s' "$_sweep" | tr '\n' ' ')"
        die 2 "secret appears outside the allowed files - batch INVALID"
    fi
    VM_PUBLIC_IP="$VM_PUBLIC_IP" RESULTS_DIR="$RESULTS_DIR" HMAC_SECRET_FILE="$BATCH_DIR/hmac_secret" "$M8_DIR/o_tests_v13/o11.sh" download > "$BATCH_DIR/download.log" 2>&1
    _rc=$?
    cat "$BATCH_DIR/download.log" >> "$BATCH_RECORD"
    cat "$BATCH_DIR/secret_delivery.log" >> "$BATCH_RECORD"
    if [ "$_rc" -ne 0 ]; then
        log "RUNNER o11 download failed (exit $_rc, see download.log)"
        die 2 "results download failed - batch INVALID"
    fi
    grep -q "O11_DOWNLOAD result=pass" "$BATCH_DIR/download.log" || die 2 "download log has no O11_DOWNLOAD result=pass"
    record_event "download=pass"
    phase_mark download
}

# H10: host-side verification + teardown. Runs o11.sh host (the
# endpoint + untrusted-result checks), o12.sh verify (the host
# freeze snapshot taken before VM creation), deletes the per-batch
# network resources, runs o13.sh (teardown verification), checks
# the poller liveness (c) - after termination, and only then
# terminates the VM (conditional cleanup - see below). Each result
# line is recorded. A failure here does not stop the remaining
# checks: every check runs, and the verdict phase decides.
#
# ORDER (Revision 8, blocker 2 - the V7 order was wrong and o13
# could never PASS as written): the V7 runner called
# host_terminate_vm() BEFORE o13, so o13 could never verify the
# external controller's termination window (the instance was
# already TERMINATED by the host, not by the controller), and it
# deleted the network resources AFTER o13, although o13 (b)
# requires them to be already deleted. V8 order: o11 host, o12
# verify, DELETE the network resources (so o13 (b) can verify
# them deleted), o13 (which polls the instance until TERMINATED -
# the controller terminates it at its deadline - and verifies the
# controller's window), poller liveness (c), and FINALLY
# host_terminate_vm() as a conditional cleanup: it terminates the
# instance ONLY if it is not already TERMINATED (i.e. only if the
# controller failed). If the controller already terminated it, the
# host does not call terminate at all.
host_phase_verify_terminate_o13() {
    phase_done verify_terminate_o13 && return 0
    log "RUNNER phase=verify_terminate_o13"
    VM_PUBLIC_IP=$(cat "$BATCH_DIR/vm_public_ip.txt")
    INSTANCE_OCID=$(cat "$BATCH_DIR/instance_ocid.txt")
    SECLIST_OCID=$(cat "$BATCH_DIR/seclist_ocid.txt")
    RESULTS_DIR="$BATCH_DIR/results"
    # o11 host mode.
    VM_PUBLIC_IP="$VM_PUBLIC_IP" HOST_EGRESS_IP="$HOST_EGRESS_IP" RESULTS_DIR="$RESULTS_DIR" HMAC_SECRET_FILE="$BATCH_DIR/hmac_secret" BATCH_MANIFEST="$RESULTS_DIR/batch.json" RESULTS_SHA256="$RESULTS_DIR/results.sha256" SECLIST_OCID="$SECLIST_OCID" OCI_CLI="$OCI_CLI" "$M8_DIR/o_tests_v13/o11.sh" host > "$BATCH_DIR/o11_host.log" 2>&1
    _o11_rc=$?
    cat "$BATCH_DIR/o11_host.log" >> "$BATCH_RECORD"
    record_event "o11_host_exit=$_o11_rc"
    # o12 verify (against the snapshot taken before VM creation).
    "$M8_DIR/o_tests_v13/o12.sh" verify "$BATCH_DIR/o12_snapshot.txt" "$M8_DIR" > "$BATCH_DIR/o12_verify.log" 2>&1
    _o12_rc=$?
    cat "$BATCH_DIR/o12_verify.log" >> "$BATCH_RECORD"
    record_event "o12_verify_exit=$_o12_rc"
    # Delete the per-batch network resources (reverse creation
    # order) BEFORE o13 runs, so o13 (b) can verify each one is
    # deleted (a get must fail with 404). In V7 this deletion
    # happened after o13, so (b) could never pass.
    for _res in seclist subnet rt igw vcn; do
        _ocid=$(cat "$BATCH_DIR/${_res}_ocid.txt" 2>/dev/null || echo "")
        [ -n "$_ocid" ] || continue
        case "$_res" in
            seclist) "$OCI_CLI" network security-list delete --security-list-id "$_ocid" --force > /dev/null 2>&1 ;;
            subnet) "$OCI_CLI" network subnet delete --subnet-id "$_ocid" --force > /dev/null 2>&1 ;;
            rt) "$OCI_CLI" network route-table delete --rt-id "$_ocid" --force > /dev/null 2>&1 ;;
            igw) "$OCI_CLI" network internet-gateway delete --ig-id "$_ocid" --force > /dev/null 2>&1 ;;
            vcn) "$OCI_CLI" network vcn delete --vcn-id "$_ocid" --force > /dev/null 2>&1 ;;
        esac
        record_event "network_deleted $_res=$_ocid"
    done
    # o13 (teardown verification). All env vars it needs are set here.
    # It polls the instance until TERMINATED - the external
    # controller terminates it at its deadline, and o13 verifies
    # that window (e4)/(e4b) from the poller log + the controller
    # run record. The host does NOT terminate the VM before o13.
    CREATION_TIME=$(cat "$BATCH_DIR/creation_time.txt")
    _creation_epoch=$(epoch_of "$CREATION_TIME")
    TIMER_DEADLINE=$(date -u -d "@$((_creation_epoch + TIMER_MINUTES * 60))" +%Y-%m-%dT%H:%M:%SZ)
    # o13.sh requires exactly these 20 variables (o13.sh lines 149-153);
    # ROUTETABLE_OCID (not RT_OCID), COMPARTMENT_OCID, TENANCY_OCID,
    # BATCH_START, JOURNAL_SNAPSHOT, BATCH_MANIFEST and RESULTS_SHA256
    # are all required - a missing one is INCONCLUSIVE, never a pass.
    INSTANCE_OCID="$INSTANCE_OCID" VCN_OCID="$(cat "$BATCH_DIR/vcn_ocid.txt")" SUBNET_OCID="$(cat "$BATCH_DIR/subnet_ocid.txt")" SECLIST_OCID="$SECLIST_OCID" ROUTETABLE_OCID="$(cat "$BATCH_DIR/rt_ocid.txt")" IGW_OCID="$(cat "$BATCH_DIR/igw_ocid.txt")" VM_PUBLIC_IP="$VM_PUBLIC_IP" COMPARTMENT_OCID="$(cat "$BATCH_DIR/tenancy_ocid.txt")" TENANCY_OCID="$(cat "$BATCH_DIR/tenancy_ocid.txt")" BATCH_START="$CREATION_TIME" WATCHDOG_RUN_RECORD="$WATCHDOG_RUN_RECORD" JOURNAL_SNAPSHOT="$RESULTS_DIR/watchdog-snapshot.txt" INSTANCE_STATE_LOG="$BATCH_DIR/instance_state.log" TIMER_DEADLINE="$TIMER_DEADLINE" BATCH_MANIFEST="$RESULTS_DIR/batch.json" RESULTS_SHA256="$RESULTS_DIR/results.sha256" HMAC_SECRET_FILE="$BATCH_DIR/hmac_secret" EXPECTED_CONTROLLER_JOB_ID="$CONTROLLER_JOB_ID" EXPECTED_TERMINATE_COMMAND="$(cat "$BATCH_DIR/expected_terminate_command.txt")" DONE_MARKER="$RESULTS_DIR/DONE" OCI_CLI="$OCI_CLI" "$M8_DIR/o_tests_v13/o13.sh" > "$BATCH_DIR/o13.log" 2>&1
    _o13_rc=$?
    cat "$BATCH_DIR/o13.log" >> "$BATCH_RECORD"
    record_event "o13_exit=$_o13_rc"
    # Liveness check (c): after termination, the poller must still
    # be alive (it performs its own liveness check after observing
    # TERMINATED and then exits 0). Recorded with a timestamp.
    POLLER_PID=$(cat "$BATCH_DIR/poller.pid" 2>/dev/null)
    sleep 5
    if [ -n "$POLLER_PID" ] && kill -0 "$POLLER_PID" 2>/dev/null; then
        record_event "poller_liveness_c=alive_after_termination time=$(iso_now)"
    else
        # The poller exits 0 after its liveness confirmation, so a
        # dead PID here is expected IF its log shows the liveness
        # confirmation; the poller.out file decides.
        if grep -q "terminated_liveness_confirmed" "$BATCH_DIR/poller.out" 2>/dev/null; then
            record_event "poller_liveness_c=exited_after_liveness_confirmation time=$(iso_now)"
        else
            record_event "poller_liveness_c=DEAD_without_liveness_confirmation time=$(iso_now)"
        fi
    fi
    # Terminate the VM LAST, and only if the controller did not
    # already terminate it (host_terminate_vm is conditional: it
    # checks the instance state first and skips the call if the
    # instance is already TERMINATED). This is the safety net for
    # a controller that failed to fire - not the primary path.
    host_terminate_vm
    phase_mark verify_terminate_o13
}

# H11: verdict (CLOSED gate, Revision 9, spec rules 31 + 34). The V8
# gate was FAIL-OPEN: it read only O13_RESULT, O11_RESULT (host) and
# O12_RESULT, so a batch whose VM-side O1-O11 tests were INCONCLUSIVE
# was declared PASS (ChatGPT V8 verdict, 2026-11-26 ~02:49 PKT - the
# V8 dry-run itself recorded O3 and O5-O9 INCONCLUSIVE while the host
# declared overall PASS). The V9 gate authenticates and inspects the
# VM's batch manifest BEFORE destroying the per-batch HMAC secret,
# and PASS requires ALL of: (a) the manifest's HMAC verifies with the
# per-batch secret; (b) its verdict field is exactly PASS; (c) its
# batch_id equals the persisted BATCH_ID; (d) every mandatory O1-O11
# case is present with an explicit PASS outcome (no missing, SKIPPED,
# INCONCLUSIVE, INVALID or FAIL case); (e) O11 host PASS; (f) O12
# PASS; (g) O13 PASS. Missing or malformed evidence is INCONCLUSIVE
# or FAIL, never PASS (HMAC mismatch and batch_id mismatch are FAIL -
# the evidence positively contradicts the batch; absent or
# unparseable evidence is INCONCLUSIVE). In dry-run mode two outcomes
# are reported separately (rule 34): lifecycle_verdict (the
# orchestration: H0-H12 in order, poller 3 liveness, H12 order,
# conditional terminate - PASS iff O11 host, O12 and O13 all PASS)
# and security_verdict (this gate's outcome over the VM's O1-O11
# evidence). The overall verdict is PASS only if BOTH are PASS.
# Exit 0 only on overall PASS; 1 if any FAIL condition; 2 if any
# INCONCLUSIVE/INVALID.
host_phase_verdict() {
    # (V10, rule 35; V11, rule 37) Verdict replay: if a final verdict
    # was already computed for this batch (verdict.txt exists), replay
    # the stored result instead of recomputing it. The per-batch HMAC
    # secret was destroyed after the first verdict, so recomputation
    # would fail closed with INCONCLUSIVE even for a stored FAIL; and
    # the old code returned 0 here whenever verdict.done existed,
    # even for a stored FAIL/INCONCLUSIVE (the V9 defect). This call
    # is normally unreachable - host_main() already replayed before
    # any phase - but it is kept as defence-in-depth. See
    # replay_stored_verdict() for the exact rules (exit= validated
    # against verdict=, unreadable/mismatched -> INCONCLUSIVE).
    replay_stored_verdict
    log "RUNNER phase=verdict"
    RESULTS_DIR=${RESULTS_DIR:-"$BATCH_DIR/results"}
    _o13=$(grep -h "O13_RESULT=" "$BATCH_DIR/o13.log" 2>/dev/null | tail -1 | cut -d= -f2)
    _o11=$(grep -h "O11_RESULT=" "$BATCH_DIR/o11_host.log" 2>/dev/null | tail -1 | cut -d= -f2)
    _o12=$(grep -h "O12_RESULT=" "$BATCH_DIR/o12_verify.log" 2>/dev/null | tail -1 | cut -d= -f2)
    # (a)-(d): the VM batch manifest gate. One python3 program does
    # the authentication + parsing so the checks are exact (no
    # grep/regex on JSON). It prints gate= / reason= / vm_verdict= /
    # vm_batch_id= / cases= lines and always exits 0 (the outcome is
    # in the printed values, so a python error cannot silently pass).
    _gate_out=$(python3 - "$RESULTS_DIR/batch.json" "$RESULTS_DIR/batch.json.hmac" "$BATCH_DIR/hmac_secret" "$BATCH_ID" <<'PYEOF' 2>/dev/null
import hashlib, hmac, json, os, sys
manifest, sidecar, secret_file, expected_bid = sys.argv[1:5]
MANDATORY = ["o01","o02","o03","o04","o05","o06","o07","o08","o09","o10","o11"]
ALLOWED_VERDICTS = ("PASS", "FAIL", "INCONCLUSIVE", "INVALID")
ALLOWED_RESULTS = ("PASS", "FAIL", "INCONCLUSIVE", "SKIPPED", "INVALID")
def out(gate, reason, verdict="", bid="", cases=""):
    print("gate=%s" % gate)
    print("reason=%s" % reason)
    print("vm_verdict=%s" % verdict)
    print("vm_batch_id=%s" % bid)
    print("cases=%s" % cases)
if not os.path.isfile(manifest):
    out("INCONCLUSIVE", "manifest_missing"); sys.exit(0)
if not os.path.isfile(sidecar):
    out("INCONCLUSIVE", "manifest_hmac_missing"); sys.exit(0)
if not os.path.isfile(secret_file):
    out("INCONCLUSIVE", "hmac_secret_missing"); sys.exit(0)
try:
    secret = open(secret_file).read().strip()
    key = bytes.fromhex(secret)
except Exception:
    out("INCONCLUSIVE", "hmac_secret_unreadable"); sys.exit(0)
try:
    data = open(manifest, "rb").read()
    expect = open(sidecar).read().strip()
except OSError:
    out("INCONCLUSIVE", "manifest_unreadable"); sys.exit(0)
got = hmac.new(key, data, hashlib.sha256).hexdigest()
if not hmac.compare_digest(got, expect):
    out("FAIL", "hmac_mismatch"); sys.exit(0)
try:
    doc = json.loads(data.decode("utf-8"))
except Exception:
    out("INCONCLUSIVE", "manifest_unparseable"); sys.exit(0)
if not isinstance(doc, dict):
    out("INCONCLUSIVE", "manifest_not_object"); sys.exit(0)
verdict = doc.get("verdict")
bid = doc.get("batch_id")
cases = doc.get("cases")
if verdict is None or bid is None or cases is None:
    out("INCONCLUSIVE", "manifest_missing_fields"); sys.exit(0)
if verdict not in ALLOWED_VERDICTS:
    out("FAIL", "unknown_verdict_value"); sys.exit(0)
if not isinstance(cases, list):
    out("INCONCLUSIVE", "cases_not_a_list"); sys.exit(0)
outcomes = {}
for entry in cases:
    if not isinstance(entry, str) or "=" not in entry:
        out("FAIL", "bad_case_entry"); sys.exit(0)
    cid, res = entry.split("=", 1)
    if cid not in MANDATORY:
        out("FAIL", "unknown_case_id"); sys.exit(0)
    if cid in outcomes:
        out("FAIL", "duplicate_case"); sys.exit(0)
    if res not in ALLOWED_RESULTS:
        out("FAIL", "bad_case_result"); sys.exit(0)
    outcomes[cid] = res
cases_str = " ".join("%s=%s" % (c, outcomes.get(c, "MISSING")) for c in MANDATORY)
# Identity first: a manifest from a different batch cannot be trusted
# regardless of its verdict (rule 31c, before 31b).
bad = [c for c in MANDATORY if outcomes.get(c) != "PASS"]
case_fail = [c for c in bad if outcomes.get(c) == "FAIL"]
if bid != expected_bid:
    out("FAIL", "batch_id_mismatch", verdict, bid, cases_str); sys.exit(0)
# (V11, rule 32/38) Case-level FAIL takes precedence over the overall
# verdict field: a well-formed manifest containing an explicit FAIL
# must report gate FAIL even if verdict says INCONCLUSIVE, INVALID
# or PASS. The old code returned INCONCLUSIVE for verdict=
# INCONCLUSIVE/INVALID before reaching the case check, so an explicit
# test failure was misclassified as INCONCLUSIVE (ChatGPT V10
# verdict, blocker 2).
if case_fail:
    out("FAIL", "case_fail", verdict, bid, cases_str); sys.exit(0)
if verdict == "FAIL":
    out("FAIL", "vm_verdict=FAIL", verdict, bid, cases_str); sys.exit(0)
if verdict in ("INCONCLUSIVE", "INVALID"):
    out("INCONCLUSIVE", "vm_verdict=%s" % verdict, verdict, bid, cases_str); sys.exit(0)
if bad:
    out("INCONCLUSIVE", "non_pass_cases", verdict, bid, cases_str); sys.exit(0)
out("PASS", "vm_verdict=PASS all_o01_o11=PASS batch_id_match", verdict, bid, cases_str)
PYEOF
)
    _vm_gate=$(printf '%s\n' "$_gate_out" | sed -n 's/^gate=//p')
    _vm_reason=$(printf '%s\n' "$_gate_out" | sed -n 's/^reason=//p')
    _vm_verdict=$(printf '%s\n' "$_gate_out" | sed -n 's/^vm_verdict=//p')
    _vm_batch_id=$(printf '%s\n' "$_gate_out" | sed -n 's/^vm_batch_id=//p')
    _vm_cases=$(printf '%s\n' "$_gate_out" | sed -n 's/^cases=//p')
    # If the gate program itself produced nothing (python3 missing or
    # crashed), that is INCONCLUSIVE - never PASS.
    if [ -z "$_vm_gate" ]; then
        _vm_gate=INCONCLUSIVE; _vm_reason="gate_program_no_output"; _vm_verdict=""; _vm_batch_id=""; _vm_cases=""
    fi
    log "RUNNER vm_manifest_gate gate=$_vm_gate reason=$_vm_reason vm_verdict=$_vm_verdict vm_batch_id=$_vm_batch_id"
    # Lifecycle verdict (dry-run only, rule 34): the orchestration
    # checks - PASS iff O11 host, O12 and O13 all PASS.
    _lifecycle=""
    _security="$_vm_gate"
    if [ "${DRYRUN:-0}" = "1" ]; then
        if [ "$_o11" = "PASS" ] && [ "$_o12" = "PASS" ] && [ "$_o13" = "PASS" ]; then
            _lifecycle=PASS
        elif [ "$_o11" = "FAIL" ] || [ "$_o12" = "FAIL" ] || [ "$_o13" = "FAIL" ]; then
            _lifecycle=FAIL
        else
            _lifecycle=INCONCLUSIVE
        fi
    fi
    # Overall verdict: PASS only if the VM gate is PASS and O11 host,
    # O12 and O13 all PASS. FAIL if any of the four is FAIL; else
    # INCONCLUSIVE.
    _verdict=INCONCLUSIVE
    _exit=2
    if [ "$_vm_gate" = "PASS" ] && [ "$_o11" = "PASS" ] && [ "$_o12" = "PASS" ] && [ "$_o13" = "PASS" ]; then
        _verdict=PASS; _exit=0
    elif [ "$_vm_gate" = "FAIL" ] || [ "$_o11" = "FAIL" ] || [ "$_o12" = "FAIL" ] || [ "$_o13" = "FAIL" ]; then
        _verdict=FAIL; _exit=1
    fi
    {
        printf 'batch_id=%s\n' "$BATCH_ID"
        printf 'verdict=%s\n' "$_verdict"
        printf 'exit=%s\n' "$_exit"
        printf 'vm_verdict=%s\n' "$_vm_verdict"
        printf 'vm_gate=%s\n' "$_vm_gate"
        printf 'vm_gate_reason=%s\n' "$_vm_reason"
        printf 'vm_batch_id=%s\n' "$_vm_batch_id"
        printf 'vm_cases=%s\n' "$_vm_cases"
        printf 'o13=%s\n' "$_o13"
        printf 'o11_host=%s\n' "$_o11"
        printf 'o12_verify=%s\n' "$_o12"
        if [ -n "$_lifecycle" ]; then
            printf 'lifecycle_verdict=%s\n' "$_lifecycle"
            printf 'security_verdict=%s\n' "$_security"
        fi
        printf 'time=%s\n' "$(iso_now)"
    } > "$BATCH_DIR/verdict.txt"
    record_event "verdict=$_verdict vm_gate=$_vm_gate vm_gate_reason=$_vm_reason vm_verdict=$_vm_verdict o13=$_o13 o11_host=$_o11 o12_verify=$_o12 lifecycle=${_lifecycle:-n/a} security=$_security"
    # Destroy the host's copy of the per-batch secret AND the host
    # private key (Sec. 11.1 step 4: the secret is destroyed after
    # the batch's results are verified; it is never reused. The
    # private key decrypts the secret, so it is destroyed with it;
    # the public key is public and stays). This happens AFTER the
    # manifest gate above - the gate needs the secret to verify the
    # HMAC.
    rm -f "$BATCH_DIR/hmac_secret" "$BATCH_DIR/hmac_host_key.pem" && record_event "hmac_secret_destroyed=1 hmac_host_key_destroyed=1" || record_event "hmac_secret_destroyed=0 hmac_host_key_destroyed=0"
    # (V10, rule 35) The verdict phase is successful ONLY when the
    # verdict is PASS. Marking it for a FAIL/INCONCLUSIVE verdict
    # would let a later invocation return 0 via the phase marker
    # (the V9 defect: phase_done verdict && return 0 at the top of
    # this function). A non-PASS verdict is replayed from verdict.txt
    # on the next invocation (see the replay block above), never from
    # a marker. verdict.done therefore exists only for PASS batches.
    if [ "$_verdict" = "PASS" ]; then
        phase_mark verdict
    fi
    log "RUNNER batch verdict: $_verdict"
    exit "$_exit"
}

# ------------------------------------------------------------------
# VM mode
# ------------------------------------------------------------------

# vm_main - the VM-side driver. Runs as root on the VM, started by
# the cloud-init bootstrap (which already cloned + verified the
# repo, copied the tree to /opt/harness, and wrote batch.env +
# hmac.key). Reads /opt/harness/batch.env (mode 600, root-only).
vm_main() {
    HARNESS_DIR=/opt/harness
    RESULTS_DIR=/results
    WORKDIR=/work
    CGROUP=/sys/fs/cgroup/workload
    VM_RECORD="$RESULTS_DIR/vm_record.txt"
    mkdir -p "$RESULTS_DIR" || { echo "VM_FATAL cannot create /results"; exit 2; }
    chmod 755 "$RESULTS_DIR" || { echo "VM_FATAL cannot chmod /results"; exit 2; }
    [ -f "$HARNESS_DIR/batch.env" ] || { echo "VM_FATAL batch.env missing"; exit 2; }
    # shellcheck disable=SC1091
    . "$HARNESS_DIR/batch.env"
    for _v in BATCH_ID REPO_URL COMMIT TIMER_MINUTES; do
        eval "_val=\${$_v:-}"
        [ -n "$_val" ] || { echo "VM_FATAL batch.env missing $_v"; exit 2; }
    done
    echo "$(iso_now) VM batch_id=$BATCH_ID commit=$COMMIT timer_min=$TIMER_MINUTES" >> "$VM_RECORD"
    if [ "${DRYRUN_VM:-0}" = "1" ]; then
        # Dry-run VM driver (spec rule 29): the mock VM already
        # provides the fake tree (fake cgroup, fake /etc/hosts,
        # 1 GiB /tmp tmpfs, fake /opt/harness + /opt/proxy), so
        # vm_setup_dryrun only does the VM-side work that is safe
        # locally (no packages, no iptables, no loopback image, no
        # systemd, no user creation - the users are the numeric
        # UIDs 1000/1001/1002 from the host).
        vm_setup_dryrun || { echo "VM_FATAL vm_setup_dryrun failed"; vm_write_invalid_setup "vm_setup_dryrun failed"; exit 2; }
        vm_setup_verify_dryrun || { echo "VM_FATAL dry-run setup verification failed"; vm_write_invalid_setup "dry-run setup verification failed"; exit 2; }
        vm_wait_for_controller_window_dryrun
    else
    vm_setup || { echo "VM_FATAL vm_setup failed"; vm_write_invalid_setup "vm_setup failed"; exit 2; }
    vm_setup_verify || { echo "VM_FATAL setup verification failed"; vm_write_invalid_setup "setup verification failed"; exit 2; }
    vm_wait_for_controller_window
    fi
    vm_run_cases
    _rc=$?
    vm_teardown "$_rc"
    exit "$_rc"
}

# vm_setup - install + configure everything the batch needs, as root.
# Runs BEFORE the iptables restrictions are applied (root egress is
# permitted during setup, Sec. 5.3). Order: (1) packages + Node;
# (2) users/dirs (re-verified - the bootstrap created them);
# (3) the workload cgroup with the Sec. 7.1 limits; (4) the /tmp
# tmpfs; (5) the iptables rules (which deny root egress for the
# workload run); (6) the results server; (7) the watchdogs;
# (8) the HMAC secret file check. Any failure stops the batch.
vm_setup() {
    log_vm "vm_setup start"
    require_tool_vm dnf python3 sha256sum curl git bwrap unshare setpriv iptables systemctl
    # (1) Packages. bwrap comes from EPEL if the base repos lack it.
    if ! command -v bwrap >/dev/null 2>&1; then
        dnf install -y bwrap >/var/log/m8-dnf-bwrap.log 2>&1 || {
            dnf install -y epel-release >/var/log/m8-dnf-epel.log 2>&1 || { log_vm "vm_setup cannot install epel-release"; return 1; }
            dnf install -y bwrap >/var/log/m8-dnf-bwrap.log 2>&1 || { log_vm "vm_setup cannot install bwrap"; return 1; }
        }
    fi
    dnf install -y gcc util-linux procps-ng coreutils findutils tar xz gzip >/var/log/m8-dnf-base.log 2>&1 || { log_vm "vm_setup dnf base install failed"; return 1; }
    # Node.js (LTS, arm64) from the prebuilt tarball. The version is
    # resolved at run time from the Node.js release index (no
    # hardcoded version), and the tarball's SHA-256 is verified
    # against the index entry. Node is NOT needed by the O-tests
    # (shell + python3 only); a failed Node install is recorded as
    # node=not_installed and does NOT stop the batch (the benchmark
    # cases will need it - flagged in the setup record).
    NODE_VERSION=""
    if command -v node >/dev/null 2>&1; then
        NODE_VERSION=$(node --version 2>/dev/null || echo "")
    fi
    if [ -z "$NODE_VERSION" ]; then
        if python3 - <<'PYEOF' >/var/log/m8-node.log 2>&1
import hashlib, json, os, subprocess, sys, tarfile, urllib.request
try:
    index = json.load(urllib.request.urlopen("https://nodejs.org/dist/index.json", timeout=60))
    lts = [r for r in index if r.get("lts")]
    if not lts:
        print("no LTS release in index")
        sys.exit(1)
    rel = lts[0]
    ver = rel["version"]
    url = "https://nodejs.org/dist/%s/node-%s-linux-arm64.tar.xz" % (ver, ver)
    # The index.json does not carry per-file hashes; fetch the SHASUMS256.txt for the release.
    sums = urllib.request.urlopen("https://nodejs.org/dist/%s/SHASUMS256.txt" % ver, timeout=60).read().decode("ascii")
    want = None
    for line in sums.splitlines():
        h, name = line.split(None, 1)
        if name.strip() == "node-%s-linux-arm64.tar.xz" % ver:
            want = h
            break
    if not want:
        print("no sha256 for %s" % ver)
        sys.exit(1)
    data = urllib.request.urlopen(url, timeout=300).read()
    got = hashlib.sha256(data).hexdigest()
    if got != want:
        print("node tarball hash mismatch got=%s want=%s" % (got, want))
        sys.exit(1)
    open("/tmp/node.tar.xz", "wb").write(data)
    print("node_version=%s" % ver)
except Exception as e:
    print("node install failed: %s" % e)
    sys.exit(1)
PYEOF
        then
            mkdir -p /usr/local/node || { log_vm "vm_setup cannot create /usr/local/node"; return 1; }
            tar -xJf /tmp/node.tar.xz -C /usr/local/node --strip-components=1 || { log_vm "vm_setup cannot extract node"; return 1; }
            ln -sf /usr/local/node/bin/node /usr/local/bin/node
            ln -sf /usr/local/node/bin/npm /usr/local/bin/npm
            NODE_VERSION=$(node --version 2>/dev/null || echo "")
            rm -f /tmp/node.tar.xz
            log_vm "vm_setup node installed $NODE_VERSION"
        else
            log_vm "vm_setup node install failed (see /var/log/m8-node.log) - recorded as not_installed; O-tests do not need Node"
            NODE_VERSION="not_installed"
        fi
    fi
    printf '%s\n' "$NODE_VERSION" > /opt/harness/node_version.txt
    # (2) Users and directories (the bootstrap created them; verify).
    for _u in "harness 1000" "workload 1001" "proxy 1002"; do
        set -- $_u
        _id=$(id -u "$1" 2>/dev/null || echo "")
        [ "$_id" = "$2" ] || { log_vm "vm_setup user $1 has uid $_id, want $2"; return 1; }
    done
    mkdir -p /opt/harness /opt/proxy /opt/stage /results /home/harness || { log_vm "vm_setup cannot create dirs"; return 1; }
    # /opt/harness is mode 0710 root:harness. /opt/proxy is mode 0710
    # root:proxy (Revision 8 fix): the results server runs as UID 1000
    # and the proxy as UID 1002, and each must traverse its own
    # directory to read its source; mode 0700 (V7) made both
    # unreadable by their own UID. 0710 still bars the workload UID
    # 1001 from reading or listing either directory, and the HMAC
    # secret stays mode 600 root.
    chown root:harness /opt/harness || { log_vm "vm_setup cannot chown harness"; return 1; }
    chmod 0710 /opt/harness || { log_vm "vm_setup cannot chmod 0710 harness"; return 1; }
    chown root:proxy /opt/proxy || { log_vm "vm_setup cannot chown proxy dir"; return 1; }
    chmod 0710 /opt/proxy || { log_vm "vm_setup cannot chmod 0710 proxy"; return 1; }
    mkdir -p /home/workload || { log_vm "vm_setup cannot create /home/workload"; return 1; }
    # /home/workload is bound from <workdir>/home per case; the base
    # directory must exist (it is replaced by the per-case bind).
    # (3) The workload cgroup (Sec. 7.1). Enable the controllers for
    # the workload subtree first (blocker A): read both the root and
    # the subtree controller lists; enable any missing controller.
    mkdir -p /sys/fs/cgroup/workload || { log_vm "vm_setup cannot create workload cgroup"; return 1; }
    for _c in cpu memory io pids; do
        if ! grep -qw "$_c" /sys/fs/cgroup/workload/cgroup.controllers 2>/dev/null; then
            printf '+%s ' "$_c" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || { log_vm "vm_setup cannot enable controller $_c"; return 1; }
        fi
    done
    for _c in cpu memory io pids; do
        grep -qw "$_c" /sys/fs/cgroup/workload/cgroup.controllers || { log_vm "vm_setup controller $_c not enabled for workload subtree"; return 1; }
    done
    printf '4194304K' > /sys/fs/cgroup/workload/memory.max || { log_vm "vm_setup cannot set memory.max"; return 1; }
    printf '3145728K' > /sys/fs/cgroup/workload/memory.high || { log_vm "vm_setup cannot set memory.high"; return 1; }
    printf '0' > /sys/fs/cgroup/workload/memory.swap.max || { log_vm "vm_setup cannot set memory.swap.max"; return 1; }
    printf '100000 100000' > /sys/fs/cgroup/workload/cpu.max || { log_vm "vm_setup cannot set cpu.max"; return 1; }
    printf '512' > /sys/fs/cgroup/workload/pids.max || { log_vm "vm_setup cannot set pids.max"; return 1; }
    # io.max per device (50 MiB/s read + write = 52428800 B/s, Sec. 7.1):
    # the boot-volume device now; the loopback device per case (when
    # it exists - set in prepare_workdir).
    BOOT_DEV=$(findmnt -no SOURCE / 2>/dev/null)
    if [ -n "$BOOT_DEV" ]; then
        # stat %t/%T give the major/minor numbers in hex; io.max wants
        # decimal major:minor. The source device itself (the partition)
        # is the block device the workload's boot-volume I/O goes through.
        _maj=$(stat -c '%t' "$BOOT_DEV" 2>/dev/null); _min=$(stat -c '%T' "$BOOT_DEV" 2>/dev/null)
        if [ -n "$_maj" ] && [ -n "$_min" ]; then
            _maj_dec=$((16#$_maj)); _min_dec=$((16#$_min))
            printf '%s:%s rbps=52428800 wbps=52428800' "$_maj_dec" "$_min_dec" > /sys/fs/cgroup/workload/io.max 2>/dev/null || log_vm "vm_setup io.max for boot device failed (recorded; O8 will catch it)"
            printf '%s:%s\n' "$_maj_dec" "$_min_dec" > /opt/harness/boot_device.txt
        else
            log_vm "vm_setup cannot determine boot device major:minor (recorded; O8 will catch it)"
        fi
    else
        log_vm "vm_setup cannot determine boot device (recorded; O8 will catch it)"
    fi
    # No swap device (Sec. 7.1): disable any swap that exists.
    if swapon --show 2>/dev/null | grep -q .; then
        swapoff -a 2>/dev/null || { log_vm "vm_setup cannot disable swap"; return 1; }
    fi
    # (4) The /tmp tmpfs (1 GiB, Sec. 4.2): pre-mounted by the harness
    # at /opt/stage/tmp and bound into the sandbox (bwrap --tmpfs
    # takes no size argument).
    mkdir -p /opt/stage/tmp || { log_vm "vm_setup cannot create /opt/stage/tmp"; return 1; }
    mount -t tmpfs -o size=1G,mode=1777 tmpfs /opt/stage/tmp || { log_vm "vm_setup cannot mount /tmp tmpfs"; return 1; }
    # (5) The iptables rules (Sec. 5.3/5.4). Applied AFTER setup, so
    # root egress was available for the installs above. From here on,
    # root has no direct outbound egress for the workload run.
    # First: replies to inbound connections (the results server's
    # responses to the host) are always allowed.
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || { log_vm "vm_setup iptables established rule failed"; return 1; }
    # Metadata TCP 80 DROP for every UID (Sec. 5.4).
    iptables -A OUTPUT -p tcp -d 169.254.169.254 --dport 80 -j DROP || { log_vm "vm_setup iptables metadata rule failed"; return 1; }
    # UID 1002 (proxy): DNS only to 169.254.169.254:53; TCP 443 except
    # the deny ranges (DROP rules first - defence in depth).
    for _net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 127.0.0.0/8; do
        iptables -A OUTPUT -m owner --uid-owner 1002 -d "$_net" -j DROP || { log_vm "vm_setup iptables proxy deny $_net failed"; return 1; }
    done
    iptables -A OUTPUT -m owner --uid-owner 1002 -p udp -d 169.254.169.254 --dport 53 -j ACCEPT || { log_vm "vm_setup iptables proxy dns udp failed"; return 1; }
    iptables -A OUTPUT -m owner --uid-owner 1002 -p tcp -d 169.254.169.254 --dport 53 -j ACCEPT || { log_vm "vm_setup iptables proxy dns tcp failed"; return 1; }
    iptables -A OUTPUT -m owner --uid-owner 1002 -p tcp --dport 443 -j ACCEPT || { log_vm "vm_setup iptables proxy 443 failed"; return 1; }
    # UID 1001 (workload) and UID 1000 (harness): only to the local proxy.
    iptables -A OUTPUT -m owner --uid-owner 1001 -d 127.0.0.1 -p tcp --dport 3128 -j ACCEPT || { log_vm "vm_setup iptables workload proxy failed"; return 1; }
    iptables -A OUTPUT -m owner --uid-owner 1000 -d 127.0.0.1 -p tcp --dport 3128 -j ACCEPT || { log_vm "vm_setup iptables harness proxy failed"; return 1; }
    # Everything else outbound is denied (default DROP for OUTPUT).
    iptables -P OUTPUT DROP || { log_vm "vm_setup iptables OUTPUT DROP failed"; return 1; }
    # (6) The results server (Sec. 5.5/7.4 item 9): a small Python
    # server, UID 1000, port 8080, whitelist only, no listing.
    cat > /opt/harness/results_server.py <<'PYEOF'
#!/usr/bin/env python3
"""results_server.py - M8 results endpoint (Revision 8).

Serves ONLY the whitelisted sanitized manifest files under /results,
as UID 1000 on port 8080. No directory listing, no path traversal,
no raw logs, no CGI. Any other path is exactly HTTP 404. Only GET.
"""
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

RESULTS_DIR = "/results"
PORT = 8080
CASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
TOP = {"batch.json", "batch.json.hmac", "results.sha256",
       "results.sha256.hmac", "DONE", "watchdog-snapshot.txt",
       "watchdog-snapshot.txt.hmac", "hmac_secret.enc", "hmac_secret.sig",
       "hmac_secret.cert.pem", "hmac_secret.intermediate.pem"}  # V13 (rule 43): the authenticated-delivery artifacts

def allowed(path):
    # path: URL path without the leading slash, percent-decoded once.
    # Returns the absolute file path, or None.
    if not path or path.startswith("/") or ".." in path.split("/"):
        return None
    parts = path.split("/")
    if len(parts) == 1:
        if parts[0] in TOP:
            return os.path.join(RESULTS_DIR, parts[0])
        return None
    if len(parts) == 2 and CASE_RE.match(parts[0]) and parts[1] in ("manifest.json", "manifest.json.hmac"):
        return os.path.join(RESULTS_DIR, parts[0], parts[1])
    return None

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        from urllib.parse import unquote
        raw = self.path.split("?", 1)[0]
        target = allowed(unquote(raw.lstrip("/")))
        if target is None or not os.path.isfile(target):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            with open(target, "rb") as f:
                data = f.read()
        except OSError:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_POST(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()
    do_PUT = do_POST
    do_DELETE = do_POST

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
PYEOF
    chmod 644 /opt/harness/results_server.py || { log_vm "vm_setup cannot chmod results server"; return 1; }
    nohup setpriv --reuid=1000 --regid=1000 --clear-groups --inh-caps=-all --ambient-caps=-all --no-new-privs python3 /opt/harness/results_server.py >/var/log/m8-results.out 2>&1 &
    sleep 2
    # (V13, spec rule 44) Plant the traversal canary OUTSIDE
    # /results: a file whose content must never be returned by the
    # results server. The directory is mode 0755 (readable by the
    # results-server UID 1000, so a traversal WOULD expose it if the
    # defence failed) but NOT writable by the workload UID 1001, so
    # the canary survives the cases. The marker is read from
    # batch.env so it needs no environment assumption.
    _canary_bid=$(grep '^BATCH_ID=' /opt/harness/batch.env 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')
    [ -n "$_canary_bid" ] || { log_vm "vm_setup cannot read BATCH_ID for traversal canary"; return 1; }
    mkdir -p /opt/traversal || { log_vm "vm_setup cannot create traversal canary dir"; return 1; }
    chmod 755 /opt/traversal || { log_vm "vm_setup cannot chmod traversal canary dir"; return 1; }
    printf 'TRAVERSAL-CANARY-%s\n' "$_canary_bid" > /opt/traversal/traversal_canary.txt || { log_vm "vm_setup cannot write traversal canary"; return 1; }
    chmod 644 /opt/traversal/traversal_canary.txt || { log_vm "vm_setup cannot chmod traversal canary"; return 1; }
    # (7) The watchdogs (Sec. 7.1/11.4): the VM-side timer (powers off
    # the VM at TIMER_MINUTES after boot) and the per-case watchdog
    # (kills the workload cgroup if a case exceeds its timeout).
    cat > /opt/harness/case_watchdog.sh <<'SHEOF'
#!/bin/sh
# case_watchdog.sh - per-case watchdog (Revision 7). Run by systemd
# every 60 s as root. Reads /opt/harness/case_start (epoch) and
# /opt/harness/case_timeout (seconds, default 600); if the case has
# run longer than its timeout, kills every process in the workload
# cgroup and logs the kill with a timestamp.
set -u
[ -f /opt/harness/case_start ] || exit 0
_start=$(cat /opt/harness/case_start 2>/dev/null)
_timeout=$(cat /opt/harness/case_timeout 2>/dev/null || echo 600)
case "$_start" in ''|*[!0-9]*) exit 0 ;; esac
case "$_timeout" in ''|*[!0-9]*) _timeout=600 ;; esac
_now=$(date -u +%s)
if [ $((_now - _start)) -gt "$_timeout" ]; then
    for _pid in $(cat /sys/fs/cgroup/workload/cgroup.procs 2>/dev/null); do
        kill -9 "$_pid" 2>/dev/null || true
    done
    printf '%s case_watchdog killed cgroup after %ss (timeout %ss)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$((_now - _start))" "$_timeout" >> /opt/harness/case_watchdog.log
fi
exit 0
SHEOF
    chmod 700 /opt/harness/case_watchdog.sh || { log_vm "vm_setup cannot chmod case watchdog"; return 1; }
    cat > /etc/systemd/system/m8-case-watchdog.service <<'SHEOF'
[Unit]
Description=M8 per-case watchdog (kills the workload cgroup on timeout)
[Service]
Type=oneshot
ExecStart=/opt/harness/case_watchdog.sh
SHEOF
    cat > /etc/systemd/system/m8-case-watchdog.timer <<'SHEOF'
[Unit]
Description=M8 per-case watchdog timer (every 60 s)
[Timer]
OnBootSec=60s
OnUnitActiveSec=60s
[Install]
WantedBy=timers.target
SHEOF
    cat > /etc/systemd/system/m8-watchdog.service <<'SHEOF'
[Unit]
Description=M8 VM lifetime watchdog (powers off the VM at the deadline)
[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl poweroff
SHEOF
    cat > /etc/systemd/system/m8-watchdog.timer <<SHEOF
[Unit]
Description=M8 VM lifetime watchdog timer
[Timer]
OnActiveSec=${TIMER_MINUTES}m
[Install]
WantedBy=timers.target
SHEOF
    systemctl daemon-reload || { log_vm "vm_setup daemon-reload failed"; return 1; }
    systemctl enable --now m8-case-watchdog.timer || { log_vm "vm_setup cannot start case watchdog timer"; return 1; }
    systemctl enable --now m8-watchdog.timer || { log_vm "vm_setup cannot start VM watchdog timer"; return 1; }
    # (8) The HMAC secret file (blocker K): written by the bootstrap.
    [ -f /opt/harness/hmac.key ] || { log_vm "vm_setup hmac.key missing"; return 1; }
    _mode=$(stat -c '%a' /opt/harness/hmac.key 2>/dev/null || echo "")
    [ "$_mode" = "600" ] || { log_vm "vm_setup hmac.key mode $_mode, want 600"; return 1; }
    log_vm "vm_setup complete"
    return 0
}

# log_vm MSG - log to the VM record + stdout.
# log_vm: log to $VM_RECORD and to STDERR (not stdout). The VM
# driver log captures both streams (the mock VM runs the driver with
# 2>&1), so the lines still appear in vm_driver.log. But stdout is
# the result channel: vm_run_cases captures run_workload/run_o3/...
# via $(...) (stdout only), so a log_vm line on stdout would pollute
# the captured result (Revision 8 fix - the dry-run showed results
# like "2026-... prepare_workdir_dryrun ...\nINCONCLUSIVE").
log_vm() {
    printf '%s VM %s\n' "$(iso_now)" "$1" >> "$VM_RECORD" 2>/dev/null || true
    printf '%s VM %s\n' "$(iso_now)" "$1" >&2
}

# require_tool_vm - fail closed if a tool is missing (vm mode).
require_tool_vm() {
    for _t in "$@"; do
        if ! command -v "$_t" >/dev/null 2>&1; then
            log_vm "vm_setup required tool missing: $_t"
            return 1
        fi
    done
    return 0
}

# raw_traversal_probe - (V13, spec rule 44) Send ONE HTTP request
# over a raw socket, preserving the literal unnormalised request
# target. curl normalises /../ before sending, so a curl probe
# cannot test the server's traversal defence - that was the V12
# false positive (check 9 and o11.sh passed without exercising the
# defence). Arguments: $1 host, $2 port, $3 request target,
# $4 canary marker (empty = no canary check). Prints one
# RAW_HTTP target=<t> status=<code> canary_leaked=<yes|no>
# body_bytes=<n> line and returns 0 only if the status is 404 AND
# the canary marker (if given) is absent from the body. A
# connection failure prints status=000 and returns 1.
raw_traversal_probe() {
    _rt_host=$1; _rt_port=$2; _rt_target=$3; _rt_canary=${4:-}
    python3 - "$_rt_host" "$_rt_port" "$_rt_target" "$_rt_canary" <<'PYEOF'
import socket, sys
host, port, target, canary = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
try:
    s = socket.create_connection((host, port), timeout=10)
except Exception as e:
    print("RAW_HTTP target=%s status=000 canary_leaked=no body_bytes=0 error=%s" % (target, e))
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
leaked = bool(canary) and canary.encode() in body
print("RAW_HTTP target=%s status=%s canary_leaked=%s body_bytes=%d" % (target, code, "yes" if leaked else "no", len(body)))
sys.exit(0 if code == "404" and not leaked else 1)
PYEOF
}

# vm_setup_verify - the 22 setup-verification checks (Sec. 7.4).
# Each check prints SETUP_CHECK n=<n> result=pass|fail detail=...
# and is recorded in /results/setup_record.json. If ANY check fails,
# the run stops before any workload starts (vm_main writes the
# INVALID batch record + DONE and exits 2). Item 5 (the loopback
# image) is per-case: it is verified by prepare_workdir before each
# case (including the first) and recorded there, because the image
# is created fresh per case.
vm_setup_verify() {
    log_vm "vm_setup_verify start"
    SETUP_FAIL=0
    SETUP_RECORD="$RESULTS_DIR/setup_record.json"
    : > /tmp/setup_checks.txt
    check() {
        # check N PASS|FAIL DETAIL
        printf 'SETUP_CHECK n=%s result=%s detail=%s\n' "$1" "$2" "$3" >> /tmp/setup_checks.txt
        printf 'SETUP_CHECK n=%s result=%s detail=%s\n' "$1" "$2" "$3"
        [ "$2" = "pass" ] || SETUP_FAIL=1
    }
    # 1. Architecture.
    if [ "$(uname -m 2>/dev/null)" = "aarch64" ]; then check 1 pass "uname-m=aarch64"; else check 1 fail "uname-m=$(uname -m 2>/dev/null)"; fi
    # 2. Controllers present at the root AND enabled for the workload subtree.
    _ok=1
    for _c in cpu memory io pids; do
        grep -qw "$_c" /sys/fs/cgroup/cgroup.controllers 2>/dev/null || _ok=0
        grep -qw "$_c" /sys/fs/cgroup/workload/cgroup.controllers 2>/dev/null || _ok=0
    done
    if [ "$_ok" -eq 1 ]; then check 2 pass "controllers cpu memory io pids in root and workload subtree"; else check 2 fail "a controller is missing at the root or the workload subtree"; fi
    # 3. Limit files read back (memory/cpu/pids now; io.max for the
    # boot device now, for the loopback device per case).
    _ok=1; _d=""
    [ "$(cat /sys/fs/cgroup/workload/memory.max 2>/dev/null)" = "4194304K" ] || { _ok=0; _d="$ _d memory.max"; }
    [ "$(cat /sys/fs/cgroup/workload/memory.high 2>/dev/null)" = "3145728K" ] || { _ok=0; _d="$_d memory.high"; }
    [ "$(cat /sys/fs/cgroup/workload/memory.swap.max 2>/dev/null)" = "0" ] || { _ok=0; _d="$_d memory.swap.max"; }
    [ "$(cat /sys/fs/cgroup/workload/cpu.max 2>/dev/null)" = "100000 100000" ] || { _ok=0; _d="$_d cpu.max"; }
    [ "$(cat /sys/fs/cgroup/workload/pids.max 2>/dev/null)" = "512" ] || { _ok=0; _d="$_d pids.max"; }
    if [ -f /opt/harness/boot_device.txt ]; then
        _bd=$(cat /opt/harness/boot_device.txt)
        grep -q "$_bd" /sys/fs/cgroup/workload/io.max 2>/dev/null || { _ok=0; _d="$_d io.max boot device $_bd"; }
    else
        _ok=0; _d="$_d io.max boot device unknown"
    fi
    if [ "$_ok" -eq 1 ]; then check 3 pass "limits read back (io.max loopback device per case)"; else check 3 fail "limit mismatch:$_d"; fi
    # 4. No swap device.
    if swapon --show 2>/dev/null | grep -q .; then check 4 fail "swap device present"; else check 4 pass "no swap device"; fi
    # 5. Loopback image - per case (see prepare_workdir). Recorded here
    # as deferred, not as a pass.
    printf 'SETUP_CHECK n=5 result=deferred detail=verified per case by prepare_workdir\n' >> /tmp/setup_checks.txt
    printf 'SETUP_CHECK n=5 result=deferred detail=verified per case by prepare_workdir\n'
    # 6. iptables rules listed back.
    _rules=$(iptables -S OUTPUT 2>/dev/null)
    _ok=1; _d=""
    printf '%s\n' "$_rules" | grep -q "169.254.169.254.*--dport 80.*DROP" || { _ok=0; _d="$_d metadata-drop"; }
    printf '%s\n' "$_rules" | grep -q "owner UID match 1002.*--dport 53" || { _ok=0; _d="$_d proxy-dns"; }
    printf '%s\n' "$_rules" | grep -q "owner UID match 1002.*--dport 443" || { _ok=0; _d="$_d proxy-443"; }
    printf '%s\n' "$_rules" | grep -q "owner UID match 1001.*127.0.0.1.*--dport 3128" || { _ok=0; _d="$_d workload-proxy"; }
    printf '%s\n' "$_rules" | grep -q "owner UID match 1000.*127.0.0.1.*--dport 3128" || { _ok=0; _d="$_d harness-proxy"; }
    if [ "$_ok" -eq 1 ]; then check 6 pass "iptables UID rules + metadata DROP present"; else check 6 fail "missing rules:$_d"; fi
    # 7. Proxy running as uid 1002; filter has exactly the five regexes.
    _proxy_pid=$(pgrep -u 1002 -f egress-proxy.py 2>/dev/null | head -1)
    _ok=1; _d=""
    [ -n "$_proxy_pid" ] || { _ok=0; _d="$_d proxy-not-running"; }
    if [ -f /opt/proxy/filter ]; then
        _n=$(grep -c . /opt/proxy/filter 2>/dev/null || echo 0)
        [ "$_n" = "5" ] || { _ok=0; _d="$_d filter-lines=$_n"; }
        grep -qx '^\^github\\.com\$$' /opt/proxy/filter || { _ok=0; _d="$_d filter-github"; }
        grep -qx '^\^objects\\.githubusercontent\\.com\$$' /opt/proxy/filter || { _ok=0; _d="$_d filter-objects"; }
        grep -qx '^\^registry\\.npmjs\\.org\$$' /opt/proxy/filter || { _ok=0; _d="$_d filter-npmjs"; }
        grep -qx '^\^pypi\\.org\$$' /opt/proxy/filter || { _ok=0; _d="$_d filter-pypi"; }
        grep -qx '^\^files\\.pythonhosted\\.org\$$' /opt/proxy/filter || { _ok=0; _d="$_d filter-pythonhosted"; }
    else
        _ok=0; _d="$_d filter-missing"
    fi
    if [ "$_ok" -eq 1 ]; then check 7 pass "proxy running as uid 1002, filter has the five regexes"; else check 7 fail "proxy/filter problem:$_d"; fi
    # 8. No Docker socket; sudo not usable by workload.
    _ok=1; _d=""
    [ -e /var/run/docker.sock ] && { _ok=0; _d="$_d docker-sock-exists"; }
    if setpriv --reuid=1001 --regid=1001 --clear-groups sudo -n true >/dev/null 2>&1; then _ok=0; _d="$_d sudo-works-for-workload"; fi
    if [ "$_ok" -eq 1 ]; then check 8 pass "no docker socket, sudo unusable by workload"; else check 8 fail "$_d"; fi
    # 9. Results server running as uid 1000 on 8080; whitelist only.
    # (V13, spec rule 44) The traversal probes use a RAW SOCKET,
    # not curl: curl normalises /../ before sending, so the V12
    # curl probe received /batch.json and passed without exercising
    # the server's traversal defence. The raw socket sends the
    # literal target. Probes: literal /../batch.json; literal
    # /../opt/traversal/traversal_canary.txt; percent-encoded
    # /%2e%2e/...; /..%2f...; double-encoded /%252e%252e/.... Each
    # must return HTTP 404 AND the canary marker must not appear in
    # any body. The listing check (curl /) is unchanged (no "..").
    _ok=1; _d=""
    _rs_pid=$(pgrep -u 1000 -f results_server.py 2>/dev/null | head -1)
    [ -n "$_rs_pid" ] || { _ok=0; _d="$_d results-server-not-running"; }
    _c1=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:8080/ 2>/dev/null || echo 000)
    [ "$_c1" = "404" ] || { _ok=0; _d="$_d listing-code=$_c1"; }
    _marker=$(cat /opt/traversal/traversal_canary.txt 2>/dev/null | tr -d '[:space:]')
    [ -n "$_marker" ] || { _ok=0; _d="$_d canary-missing"; }
    for _t in "/../batch.json" "/../opt/traversal/traversal_canary.txt" "/%2e%2e/opt/traversal/traversal_canary.txt" "/..%2fopt/traversal/traversal_canary.txt" "/%252e%252e/opt/traversal/traversal_canary.txt"; do
        _probe_out=$(raw_traversal_probe 127.0.0.1 8080 "$_t" "$_marker" 2>&1)
        _probe_rc=$?
        if [ "$_probe_rc" -ne 0 ]; then _ok=0; _d="$_d traversal-fail:$_t:$_probe_out"; fi
    done
    if [ "$_ok" -eq 1 ]; then check 9 pass "results server uid 1000 on 8080, listing 404, raw-socket literal+encoded traversal 404 with no canary leak"; else check 9 fail "$_d"; fi
    # 10. Versions recorded.
    {
        printf 'node=%s\n' "$(node --version 2>/dev/null || echo not_installed)"
        printf 'python3=%s\n' "$(python3 --version 2>&1 || echo missing)"
        printf 'git=%s\n' "$(git --version 2>/dev/null || echo missing)"
        printf 'bwrap=%s\n' "$(bwrap --version 2>/dev/null || echo missing)"
        printf 'iptables=%s\n' "$(iptables --version 2>/dev/null || echo missing)"
        printf 'proxy=%s\n' "$(sha256sum /opt/proxy/egress-proxy.py 2>/dev/null | awk '{print $1}')"
    } > /opt/harness/versions.txt
    check 10 pass "versions recorded in /opt/harness/versions.txt"
    # 11. IPv6 disabled.
    _ok=1; _d=""
    if ip -6 addr show scope global 2>/dev/null | grep -q .; then _ok=0; _d="$_d global-ipv6-present"; fi
    if [ -s /proc/net/if_inet6 ]; then _ok=0; _d="$_d if_inet6-nonempty"; fi
    if [ "$_ok" -eq 1 ]; then check 11 pass "no global IPv6, if_inet6 empty/absent"; else check 11 fail "$_d"; fi
    # 12. Privilege state: a UID 1001 process has NoNewPrivs 1, CapEff 0;
    # UID 1001 cannot write the workload cgroup or the parent cgroup.procs;
    # cannot read /root, /home/harness, /proc/1/root, or the user-data file.
    _ok=1; _d=""
    _probe_out=$(setpriv --reuid=1001 --regid=1001 --clear-groups --inh-caps=-all --ambient-caps=-all --no-new-privs sh -c 'grep -E "^(NoNewPrivs|CapEff):" /proc/self/status' 2>/dev/null)
    printf '%s\n' "$_probe_out" | grep -q "NoNewPrivs:	1" || { _ok=0; _d="$_d nonewprivs"; }
    printf '%s\n' "$_probe_out" | grep -q "CapEff:	0000000000000000" || { _ok=0; _d="$_d capeff"; }
    if setpriv --reuid=1001 --regid=1001 --clear-groups sh -c 'printf x > /sys/fs/cgroup/workload/o13_test && echo WRITABLE || echo DENIED' 2>/dev/null | grep -q WRITABLE; then _ok=0; _d="$_d cgroup-writable"; fi
    if setpriv --reuid=1001 --regid=1001 --clear-groups sh -c 'echo $$ > /sys/fs/cgroup/cgroup.procs && echo MOVED || echo DENIED' 2>/dev/null | grep -q MOVED; then _ok=0; _d="$_d cgroup-move"; fi
    for _p in /root /home/harness /proc/1/root /var/lib/cloud/instance/user-data.txt; do
        if setpriv --reuid=1001 --regid=1001 --clear-groups sh -c "test -r $_p" 2>/dev/null; then _ok=0; _d="$_d readable:$_p"; fi
    done
    if [ "$_ok" -eq 1 ]; then check 12 pass "NoNewPrivs 1, CapEff 0, cgroup unwritable/unmovable, protected paths unreadable by 1001"; else check 12 fail "$_d"; fi
    # 13. User-data file mode 600, root-owned, no secrets.
    _ok=1; _d=""
    _ud=/var/lib/cloud/instance/user-data.txt
    if [ -f "$_ud" ]; then
        [ "$(stat -c '%a' "$_ud" 2>/dev/null)" = "600" ] || { _ok=0; _d="$_d user-data-mode"; }
        [ "$(stat -c '%U' "$_ud" 2>/dev/null)" = "root" ] || { _ok=0; _d="$_d user-data-owner"; }
        if grep -qE 'ocid1\.|BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY|ghp_[A-Za-z0-9]|github_pat_|password[[:space:]]*=' "$_ud" 2>/dev/null; then _ok=0; _d="$_d user-data-has-credential-pattern"; fi
    else
        _ok=0; _d="$_d user-data-missing"
    fi
    if [ "$_ok" -eq 1 ]; then check 13 pass "user-data mode 600 root, no credential pattern"; else check 13 fail "$_d"; fi
    # 14. /opt/harness mode 0710 root:harness; /opt/proxy mode
    # 0710 root:proxy (Revision 8 fix - the results server runs
    # as UID 1000 and the proxy as UID 1002, and each must
    # traverse its own directory to read its source; mode 0700
    # made both unreadable by their own UID). The workload UID
    # 1001 is in neither group, so it still cannot read or list
    # either directory.
    _ok=1; _d=""
    [ "$(stat -c '%a' /opt/harness 2>/dev/null)" = "710" ] || { _ok=0; _d="$_d harness-mode"; }
    [ "$(stat -c '%U' /opt/harness 2>/dev/null)" = "root" ] || { _ok=0; _d="$_d harness-owner"; }
    [ "$(stat -c '%G' /opt/harness 2>/dev/null)" = "harness" ] || { _ok=0; _d="$_d harness-group"; }
    [ "$(stat -c '%a' /opt/proxy 2>/dev/null)" = "710" ] || { _ok=0; _d="$_d proxy-mode"; }
    [ "$(stat -c '%U' /opt/proxy 2>/dev/null)" = "root" ] || { _ok=0; _d="$_d proxy-owner"; }
    [ "$(stat -c '%G' /opt/proxy 2>/dev/null)" = "proxy" ] || { _ok=0; _d="$_d proxy-group"; }
    if [ "$_ok" -eq 1 ]; then check 14 pass "/opt/harness mode 0710 root:harness, /opt/proxy mode 0710 root:proxy"; else check 14 fail "$_d"; fi
    # 15. Expected protected paths exist.
    _ok=1; _d=""
    for _p in /etc/shadow /root /home/harness /opt/harness /opt/proxy /var/lib/cloud/instance/user-data.txt; do
        [ -e "$_p" ] || { _ok=0; _d="$_d missing:$_p"; }
    done
    if [ "$_ok" -eq 1 ]; then check 15 pass "all expected protected paths exist"; else check 15 fail "$_d"; fi
    # 16. HMAC secret file + user-data cleanliness (Revision 12, spec rule 41;
    # V13, spec rule 43: the per-batch challenge is present in user-data).
    _ok=1; _d=""
    _secret=$(cat /opt/harness/hmac.key 2>/dev/null | tr -d '[:space:]')
    if [ -f /opt/harness/hmac.key ]; then
        [ "$(stat -c '%a' /opt/harness/hmac.key 2>/dev/null)" = "600" ] || { _ok=0; _d="$_d hmac-mode"; }
        [ "$(stat -c '%U' /opt/harness/hmac.key 2>/dev/null)" = "root" ] || { _ok=0; _d="$_d hmac-owner"; }
        case "$_secret" in ????????????????????????????????????????????????????????????????) : ;; *) _ok=0; _d="$_d hmac-not-64-hex" ;; esac
        case "$_secret" in ''|*[!0-9a-f]*) _ok=0; _d="$_d hmac-not-hex" ;; esac
        if setpriv --reuid=1001 --regid=1001 --clear-groups sh -c 'test -r /opt/harness/hmac.key' 2>/dev/null; then _ok=0; _d="$_d hmac-readable-by-1001"; fi
        if [ -f /var/lib/cloud/instance/user-data.txt ]; then
            grep -q "BEGIN PUBLIC KEY" /var/lib/cloud/instance/user-data.txt 2>/dev/null || { _ok=0; _d="$_d user-data-no-pubkey"; }
            if grep -q "PRIVATE KEY" /var/lib/cloud/instance/user-data.txt 2>/dev/null; then _ok=0; _d="$_d user-data-has-private-key"; fi
            if grep -q "HMAC_SECRET=" /var/lib/cloud/instance/user-data.txt 2>/dev/null; then _ok=0; _d="$_d user-data-has-secret-assignment"; fi
            # V13 (rule 43): the per-batch challenge is present in
            # user-data as a public nonce (32 hex chars) - the VM
            # signs over it, so it must be there.
            _chal_line=$(grep '^BATCH_CHALLENGE=' /var/lib/cloud/instance/user-data.txt 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')
            printf '%s' "$_chal_line" | grep -Eq '^[0-9a-f]{32}$' || { _ok=0; _d="$_d user-data-challenge"; }
        else
            _ok=0; _d="$_d user-data-missing"
        fi
        if [ -f /var/lib/cloud/instance/user-data.txt ] && grep -qF "$_secret" /var/lib/cloud/instance/user-data.txt 2>/dev/null; then _ok=0; _d="$_d secret-in-user-data"; fi
    else
        _ok=0; _d="$_d hmac-missing"
    fi
    if [ "$_ok" -eq 1 ]; then check 16 pass "hmac.key mode 600 root 64-hex unreadable by 1001, secret absent from user-data, host public key present, no private key, per-batch challenge present (32 hex)"; else check 16 fail "$_d"; fi
    # 17. Sandbox layout (probe sandbox, Sec. 4.2 command).
    _probe17=$(vm_probe_sandbox 'for _p in /results /opt/harness /opt/proxy /var/lib/cloud /root /home/harness; do if [ -e "$_p" ]; then if printf x > "$_p/.o17_test" 2>/dev/null; then rm -f "$_p/.o17_test"; echo "WRITABLE $_p"; else echo "READONLY $_p"; fi; else echo "MISSING $_p"; fi; done; df -B1 /tmp | awk "NR==2 {print \"TMP_SIZE=\" \$2 \" TMP_SRC=\" \$1}"' 2>&1)
    _ok=1; _d=""
    for _p in /results /opt/harness /opt/proxy /var/lib/cloud /root /home/harness; do
        printf '%s\n' "$_probe17" | grep -q "READONLY $_p" || { _ok=0; _d="$_d $_p not readonly-visible"; }
    done
    _tmp_size=$(printf '%s\n' "$_probe17" | awk -F= '/^TMP_SIZE=/ {print $2}' | awk '{print $1}')
    if [ -n "$_tmp_size" ]; then
        if [ "$_tmp_size" -ge 1072693248 ] && [ "$_tmp_size" -le 1074790400 ]; then :; else _ok=0; _d="$_d tmp-size=$_tmp_size"; fi
    else
        _ok=0; _d="$_d tmp-size-unreadable"
    fi
    if [ "$_ok" -eq 1 ]; then check 17 pass "sandbox layout: protected paths visible + read-only, /tmp 1 GiB tmpfs"; else check 17 fail "$_d"; fi
    # 18. Installed egress-proxy.py hash.
    _ph=$(sha256sum /opt/proxy/egress-proxy.py 2>/dev/null | awk '{print $1}')
    if [ "$_ph" = "ebde47e446f4e6f4f127e25390ed6e0305b6b23d535cb4db98e40ab6145967c0" ]; then check 18 pass "egress-proxy.py hash matches the reviewed source"; else check 18 fail "proxy hash $_ph"; fi
    # 19. VM timezone UTC.
    if [ "$(date +%Z 2>/dev/null)" = "UTC" ]; then check 19 pass "timezone UTC"; else check 19 fail "timezone $(date +%Z 2>/dev/null)"; fi
    # 20. Sandbox environment (probe sandbox, Sec. 4.2 command).
    _probe20=$(vm_probe_sandbox 'env | sort' 2>&1)
    _ok=1; _d=""
    for _ev in "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "HOME=/home/workload" "http_proxy=http://127.0.0.1:3128" "https_proxy=http://127.0.0.1:3128" "HTTP_PROXY=http://127.0.0.1:3128" "HTTPS_PROXY=http://127.0.0.1:3128" "PROXY_PORT=3128"; do
        printf '%s\n' "$_probe20" | grep -qx "$_ev" || { _ok=0; _d="$_d missing:$_ev"; }
    done
    # The probe shell adds PWD (and SHLVL) to the environment; they
    # are shell-added, not sandbox variables. Filter them out before
    # counting. (Revision 8 fix - V7 counted them and expected exactly
    # 7, so the check always failed: the real env is 7 + PWD = 8.)
    _n_env=$(printf '%s\n' "$_probe20" | grep -v '^PWD=' | grep -v '^SHLVL=' | grep -c . || echo 0)
    [ "$_n_env" = "7" ] || { _ok=0; _d="$_d env-count=$_n_env want 7 (PWD/SHLVL excluded)"; }
    _hw_mode=$(stat -c '%a' /home/workload 2>/dev/null || echo "")
    _hw_owner=$(stat -c '%u:%g' /home/workload 2>/dev/null || echo "")
    [ "$_hw_mode" = "700" ] || { _ok=0; _d="$_d home-mode=$_hw_mode"; }
    [ "$_hw_owner" = "1001:1001" ] || { _ok=0; _d="$_d home-owner=$_hw_owner"; }
    if [ "$_ok" -eq 1 ]; then check 20 pass "sandbox env exactly the 7 variables, /home/workload 700 1001:1001"; else check 20 fail "$_d"; fi
    # 21. Proxy cgroup (Revision 12, spec rule 40): the proxy runs
    # inside /sys/fs/cgroup/proxy/ with its own limits, independent
    # of the workload cgroup. The limits must read back, the proxy
    # process must be in the proxy cgroup, and it must NOT be in
    # the workload cgroup.
    _ok=1; _d=""
    _proxy_pid21=$(pgrep -u 1002 -f egress-proxy.py 2>/dev/null | head -1)
    [ -n "$_proxy_pid21" ] || { _ok=0; _d="$_d proxy-not-running"; }
    [ "$(cat /sys/fs/cgroup/proxy/memory.max 2>/dev/null)" = "536870912" ] || { _ok=0; _d="$_d proxy-memory.max"; }
    [ "$(cat /sys/fs/cgroup/proxy/cpu.max 2>/dev/null)" = "50000 100000" ] || { _ok=0; _d="$_d proxy-cpu.max"; }
    [ "$(cat /sys/fs/cgroup/proxy/pids.max 2>/dev/null)" = "64" ] || { _ok=0; _d="$_d proxy-pids.max"; }
    if [ -n "$_proxy_pid21" ]; then
        grep -q "^$_proxy_pid21$" /sys/fs/cgroup/proxy/cgroup.procs 2>/dev/null || { _ok=0; _d="$_d proxy-not-in-proxy-cgroup"; }
        if grep -q "^$_proxy_pid21$" /sys/fs/cgroup/workload/cgroup.procs 2>/dev/null; then _ok=0; _d="$_d proxy-in-workload-cgroup"; fi
    fi
    if [ "$_ok" -eq 1 ]; then check 21 pass "proxy cgroup limits read back, proxy in proxy cgroup, not in workload cgroup"; else check 21 fail "$_d"; fi
    # 22. Authenticated secret delivery (V13, spec rule 43): the
    # identity artifacts exist, the certificate parses with valid
    # dates, its OCID is this instance's OCID (from batch.env), and
    # the signature verifies over batch_id + challenge + the
    # ciphertext SHA-256 (reconstructed from batch.env + the
    # published ciphertext). This is the VM-side proof that the
    # delivery the host will authenticate was actually signed by
    # THIS instance.
    _ok=1; _d=""
    _v22_bid=$(grep '^BATCH_ID=' /opt/harness/batch.env 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')
    _v22_chal=$(grep '^BATCH_CHALLENGE=' /opt/harness/batch.env 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')
    _v22_ocid=$(grep '^INSTANCE_OCID=' /opt/harness/batch.env 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')
    for _f in /results/hmac_secret.sig /results/hmac_secret.cert.pem /results/hmac_secret.intermediate.pem; do
        [ -f "$_f" ] || { _ok=0; _d="$_d missing:$_f"; }
    done
    [ -n "$_v22_bid" ] || { _ok=0; _d="$_d batch-id-missing"; }
    [ -n "$_v22_chal" ] || { _ok=0; _d="$_d challenge-missing"; }
    [ -n "$_v22_ocid" ] || { _ok=0; _d="$_d instance-ocid-missing"; }
    if [ "$_ok" -eq 1 ]; then
        openssl x509 -noout -checkend 0 -in /results/hmac_secret.cert.pem >/dev/null 2>&1 || { _ok=0; _d="$_d cert-dates"; }
        openssl x509 -noout -text -in /results/hmac_secret.cert.pem 2>/dev/null | grep -qF "$_v22_ocid" || { _ok=0; _d="$_d cert-ocid-mismatch"; }
        _v22_sha=$(sha256sum /results/hmac_secret.enc 2>/dev/null | awk '{print $1}')
        [ -n "$_v22_sha" ] || { _ok=0; _d="$_d ciphertext-missing"; }
        printf 'BATCH_ID=%s\nCHALLENGE=%s\nCIPHERTEXT_SHA256=%s\n' "$_v22_bid" "$_v22_chal" "$_v22_sha" > /tmp/m8-check22-data.txt || { _ok=0; _d="$_d cannot-write-delivery-data"; }
        openssl x509 -noout -pubkey -in /results/hmac_secret.cert.pem -out /tmp/m8-check22-pubkey.pem 2>/dev/null || { _ok=0; _d="$_d cert-pubkey"; }
        openssl dgst -sha256 -verify /tmp/m8-check22-pubkey.pem -signature /results/hmac_secret.sig /tmp/m8-check22-data.txt >/dev/null 2>&1 || { _ok=0; _d="$_d signature"; }
        rm -f /tmp/m8-check22-data.txt /tmp/m8-check22-pubkey.pem
    fi
    if [ "$_ok" -eq 1 ]; then check 22 pass "identity artifacts present, cert dates valid, cert OCID is this instance, signature verifies over batch_id+challenge+ciphertext hash"; else check 22 fail "$_d"; fi
    # Write the setup record (JSON).
    python3 - /tmp/setup_checks.txt "$SETUP_RECORD" <<'PYEOF'
import json, sys
checks = {}
for line in open(sys.argv[1]):
    line = line.strip()
    if not line.startswith("SETUP_CHECK "):
        continue
    parts = line.split(" ", 3)
    kv = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            kv[k] = v
    checks[kv.get("n", "?")] = {"result": kv.get("result", "?"), "detail": kv.get("detail", "")}
json.dump({"setup_checks": checks}, open(sys.argv[2], "w"), indent=2)
PYEOF
    if [ "$SETUP_FAIL" -ne 0 ]; then
        log_vm "vm_setup_verify FAILED (see setup_record.json)"
        return 1
    fi
    log_vm "vm_setup_verify all 22 checks pass (item 5 deferred to per-case prepare_workdir)"
    return 0
}

# vm_setup_dryrun - the dry-run VM-side setup (spec rule 29).
# The mock VM (mock_vm.sh) already provides the fake tree (fake
# cgroup, fake /etc/hosts, 1 GiB /tmp tmpfs, fake /opt/harness +
# /opt/proxy, the O-test scripts, the egress proxy source). This
# function does only the VM-side work that is safe locally: it
# writes the Sec. 7.1 limits into the FAKE cgroup files, writes
# the proxy filter, starts the egress proxy (UID 1002) and the
# results server (UID 1000), generates the per-batch HMAC secret
# INSIDE the VM and writes it to /opt/harness/hmac.key (mode 600),
# encrypts it with the host public key for the host to pull, and
# fixes /home/workload
# ownership. It does NOT install packages, create users, touch
# iptables, create a loopback image, or touch systemd (none of
# those exist in the mock VM). The proxy's log file
# (/var/log/m8-proxy.log) is created on the host's real /var/log
# (the mock VM has no fake /var/log bind) - the dry-run driver
# removes it afterwards.
vm_setup_dryrun() {
    log_vm "vm_setup_dryrun start"
    [ -f /opt/harness/batch.env ] || { log_vm "vm_setup_dryrun batch.env missing"; return 1; }
    [ -f /opt/proxy/egress-proxy.py ] || { log_vm "vm_setup_dryrun egress-proxy.py missing"; return 1; }
    [ -d /sys/fs/cgroup/workload ] || { log_vm "vm_setup_dryrun fake workload cgroup missing"; return 1; }
    # (3) The workload cgroup limits (Sec. 7.1), written into the
    # FAKE cgroup files (they are regular files in the fake tree).
    printf '4194304K' > /sys/fs/cgroup/workload/memory.max || { log_vm "vm_setup_dryrun cannot set memory.max"; return 1; }
    printf '3145728K' > /sys/fs/cgroup/workload/memory.high || { log_vm "vm_setup_dryrun cannot set memory.high"; return 1; }
    printf '0' > /sys/fs/cgroup/workload/memory.swap.max || { log_vm "vm_setup_dryrun cannot set memory.swap.max"; return 1; }
    printf '100000 100000' > /sys/fs/cgroup/workload/cpu.max || { log_vm "vm_setup_dryrun cannot set cpu.max"; return 1; }
    printf '512' > /sys/fs/cgroup/workload/pids.max || { log_vm "vm_setup_dryrun cannot set pids.max"; return 1; }
    if [ -f /opt/harness/boot_device.txt ]; then
        _bd=$(cat /opt/harness/boot_device.txt)
        printf '%s rbps=52428800 wbps=52428800' "$_bd" > /sys/fs/cgroup/workload/io.max 2>/dev/null || log_vm "vm_setup_dryrun io.max for boot device failed (recorded; O8 will catch it)"
    fi
    # (4) /tmp is the 1 GiB tmpfs (bound by the mock VM from
    # /opt/stage/tmp). Verify it, do not mount it.
    _tmp_total=$(df -B1 /tmp 2>/dev/null | awk 'NR==2 {print $2}')
    if [ -z "$_tmp_total" ] || [ "$_tmp_total" -lt 1072693248 ] || [ "$_tmp_total" -gt 1074790400 ]; then
        log_vm "vm_setup_dryrun /tmp tmpfs wrong size: $_tmp_total"; return 1
    fi
    # (6) The egress proxy filter + the proxy itself (UID 1002).
    # The filter is the same five regexes as the real setup.
    printf '%s\n' '^github\.com$' '^objects\.githubusercontent\.com$' '^registry\.npmjs\.org$' '^pypi\.org$' '^files\.pythonhosted\.org$' > /opt/proxy/filter || { log_vm "vm_setup_dryrun cannot write filter"; return 1; }
    # The proxy runs as UID 1002, so the filter must be readable by
    # that UID: mode 640 root:1002 (Revision 8 fix - V7 chmod 600
    # made it unreadable by its own UID).
    chown root:1002 /opt/proxy/filter 2>/dev/null || true
    chmod 640 /opt/proxy/filter || { log_vm "vm_setup_dryrun cannot chmod filter"; return 1; }
    touch /var/log/m8-proxy.log || { log_vm "vm_setup_dryrun cannot create proxy log"; return 1; }
    chown 1002:1002 /var/log/m8-proxy.log 2>/dev/null || true
    chmod 644 /var/log/m8-proxy.log || { log_vm "vm_setup_dryrun cannot chmod proxy log"; return 1; }
    nohup setpriv --reuid=1002 --regid=1002 --clear-groups --inh-caps=-all --ambient-caps=-all --no-new-privs python3 /opt/proxy/egress-proxy.py >/var/log/m8-proxy.out 2>&1 &
    sleep 2
    pgrep -u 1002 -f egress-proxy.py >/dev/null 2>&1 || { log_vm "vm_setup_dryrun proxy did not start"; return 1; }
    # The results server (UID 1000, port 8080) - the same source as
    # the real vm_setup (whitelist-only, no listing, no traversal).
    cat > /opt/harness/results_server.py <<'PYEOF'
#!/usr/bin/env python3
"""results_server.py - M8 results endpoint (Revision 8).

Serves ONLY the whitelisted sanitized manifest files under /results,
as UID 1000 on port 8080. No directory listing, no path traversal,
no raw logs, no CGI. Any other path is exactly HTTP 404. Only GET.
"""
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

RESULTS_DIR = "/results"
PORT = 8080
CASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
TOP = {"batch.json", "batch.json.hmac", "results.sha256",
       "results.sha256.hmac", "DONE", "watchdog-snapshot.txt",
       "watchdog-snapshot.txt.hmac", "hmac_secret.enc", "hmac_secret.sig",
       "hmac_secret.cert.pem", "hmac_secret.intermediate.pem"}  # V13 (rule 43): the authenticated-delivery artifacts

def allowed(path):
    if not path or path.startswith("/") or ".." in path.split("/"):
        return None
    parts = path.split("/")
    if len(parts) == 1:
        if parts[0] in TOP:
            return os.path.join(RESULTS_DIR, parts[0])
        return None
    if len(parts) == 2 and CASE_RE.match(parts[0]) and parts[1] in ("manifest.json", "manifest.json.hmac"):
        return os.path.join(RESULTS_DIR, parts[0], parts[1])
    return None

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        from urllib.parse import unquote
        raw = self.path.split("?", 1)[0]
        target = allowed(unquote(raw.lstrip("/")))
        if target is None or not os.path.isfile(target):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            with open(target, "rb") as f:
                data = f.read()
        except OSError:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def do_POST(self):
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()
    do_PUT = do_POST
    do_DELETE = do_POST

if __name__ == "__main__":
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
PYEOF
    chmod 644 /opt/harness/results_server.py || { log_vm "vm_setup_dryrun cannot chmod results server"; return 1; }
    nohup setpriv --reuid=1000 --regid=1000 --clear-groups --inh-caps=-all --ambient-caps=-all --no-new-privs python3 /opt/harness/results_server.py >/var/log/m8-results.out 2>&1 &
    sleep 2
    pgrep -u 1000 -f results_server.py >/dev/null 2>&1 || { log_vm "vm_setup_dryrun results server did not start"; return 1; }
    # (V13, spec rule 44) Plant the traversal canary OUTSIDE
    # /results (same as the real vm_setup): mode 0755, readable by
    # the results-server UID 1000, not writable by UID 1001.
    _canary_bid=$(grep '^BATCH_ID=' /opt/harness/batch.env 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')
    [ -n "$_canary_bid" ] || { log_vm "vm_setup_dryrun cannot read BATCH_ID for traversal canary"; return 1; }
    mkdir -p /opt/traversal || { log_vm "vm_setup_dryrun cannot create traversal canary dir"; return 1; }
    chmod 755 /opt/traversal || { log_vm "vm_setup_dryrun cannot chmod traversal canary dir"; return 1; }
    printf 'TRAVERSAL-CANARY-%s\n' "$_canary_bid" > /opt/traversal/traversal_canary.txt || { log_vm "vm_setup_dryrun cannot write traversal canary"; return 1; }
    chmod 644 /opt/traversal/traversal_canary.txt || { log_vm "vm_setup_dryrun cannot chmod traversal canary"; return 1; }
    # The per-batch HMAC secret (Revision 12, spec rule 41): generated
    # INSIDE the VM, never in user-data - mirroring the real bootstrap.
    # The host's per-batch PUBLIC key comes from the user-data file
    # (mock_vm.sh copied the host's generated user-data into the fake
    # tree); the secret is encrypted with it (RSA-OAEP SHA-256) and
    # published as /results/hmac_secret.enc for the host to pull.
    [ -f /var/lib/cloud/instance/user-data.txt ] || { log_vm "vm_setup_dryrun user-data.txt missing"; return 1; }
    python3 - /var/lib/cloud/instance/user-data.txt /opt/harness/host_pubkey.pem <<'PYEOF' || { log_vm "vm_setup_dryrun cannot extract host public key from user-data"; return 1; }
import sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src).read()
start = text.find("-----BEGIN PUBLIC KEY-----")
end = text.find("-----END PUBLIC KEY-----")
if start < 0 or end < 0:
    print("no public key block in user-data")
    sys.exit(1)
end += len("-----END PUBLIC KEY-----")
open(dst, "w").write(text[start:end] + "\n")
PYEOF
    chmod 600 /opt/harness/host_pubkey.pem || { log_vm "vm_setup_dryrun cannot chmod host_pubkey.pem"; return 1; }
    python3 -c "import sys, secrets; sys.stdout.write(secrets.token_hex(32))" > /opt/harness/hmac.key || { log_vm "vm_setup_dryrun cannot generate hmac.key"; return 1; }
    chmod 600 /opt/harness/hmac.key || { log_vm "vm_setup_dryrun cannot chmod hmac.key"; return 1; }
    chown root:root /opt/harness/hmac.key || { log_vm "vm_setup_dryrun cannot chown hmac.key"; return 1; }
    # The secret must NOT appear in user-data (it was never written
    # there): verify by grep with the generated value. A hit is a
    # setup failure - no case runs.
    _s=$(cat /opt/harness/hmac.key | tr -d '[:space:]')
    if grep -qF "$_s" /var/lib/cloud/instance/user-data.txt 2>/dev/null; then log_vm "vm_setup_dryrun secret present in user-data"; return 1; fi
    command -v openssl >/dev/null 2>&1 || { log_vm "vm_setup_dryrun openssl missing"; return 1; }
    openssl pkeyutl -encrypt -pubin -inkey /opt/harness/host_pubkey.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in /opt/harness/hmac.key -out /results/hmac_secret.enc || { log_vm "vm_setup_dryrun cannot encrypt hmac secret"; return 1; }
    chmod 644 /results/hmac_secret.enc || { log_vm "vm_setup_dryrun cannot chmod hmac_secret.enc"; return 1; }
    # (V13, spec rule 43) Sign the delivery with the mock instance
    # identity (dry-run mirror of the real bootstrap): read the
    # mock leaf + intermediate + private key from the fake IMDS
    # (/opt/harness/imds/, placed by mock_vm.sh), verify the key
    # matches the certificate, sign batch_id + challenge +
    # ciphertext SHA-256, publish the signature + certificates on
    # the results endpoint, then DELETE the private key. The
    # challenge and batch id come from batch.env.
    [ -f /opt/harness/imds/cert.pem ] || { log_vm "vm_setup_dryrun mock instance certificate missing"; return 1; }
    [ -f /opt/harness/imds/intermediate.pem ] || { log_vm "vm_setup_dryrun mock intermediate certificate missing"; return 1; }
    [ -f /opt/harness/imds/key.pem ] || { log_vm "vm_setup_dryrun mock instance private key missing"; return 1; }
    chmod 600 /opt/harness/imds/key.pem || { log_vm "vm_setup_dryrun cannot chmod mock instance key"; return 1; }
    chmod 644 /opt/harness/imds/cert.pem /opt/harness/imds/intermediate.pem || { log_vm "vm_setup_dryrun cannot chmod mock identity certificates"; return 1; }
    _cert_pub=$(openssl x509 -noout -pubkey -in /opt/harness/imds/cert.pem 2>/dev/null) || { log_vm "vm_setup_dryrun mock instance certificate does not parse"; return 1; }
    _key_pub=$(openssl pkey -in /opt/harness/imds/key.pem -pubout 2>/dev/null) || { log_vm "vm_setup_dryrun mock instance key does not parse"; return 1; }
    [ "$_cert_pub" = "$_key_pub" ] || { log_vm "vm_setup_dryrun mock instance key does not match certificate"; return 1; }
    _bid=$(grep '^BATCH_ID=' /opt/harness/batch.env 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')
    _chal=$(grep '^BATCH_CHALLENGE=' /opt/harness/batch.env 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')
    [ -n "$_bid" ] || { log_vm "vm_setup_dryrun BATCH_ID missing for delivery data"; return 1; }
    [ -n "$_chal" ] || { log_vm "vm_setup_dryrun BATCH_CHALLENGE missing for delivery data"; return 1; }
    _enc_sha=$(sha256sum /results/hmac_secret.enc | awk '{print $1}')
    printf 'BATCH_ID=%s\nCHALLENGE=%s\nCIPHERTEXT_SHA256=%s\n' "$_bid" "$_chal" "$_enc_sha" > /opt/harness/delivery_data.txt || { log_vm "vm_setup_dryrun cannot write delivery_data.txt"; return 1; }
    chmod 600 /opt/harness/delivery_data.txt || { log_vm "vm_setup_dryrun cannot chmod delivery_data.txt"; return 1; }
    openssl dgst -sha256 -sign /opt/harness/imds/key.pem -out /results/hmac_secret.sig /opt/harness/delivery_data.txt || { log_vm "vm_setup_dryrun cannot sign secret delivery"; return 1; }
    chmod 644 /results/hmac_secret.sig || { log_vm "vm_setup_dryrun cannot chmod hmac_secret.sig"; return 1; }
    cp /opt/harness/imds/cert.pem /results/hmac_secret.cert.pem || { log_vm "vm_setup_dryrun cannot publish instance certificate"; return 1; }
    cp /opt/harness/imds/intermediate.pem /results/hmac_secret.intermediate.pem || { log_vm "vm_setup_dryrun cannot publish instance intermediate certificate"; return 1; }
    chmod 644 /results/hmac_secret.cert.pem /results/hmac_secret.intermediate.pem || { log_vm "vm_setup_dryrun cannot chmod identity certificates"; return 1; }
    rm -f /opt/harness/imds/key.pem || { log_vm "vm_setup_dryrun cannot delete mock instance private key"; return 1; }
    [ ! -e /opt/harness/imds/key.pem ] || { log_vm "vm_setup_dryrun mock instance private key still present after delete"; return 1; }
    log_vm "vm_setup_dryrun secret delivery signed with mock instance identity"
    # The proxy cgroup fixtures (Revision 12, spec rule 40): the
    # proxy runs inside /sys/fs/cgroup/proxy/ with its own limits
    # (Sec. 7.1). Static fixtures, mirroring the workload cgroup
    # above; enforcement is NOT proven by these fixtures (the
    # dry-run proves the in-process cap via O5(h) + the driver
    # concurrency regression; the cgroup limits are proven by the
    # real-VM setup check, Sec. 7.4 item 21).
    printf '536870912' > /sys/fs/cgroup/proxy/memory.max || { log_vm "vm_setup_dryrun cannot set proxy memory.max"; return 1; }
    printf '50000 100000' > /sys/fs/cgroup/proxy/cpu.max || { log_vm "vm_setup_dryrun cannot set proxy cpu.max"; return 1; }
    printf '64' > /sys/fs/cgroup/proxy/pids.max || { log_vm "vm_setup_dryrun cannot set proxy pids.max"; return 1; }
    # /home/workload (the per-case home) owned by the workload UID.
    chown 1001:1001 /home/workload 2>/dev/null || true
    chmod 700 /home/workload 2>/dev/null || true
    # Node version (recorded; the O-tests do not need Node).
    printf '%s\n' "$(node --version 2>/dev/null || echo not_installed)" > /opt/harness/node_version.txt
    log_vm "vm_setup_dryrun complete"
    return 0
}

# vm_setup_verify_dryrun - the 22-check subset for the dry-run
# (spec rule 29). Checks 3, 7, 9, 10, 12 (partial - the /proc/1/root
# sub-part is the host's /proc, not a VM's, so it is skipped with
# its reason), 13, 14, 15, 16, 17, 18, 19, 20 RUN against the fake
# tree / the real services. Checks 1, 2, 4, 6, 8, 11 are recorded
# as DRYRUN_SKIP with their reason (host is x86_64 not aarch64; no
# real cgroup/iptables/loopback/systemd; host has swap and IPv6).
# Check 5 is deferred (verified per case by prepare_workdir_dryrun).
# A DRYRUN_SKIP is not a pass and not a fail - it is recorded in
# the setup record so the evidence log can state exactly what the
# dry-run did and did not verify.
vm_setup_verify_dryrun() {
    log_vm "vm_setup_verify_dryrun start"
    SETUP_FAIL=0
    SETUP_RECORD="$RESULTS_DIR/setup_record.json"
    : > /tmp/setup_checks.txt
    check() {
        printf 'SETUP_CHECK n=%s result=%s detail=%s\n' "$1" "$2" "$3" >> /tmp/setup_checks.txt
        printf 'SETUP_CHECK n=%s result=%s detail=%s\n' "$1" "$2" "$3"
        case "$2" in pass|dryrun_skip|deferred) : ;; *) SETUP_FAIL=1 ;; esac
    }
    # 1. Architecture - DRYRUN_SKIP (host is x86_64, not aarch64).
    printf 'SETUP_CHECK n=1 result=dryrun_skip detail=host is x86_64, not aarch64 (a real A1 VM is aarch64)\n' >> /tmp/setup_checks.txt
    printf 'SETUP_CHECK n=1 result=dryrun_skip detail=host is x86_64, not aarch64 (a real A1 VM is aarch64)\n'
    # 2. Controllers - DRYRUN_SKIP (the fake cgroup is static fixture
    # text, not a real controller tree; the values are not enforced).
    printf 'SETUP_CHECK n=2 result=dryrun_skip detail=fake cgroup is static fixture text, controllers not really enabled\n' >> /tmp/setup_checks.txt
    printf 'SETUP_CHECK n=2 result=dryrun_skip detail=fake cgroup is static fixture text, controllers not really enabled\n'
    # 3. Limits read back (from the fake cgroup files).
    _ok=1; _d=""
    [ "$(cat /sys/fs/cgroup/workload/memory.max 2>/dev/null)" = "4194304K" ] || { _ok=0; _d="$_d memory.max"; }
    [ "$(cat /sys/fs/cgroup/workload/memory.high 2>/dev/null)" = "3145728K" ] || { _ok=0; _d="$_d memory.high"; }
    [ "$(cat /sys/fs/cgroup/workload/memory.swap.max 2>/dev/null)" = "0" ] || { _ok=0; _d="$_d memory.swap.max"; }
    [ "$(cat /sys/fs/cgroup/workload/cpu.max 2>/dev/null)" = "100000 100000" ] || { _ok=0; _d="$_d cpu.max"; }
    [ "$(cat /sys/fs/cgroup/workload/pids.max 2>/dev/null)" = "512" ] || { _ok=0; _d="$_d pids.max"; }
    if [ -f /opt/harness/boot_device.txt ]; then
        _bd=$(cat /opt/harness/boot_device.txt)
        grep -q "$_bd" /sys/fs/cgroup/workload/io.max 2>/dev/null || { _ok=0; _d="$_d io.max boot device $_bd"; }
    else
        _ok=0; _d="$_d io.max boot device unknown"
    fi
    if [ "$_ok" -eq 1 ]; then check 3 pass "limits read back from fake cgroup (io.max loopback device per case)"; else check 3 fail "limit mismatch:$_d"; fi
    # 4. No swap - DRYRUN_SKIP (the host has swap; the mock VM
    # cannot disable the host's swap).
    printf 'SETUP_CHECK n=4 result=dryrun_skip detail=host has swap (/dev/loop0), mock VM cannot disable it\n' >> /tmp/setup_checks.txt
    printf 'SETUP_CHECK n=4 result=dryrun_skip detail=host has swap (/dev/loop0), mock VM cannot disable it\n'
    # 5. Loopback image - deferred (verified per case by
    # prepare_workdir_dryrun, which uses a disk-backed fake workdir
    # instead of a 20 GB loopback image).
    printf 'SETUP_CHECK n=5 result=deferred detail=verified per case by prepare_workdir_dryrun (disk-backed fake workdir, not a 20 GB loopback image)\n' >> /tmp/setup_checks.txt
    printf 'SETUP_CHECK n=5 result=deferred detail=verified per case by prepare_workdir_dryrun (disk-backed fake workdir, not a 20 GB loopback image)\n'
    # 6. iptables - DRYRUN_SKIP (no iptables in the mock VM).
    printf 'SETUP_CHECK n=6 result=dryrun_skip detail=no iptables in the mock VM\n' >> /tmp/setup_checks.txt
    printf 'SETUP_CHECK n=6 result=dryrun_skip detail=no iptables in the mock VM\n'
    # 7. Proxy running as uid 1002; filter has exactly the five regexes.
    _proxy_pid=$(pgrep -u 1002 -f egress-proxy.py 2>/dev/null | head -1)
    _ok=1; _d=""
    [ -n "$_proxy_pid" ] || { _ok=0; _d="$_d proxy-not-running"; }
    if [ -f /opt/proxy/filter ]; then
        _n=$(grep -c . /opt/proxy/filter 2>/dev/null || echo 0)
        [ "$_n" = "5" ] || { _ok=0; _d="$_d filter-lines=$_n"; }
        grep -qx '^\^github\\.com\$$' /opt/proxy/filter || { _ok=0; _d="$_d filter-github"; }
        grep -qx '^\^objects\\.githubusercontent\\.com\$$' /opt/proxy/filter || { _ok=0; _d="$_d filter-objects"; }
        grep -qx '^\^registry\\.npmjs\\.org\$$' /opt/proxy/filter || { _ok=0; _d="$_d filter-npmjs"; }
        grep -qx '^\^pypi\\.org\$$' /opt/proxy/filter || { _ok=0; _d="$_d filter-pypi"; }
        grep -qx '^\^files\\.pythonhosted\\.org\$$' /opt/proxy/filter || { _ok=0; _d="$_d filter-pythonhosted"; }
    else
        _ok=0; _d="$_d filter-missing"
    fi
    if [ "$_ok" -eq 1 ]; then check 7 pass "proxy running as uid 1002, filter has the five regexes"; else check 7 fail "proxy/filter problem:$_d"; fi
    # 8. Docker/sudo - DRYRUN_SKIP (host properties, not mock VM
    # properties; the mock VM has no Docker socket).
    printf 'SETUP_CHECK n=8 result=dryrun_skip detail=no Docker in the mock VM; sudo is a host property\n' >> /tmp/setup_checks.txt
    printf 'SETUP_CHECK n=8 result=dryrun_skip detail=no Docker in the mock VM; sudo is a host property\n'
    # 9. Results server running as uid 1000 on 8080; whitelist only.
    # (V13, spec rule 44) The traversal probes use a RAW SOCKET,
    # not curl - same as the real check 9 (curl normalises /../).
    # Probes: literal /../batch.json; literal canary path;
    # percent-encoded /%2e%2e/...; /..%2f...; double-encoded
    # /%252e%252e/.... Each must return HTTP 404 AND the canary
    # marker must not appear in any body.
    _ok=1; _d=""
    _rs_pid=$(pgrep -u 1000 -f results_server.py 2>/dev/null | head -1)
    [ -n "$_rs_pid" ] || { _ok=0; _d="$_d results-server-not-running"; }
    _c1=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:8080/ 2>/dev/null || echo 000)
    [ "$_c1" = "404" ] || { _ok=0; _d="$_d listing-code=$_c1"; }
    _marker=$(cat /opt/traversal/traversal_canary.txt 2>/dev/null | tr -d '[:space:]')
    [ -n "$_marker" ] || { _ok=0; _d="$_d canary-missing"; }
    for _t in "/../batch.json" "/../opt/traversal/traversal_canary.txt" "/%2e%2e/opt/traversal/traversal_canary.txt" "/..%2fopt/traversal/traversal_canary.txt" "/%252e%252e/opt/traversal/traversal_canary.txt"; do
        _probe_out=$(raw_traversal_probe 127.0.0.1 8080 "$_t" "$_marker" 2>&1)
        _probe_rc=$?
        if [ "$_probe_rc" -ne 0 ]; then _ok=0; _d="$_d traversal-fail:$_t:$_probe_out"; fi
    done
    if [ "$_ok" -eq 1 ]; then check 9 pass "results server uid 1000 on 8080, listing 404, raw-socket literal+encoded traversal 404 with no canary leak"; else check 9 fail "$_d"; fi
    # 10. Versions recorded.
    {
        printf 'node=%s\n' "$(node --version 2>/dev/null || echo not_installed)"
        printf 'python3=%s\n' "$(python3 --version 2>&1 || echo missing)"
        printf 'git=%s\n' "$(git --version 2>/dev/null || echo missing)"
        printf 'bwrap=%s\n' "$(bwrap --version 2>/dev/null || echo missing)"
        printf 'iptables=%s\n' "$(iptables --version 2>/dev/null || echo missing)"
        printf 'proxy=%s\n' "$(sha256sum /opt/proxy/egress-proxy.py 2>/dev/null | awk '{print $1}')"
    } > /opt/harness/versions.txt
    check 10 pass "versions recorded in /opt/harness/versions.txt"
    # 11. IPv6 - DRYRUN_SKIP (the host has IPv6; the mock VM cannot
    # disable the host's IPv6).
    printf 'SETUP_CHECK n=11 result=dryrun_skip detail=host has IPv6 (if_inet6 non-empty), mock VM cannot disable it\n' >> /tmp/setup_checks.txt
    printf 'SETUP_CHECK n=11 result=dryrun_skip detail=host has IPv6 (if_inet6 non-empty), mock VM cannot disable it\n'
    # 12. Privilege state (partial): NoNewPrivs 1, CapEff 0; UID 1001
    # cannot write the fake workload cgroup or the parent
    # cgroup.procs; cannot read /root, /home/harness, or the
    # user-data file. The /proc/1/root sub-part is SKIPPED: the mock
    # VM shares the host's /proc, so /proc/1/root is the host
    # init's root, not a VM init's (verified: it is NOT readable by
    # UID 1001 on this host, but the property is a host property,
    # not a mock VM property, so it is not counted as a pass).
    _ok=1; _d=""
    _probe_out=$(setpriv --reuid=1001 --regid=1001 --clear-groups --inh-caps=-all --ambient-caps=-all --no-new-privs sh -c 'grep -E "^(NoNewPrivs|CapEff):" /proc/self/status' 2>/dev/null)
    printf '%s\n' "$_probe_out" | grep -qE "^NoNewPrivs:[[:space:]]+1$" || { _ok=0; _d="$_d nonewprivs"; }
    printf '%s\n' "$_probe_out" | grep -qE "^CapEff:[[:space:]]+0{16}$" || { _ok=0; _d="$_d capeff"; }
    if setpriv --reuid=1001 --regid=1001 --clear-groups sh -c 'printf x > /sys/fs/cgroup/workload/o13_test && echo WRITABLE || echo DENIED' 2>/dev/null | grep -q WRITABLE; then _ok=0; _d="$_d cgroup-writable"; fi
    if setpriv --reuid=1001 --regid=1001 --clear-groups sh -c 'echo $$ > /sys/fs/cgroup/cgroup.procs && echo MOVED || echo DENIED' 2>/dev/null | grep -q MOVED; then _ok=0; _d="$_d cgroup-move"; fi
    for _p in /root /home/harness /var/lib/cloud/instance/user-data.txt; do
        if setpriv --reuid=1001 --regid=1001 --clear-groups sh -c "test -r $_p" 2>/dev/null; then _ok=0; _d="$_d readable:$_p"; fi
    done
    rm -f /sys/fs/cgroup/workload/o13_test 2>/dev/null || true
    if [ "$_ok" -eq 1 ]; then check 12 pass "NoNewPrivs 1, CapEff 0, cgroup unwritable/unmovable, protected paths unreadable by 1001 (/proc/1/root skipped - host /proc)"; else check 12 fail "$_d"; fi
    # 13. User-data file mode 600, root-owned, no secrets.
    _ok=1; _d=""
    _ud=/var/lib/cloud/instance/user-data.txt
    if [ -f "$_ud" ]; then
        [ "$(stat -c '%a' "$_ud" 2>/dev/null)" = "600" ] || { _ok=0; _d="$_d user-data-mode"; }
        [ "$(stat -c '%U' "$_ud" 2>/dev/null)" = "root" ] || { _ok=0; _d="$_d user-data-owner"; }
        if grep -qE 'ocid1\.|BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY|ghp_[A-Za-z0-9]|github_pat_|password[[:space:]]*=' "$_ud" 2>/dev/null; then _ok=0; _d="$_d user-data-has-credential-pattern"; fi
    else
        _ok=0; _d="$_d user-data-missing"
    fi
    if [ "$_ok" -eq 1 ]; then check 13 pass "user-data mode 600 root, no credential pattern"; else check 13 fail "$_d"; fi
    # 14. /opt/harness mode 0711 root; /opt/proxy mode 0711
    # root (Revision 8 fix - the results server runs as UID 1000
    # and the proxy as UID 1002, and each must traverse its own
    # directory to read its source; mode 0700 made both unreadable
    # by their own UID). The MOCK uses 0711, not the real 0710
    # root:harness / root:proxy, because this host's overlay
    # filesystem refuses chown of a directory to a non-root owner
    # (verified EPERM), so the mock cannot set either group on
    # the directories. The contents are still protected: the HMAC
    # secret is 600 root and the scripts are 700 root, so the
    # workload UID 1001 can traverse the directories but cannot
    # read anything sensitive in them. The groups are therefore
    # NOT checked in the dry-run.
    _ok=1; _d=""
    [ "$(stat -c '%a' /opt/harness 2>/dev/null)" = "711" ] || { _ok=0; _d="$_d harness-mode"; }
    [ "$(stat -c '%U' /opt/harness 2>/dev/null)" = "root" ] || { _ok=0; _d="$_d harness-owner"; }
    [ "$(stat -c '%a' /opt/proxy 2>/dev/null)" = "711" ] || { _ok=0; _d="$_d proxy-mode"; }
    [ "$(stat -c '%U' /opt/proxy 2>/dev/null)" = "root" ] || { _ok=0; _d="$_d proxy-owner"; }
    if [ "$_ok" -eq 1 ]; then check 14 pass "/opt/harness mode 0711 root, /opt/proxy mode 0711 root (mock)"; else check 14 fail "$_d"; fi
    # 15. Expected protected paths exist.
    _ok=1; _d=""
    for _p in /etc/shadow /root /home/harness /opt/harness /opt/proxy /var/lib/cloud/instance/user-data.txt; do
        [ -e "$_p" ] || { _ok=0; _d="$_d missing:$_p"; }
    done
    if [ "$_ok" -eq 1 ]; then check 15 pass "all expected protected paths exist"; else check 15 fail "$_d"; fi
    # 16. HMAC secret file + user-data cleanliness (Revision 12, spec rule 41;
    # V13, spec rule 43: the per-batch challenge is present in user-data).
    _ok=1; _d=""
    _secret=$(cat /opt/harness/hmac.key 2>/dev/null | tr -d '[:space:]')
    if [ -f /opt/harness/hmac.key ]; then
        [ "$(stat -c '%a' /opt/harness/hmac.key 2>/dev/null)" = "600" ] || { _ok=0; _d="$_d hmac-mode"; }
        [ "$(stat -c '%U' /opt/harness/hmac.key 2>/dev/null)" = "root" ] || { _ok=0; _d="$_d hmac-owner"; }
        case "$_secret" in ????????????????????????????????????????????????????????????????) : ;; *) _ok=0; _d="$_d hmac-not-64-hex" ;; esac
        case "$_secret" in ''|*[!0-9a-f]*) _ok=0; _d="$_d hmac-not-hex" ;; esac
        if setpriv --reuid=1001 --regid=1001 --clear-groups sh -c 'test -r /opt/harness/hmac.key' 2>/dev/null; then _ok=0; _d="$_d hmac-readable-by-1001"; fi
        if [ -f /var/lib/cloud/instance/user-data.txt ]; then
            grep -q "BEGIN PUBLIC KEY" /var/lib/cloud/instance/user-data.txt 2>/dev/null || { _ok=0; _d="$_d user-data-no-pubkey"; }
            if grep -q "PRIVATE KEY" /var/lib/cloud/instance/user-data.txt 2>/dev/null; then _ok=0; _d="$_d user-data-has-private-key"; fi
            if grep -q "HMAC_SECRET=" /var/lib/cloud/instance/user-data.txt 2>/dev/null; then _ok=0; _d="$_d user-data-has-secret-assignment"; fi
            # V13 (rule 43): the per-batch challenge is present in
            # user-data as a public nonce (32 hex chars) - the VM
            # signs over it, so it must be there.
            _chal_line=$(grep '^BATCH_CHALLENGE=' /var/lib/cloud/instance/user-data.txt 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')
            printf '%s' "$_chal_line" | grep -Eq '^[0-9a-f]{32}$' || { _ok=0; _d="$_d user-data-challenge"; }
        else
            _ok=0; _d="$_d user-data-missing"
        fi
        if [ -f /var/lib/cloud/instance/user-data.txt ] && grep -qF "$_secret" /var/lib/cloud/instance/user-data.txt 2>/dev/null; then _ok=0; _d="$_d secret-in-user-data"; fi
    else
        _ok=0; _d="$_d hmac-missing"
    fi
    if [ "$_ok" -eq 1 ]; then check 16 pass "hmac.key mode 600 root 64-hex unreadable by 1001, secret absent from user-data, host public key present, no private key, per-batch challenge present (32 hex)"; else check 16 fail "$_d"; fi
    # 17. Sandbox layout (probe sandbox, Sec. 4.2 command).
    _probe17=$(vm_probe_sandbox 'for _p in /results /opt/harness /opt/proxy /var/lib/cloud /root /home/harness; do if [ -e "$_p" ]; then if printf x > "$_p/.o17_test" 2>/dev/null; then rm -f "$_p/.o17_test"; echo "WRITABLE $_p"; else echo "READONLY $_p"; fi; else echo "MISSING $_p"; fi; done; df -B1 /tmp | awk "NR==2 {print \"TMP_SIZE=\" \$2 \" TMP_SRC=\" \$1}"' 2>&1)
    _ok=1; _d=""
    for _p in /results /opt/harness /opt/proxy /var/lib/cloud /root /home/harness; do
        printf '%s\n' "$_probe17" | grep -q "READONLY $_p" || { _ok=0; _d="$_d $_p not readonly-visible"; }
    done
    _tmp_size=$(printf '%s\n' "$_probe17" | awk -F= '/^TMP_SIZE=/ {print $2}' | awk '{print $1}')
    if [ -n "$_tmp_size" ]; then
        if [ "$_tmp_size" -ge 1072693248 ] && [ "$_tmp_size" -le 1074790400 ]; then :; else _ok=0; _d="$_d tmp-size=$_tmp_size"; fi
    else
        _ok=0; _d="$_d tmp-size-unreadable"
    fi
    if [ "$_ok" -eq 1 ]; then check 17 pass "sandbox layout: protected paths visible + read-only, /tmp 1 GiB tmpfs"; else check 17 fail "$_d"; fi
    # 18. Installed egress-proxy.py hash.
    _ph=$(sha256sum /opt/proxy/egress-proxy.py 2>/dev/null | awk '{print $1}')
    if [ "$_ph" = "ebde47e446f4e6f4f127e25390ed6e0305b6b23d535cb4db98e40ab6145967c0" ]; then check 18 pass "egress-proxy.py hash matches the reviewed source"; else check 18 fail "proxy hash $_ph"; fi
    # 19. VM timezone UTC.
    if [ "$(date +%Z 2>/dev/null)" = "UTC" ]; then check 19 pass "timezone UTC"; else check 19 fail "timezone $(date +%Z 2>/dev/null)"; fi
    # 20. Sandbox environment (probe sandbox, Sec. 4.2 command).
    _probe20=$(vm_probe_sandbox 'env | sort' 2>&1)
    _ok=1; _d=""
    for _ev in "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "HOME=/home/workload" "http_proxy=http://127.0.0.1:3128" "https_proxy=http://127.0.0.1:3128" "HTTP_PROXY=http://127.0.0.1:3128" "HTTPS_PROXY=http://127.0.0.1:3128" "PROXY_PORT=3128"; do
        printf '%s\n' "$_probe20" | grep -qx "$_ev" || { _ok=0; _d="$_d missing:$_ev"; }
    done
    # The probe shell adds PWD (and SHLVL) to the environment; they
    # are shell-added, not sandbox variables. Filter them out before
    # counting. (Revision 8 fix - V7 counted them and expected exactly
    # 7, so the check always failed: the real env is 7 + PWD = 8.)
    _n_env=$(printf '%s\n' "$_probe20" | grep -v '^PWD=' | grep -v '^SHLVL=' | grep -c . || echo 0)
    [ "$_n_env" = "7" ] || { _ok=0; _d="$_d env-count=$_n_env want 7 (PWD/SHLVL excluded)"; }
    _hw_owner_note=""
    _hw_mode=$(stat -c '%a' /home/workload 2>/dev/null || echo "")
    _hw_owner=$(stat -c '%u:%g' /home/workload 2>/dev/null || echo "")
    [ "$_hw_mode" = "700" ] || { _ok=0; _d="$_d home-mode=$_hw_mode"; }
    if [ "$_hw_owner" = "1001:1001" ]; then :; elif [ "$_hw_owner" = "0:65534" ]; then _hw_owner_note=" (home owner 0:65534 - this host's overlay filesystem refuses chown of a directory to a non-root owner, so the mock cannot set 1001:1001; the mode is still 700 - DRYRUN limitation, not a pass of the real check)"; else _ok=0; _d="$_d home-owner=$_hw_owner"; fi
    if [ "$_ok" -eq 1 ]; then check 20 pass "sandbox env exactly the 7 variables (PWD/SHLVL excluded), /home/workload 700$_hw_owner_note"; else check 20 fail "$_d"; fi
    # 21. Proxy cgroup fixtures (Revision 12, spec rule 40): the
    # limits read back from the fake proxy cgroup files. Membership
    # (proxy PID in the proxy cgroup) is DRYRUN_SKIP - the mock has
    # no real cgroup, so the proxy process is not in any cgroup on
    # this host; the real-VM check (item 21) proves membership.
    _ok=1; _d=""
    [ "$(cat /sys/fs/cgroup/proxy/memory.max 2>/dev/null)" = "536870912" ] || { _ok=0; _d="$_d proxy-memory.max"; }
    [ "$(cat /sys/fs/cgroup/proxy/cpu.max 2>/dev/null)" = "50000 100000" ] || { _ok=0; _d="$_d proxy-cpu.max"; }
    [ "$(cat /sys/fs/cgroup/proxy/pids.max 2>/dev/null)" = "64" ] || { _ok=0; _d="$_d proxy-pids.max"; }
    if [ "$_ok" -eq 1 ]; then check 21 pass "proxy cgroup fixture limits read back (membership dryrun_skip - no real cgroup on this host)"; else check 21 fail "$_d"; fi
    # 22. Authenticated secret delivery (V13, spec rule 43) - dry-run
    # mirror of the real check 22, against the MOCK identity: the
    # artifacts exist, the mock certificate parses with valid dates,
    # its OCID is the mock instance's OCID (from batch.env), and the
    # signature verifies over batch_id + challenge + the ciphertext
    # SHA-256. The mock CA is a fixture (not OCI issuance) - the
    # check proves the sign/verify/bind logic end to end.
    _ok=1; _d=""
    _v22_bid=$(grep '^BATCH_ID=' /opt/harness/batch.env 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')
    _v22_chal=$(grep '^BATCH_CHALLENGE=' /opt/harness/batch.env 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')
    _v22_ocid=$(grep '^INSTANCE_OCID=' /opt/harness/batch.env 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')
    for _f in /results/hmac_secret.sig /results/hmac_secret.cert.pem /results/hmac_secret.intermediate.pem; do
        [ -f "$_f" ] || { _ok=0; _d="$_d missing:$_f"; }
    done
    [ -n "$_v22_bid" ] || { _ok=0; _d="$_d batch-id-missing"; }
    [ -n "$_v22_chal" ] || { _ok=0; _d="$_d challenge-missing"; }
    [ -n "$_v22_ocid" ] || { _ok=0; _d="$_d instance-ocid-missing"; }
    if [ "$_ok" -eq 1 ]; then
        openssl x509 -noout -checkend 0 -in /results/hmac_secret.cert.pem >/dev/null 2>&1 || { _ok=0; _d="$_d cert-dates"; }
        openssl x509 -noout -text -in /results/hmac_secret.cert.pem 2>/dev/null | grep -qF "$_v22_ocid" || { _ok=0; _d="$_d cert-ocid-mismatch"; }
        _v22_sha=$(sha256sum /results/hmac_secret.enc 2>/dev/null | awk '{print $1}')
        [ -n "$_v22_sha" ] || { _ok=0; _d="$_d ciphertext-missing"; }
        printf 'BATCH_ID=%s\nCHALLENGE=%s\nCIPHERTEXT_SHA256=%s\n' "$_v22_bid" "$_v22_chal" "$_v22_sha" > /tmp/m8-check22-data.txt || { _ok=0; _d="$_d cannot-write-delivery-data"; }
        openssl x509 -noout -pubkey -in /results/hmac_secret.cert.pem -out /tmp/m8-check22-pubkey.pem 2>/dev/null || { _ok=0; _d="$_d cert-pubkey"; }
        openssl dgst -sha256 -verify /tmp/m8-check22-pubkey.pem -signature /results/hmac_secret.sig /tmp/m8-check22-data.txt >/dev/null 2>&1 || { _ok=0; _d="$_d signature"; }
        rm -f /tmp/m8-check22-data.txt /tmp/m8-check22-pubkey.pem
    fi
    if [ "$_ok" -eq 1 ]; then check 22 pass "mock identity artifacts present, cert dates valid, cert OCID is this instance, signature verifies over batch_id+challenge+ciphertext hash"; else check 22 fail "$_d"; fi
    # Write the setup record (JSON) - the same format as the real
    # verify (dryrun_skip and deferred are recorded as results, not
    # as failures).
    python3 - /tmp/setup_checks.txt "$SETUP_RECORD" <<'PYEOF'
import json, sys
checks = {}
for line in open(sys.argv[1]):
    line = line.strip()
    if not line.startswith("SETUP_CHECK "):
        continue
    parts = line.split(" ", 3)
    kv = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            kv[k] = v
    checks[kv.get("n", "?")] = {"result": kv.get("result", "?"), "detail": kv.get("detail", "")}
json.dump({"setup_checks": checks}, open(sys.argv[2], "w"), indent=2)
PYEOF
    if [ "$SETUP_FAIL" -ne 0 ]; then
        log_vm "vm_setup_verify_dryrun FAILED (see setup_record.json)"
        return 1
    fi
    log_vm "vm_setup_verify_dryrun done (checks 1,2,4,6,8,11 dryrun_skip; 5 deferred; 21 membership dryrun_skip)"
    return 0
}

# vm_wait_for_controller_window_dryrun - the dry-run controller
# window: poll $BATCH_DIR/controller_verified every 5 s (up to
# 120 s) until its command= line is the EXACT terminate command
# for this instance (built from INSTANCE_OCID in batch.env). The
# dry-run driver performs the mock operator step (writes the
# exact command) after host invocation 1 exits. If the exact
# command never appears, the VM-side sequence does not start
# (return 1 - vm_main marks the setup INVALID).
vm_wait_for_controller_window_dryrun() {
    _expected="oci compute instance terminate --instance-id $INSTANCE_OCID --force --preserve-boot-volume false"
    _waited=0
    while [ "$_waited" -lt 120 ]; do
        _cmd=$(grep '^command=' "$BATCH_DIR/controller_verified" 2>/dev/null | cut -d= -f2-)
        if [ "$_cmd" = "$_expected" ]; then
            log_vm "vm_wait controller verified (exact command, after ${_waited}s)"
            return 0
        fi
        sleep 5
        _waited=$((_waited + 5))
    done
    log_vm "vm_wait controller NOT verified within 120 s - VM-side sequence does not start"
    return 1
}

# prepare_workdir_dryrun CASE - the dry-run per-case workdir
# (spec rule 29). The fake /work is a disk-backed host directory
# (there is no /dev/loop*, so no loopback image and no 20 GB
# volume): clear it, recreate /work/home (1001:1001), and write
# the io.max fixture for BOTH the boot device and the loop device
# (the loop device is the placeholder 7:0 from loop_dev.txt - the
# file exists so o08.sh can read it, but no real loopback device
# enforces the throttle). Setup item 5 (20 GB, nosuid,nodev) is
# recorded as DRYRUN_SKIP, not as a pass - the fake workdir is
# neither 20 GB nor mounted nosuid,nodev. Returns 0 so the case
# proceeds (the case's own checks decide its result).
prepare_workdir_dryrun() {
    _case=$1
    # `rm -rf /work/*` does NOT match hidden files (dotfiles), so
    # the o10 sentinel (/work/.o10_sentinel) survived a clear and
    # the check reported FAIL. Use find -mindepth 1 -delete, which
    # removes all contents including hidden files but not /work.
    # (Revision 8 fix, found by the dry-run.)
    find /work -mindepth 1 -delete 2>/dev/null || { log_vm "prepare_workdir_dryrun $_case cannot clear /work"; return 1; }
    mkdir -p /work/home || { log_vm "prepare_workdir_dryrun $_case cannot create /work/home"; return 1; }
    chown 1001:1001 /work /work/home 2>/dev/null || true
    # Overlay chown limitation (verified): chown of a directory to
    # a non-root owner fails on this host, so /work stays
    # root-owned and UID 1001 cannot write it. Fall back to chmod
    # 1777 (sticky + world-writable, like /tmp) so UID 1001 can
    # write the workdir and its $HOME (/work/home); the real VM
    # uses chown 1001:1001 (mode 755, owned by 1001). Mock
    # limitation, not the real mode.
    # (Revision 8 fix, found by the dry-run.)
    chmod 1777 /work /work/home 2>/dev/null || true
    _bd=$(cat /opt/harness/boot_device.txt 2>/dev/null || echo "")
    _ld=$(cat /opt/harness/loop_dev.txt 2>/dev/null || echo "")
    {
        [ -n "$_bd" ] && printf '%s rbps=52428800 wbps=52428800\n' "$_bd"
        [ -n "$_ld" ] && printf '%s rbps=52428800 wbps=52428800\n' "$_ld"
    } > /sys/fs/cgroup/workload/io.max 2>/dev/null || log_vm "prepare_workdir_dryrun $_case io.max write failed (recorded; O8 will catch it)"
    log_vm "prepare_workdir_dryrun $_case item5 DRYRUN_SKIP (disk-backed fake workdir, not a 20 GB loopback image)"
    return 0
}

# destroy_workdir_dryrun CASE - clear the fake workdir (no umount,
# no losetup, no work image - none exist in the dry-run).
destroy_workdir_dryrun() {
    _case=$1
    # Same hidden-file fix as prepare_workdir_dryrun (see above):
    # `rm -rf /work/*` misses dotfiles like the o10 sentinel.
    find /work -mindepth 1 -delete 2>/dev/null || { log_vm "destroy_workdir_dryrun $_case cannot clear /work"; return 1; }
    mkdir -p /work/home || { log_vm "destroy_workdir_dryrun $_case cannot recreate /work/home"; return 1; }
    chown 1001:1001 /work /work/home 2>/dev/null || true
    return 0
}

# vm_probe_sandbox CMD - run CMD inside a probe sandbox (the Sec. 4.2
# command, with /work bound to a probe dir). Prints CMD's stdout.
# Used by setup checks 17 and 20 only. No workload runs here.
vm_probe_sandbox() {
    _cmd=$1
    mkdir -p /opt/stage/probe_home
    chown 1001:1001 /opt/stage/probe_home 2>/dev/null || true
    chmod 700 /opt/stage/probe_home 2>/dev/null || true
    unshare --pid --fork --mount-proc sh -c '
bwrap --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
  --ro-bind /etc /etc --proc /proc --dev /dev \
  --symlink /usr/bin /bin --symlink /usr/sbin /sbin \
  --ro-bind /sys/fs/cgroup /sys/fs/cgroup \
  --ro-bind /results /results --dir /opt --ro-bind /opt/harness /opt/harness \
  --ro-bind /opt/proxy /opt/proxy --dir /var --dir /var/lib --ro-bind /var/lib/cloud /var/lib/cloud \
  --ro-bind /root /root --dir /home --ro-bind /home/harness /home/harness \
  --bind /opt/stage/tmp /tmp \
  --bind /opt/stage/probe_home /work \
  --bind /opt/stage/probe_home /home/workload \
  --unshare-ipc --unshare-uts --unshare-cgroup --clearenv \
  --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  --setenv HOME /home/workload \
  --setenv http_proxy http://127.0.0.1:3128 \
  --setenv https_proxy http://127.0.0.1:3128 \
  --setenv HTTP_PROXY http://127.0.0.1:3128 \
  --setenv HTTPS_PROXY http://127.0.0.1:3128 \
  --setenv PROXY_PORT 3128 \
  setpriv --reuid=1001 --regid=1001 --clear-groups --inh-caps=-all --ambient-caps=-all --no-new-privs \
  sh -c "$1"
' sh "$_cmd" 2>&1
}

# vm_wait_for_controller_window - after setup verification, wait until
# 20 minutes after BOOT before starting the case loop. The host's
# --resume (controller verified + poller started) is expected within
# 20 minutes of VM creation; the VM-side sequence must not start
# before the controller is verified (Sec. 11.1 step 3). The VM has
# no inbound channel from the host, so this is a fixed wait, not a
# signal - recorded honestly as a known inefficiency (open item).
vm_wait_for_controller_window() {
    _btime=$(awk '/^btime/ {print $2}' /proc/stat 2>/dev/null)
    if [ -z "$_btime" ]; then
        log_vm "vm_wait boot time unknown - waiting a fixed 1200 s"
        sleep 1200
        return 0
    fi
    _now=$(date -u +%s)
    _wait=$(( _btime + 1200 - _now ))
    if [ "$_wait" -gt 0 ]; then
        log_vm "vm_wait waiting ${_wait}s until boot+20min for the controller verification window"
        sleep "$_wait"
    else
        log_vm "vm_wait boot+20min already passed (setup took longer) - starting cases"
    fi
}

# prepare_workdir CASE - create a fresh 20 GB loopback image per case,
# mount it at /work (nosuid,nodev), set the io.max cap for the
# loopback device, and verify setup item 5 (mount, size, options).
# Records the verification in the VM record. Returns 1 on failure.
prepare_workdir() {
    _case=$1
    rm -f /opt/stage/work.img
    dd if=/dev/zero of=/opt/stage/work.img bs=1M count=0 seek=20480 2>/dev/null || { log_vm "prepare_workdir $_case dd failed"; return 1; }
    mkfs.ext4 -q /opt/stage/work.img 2>/dev/null || { log_vm "prepare_workdir $_case mkfs failed"; return 1; }
    _loop=$(losetup -f --show /opt/stage/work.img 2>/dev/null) || { log_vm "prepare_workdir $_case losetup failed"; return 1; }
    printf '%s\n' "$_loop" > /opt/harness/loop_device.txt
    # loop_dev.txt (Revision 8, O8 defect fix): the loop device's
    # major:minor as DECIMAL (e.g. 7:0), the form o08.sh expects.
    # boot_device.txt is written by vm_setup; both files are read
    # by o08.sh (the V7 script read BOOT_DEV / LOOP_DEV from the
    # environment, but the sandbox uses --clearenv with exactly 7
    # vars and the runner never exported them, so V7 o08 always
    # exited INCONCLUSIVE).
    _lmaj=$(stat -c '%t' "$_loop" 2>/dev/null); _lmin=$(stat -c '%T' "$_loop" 2>/dev/null)
    if [ -n "$_lmaj" ] && [ -n "$_lmin" ]; then
        printf '%s:%s\n' "$((16#$_lmaj))" "$((16#$_lmin))" > /opt/harness/loop_dev.txt
    fi
    mount -o nosuid,nodev "$_loop" /work 2>/dev/null || { log_vm "prepare_workdir $_case mount failed"; return 1; }
    chown 1001:1001 /work || { log_vm "prepare_workdir $_case chown work failed"; return 1; }
    mkdir -p /work/home || { log_vm "prepare_workdir $_case mkdir home failed"; return 1; }
    chown 1001:1001 /work/home || { log_vm "prepare_workdir $_case chown home failed"; return 1; }
    # io.max for the loopback device (50 MiB/s, Sec. 7.1).
    _maj=$(stat -c '%t' "$_loop" 2>/dev/null); _min=$(stat -c '%T' "$_loop" 2>/dev/null)
    if [ -n "$_maj" ] && [ -n "$_min" ]; then
        printf '%s:%s rbps=52428800 wbps=52428800' "$((16#$_maj))" "$((16#$_min))" > /sys/fs/cgroup/workload/io.max 2>/dev/null || log_vm "prepare_workdir $_case io.max loopback failed (recorded; O8 will catch it)"
    fi
    # Setup item 5 (per case): /work mounted, 20 GB, nosuid,nodev.
    _size=$(df -B1 /work 2>/dev/null | awk 'NR==2 {print $2}')
    _opts=$(findmnt -no OPTIONS /work 2>/dev/null)
    if [ "$_size" = "20971520000" ] || { [ -n "$_size" ] && [ "$_size" -ge 20961034240 ] && [ "$_size" -le 20982005760 ]; }; then
        case "$_opts" in *nosuid*nodev*|*nodev*nosuid*) log_vm "prepare_workdir $_case item5 pass size=$_size opts=$_opts" ;; *) log_vm "prepare_workdir $_case item5 FAIL opts=$_opts"; return 1 ;; esac
    else
        log_vm "prepare_workdir $_case item5 FAIL size=$_size"
        return 1
    fi
    return 0
}

# destroy_workdir CASE - unmount + delete the loopback image, verify gone.
destroy_workdir() {
    _case=$1
    umount /work 2>/dev/null || log_vm "destroy_workdir $_case umount failed (recorded)"
    _loop=$(cat /opt/harness/loop_device.txt 2>/dev/null)
    if [ -n "$_loop" ]; then
        losetup -d "$_loop" 2>/dev/null || log_vm "destroy_workdir $_case losetup -d failed (recorded)"
    fi
    rm -f /opt/stage/work.img /opt/harness/loop_device.txt
    if [ -e /opt/stage/work.img ]; then log_vm "destroy_workdir $_case image still exists"; return 1; fi
    return 0
}

# run_sandbox SCRIPT ARGS TIMEOUT STDOUT STDERR - run one script inside
# the Sec. 4.2 sandbox command as UID 1001, under `timeout` (0 = no
# timeout wrapper - used only by the O9 watchdog sub-check). Writes
# case_start/case_timeout for the per-case watchdog before starting
# and clears them after. Prints the sandbox exit code on stdout.
run_sandbox() {
    _script=$1; shift
    _timeout=$1; shift
    _out=$1; shift
    _err=$1; shift
    printf '%s\n' "$(date -u +%s)" > /opt/harness/case_start
    # The per-case watchdog's limit stays 600 s even when the harness
    # `timeout` wrapper is disabled (the O9 watchdog sub-check): the
    # watchdog is the mechanism being tested there, so it must still
    # fire at 600 s.
    if [ "$_timeout" = "0" ]; then
        _to_cmd=""
        printf '%s\n' "600" > /opt/harness/case_timeout
    else
        _to_cmd="timeout $_timeout"
        printf '%s\n' "$_timeout" > /opt/harness/case_timeout
    fi
    # Dry-run resource bounds (spec rule 29, per case): the mock
    # cgroup enforces nothing, so the bounds are applied with
    # ulimit inside the sandbox instead. O6 (memory): RLIMIT_AS
    # 192 MB, so the workload's allocation fails with MemoryError
    # (the O6 workload is a Python script; Python itself starts
    # fine under 192 MB - its VmSize is ~15 MB - and a 300 MB
    # allocation fails, verified 2026-11-26). O7 (fork bomb):
    # RLIMIT_NPROC 600, so fork fails with EAGAIN at ~600
    # processes. Other cases get no limits (a blanket RLIMIT_AS
    # could break a legitimate script). The limits are set in the
    # inner sh -c before bwrap, so they are inherited by the
    # workload; they are NOT a cgroup, and the dry-run evidence
    # log says so.
    _dryrun_limits=""
    if [ "${DRYRUN_VM:-0}" = "1" ]; then
        case "$_script" in
            *o06.sh) _dryrun_limits="ulimit -v 196608; " ;;
            *o07.sh) _dryrun_limits="ulimit -u 600; " ;;
        esac
    fi
    # shellcheck disable=SC2086
    $_to_cmd unshare --pid --fork --mount-proc sh -c "$_dryrun_limits
bwrap --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 \\
  --ro-bind /etc /etc --proc /proc --dev /dev \\
  --symlink /usr/bin /bin --symlink /usr/sbin /sbin \\
  --ro-bind /sys/fs/cgroup /sys/fs/cgroup \\
  --ro-bind /results /results --dir /opt --ro-bind /opt/harness /opt/harness \\
  --ro-bind /opt/proxy /opt/proxy --dir /var --dir /var/lib --ro-bind /var/lib/cloud /var/lib/cloud \\
  --ro-bind /root /root --dir /home --ro-bind /home/harness /home/harness \\
  --bind /opt/stage/tmp /tmp \\
  --bind /work /work \\
  --bind /work/home /home/workload \\
  --unshare-ipc --unshare-uts --unshare-cgroup --clearenv \\
  --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \\
  --setenv HOME /home/workload \\
  --setenv http_proxy http://127.0.0.1:3128 \\
  --setenv https_proxy http://127.0.0.1:3128 \\
  --setenv HTTP_PROXY http://127.0.0.1:3128 \\
  --setenv HTTPS_PROXY http://127.0.0.1:3128 \\
  --setenv PROXY_PORT 3128 \\
  setpriv --reuid=1001 --regid=1001 --clear-groups --inh-caps=-all --ambient-caps=-all --no-new-privs \\
  \"\$@\"" sh "$_script" "$@" > "$_out" 2> "$_err"
    _rc=$?
    rm -f /opt/harness/case_start /opt/harness/case_timeout
    printf '%s\n' "$_rc"
}

# read_cgroup_measurements CASE - read the Sec. 7.3 measurements from
# the workload cgroup and append them (key=value) to the case's
# measurement file. Called after each workload run.
read_cgroup_measurements() {
    _case=$1
    _mf="$RESULTS_DIR/$_case/measurements.txt"
    {
        printf 'memory.current=%s\n' "$(cat /sys/fs/cgroup/workload/memory.current 2>/dev/null || echo unreadable)"
        printf 'memory.peak=%s\n' "$(cat /sys/fs/cgroup/workload/memory.peak 2>/dev/null || echo unreadable)"
        printf 'memory.events=%s\n' "$(tr '\n' ' ' < /sys/fs/cgroup/workload/memory.events 2>/dev/null || echo unreadable)"
        printf 'cpu.stat=%s\n' "$(tr '\n' ' ' < /sys/fs/cgroup/workload/cpu.stat 2>/dev/null || echo unreadable)"
        printf 'pids.current=%s\n' "$(cat /sys/fs/cgroup/workload/pids.current 2>/dev/null || echo unreadable)"
        printf 'pids.events=%s\n' "$(tr '\n' ' ' < /sys/fs/cgroup/workload/pids.events 2>/dev/null || echo unreadable)"
        printf 'io.stat=%s\n' "$(tr '\n' ' ' < /sys/fs/cgroup/workload/io.stat 2>/dev/null || echo unreadable)"
        printf 'cgroup.procs=%s\n' "$(cat /sys/fs/cgroup/workload/cgroup.procs 2>/dev/null | tr '\n' ' ' || echo unreadable)"
    } > "$_mf" 2>/dev/null || true
}

# write_case_manifest CASE SCRIPT EXIT_CODE START END RESULT - write
# /results/<case>/manifest.json (Sec. 11.3 fields + the O-test note)
# and its HMAC sidecar. The test_hash is the script's SHA-256.
write_case_manifest() {
    _case=$1; _script=$2; _exit=$3; _start=$4; _end=$5; _result=$6
    _test_hash=$(sha256sum "$_script" 2>/dev/null | awk '{print $1}')
    _mem_peak=$(awk -F= '/^memory.peak=/ {print $2}' "$RESULTS_DIR/$_case/measurements.txt" 2>/dev/null || echo 0)
    _cpu=$(awk -F= '/^cpu.stat=/ {print $2}' "$RESULTS_DIR/$_case/measurements.txt" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i ~ /^usage_usec/) print $i}' | cut -d' ' -f2)
    python3 - "$RESULTS_DIR/$_case/manifest.json" "$_case" "$REPO_URL" "$COMMIT" "$_test_hash" "$_exit" "$_mem_peak" "${_cpu:-0}" "$_start" "$_end" "$_result" <<'PYEOF'
import json, sys
out, case, repo, commit, thash, exit_code, mem_peak, cpu, start, end, result = sys.argv[1:12]
doc = {
    "case_id": case,
    "repo_url": repo,
    "commit": commit,
    "patch_hash": "",
    "test_hash": thash,
    "harness_version": "m8-v7-run_batch",
    "exit_code_before": int(exit_code),
    "exit_code_after": int(exit_code),
    "memory_peak_bytes": int(mem_peak) if str(mem_peak).isdigit() else 0,
    "cpu_usage_usec": int(cpu) if str(cpu).isdigit() else 0,
    "started_at": start,
    "ended_at": end,
    "o_test": True,
    "note": "O-test: single run, no before/after - both exit codes are the workload exit code.",
    "result": result,
}
json.dump(doc, open(out, "w"), indent=2)
PYEOF
    hmac_file "$RESULTS_DIR/$_case/manifest.json"
}

# hmac_file PATH - compute HMAC-SHA256 of PATH with the per-batch
# secret and write it as PATH.hmac (lowercase hex). The secret is
# read from /opt/harness/hmac.key (root-only); it is never printed.
hmac_file() {
    _f=$1
    python3 - "$_f" <<'PYEOF'
import hashlib, hmac, sys
secret = open("/opt/harness/hmac.key").read().strip()
key = bytes.fromhex(secret)
data = open(sys.argv[1], "rb").read()
open(sys.argv[1] + ".hmac", "w").write(hmac.new(key, data, hashlib.sha256).hexdigest())
PYEOF
}

# run_workload CASE SCRIPT TIMEOUT - run one O-test workload in the
# sandbox and record its outcome. Prepares a fresh workdir, runs the
# script, reads the cgroup measurements, writes the case manifest +
# HMAC, destroys the workdir. Prints PASS|FAIL|INCONCLUSIVE on
# stdout (the caller captures it); the full output is in the case
# dir. A missing result line is INCONCLUSIVE (the harness records
# the outcome - open item 4, 2026-11-25 ~23:30 PKT).
run_workload() {
    _rw_case=$1; _rw_script=$2; _rw_timeout=$3
    # Dry-run (spec rule 29): cap the per-case timeout at 120 s
    # (the real 600/900 s timeouts would make the dry-run last
    # hours) and use the disk-backed fake workdir (no loopback
    # image - this host has no /dev/loop*).
    if [ "${DRYRUN_VM:-0}" = "1" ]; then
        if [ "$_rw_timeout" -gt 120 ]; then _rw_timeout=120; fi
    fi
    _rw_start=$(iso_now)
    mkdir -p "$RESULTS_DIR/$_rw_case" || { printf 'INCONCLUSIVE\n'; return 2; }
    if [ "${DRYRUN_VM:-0}" = "1" ]; then
        if ! prepare_workdir_dryrun "$_rw_case"; then
            printf 'INCONCLUSIVE\n'
            log_vm "run_workload $_rw_case prepare_workdir_dryrun failed"
            return 2
        fi
    elif ! prepare_workdir "$_rw_case"; then
        printf 'INCONCLUSIVE\n'
        log_vm "run_workload $_rw_case prepare_workdir failed"
        return 2
    fi
    _rw_rc=$(run_sandbox "$_rw_script" "$_rw_timeout" "$RESULTS_DIR/$_rw_case/stdout.log" "$RESULTS_DIR/$_rw_case/stderr.log")
    _rw_end=$(iso_now)
    read_cgroup_measurements "$_rw_case"
    _rw_line=$(grep -h "^O[0-9]*_RESULT=" "$RESULTS_DIR/$_rw_case/stdout.log" 2>/dev/null | tail -1)
    _rw_result=INCONCLUSIVE
    case "$_rw_line" in
        *=PASS) _rw_result=PASS ;;
        *=FAIL) _rw_result=FAIL ;;
        *=INCONCLUSIVE) _rw_result=INCONCLUSIVE ;;
        *) _rw_result=INCONCLUSIVE ;;
    esac
    # A timeout (exit 124) with no result line is INCONCLUSIVE, never
    # a pass - except O9, whose TIMEOUT outcome is recorded by run_o9
    # (the O9 workload never exits on its own).
    if [ "$_rw_rc" = "124" ] && [ "$_rw_case" != "o09" ]; then
        _rw_result=INCONCLUSIVE
    fi
    # O9 TIMEOUT (Revision 8 fix, found while building the dry-run):
    # the O9 workload never exits on its own, so a harness-timeout
    # kill (exit 124) with no result line IS the expected outcome -
    # TIMEOUT, not INCONCLUSIVE. V7 recorded it as INCONCLUSIVE, so
    # run_o9's sub-check 1 (which treats _r1rc=2 as INCONCLUSIVE)
    # could never pass. TIMEOUT returns 0 here; run_o9 then checks
    # the CPU samples + cgroup.procs for sub-check 1.
    if [ "$_rw_case" = "o09" ] && [ "$_rw_rc" = "124" ] && [ -z "$_rw_line" ]; then
        _rw_result=TIMEOUT
    fi
    write_case_manifest "$_rw_case" "$_rw_script" "$_rw_rc" "$_rw_start" "$_rw_end" "$_rw_result"
    if [ "${DRYRUN_VM:-0}" = "1" ]; then
        destroy_workdir_dryrun "$_rw_case" || log_vm "run_workload $_rw_case destroy_workdir_dryrun failed (recorded)"
    else
        destroy_workdir "$_rw_case" || log_vm "run_workload $_rw_case destroy_workdir failed (recorded)"
    fi
    printf '%s VM case=%s result=%s exit=%s line=%s\n' "$(iso_now)" "$_rw_case" "$_rw_result" "$_rw_rc" "${_rw_line:-none}" >> "$VM_RECORD"
    printf '%s\n' "$_rw_result"
    case "$_rw_result" in PASS|TIMEOUT) return 0 ;; FAIL) return 1 ;; *) return 2 ;; esac
}

# run_o3 - O3 with its positive control (blocker F). The harness runs
# o03.sh positive (as root, drops to UID 1002, resolves
# registry.npmjs.org) BEFORE the workload O3; if the positive
# control fails, O3 cannot pass (DNS itself is broken, so a workload
# timeout proves nothing).
run_o3() {
    mkdir -p "$RESULTS_DIR/o03" || { printf 'INCONCLUSIVE\n'; return 2; }
    _pos_out=$("$HARNESS_DIR/o03.sh" positive 2>&1)
    printf '%s\n' "$_pos_out" > "$RESULTS_DIR/o03/positive.log"
    if printf '%s\n' "$_pos_out" | grep -q "O3_POSITIVE_CONTROL result=resolved"; then
        log_vm "run_o3 positive control ok"
    else
        log_vm "run_o3 positive control FAILED - O3 cannot pass"
        printf 'INCONCLUSIVE\n'
        return 2
    fi
    run_workload o03 "$HARNESS_DIR/o03.sh" 600
}

# run_o4 - O4 with its harness halves (g)/(h). The workload script
# runs first; then the harness performs the cgroup write/move
# attempts as UID 1001 OUTSIDE the sandbox (the exact procedure in
# the o04.sh header). Both must be DENIED for O4 to pass.
run_o4() {
    _w=$(run_workload o04 "$HARNESS_DIR/o04.sh" 600)
    _wrc=$?
    _g=$(setpriv --reuid=1001 --regid=1001 --clear-groups sh -c 'printf x > /sys/fs/cgroup/workload/o04_test && echo WRITABLE || echo DENIED' 2>/dev/null)
    _h=$(setpriv --reuid=1001 --regid=1001 --clear-groups sh -c 'echo $$ > /sys/fs/cgroup/cgroup.procs && echo MOVED || echo DENIED' 2>/dev/null)
    printf 'O4_HARNESS_HALF g=%s h=%s\n' "$_g" "$_h" >> "$VM_RECORD"
    rm -f /sys/fs/cgroup/workload/o04_test 2>/dev/null || true
    if [ "$_wrc" -ne 0 ]; then
        printf '%s\n' "$_w"
        return "$_wrc"
    fi
    if [ "$_g" = "DENIED" ] && [ "$_h" = "DENIED" ]; then
        printf 'PASS\n'
        return 0
    fi
    printf 'FAIL\n'
    return 1
}

# run_o5_sequence - the whole O5 sequence in a subshell with the
# whole-sequence cleanup trap IN CODE (blocker G, 2026-11-25 ~23:30
# PKT). setup adds the test-only entries (and records the proxy-log
# marker); pre verifies them; the workload runs; post verifies from
# the isolated log slice and ALWAYS removes the entries. post runs
# explicitly on the normal path AND via `trap ... EXIT` on every
# abnormal path (setup/pre failure, signal). post is idempotent, so
# the trap is removed before the final exit to avoid running it twice.
run_o5_sequence() {
    (
        # The harness output goes to STDERR (the VM driver log), not
        # stdout: stdout is the result channel captured by vm_run_cases,
        # and the O5_HARNESS_* lines would pollute it (Revision 8 fix).
        trap '/opt/harness/o05_harness.sh post >&2' EXIT
        /opt/harness/o05_harness.sh setup >&2 || exit 2
        /opt/harness/o05_harness.sh pre >&2 || exit 2
        _w=$(run_workload o05 /opt/harness/o05.sh 600)
        _wrc=$?
        /opt/harness/o05_harness.sh post >&2
        _prc=$?
        trap - EXIT
        if [ "$_wrc" -eq 0 ] && [ "$_prc" -eq 0 ]; then
            printf 'PASS\n'; exit 0
        elif [ "$_wrc" -eq 1 ] || [ "$_prc" -eq 1 ]; then
            printf 'FAIL\n'; exit 1
        else
            printf 'INCONCLUSIVE\n'; exit 2
        fi
    )
}

# run_o9 - O9 with both sub-checks recorded (open item 4, 2026-11-25
# ~23:30 PKT). (1) The workload runs under timeout 600; the runner
# parses the O9_CPU_SAMPLE lines from its stdout and checks every
# corrected ratio is <= 1.05, and checks cgroup.procs is empty
# after. (2) The watchdog sub-check: the workload runs a second time
# with the harness timeout DISABLED; the runner polls cgroup.procs
# every 10 s and records when it empties + whether the case-watchdog
# log shows the kill. O9 passes only if both sub-checks pass.
run_o9() {
    # Dry-run (spec rule 29): sub-check 1 runs with a 90 s harness
    # timeout (the real 600 s would make the dry-run last 10 min
    # for this case alone); sub-check 2 (the systemd watchdog kill
    # with the harness timeout disabled) is SKIPPED - there is no
    # systemd in the mock VM, so the watchdog kill cannot be
    # exercised. O9's dry-run result is sub-check 1's result, with
    # the skip recorded. This is honest: the dry-run proves the
    # harness timeout + the CPU-sample check, NOT the watchdog.
    if [ "${DRYRUN_VM:-0}" = "1" ]; then
        _r1=$(run_workload o09 "$HARNESS_DIR/o09.sh" 90)
        _r1rc=$?
    else
    _r1=$(run_workload o09 "$HARNESS_DIR/o09.sh" 600)
    _r1rc=$?
    fi
    # Sub-check 1: every corrected ratio <= 1.05, cgroup empty after.
    _max=$(awk -F'corrected=' '/^O9_CPU_SAMPLE/ {split($2, a, " "); if (a[1] + 0 > m) m = a[1] + 0} END {print m + 0}' "$RESULTS_DIR/o09/stdout.log" 2>/dev/null)
    _n_samples=$(grep -c '^O9_CPU_SAMPLE' "$RESULTS_DIR/o09/stdout.log" 2>/dev/null || echo 0)
    _procs_after=$(cat /sys/fs/cgroup/workload/cgroup.procs 2>/dev/null | wc -l)
    _sub1=PASS
    if [ "$_r1rc" -eq 1 ]; then _sub1=FAIL; fi
    if [ "$_r1rc" -eq 2 ]; then _sub1=INCONCLUSIVE; fi
    if [ "$_n_samples" = "0" ]; then _sub1=INCONCLUSIVE; fi
    if [ "$_procs_after" != "0" ]; then _sub1=FAIL; fi
    if [ "$_sub1" = "PASS" ]; then
        _over=$(awk -v max="$_max" 'BEGIN {print (max > 1.05) ? 1 : 0}')
        [ "$_over" = "1" ] && _sub1=FAIL
    fi
    printf 'O9_SUBCHECK1 samples=%s max_corrected=%s procs_after=%s result=%s\n' "$_n_samples" "$_max" "$_procs_after" "$_sub1" >> "$VM_RECORD"
    if [ "${DRYRUN_VM:-0}" = "1" ]; then
        printf 'O9_SUBCHECK2 result=DRYRUN_SKIP reason=no_systemd_in_mock_vm (watchdog kill not exercised)\n' >> "$VM_RECORD"
        if [ "$_sub1" = "PASS" ]; then
            printf 'PASS\n'; return 0
        elif [ "$_sub1" = "FAIL" ]; then
            printf 'FAIL\n'; return 1
        else
            printf 'INCONCLUSIVE\n'; return 2
        fi
    fi
    # Sub-check 2: watchdog kill with the harness timeout disabled.
    mkdir -p "$RESULTS_DIR/o09_watchdog" || true
    prepare_workdir o09_watchdog || { printf 'INCONCLUSIVE\n'; return 2; }
    _wd_start=$(date -u +%s)
    run_sandbox "$HARNESS_DIR/o09.sh" 0 "$RESULTS_DIR/o09_watchdog/stdout.log" "$RESULTS_DIR/o09_watchdog/stderr.log" > /tmp/o09_wd_rc.txt 2>&1 &
    _wd_pid=$!
    _wd_elapsed=0
    while [ "$_wd_elapsed" -lt 660 ]; do
        sleep 10
        _wd_elapsed=$((_wd_elapsed + 10))
        if [ -z "$(cat /sys/fs/cgroup/workload/cgroup.procs 2>/dev/null)" ]; then
            break
        fi
    done
    wait "$_wd_pid" 2>/dev/null || true
    _wd_end=$(date -u +%s)
    _wd_total=$((_wd_end - _wd_start))
    destroy_workdir o09_watchdog || log_vm "run_o9 destroy_workdir failed (recorded)"
    _sub2=INCONCLUSIVE
    if [ "$_wd_total" -ge 540 ] && [ "$_wd_total" -le 660 ]; then
        if grep -q "case_watchdog killed cgroup" /opt/harness/case_watchdog.log 2>/dev/null; then
            _sub2=PASS
        fi
    fi
    printf 'O9_SUBCHECK2 elapsed_s=%s result=%s\n' "$_wd_total" "$_sub2" >> "$VM_RECORD"
    if [ "$_sub1" = "PASS" ] && [ "$_sub2" = "PASS" ]; then
        printf 'PASS\n'; return 0
    elif [ "$_sub1" = "FAIL" ] || [ "$_sub2" = "FAIL" ]; then
        printf 'FAIL\n'; return 1
    else
        printf 'INCONCLUSIVE\n'; return 2
    fi
}

# run_o10 - O10 with its outcome recorded (open item 4, 2026-11-25
# ~23:30 PKT). The write and check modes MUST both run inside the
# sandbox as UID 1001 (o10.sh refuses any other UID at the top), in
# TWO DIFFERENT cases with a fresh workdir between them: (a) write
# runs o10.sh write in the sandbox and prints O10_SENTINEL_WRITTEN;
# (b) the workdir is destroyed and a fresh one prepared; (c) check
# runs o10.sh check in the sandbox in the fresh workdir and prints
# O10_RESULT. The check mode's result is the verdict. The o10
# manifest is written from the check run.
# (Revision 8 fix: run_o10 previously ran write and check DIRECTLY
# as root, so o10.sh's UID check failed ("not running as UID 1001
# (got 0)"), run_o10 returned early with INCONCLUSIVE, and no o10
# manifest was ever written - so the host download 404'd on
# o10/manifest.json. Found by the dry-run.)
run_o10() {
    _o10_start=$(iso_now)
    mkdir -p "$RESULTS_DIR/o10" || true
    # (a) Write the sentinel in the sandbox as UID 1001.
    if [ "${DRYRUN_VM:-0}" = "1" ]; then
        prepare_workdir_dryrun "o10" || { printf 'INCONCLUSIVE\n'; return 2; }
    elif ! prepare_workdir "o10"; then
        printf 'INCONCLUSIVE\n'; return 2
    fi
    # run_sandbox prints the sandbox exit code to stdout (its
    # function exit code is always 0); capture stdout as the rc.
    _wrc_write=$(run_sandbox "$HARNESS_DIR/o10.sh" 600 "$RESULTS_DIR/o10/write.log" "$RESULTS_DIR/o10/write.err" write)
    if [ "${DRYRUN_VM:-0}" = "1" ]; then
        destroy_workdir_dryrun "o10" || true
    else
        destroy_workdir "o10" || true
    fi
    if [ "$_wrc_write" -ne 0 ] || ! grep -q "O10_SENTINEL_WRITTEN" "$RESULTS_DIR/o10/write.log" 2>/dev/null; then
        log_vm "run_o10 write mode failed (exit $_wrc_write)"
        _o10_end=$(iso_now)
        write_case_manifest "o10" "$HARNESS_DIR/o10.sh" "$_wrc_write" "$_o10_start" "$_o10_end" "INCONCLUSIVE"
        printf 'INCONCLUSIVE\n'; return 2
    fi
    # (b) Fresh workdir, then (c) check in the sandbox as UID 1001.
    if [ "${DRYRUN_VM:-0}" = "1" ]; then
        prepare_workdir_dryrun "o10" || { printf 'INCONCLUSIVE\n'; return 2; }
    elif ! prepare_workdir "o10"; then
        printf 'INCONCLUSIVE\n'; return 2
    fi
    _crc=$(run_sandbox "$HARNESS_DIR/o10.sh" 600 "$RESULTS_DIR/o10/check.log" "$RESULTS_DIR/o10/check.err" check)
    if [ "${DRYRUN_VM:-0}" = "1" ]; then
        destroy_workdir_dryrun "o10" || true
    else
        destroy_workdir "o10" || true
    fi
    _check_line=$(grep -h "^O10_RESULT=" "$RESULTS_DIR/o10/check.log" 2>/dev/null | tail -1)
    _o10_end=$(iso_now)
    printf 'O10 workload_result=check workload_exit=%s check_line=%s\n' "$_crc" "${_check_line:-none}" >> "$VM_RECORD"
    case "$_check_line" in
        *=PASS) _o10_result=PASS; _o10_rc=0 ;;
        *=FAIL) _o10_result=FAIL; _o10_rc=1 ;;
        *) _o10_result=INCONCLUSIVE; _o10_rc=2 ;;
    esac
    write_case_manifest "o10" "$HARNESS_DIR/o10.sh" "$_crc" "$_o10_start" "$_o10_end" "$_o10_result"
    printf '%s\n' "$_o10_result"
    return "$_o10_rc"
}

# vm_run_cases - drive O1-O11 in order. O12 and O13 are host-side
# (recorded by the host mode). After each case the result is
# recorded; on any non-PASS the loop STOPS (remaining cases are
# skipped, recorded as SKIPPED) and the batch goes to teardown with
# the failure. Returns 0 only if all cases PASS.
# Dry-run (spec rule 29): the loop RECORDS ALL cases (it continues
# past failures and records each result) instead of stopping at the
# first non-PASS - the dry-run's purpose is to exercise the whole
# lifecycle and record every case's outcome, so a single failing
# case must not hide the rest. The overall return code is still
# non-zero if any case is not PASS.
vm_run_cases() {
    _overall=0
    _results=""
    for _case in o01 o02 o03 o04 o05 o06 o07 o08 o09 o10 o11; do
        _r="SKIPPED"
        case "$_case" in
            o01) _r=$(run_workload o01 "$HARNESS_DIR/o01.sh" 600); _rc=$? ;;
            o02) _r=$(run_workload o02 "$HARNESS_DIR/o02.sh" 600); _rc=$? ;;
            o03) _r=$(run_o3); _rc=$? ;;
            o04) _r=$(run_o4); _rc=$? ;;
            o05) _r=$(run_o5_sequence); _rc=$? ;;
            o06) _r=$(run_workload o06 "$HARNESS_DIR/o06.sh" 600); _rc=$? ;;
            o07) _r=$(run_workload o07 "$HARNESS_DIR/o07.sh" 600); _rc=$? ;;
            o08) _r=$(run_workload o08 "$HARNESS_DIR/o08.sh" 900); _rc=$? ;;
            o09) _r=$(run_o9); _rc=$? ;;
            o10) _r=$(run_o10); _rc=$? ;;
            o11) _r=$(run_workload o11 "$HARNESS_DIR/o11.sh" 600); _rc=$? ;;
        esac
        # Dry-run injection (Revision 9, spec rule 34): a regression
        # run forces one case's RECORDED outcome to FAIL or
        # INCONCLUSIVE, so the verdict gate (rule 31) must block an
        # overall PASS. The injection is at the recording layer - the
        # same layer the gate reads - which is exactly what the gate
        # is supposed to catch. In the dry-run the loop records ALL
        # cases (it continues past failures), so the injected outcome
        # appears in case_results.txt and in the batch manifest.
        if [ "${DRYRUN_INJECT_FAIL:-}" = "$_case" ]; then
            _r=FAIL; _rc=1
            log_vm "vm_run_cases DRYRUN_INJECT $_case forced FAIL"
        elif [ "${DRYRUN_INJECT_INCONCLUSIVE:-}" = "$_case" ]; then
            _r=INCONCLUSIVE; _rc=2
            log_vm "vm_run_cases DRYRUN_INJECT $_case forced INCONCLUSIVE"
        elif [ "${DRYRUN_INJECT_ALL_PASS:-0}" = "1" ]; then
            # (V10, rule 35) Force every case's RECORDED outcome to
            # PASS, so the full PASS path can be exercised in the
            # dry-run: overall PASS, exit 0, verdict.done written,
            # and a later resume replaying exit 0. The injection is
            # at the recording layer - the same layer the gate reads -
            # which is exactly what the gate is supposed to judge.
            # An explicit per-case FAIL/INCONCLUSIVE injection above
            # still wins over ALL_PASS if both are set.
            _r=PASS; _rc=0
            log_vm "vm_run_cases DRYRUN_INJECT_ALL_PASS $_case forced PASS"
        fi
        _results="$_results $_case=$_r"
        log_vm "vm_run_cases $_case result=$_r"
        if [ "$_rc" -ne 0 ]; then
            # Worst outcome wins (Revision 9, found by the regression
            # dry-run 2026-11-26 ~22:18 PKT): FAIL (rc 1) dominates
            # INCONCLUSIVE (rc 2). The old code overwrote _overall
            # with each failure, so the LAST non-PASS case decided the
            # return code - in the regression_fail run, o07 FAIL was
            # overwritten by o08/o09 INCONCLUSIVE and the manifest
            # verdict came out INCONCLUSIVE instead of FAIL. In a real
            # run the loop breaks at the first non-PASS, so this only
            # changes the dry-run's continue-past-failures path.
            if [ "$_rc" -eq 1 ] || [ "$_overall" -eq 0 ]; then
                _overall=$_rc
            fi
            if [ "${DRYRUN_VM:-0}" = "1" ]; then
                log_vm "vm_run_cases $_case result $_r - dry-run records all cases, continuing"
            else
            log_vm "vm_run_cases stopping after $_case (result $_r) - remaining cases skipped"
            break
            fi
        fi
    done
    printf '%s\n' "$_results" > "$RESULTS_DIR/case_results.txt"
    return "$_overall"
}

# manifest_batch_id - the batch_id written into the VM batch manifest
# (vm_write_invalid_setup + vm_teardown, both modes). Normally the
# persisted BATCH_ID. In a regression dry-run with
# DRYRUN_INJECT_BATCH_ID_MISMATCH=1 the manifest carries a tampered
# batch_id (the real one with "-tampered" appended) while its HMAC
# still verifies - so the ONLY check that can catch it is the verdict
# gate's value comparison (rule 31c). This simulates a VM whose
# evidence belongs to a different batch.
manifest_batch_id() {
    if [ "${DRYRUN_INJECT_BATCH_ID_MISMATCH:-0}" = "1" ]; then
        log_vm "DRYRUN_INJECT batch_id tampered in manifest"
        printf '%s-tampered\n' "$BATCH_ID"
    else
        printf '%s\n' "$BATCH_ID"
    fi
}

# vm_write_invalid_setup REASON - write the INVALID batch record when
# setup fails (before any case runs): batch.json (INVALID,
# setup_failed) + results.sha256 + HMACs + DONE, so the host can
# download the evidence. The results server is still running.
vm_write_invalid_setup() {
    _reason=$1
    python3 - "$RESULTS_DIR/batch.json" "$(manifest_batch_id)" "$REPO_URL" "$COMMIT" "$_reason" <<'PYEOF'
import json, sys
out, batch, repo, commit, reason = sys.argv[1:6]
doc = {
    "batch_id": batch,
    "cases": [],
    "setup_record": {},
    "verdict": "INVALID",
    "reason": reason,
    "repo_url": repo,
    "commit": commit,
}
try:
    doc["setup_record"] = json.load(open("/results/setup_record.json"))
except Exception:
    doc["setup_record"] = {"error": "setup_record.json unreadable"}
# proxy_log (schema-required list): the egress proxy's log lines,
# bounded to the last 1000. Empty list if the log is unreadable.
try:
    with open("/var/log/m8-proxy.log") as _pf:
        _plines = _pf.read().splitlines()
    doc["proxy_log"] = _plines[-1000:]
except Exception:
    doc["proxy_log"] = []
# teardown_record (schema-required dict): this is an invalid-setup
# batch (setup failed before any case ran), so no teardown ran.
doc["teardown_record"] = {"invalid_setup": True, "reason": reason, "done_written": True}
json.dump(doc, open(out, "w"), indent=2)
PYEOF
    # results.sha256 lists ONLY the downloadable evidence set
    # (watchdog-snapshot.txt + per-case manifest.json); see the
    # comment at the dry-run teardown site for why batch.json and
    # the raw logs are excluded. (Revision 8 fix, found by the
    # dry-run.)
    (cd "$RESULTS_DIR" && { sha256sum watchdog-snapshot.txt 2>/dev/null; find . -type f -name 'manifest.json' -exec sha256sum {} \; ; } | sort > results.sha256)
    _rs=$(sha256sum "$RESULTS_DIR/results.sha256" | awk '{print $1}')
    python3 - "$RESULTS_DIR/batch.json" "$_rs" <<'PYEOF'
import json, sys
p = sys.argv[1]
doc = json.load(open(p))
doc["results_sha256"] = sys.argv[2]
json.dump(doc, open(p, "w"), indent=2)
PYEOF
    hmac_file "$RESULTS_DIR/batch.json"
    hmac_file "$RESULTS_DIR/results.sha256"
    printf '' > "$RESULTS_DIR/DONE"
    log_vm "vm_write_invalid_setup wrote INVALID batch.json + DONE"
}

# vm_teardown RC - the VM-side teardown (Sec. 11.2 steps 1-6, in
# order). (1) Kill every process in the workload cgroup and verify
# it is empty. (2) Unmount + delete the loopback work image (already
# done per case; verify gone). (3) Remove the workload cgroup.
# (4) Write the watchdog snapshot (three sections) + its HMAC, and
# verify it is non-empty with all three sections BEFORE writing
# DONE - otherwise DONE is NOT written and the batch is INVALID.
# (5) Write DONE + the batch manifest + results.sha256 + HMACs.
# (6) Stop the egress proxy. Do NOT stop the results server - it
# stays up until the host's terminate call.
vm_teardown() {
    _rc=$1
    log_vm "vm_teardown start (cases exit $_rc)"
    if [ "${DRYRUN_VM:-0}" = "1" ]; then
        # Dry-run teardown (spec rule 29): no workload cgroup to
        # kill (the fake cgroup.procs is always empty), no work
        # image (prepare_workdir_dryrun creates none), and the
        # fake workload cgroup dir is left in place for inspection.
        # The watchdog snapshot is written with the same three
        # sections, but systemd does not exist in the mock VM, so
        # each section records that honestly instead of a systemctl
        # / journalctl dump. The DONE + batch manifest +
        # results.sha256 + HMACs are written exactly as in the real
        # teardown, so the host download + o11 + o13 run unchanged.
        # Dry-run watchdog snapshot: a SIMULATED armed timer, so o13
        # can exercise its full journal verification (parse the
        # snapshot, check ActiveState=active, compare NEXT to the
        # timer deadline). The mock VM has no systemd, so there is
        # no real m8-watchdog.timer; this fixture simulates the
        # timer ARMED with NEXT exactly at the timer deadline (the
        # behaviour a correct real VM exhibits). It is labelled as
        # a mock fixture IN the snapshot itself, and the dry-run
        # evidence log + corrections doc state plainly that it
        # proves only that o13's verification LOGIC works on an
        # armed-timer snapshot - NOT that a real VM's timer will be
        # armed. Only a real VM run proves that. (Revision 8 fix:
        # the previous DRYRUN_SKIP snapshot made o13's journal check
        # fail (not_armed) on every dry-run, so o13 could never pass
        # and its verification logic was never exercised.)
        _td_iso=$(date -u -d "@$TIMER_EPOCH" '+%a %Y-%m-%d %H:%M:%S UTC' 2>/dev/null || echo "Wed 2026-11-25 00:00:00 UTC")
        {
            printf '=== section 1: systemctl show m8-watchdog.timer ===\n'
            printf 'DRYRUN_MOCK_FIXTURE: simulated armed timer (no systemd in the mock VM)\n'
            printf 'ActiveState=active\n'
            printf 'SubState=waiting\n'
            printf '=== section 2: systemctl list-timers m8-watchdog.timer ===\n'
            printf 'DRYRUN_MOCK_FIXTURE: simulated armed timer (no systemd in the mock VM)\n'
            printf 'NEXT                         LEFT          LAST                         PASSED       UNIT\n'
            printf '%s  -             -                            -            m8-watchdog.timer\n' "$_td_iso"
            printf '=== section 3: journalctl m8-watchdog.timer + m8-watchdog.service ===\n'
            printf 'DRYRUN_MOCK_FIXTURE: simulated armed timer (no systemd in the mock VM)\n'
            printf '%s mock-vm m8-watchdog.timer: timer armed, next trigger %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$_td_iso"
        } > "$RESULTS_DIR/watchdog-snapshot.txt"
        _snap_ok=1
        [ -s "$RESULTS_DIR/watchdog-snapshot.txt" ] || _snap_ok=0
        grep -q "section 1:" "$RESULTS_DIR/watchdog-snapshot.txt" || _snap_ok=0
        grep -q "section 2:" "$RESULTS_DIR/watchdog-snapshot.txt" || _snap_ok=0
        grep -q "section 3:" "$RESULTS_DIR/watchdog-snapshot.txt" || _snap_ok=0
        if [ "$_snap_ok" -ne 1 ]; then
            log_vm "vm_teardown dry-run watchdog snapshot invalid - DONE NOT written, batch INVALID"
            _rc=2
        else
            hmac_file "$RESULTS_DIR/watchdog-snapshot.txt"
        fi
        if [ "$_snap_ok" -eq 1 ]; then
            _case_results=$(cat "$RESULTS_DIR/case_results.txt" 2>/dev/null || echo "")
            python3 - "$RESULTS_DIR/batch.json" "$(manifest_batch_id)" "$REPO_URL" "$COMMIT" "$_rc" "$_case_results" <<'PYEOF'
import json, sys
out, batch, repo, commit, rc, results = sys.argv[1:7]
doc = {
    "batch_id": batch,
    "cases": results.split(),
    "setup_record": {},
    "verdict": "PASS" if int(rc) == 0 else ("FAIL" if int(rc) == 1 else "INCONCLUSIVE"),
    "repo_url": repo,
    "commit": commit,
}
try:
    doc["setup_record"] = json.load(open("/results/setup_record.json"))
except Exception:
    doc["setup_record"] = {"error": "setup_record.json unreadable"}
# proxy_log (schema-required list): the egress proxy's log lines,
# bounded to the last 1000. Empty list if the log is unreadable.
try:
    with open("/var/log/m8-proxy.log") as _pf:
        _plines = _pf.read().splitlines()
    doc["proxy_log"] = _plines[-1000:]
except Exception:
    doc["proxy_log"] = []
# teardown_record (schema-required dict): dry-run teardown - no
# real cgroup or work image (fake cgroup, disk-backed workdir).
doc["teardown_record"] = {"dryrun": True, "watchdog_snapshot_valid": True, "cases_exit_code": int(rc), "done_written": True, "note": "dry-run: no real cgroup/work image; fake workload cgroup left in place"}
json.dump(doc, open(out, "w"), indent=2)
PYEOF
            # results.sha256 lists ONLY the downloadable evidence
            # set (watchdog-snapshot.txt + per-case manifest.json).
            # The download fetches only the whitelisted set, so
            # listing every file made the host report the
            # non-downloaded files (raw logs, measurements,
            # case_results.txt, setup_record.json, vm_record.txt)
            # as "missing". batch.json is EXCLUDED: it is modified
            # AFTER this hash is computed (to add the results_sha256
            # binding field), so its entry would be stale
            # (hash_mismatch) - a true cycle. batch.json integrity
            # is covered by its HMAC (spec rule 15 step 1).
            # (Revision 8 fix, found by the dry-run.)
            # results.sha256 lists ONLY the downloadable evidence set
        # (see the comment at the dry-run teardown site).
        # (Revision 8 fix, found by the dry-run.)
        (cd "$RESULTS_DIR" && { sha256sum watchdog-snapshot.txt 2>/dev/null; find . -type f -name 'manifest.json' -exec sha256sum {} \; ; } | sort > results.sha256)
            _rs=$(sha256sum "$RESULTS_DIR/results.sha256" | awk '{print $1}')
            python3 - "$RESULTS_DIR/batch.json" "$_rs" <<'PYEOF'
import json, sys
p = sys.argv[1]
doc = json.load(open(p))
doc["results_sha256"] = sys.argv[2]
json.dump(doc, open(p, "w"), indent=2)
PYEOF
            hmac_file "$RESULTS_DIR/batch.json"
            hmac_file "$RESULTS_DIR/results.sha256"
            printf '' > "$RESULTS_DIR/DONE"
            # The results server runs as UID 1000 and must read these
            # files; chmod them 644 so the download works regardless
            # of the process umask (the dry-run inherits umask 0007,
            # which makes files 660 and unreadable by UID 1000).
            # (Revision 8 fix, found by the dry-run.)
            chmod 644 "$RESULTS_DIR/DONE" "$RESULTS_DIR/batch.json" "$RESULTS_DIR/batch.json.hmac" "$RESULTS_DIR/results.sha256" "$RESULTS_DIR/results.sha256.hmac" "$RESULTS_DIR/watchdog-snapshot.txt" "$RESULTS_DIR/watchdog-snapshot.txt.hmac" 2>/dev/null || true
            find "$RESULTS_DIR" -name 'manifest.json' -o -name 'manifest.json.hmac' | xargs -r chmod 644 2>/dev/null || true
            # Per-case dirs must be traversable by UID 1000 too (the
            # results server); under umask 0007 they are mode 770 and
            # UID 1000 cannot traverse them, so every per-case
            # manifest returns 404. (Revision 8 fix.)
            find "$RESULTS_DIR" -type d -exec chmod 755 {} + 2>/dev/null || true
            log_vm "vm_teardown (dry-run) DONE written"
        fi
        # (6) Stop the egress proxy. Do NOT stop the results
        # server - the host downloads DONE/results from it, and the
        # real teardown (step 6) explicitly does not stop it either.
        # The mock VM's background timer stops it at the timer
        # deadline, as the real VM's timer powers off the VM.
        # (Revision 8 fix: the dry-run teardown previously killed
        # both, so the host could never see DONE and the batch went
        # INVALID - found by the dry-run.)
        pkill -u 1002 -f egress-proxy.py 2>/dev/null || true
        log_vm "vm_teardown (dry-run) complete"
        return "$_rc"
    fi
    # (1) Kill the workload cgroup.
    for _pid in $(cat /sys/fs/cgroup/workload/cgroup.procs 2>/dev/null); do
        kill -9 "$_pid" 2>/dev/null || true
    done
    sleep 2
    if [ -n "$(cat /sys/fs/cgroup/workload/cgroup.procs 2>/dev/null)" ]; then
        log_vm "vm_teardown cgroup.procs not empty after kill (recorded)"
    fi
    # (2) Work image gone (per-case destroy already ran; verify).
    if [ -e /opt/stage/work.img ]; then
        log_vm "vm_teardown work image still exists - removing"
        umount /work 2>/dev/null || true
        rm -f /opt/stage/work.img
    fi
    # (3) Remove the workload cgroup.
    rmdir /sys/fs/cgroup/workload 2>/dev/null || log_vm "vm_teardown rmdir workload cgroup failed (recorded)"
    # (4) The watchdog snapshot (three sections, in order).
    {
        printf '=== section 1: systemctl show m8-watchdog.timer ===\n'
        systemctl show m8-watchdog.timer -p ActiveState -p SubState 2>&1
        printf '=== section 2: systemctl list-timers m8-watchdog.timer ===\n'
        systemctl list-timers m8-watchdog.timer --no-pager 2>&1
        printf '=== section 3: journalctl m8-watchdog.timer + m8-watchdog.service ===\n'
        journalctl -u m8-watchdog.timer -u m8-watchdog.service --no-pager -o short-iso 2>&1
    } > "$RESULTS_DIR/watchdog-snapshot.txt"
    _snap_ok=1
    [ -s "$RESULTS_DIR/watchdog-snapshot.txt" ] || _snap_ok=0
    grep -q "section 1:" "$RESULTS_DIR/watchdog-snapshot.txt" || _snap_ok=0
    grep -q "section 2:" "$RESULTS_DIR/watchdog-snapshot.txt" || _snap_ok=0
    grep -q "section 3:" "$RESULTS_DIR/watchdog-snapshot.txt" || _snap_ok=0
    if [ "$_snap_ok" -ne 1 ]; then
        log_vm "vm_teardown watchdog snapshot invalid - DONE NOT written, batch INVALID"
        _rc=2
    else
        hmac_file "$RESULTS_DIR/watchdog-snapshot.txt"
    fi
    # (5) DONE + the batch manifest + results.sha256 + HMACs.
    if [ "$_snap_ok" -eq 1 ]; then
        _case_results=$(cat "$RESULTS_DIR/case_results.txt" 2>/dev/null || echo "")
        python3 - "$RESULTS_DIR/batch.json" "$(manifest_batch_id)" "$REPO_URL" "$COMMIT" "$_rc" "$_case_results" <<'PYEOF'
import json, sys
out, batch, repo, commit, rc, results = sys.argv[1:7]
doc = {
    "batch_id": batch,
    "cases": results.split(),
    "setup_record": {},
    "verdict": "PASS" if int(rc) == 0 else ("FAIL" if int(rc) == 1 else "INCONCLUSIVE"),
    "repo_url": repo,
    "commit": commit,
}
try:
    doc["setup_record"] = json.load(open("/results/setup_record.json"))
except Exception:
    doc["setup_record"] = {"error": "setup_record.json unreadable"}
# proxy_log (schema-required list): the egress proxy's log lines,
# bounded to the last 1000. Empty list if the log is unreadable.
try:
    with open("/var/log/m8-proxy.log") as _pf:
        _plines = _pf.read().splitlines()
    doc["proxy_log"] = _plines[-1000:]
except Exception:
    doc["proxy_log"] = []
# teardown_record (schema-required dict): real teardown steps
# (cgroup kill, work image removal, cgroup removal, watchdog
# snapshot, DONE). The individual step outcomes are in the VM record.
doc["teardown_record"] = {"watchdog_snapshot_valid": True, "cases_exit_code": int(rc), "done_written": True, "note": "real teardown: workload cgroup killed + removed, work image removed, watchdog snapshot written"}
json.dump(doc, open(out, "w"), indent=2)
PYEOF
        (cd "$RESULTS_DIR" && { sha256sum watchdog-snapshot.txt 2>/dev/null; find . -type f -name 'manifest.json' -exec sha256sum {} \; ; } | sort > results.sha256)
        _rs=$(sha256sum "$RESULTS_DIR/results.sha256" | awk '{print $1}')
        python3 - "$RESULTS_DIR/batch.json" "$_rs" <<'PYEOF'
import json, sys
p = sys.argv[1]
doc = json.load(open(p))
doc["results_sha256"] = sys.argv[2]
json.dump(doc, open(p, "w"), indent=2)
PYEOF
        hmac_file "$RESULTS_DIR/batch.json"
        hmac_file "$RESULTS_DIR/results.sha256"
        printf '' > "$RESULTS_DIR/DONE"
        # The results server runs as UID 1000 and must read these
        # files; chmod them 644 so the download works regardless of
        # the process umask. (Revision 8 fix, found by the dry-run:
        # under umask 0007 the files are 660 and UID 1000 cannot read
        # them, so the server returns 404 for every file.)
        chmod 644 "$RESULTS_DIR/DONE" "$RESULTS_DIR/batch.json" "$RESULTS_DIR/batch.json.hmac" "$RESULTS_DIR/results.sha256" "$RESULTS_DIR/results.sha256.hmac" "$RESULTS_DIR/watchdog-snapshot.txt" "$RESULTS_DIR/watchdog-snapshot.txt.hmac" 2>/dev/null || true
        find "$RESULTS_DIR" -name 'manifest.json' -o -name 'manifest.json.hmac' | xargs -r chmod 644 2>/dev/null || true
        # Per-case dirs must be traversable by UID 1000 too (the
        # results server); under a restrictive umask they are mode
        # 770 and UID 1000 cannot traverse them, so every per-case
        # manifest returns 404. (Revision 8 fix, found by the
        # dry-run.)
        find "$RESULTS_DIR" -type d -exec chmod 755 {} + 2>/dev/null || true
        log_vm "vm_teardown DONE written"
    fi
    # (6) Stop the egress proxy. Do NOT stop the results server.
    pkill -u 1002 -f egress-proxy.py 2>/dev/null || true
    # Unmount the /tmp tmpfs staging dir.
    umount /opt/stage/tmp 2>/dev/null || true
    log_vm "vm_teardown complete"
    return "$_rc"
}

# ------------------------------------------------------------------
# Dispatch
# ------------------------------------------------------------------

case "${1:-}" in
    host) shift; host_main "$@" ;;
    vm) vm_main ;;
    dryrun) shift; dryrun_main "$@" ;;
    dryrun-regressions) shift; dryrun_regressions "$@" ;;
    *) echo "usage: run_batch.sh host --batch-dir DIR [--resume] | run_batch.sh vm | run_batch.sh dryrun --batch-dir DIR | run_batch.sh dryrun-regressions --batch-dir DIR" >&2; exit 2 ;;
esac
