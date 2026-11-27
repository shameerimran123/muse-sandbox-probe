#!/bin/sh
# O12 - Host + protected directories unchanged (global)
# Spec: O_TESTS_SPEC_V8.md, O12. Environment: M8_PROPOSAL_V9.md Sec. 11.3.
#
# *** HOST-SIDE SCRIPT. It does NOT run on the VM and NOT as UID 1001. ***
# It runs on the host (the coordinator machine), before the batch and
# after it, to verify the run changed nothing outside the VM.
# NOT YET EXECUTED - written for review only.
#
# Usage:
#   o12.sh snapshot <manifest-out> <path>...
#     Hash every regular file and record every symlink under each <path>
#     (a file hashes itself; a directory covers every file and symlink
#     under it, recursively) and write the sorted manifest to
#     <manifest-out>. Run BEFORE the batch.
#   o12.sh verify <manifest-in> <path>...
#     Re-hash the same paths and compare with <manifest-in>. Run AFTER
#     the batch. The <path> arguments must be the same ones used for
#     the snapshot.
#
# Manifest line format (spec V4 blocker J):
#   F <sha256>  <path>    for a regular file
#   L <target>  <path>    for a symlink (target = readlink output)
#
# PASS: all hashes and symlink targets are unchanged.
# FAIL: any hash changes, any symlink target changes, any file added or
# removed, any type change (a file replaced by a symlink, or a symlink
# replaced by a file). A change is a FAIL of the whole run, not of one
# case.
# INCONCLUSIVE (exit 2): the script errors, times out, or the before /
# after hashes cannot both be obtained (e.g., a snapshot path does not
# exist at snapshot time). ALSO INCONCLUSIVE: ANY traversal error from
# find (permission denied, I/O error, or any other find error) - find's
# stderr is captured, and any output there makes the run INCONCLUSIVE;
# traversal errors are never silently swallowed. ALSO INCONCLUSIVE: a
# sort failure (blocker J, 2026-11-25 ~22:39 PKT) - the file list is
# sorted into a temp file FIRST with sort's exit code checked
# explicitly, and the hashing loop reads that file by redirection (not
# through a pipeline, whose exit status would be the loop's, not
# sort's, so a sort failure could be swallowed).
#
# Exit: 0 = PASS, 1 = FAIL, 2 = error/inconclusive.
# Result line: O12_RESULT=PASS | FAIL | INCONCLUSIVE
#
# Recommended path set (the harness passes these; see O_TESTS_README.md):
# the M1-M7 frozen manifest files, the m8 proposal / spec / scripts, and
# the harness source directory (when it exists on the host). This script
# writes only its manifest output (snapshot mode) and temp files
# (verify mode, removed on exit); it modifies nothing else.
set -u

mode=${1:-}
manifest=${2:-}
shift 2 || true

if [ -z "$mode" ] || [ -z "$manifest" ]; then
    echo "O12_ERROR=usage: o12.sh snapshot|verify <manifest> <path>..."
    echo "O12_RESULT=INCONCLUSIVE"
    exit 2
fi
if [ "$#" -eq 0 ]; then
    echo "O12_ERROR=no paths given"
    echo "O12_RESULT=INCONCLUSIVE"
    exit 2
fi

for _tool in find sha256sum sort diff mktemp readlink; do
    if ! command -v "$_tool" >/dev/null 2>&1; then
        echo "O12_ERROR=required tool missing: $_tool"
        echo "O12_RESULT=INCONCLUSIVE"
        exit 2
    fi
done

# hash_paths <out-file> <paths...>
# Write the sorted manifest lines ("F <sha256>  <path>" for regular
# files, "L <target>  <path>" for symlinks) for every file/symlink under
# the paths to <out-file>. Returns 2 if any path does not exist or if
# find reports ANY traversal error (its stderr is captured and checked).
hash_paths() {
    _out=$1
    shift
    : > "$_out" || return 2
    _list=$(mktemp) || return 2
    _err=$(mktemp) || { rm -f "$_list"; return 2; }
    _rc=0
    for _p in "$@"; do
        if [ -L "$_p" ]; then
            _t=$(readlink "$_p" 2>/dev/null) || _rc=2
            printf 'L %s  %s\n' "$_t" "$_p" >> "$_out" || _rc=2
        elif [ -f "$_p" ]; then
            if ! _line=$(sha256sum "$_p" 2>>"$_err"); then
                _rc=2
            else
                printf 'F %s\n' "$_line" >> "$_out" || _rc=2
            fi
        elif [ -d "$_p" ]; then
            find "$_p" \( -type f -o -type l \) -print0 2>"$_err" > "$_list" || _rc=2
            if [ -s "$_err" ]; then
                sed 's/^/O12_FIND_ERROR /' "$_err"
                _rc=2
            fi
            if [ "$_rc" -eq 0 ]; then
                # Sort FIRST, into a temp file, with sort's exit code
                # checked explicitly (blocker J, 2026-11-25 ~22:39 PKT).
                # The old form piped sort into the while loop, so the
                # pipeline's exit status was the loop's, not sort's,
                # and a sort failure was swallowed. The loop below reads
                # the sorted file by redirection (no pipeline), and a
                # failure inside it sets _loop_rc and breaks - it does
                # NOT call exit (the loop runs in this shell now, so
                # exit would kill the script, not just the loop).
                _sorted=$(mktemp) || _rc=2
                if [ "$_rc" -eq 0 ]; then
                    if ! sort -z -o "$_sorted" "$_list"; then
                        echo "O12_ERROR=sort failed for path: $_p"
                        _rc=2
                    fi
                fi
                if [ "$_rc" -eq 0 ]; then
                    # Read the NUL-delimited sorted file and hash
                    # each path. `read -d ''` is a bash extension
                    # and fails under #!/bin/sh (dash) with
                    # "Illegal option -d", so the loop never ran and
                    # O12 passed vacuously (empty snapshots diff to
                    # 0 changed files). Python reads the NUL-delimited
                    # file directly, preserving the exact output
                    # format ("F <hash>  <path>" / "L <target>
                    # <path>") and the failure signalling via its
                    # exit code. (Revision 8 fix, found by the
                    # dry-run.)
                    python3 - "$_sorted" "$_out" <<'PYEOF12'
import hashlib, os, sys
_sorted, _out = sys.argv[1], sys.argv[2]
try:
    with open(_sorted, "rb") as f:
        data = f.read()
except OSError:
    sys.exit(2)
paths = [p for p in data.split(b"\0") if p]
_rc = 0
try:
    out = open(_out, "a")
except OSError:
    sys.exit(2)
for _pb in paths:
    _f = _pb.decode("utf-8", "surrogateescape")
    if os.path.islink(_f):
        try:
            _t = os.readlink(_f)
        except OSError:
            _rc = 2
            break
        out.write("L %s  %s\n" % (_t, _f))
    else:
        try:
            _h = hashlib.sha256(open(_f, "rb").read()).hexdigest()
        except OSError:
            _rc = 2
            break
        out.write("F %s  %s\n" % (_h, _f))
out.close()
sys.exit(_rc)
PYEOF12
                    _loop_rc=$?
                    if [ "$_loop_rc" -ne 0 ]; then
                        _rc=2
                    fi
                fi
                [ -n "${_sorted:-}" ] && rm -f "$_sorted"
            fi
        else
            echo "O12_ERROR=path does not exist: $_p"
            _rc=2
        fi
    done
    rm -f "$_list" "$_err"
    if [ "$_rc" -ne 0 ]; then
        return 2
    fi
    sort -o "$_out" "$_out" || return 2
    return 0
}

case "$mode" in
    snapshot)
        {
            echo "# O12 snapshot $(date -u +%Y-%m-%dT%H:%M:%SZ)"
            echo "# paths: $*"
        } > "$manifest" || {
            echo "O12_ERROR=cannot write $manifest"
            echo "O12_RESULT=INCONCLUSIVE"
            exit 2
        }
        _tmp=$(mktemp) || {
            echo "O12_ERROR=cannot create temp file"
            echo "O12_RESULT=INCONCLUSIVE"
            exit 2
        }
        if ! hash_paths "$_tmp" "$@"; then
            rm -f "$_tmp"
            echo "O12_RESULT=INCONCLUSIVE"
            exit 2
        fi
        cat "$_tmp" >> "$manifest"
        rm -f "$_tmp"
        _n=$(grep -vc '^#' "$manifest")
        echo "O12_SNAPSHOT files=$_n manifest=$manifest"
        exit 0
        ;;
    verify)
        if [ ! -f "$manifest" ]; then
            echo "O12_ERROR=manifest not found: $manifest"
            echo "O12_RESULT=INCONCLUSIVE"
            exit 2
        fi
        _tmp=$(mktemp) || {
            echo "O12_ERROR=cannot create temp file"
            echo "O12_RESULT=INCONCLUSIVE"
            exit 2
        }
        trap 'rm -f "$_tmp"' EXIT
        if ! hash_paths "$_tmp" "$@"; then
            echo "O12_RESULT=INCONCLUSIVE"
            exit 2
        fi
        _before=$(mktemp) || {
            echo "O12_ERROR=cannot create temp file"
            echo "O12_RESULT=INCONCLUSIVE"
            exit 2
        }
        _diffout=$(mktemp) || {
            echo "O12_ERROR=cannot create temp file"
            echo "O12_RESULT=INCONCLUSIVE"
            exit 2
        }
        trap 'rm -f "$_tmp" "$_before" "$_diffout"' EXIT
        grep -v '^#' "$manifest" > "$_before"
        diff "$_before" "$_tmp" > "$_diffout" 2>&1
        _diff_rc=$?
        if [ "$_diff_rc" -eq 0 ]; then
            echo "O12_CHANGED files=0"
            echo "O12_RESULT=PASS"
            exit 0
        elif [ "$_diff_rc" -eq 1 ]; then
            _n=$(grep -c '^[<>]' "$_diffout" || true)
            echo "O12_CHANGED diff_lines=$_n"
            grep '^[<>]' "$_diffout" | sed 's/^/O12_DIFF /'
            echo "O12_RESULT=FAIL"
            exit 1
        else
            echo "O12_ERROR=diff failed rc=$_diff_rc"
            echo "O12_RESULT=INCONCLUSIVE"
            exit 2
        fi
        ;;
    *)
        echo "O12_ERROR=unknown mode: $mode (want snapshot|verify)"
        echo "O12_RESULT=INCONCLUSIVE"
        exit 2
        ;;
esac
