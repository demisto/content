#!/usr/bin/env bash
#
# run_step11_parity.sh — batch-run the `param parity test passes` gate (step 11)
# for every integration listed in .step11_ids.txt.
#
# RUN THIS IN YOUR OWN TERMINAL (not via the agent):
#   - connected to the israel-gw VPN
#   - with a live param-parity session (session_setup.py already run)
#   - from /Users/nodavidi/dev/demisto/content
#
# Usage:
#   ./run_step11_parity.sh                 # process all not-yet-passed IDs
#   ./run_step11_parity.sh --dry-run       # show what would run, do nothing
#   ./run_step11_parity.sh --only "Active Directory Query v2"   # one ID
#
# Idempotent: IDs already recorded as PASS in .step11_results.tsv are skipped,
# so you can Ctrl-C and re-run to resume. Per-integration output is saved under
# .step11_logs/<sanitized-id>.log for debugging failures.

set -uo pipefail

PY=.venv/bin/python
CLI="connectus/workflow_state.py"
IDS_FILE=".step11_ids.txt"
RESULTS=".step11_results.tsv"
LOGDIR=".step11_logs"

DRY_RUN=0
ONLY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --only)    ONLY="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -f "$IDS_FILE" ]] || { echo "missing $IDS_FILE" >&2; exit 1; }
mkdir -p "$LOGDIR"
touch "$RESULTS"

sanitize() { echo "$1" | tr -c 'A-Za-z0-9._-' '_'; }

already_passed() {
  # column1==id AND column2==PASS
  awk -F'\t' -v id="$1" '$1==id && $2=="PASS"{found=1} END{exit found?0:1}' "$RESULTS"
}

run_one() {
  local id="$1"
  if already_passed "$id"; then
    echo "  [SKIP] already PASS: $id"
    return 0
  fi
  local log="$LOGDIR/$(sanitize "$id").log"
  echo "  [RUN ] $id  (log: $log)"
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "         (dry-run, not executing)"
    return 0
  fi
  if "$PY" "$CLI" markpass "$id" "param parity test passes" >"$log" 2>&1; then
    printf '%s\tPASS\t%s\n' "$id" "$(date -u +%FT%TZ)" >>"$RESULTS"
    echo "         => PASS"
  else
    local rc=$?
    printf '%s\tFAIL(rc=%s)\t%s\n' "$id" "$rc" "$(date -u +%FT%TZ)" >>"$RESULTS"
    echo "         => FAIL (rc=$rc) — see tail below:"
    tail -n 8 "$log" | sed 's/^/           | /'
  fi
}

# --- session sanity check before doing anything expensive ---
if [[ "$DRY_RUN" != "1" ]]; then
  if ! "$PY" connectus/runtime_demisto.params_parity/session_setup.py --check >/dev/null 2>&1; then
    echo "ERROR: param-parity session is NOT live. On the israel-gw VPN run:" >&2
    echo "  $PY connectus/runtime_demisto.params_parity/session_setup.py" >&2
    exit 1
  fi
  echo "Session OK. Starting batch."
fi

total=0; pass=0; fail=0; skip=0
while IFS= read -r id; do
  [[ -z "$id" ]] && continue
  [[ -n "$ONLY" && "$id" != "$ONLY" ]] && continue
  total=$((total+1))
  if already_passed "$id"; then skip=$((skip+1)); fi
  run_one "$id"
done < "$IDS_FILE"

echo ""
echo "=================== SUMMARY ==================="
echo "PASS:  $(awk -F'\t' '$2=="PASS"{c++} END{print c+0}' "$RESULTS")"
echo "FAIL:  $(awk -F'\t' '$2 ~ /^FAIL/{c++} END{print c+0}' "$RESULTS")"
echo "Results ledger: $RESULTS"
echo "Per-integration logs: $LOGDIR/"
echo ""
echo "Failed IDs:"
awk -F'\t' '$2 ~ /^FAIL/{print "  "$1"  ("$2")"}' "$RESULTS" | sort -u
