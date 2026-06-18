#!/usr/bin/env bash
#
# run_step11_survey.sh — batch-run step 11 (param parity) for ALL integrations
# assigned to the current user, with connector + base-pack deploy SKIPPED, and
# SKIP-ON-FAILURE (a failing integration is recorded and the batch continues).
#
# RUN IN YOUR OWN TERMINAL (not via the agent):
#   - israel-gw VPN connected
#   - live param-parity session (session_setup.py already run)
#   - from /Users/nodavidi/dev/demisto/content
#
# Usage:
#   ./run_step11_survey.sh
#
# Produces:
#   .step11_survey_results.tsv   — one row per integration: <id>\t<PASS|FAIL|BLOCKED>\t<rc>\t<ts>
#   .step11_survey_logs/<id>.log — full per-integration output
# Prints a final summary table at the end.

set -uo pipefail

PY=.venv/bin/python
CLI="connectus/workflow_state.py"
RESULTS=".step11_survey_results.tsv"
LOGDIR=".step11_survey_logs"

# ── Deploy-scope skips (speed): test against the ALREADY-deployed connector
#    and skip the Base pack upload. Parity check still runs and must exit 0. ──
export CONNECTUS_PARITY_SKIP_CONNECTOR=1
export CONNECTUS_PARITY_SKIP_BASE_PACK=1
# Redirect demisto-sdk logs to a writable dir (harmless in your terminal too).
export DEMISTO_SDK_LOG_FILE_PATH="$(pwd)/.sdk-logs"
# The tenant domain is in .env NO_PROXY, but demisto-sdk's HTTP client does NOT
# honor NO_PROXY reliably — it routes through HTTP(S)_PROXY and fails (403). The
# tenant is directly routable (NO_PROXY/VPN), so unset the proxy entirely for
# this process tree so demisto-sdk connects direct.
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy

mkdir -p "$LOGDIR" "$(pwd)/.sdk-logs"
: > "$RESULTS"   # fresh ledger each run

sanitize() { echo "$1" | tr -c 'A-Za-z0-9._-' '_'; }

# ── Session sanity check ──
if ! "$PY" connectus/runtime_demisto.params_parity/session_setup.py --check >/dev/null 2>&1; then
  echo "ERROR: param-parity session is NOT live. On the israel-gw VPN run:" >&2
  echo "  $PY connectus/runtime_demisto.params_parity/session_setup.py" >&2
  exit 1
fi
echo "Session OK. SKIP_CONNECTOR=1 SKIP_BASE_PACK=1. Starting survey."
echo ""

# ── Enumerate the current user's in-progress step-11 integrations ──
IDS_FILE="$(mktemp)"
"$PY" "$CLI" next --mine 2>/dev/null \
  | grep "step 11 of 15" \
  | sed -E 's/ — step 11 of 15.*//' > "$IDS_FILE"

total=$(wc -l < "$IDS_FILE" | tr -d ' ')
if [[ "$total" -eq 0 ]]; then
  echo "No integrations at step 11 assigned to you. Nothing to do."
  exit 0
fi
echo "Found $total integration(s) at step 11."
echo ""

i=0
while IFS= read -r id; do
  [[ -z "$id" ]] && continue
  i=$((i+1))
  log="$LOGDIR/$(sanitize "$id").log"
  printf "[%d/%d] %s ... " "$i" "$total" "$id"

  if "$PY" "$CLI" markpass "$id" "param parity test passes" >"$log" 2>&1; then
    printf 'PASS\n'
    printf '%s\tPASS\t0\t%s\n' "$id" "$(date -u +%FT%TZ)" >>"$RESULTS"
  else
    rc=$?
    # Distinguish BLOCKED (exit 11) from genuine parity FAIL (exit 10) and others.
    state="FAIL"
    if grep -q "exited 11" "$log" 2>/dev/null; then state="BLOCKED"; fi
    printf '%s (rc=%s) — skipped\n' "$state" "$rc"
    printf '%s\t%s\t%s\t%s\n' "$id" "$state" "$rc" "$(date -u +%FT%TZ)" >>"$RESULTS"
  fi
done < "$IDS_FILE"
rm -f "$IDS_FILE"

# ── Final summary ──
echo ""
echo "================= STEP 11 SURVEY SUMMARY ================="
pass=$(awk -F'\t' '$2=="PASS"{c++} END{print c+0}' "$RESULTS")
fail=$(awk -F'\t' '$2=="FAIL"{c++} END{print c+0}' "$RESULTS")
blocked=$(awk -F'\t' '$2=="BLOCKED"{c++} END{print c+0}' "$RESULTS")
echo "Total:   $total"
echo "PASS:    $pass"
echo "FAIL:    $fail   (real parity mismatch — needs connector fix)"
echo "BLOCKED: $blocked   (exit 11 — setup/rollout; often just retry)"
echo ""
echo "PASSED integrations:"
awk -F'\t' '$2=="PASS"{print "  ✅ "$1}' "$RESULTS"
echo ""
echo "FAILED (parity):"
awk -F'\t' '$2=="FAIL"{print "  ❌ "$1}' "$RESULTS"
echo ""
echo "BLOCKED:"
awk -F'\t' '$2=="BLOCKED"{print "  ⏸  "$1}' "$RESULTS"
echo ""
echo "Ledger: $RESULTS   |   Per-integration logs: $LOGDIR/"
