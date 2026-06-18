#!/usr/bin/env bash
# Runs connectus-migration steps 8-10 for a single integration.
# Usage: run_steps_8_10.sh "<Integration ID>"
# Exit 0 = all three steps passed; non-zero = blocked (message on stderr).
set -uo pipefail

export CONNECTUS_REPO_DIR=/Users/jlevy/dev/demisto/content/unified-connectors-content
PY=.venv/bin/python
WS() { "$PY" connectus/workflow_state.py "$@"; }

ID="$1"
echo "============================================================"
echo "  $ID — steps 8-10"
echo "============================================================"

YML="$(WS files "$ID" --format=paths | head -1)"
TITLE="$(WS context "$ID" | "$PY" -c 'import json,sys;print(json.load(sys.stdin)["connector_id"])')"
MAPPED="$(WS show-step --raw "$ID" "Params to Capabilities")"
AUTH="$(WS show-step --raw "$ID" "Auth Details")"

# slug = lowercase title, whitespace runs -> single dash
SLUG="$("$PY" -c 'import re,sys;print(re.sub(r"\s+","-",sys.argv[1].strip().lower()))' "$TITLE")"
CONNDIR="$CONNECTUS_REPO_DIR/connectors/$SLUG"

echo "  yml=$YML"
echo "  title=$TITLE  slug=$SLUG"
if [ -f "$CONNDIR/connector.yaml" ]; then
  echo "  mode=APPEND-HANDLER (connector.yaml exists)"
else
  echo "  mode=FROM-SCRATCH"
  # ensure clean state for from-scratch (remove any empty/partial dir)
  [ -d "$CONNDIR" ] && rm -rf "$CONNDIR"
fi

echo "--- Step 8: generate manifest ---"
"$PY" connectus/connectus_migration/manifest_generator.py \
  "$YML" "$TITLE" "$MAPPED" "$AUTH" \
  --connectors-root "$CONNECTUS_REPO_DIR/connectors" 2>&1 | grep -iE "Generated|Creating|Append|Registered|Error|Traceback|RuntimeError" 
gen_rc=${PIPESTATUS[0]}
if [ "$gen_rc" -ne 0 ]; then
  echo "BLOCKED: manifest generation failed (rc=$gen_rc)" >&2
  exit 11
fi

WS set-connector-path "$ID" "connectors/$SLUG" >/dev/null 2>&1 || { echo "BLOCKED: set-connector-path failed" >&2; exit 12; }
WS markpass "$ID" "generated manifest" 2>&1 | tail -2
mp8_rc=${PIPESTATUS[0]}
[ "$mp8_rc" -ne 0 ] && { echo "BLOCKED: markpass 'generated manifest' failed" >&2; exit 13; }

echo "--- Step 9: handler param coverage ---"
COV="$("$PY" connectus/check_handler_param_coverage.py --integration-id "$ID" --json 2>&1)"
PASS="$(echo "$COV" | "$PY" -c 'import json,sys
try:
  d=json.load(sys.stdin); print("true" if d.get("pass") else "false"); 
except Exception as e:
  print("err")' 2>/dev/null)"
echo "  coverage pass=$PASS"
if [ "$PASS" = "true" ]; then
  WS markpass "$ID" "handler param coverage" 2>&1 | tail -1
else
  echo "  missing params:"; echo "$COV" | "$PY" -c 'import json,sys;print(json.load(sys.stdin).get("missing"))' 2>/dev/null
  echo "COVERAGE_NOT_PASS"  # signal to caller for autonomous decision
  exit 9
fi

echo "--- Step 10: make validate ---"
make -C unified-connectors-content validate connector="connectors/$SLUG" 2>&1 | grep -iE "VALID|INVALID|violation|missing|Summary"
WS markpass "$ID" "run manifest make validate" 2>&1 | tail -3
mp10_rc=${PIPESTATUS[0]}
[ "$mp10_rc" -ne 0 ] && { echo "BLOCKED: step 10 gate failed" >&2; exit 10; }

echo "  >>> $ID: steps 8-10 PASSED"
exit 0
