#!/bin/zsh
# steps_8_10.sh — run connectus migration steps 8-10 for one integration
# Run from the content/ repo root. Uses .venv python.
# Usage: ./steps_8_10.sh "<Integration ID>"
set -u
PY=.venv/bin/python
WS="$PY connectus/workflow_state.py"
ID="$1"
CR="unified-connectors-content/connectors"

echo "############################################################"
echo "# INTEGRATION: $ID"
echo "############################################################"

# --- gather inputs ---
YML=$($PY connectus/workflow_state.py files "$ID" --format=paths | head -1)
TITLE=$($PY connectus/workflow_state.py context "$ID" | $PY -c 'import json,sys;print(json.load(sys.stdin)["connector_id"])')
MAPPED=$($PY connectus/workflow_state.py show-step --raw "$ID" "Params to Capabilities")
AUTH=$($PY connectus/workflow_state.py show-step --raw "$ID" "Auth Details")

echo "YML:   $YML"
echo "TITLE: $TITLE"

# current step index
IDX=$($PY connectus/workflow_state.py context "$ID" | $PY -c 'import json,sys;print(json.load(sys.stdin)["current_step_index"])')
echo "current_step_index: $IDX"

# ---------- STEP 8: generated manifest ----------
if [ "$IDX" -le 8 ]; then
  echo "----- STEP 8: generate manifest -----"
  $PY connectus/connectus_migration/manifest_generator.py \
    "$YML" "$TITLE" "$MAPPED" "$AUTH" \
    --connectors-root "$CR"
  GEN_RC=$?
  echo "manifest_generator exit=$GEN_RC"
  if [ "$GEN_RC" -ne 0 ]; then
    echo "RESULT: BLOCKED at step 8 (manifest_generator failed)"
    exit 8
  fi
  # slug the connector id
  SLUG=$($PY -c 'import re,sys;s=sys.argv[1].strip().lower();s=re.sub(r"\s+","-",s);s=re.sub(r"-+","-",s);print(s)' "$TITLE")
  echo "slug: $SLUG"
  $PY connectus/workflow_state.py set-connector-path "$ID" "connectors/$SLUG"
  $PY connectus/workflow_state.py markpass "$ID" "generated manifest"
  MP8=$?
  echo "markpass step8 exit=$MP8"
  if [ "$MP8" -ne 0 ]; then echo "RESULT: BLOCKED at step 8 (markpass failed)"; exit 8; fi
else
  echo "----- STEP 8 already complete (idx=$IDX), skipping -----"
fi

# ---------- STEP 9: handler param coverage ----------
echo "----- STEP 9: handler param coverage -----"
COV=$($PY connectus/check_handler_param_coverage.py --integration-id "$ID" --json 2>&1)
echo "$COV"
PASS=$(echo "$COV" | $PY -c 'import json,sys
try:
    print(str(json.load(sys.stdin).get("pass")))
except Exception:
    print("PARSEERR")')
echo "coverage pass=$PASS"
if [ "$PASS" = "True" ]; then
  $PY connectus/workflow_state.py markpass "$ID" "handler param coverage"
  MP9=$?
  echo "markpass step9 exit=$MP9"
  if [ "$MP9" -ne 0 ]; then echo "RESULT: BLOCKED at step 9 (markpass failed)"; exit 9; fi
else
  echo "RESULT: BLOCKED at step 9 (handler param coverage pass=$PASS)"
  exit 9
fi

# ---------- STEP 10: run manifest make validate ----------
echo "----- STEP 10: run manifest make validate -----"
$PY connectus/workflow_state.py markpass "$ID" "run manifest make validate"
MP10=$?
echo "markpass step10 exit=$MP10"
if [ "$MP10" -ne 0 ]; then echo "RESULT: BLOCKED at step 10 (make validate failed)"; exit 10; fi

echo "RESULT: PASSED steps 8-10"
exit 0
