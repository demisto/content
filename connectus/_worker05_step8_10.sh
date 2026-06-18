#!/bin/zsh
# Worker-05 helper: run steps 8-10 for a single integration ID.
# Run from the content repo root. Usage: zsh connectus/_worker05_step8_10.sh "<Integration ID>"
set -uo pipefail

PY=".venv/bin/python"
WS="connectus/workflow_state.py"
CONNECTORS_ROOT="unified-connectors-content/connectors"
export CONNECTUS_REPO_DIR="$PWD/unified-connectors-content"

ID="$1"
echo "############################################################"
echo "## $ID"
echo "############################################################"

# --- Step 8: generate manifest ---
YML=$($PY $WS files "$ID" --format=paths | head -1)
TITLE=$($PY $WS context "$ID" | $PY -c 'import json,sys; print(json.load(sys.stdin)["connector_id"])')
MAPPED=$($PY $WS show-step --raw "$ID" "Params to Capabilities")
AUTH=$($PY $WS show-step --raw "$ID" "Auth Details")

echo "--- STEP 8: manifest_generator (title=$TITLE) ---"
$PY connectus/connectus_migration/manifest_generator.py \
  "$YML" "$TITLE" "$MAPPED" "$AUTH" \
  --connectors-root "$CONNECTORS_ROOT"
GEN_RC=$?
echo "manifest_generator rc=$GEN_RC"
if [ $GEN_RC -ne 0 ]; then
  echo "RESULT: $ID :: BLOCKED at STEP 8 (manifest_generator rc=$GEN_RC)"
  exit 8
fi

# slug = Connector ID lowercased, whitespace runs -> single dash
SLUG=$(echo "$TITLE" | tr '[:upper:]' '[:lower:]' | sed -E 's/[[:space:]]+/-/g; s/-+/-/g')
echo "--- set-connector-path connectors/$SLUG ---"
$PY $WS set-connector-path "$ID" "connectors/$SLUG"

echo "--- markpass 'generated manifest' ---"
$PY $WS markpass "$ID" "generated manifest"
MP8=$?
if [ $MP8 -ne 0 ]; then
  echo "RESULT: $ID :: BLOCKED at STEP 8 markpass (rc=$MP8)"
  exit 8
fi

# --- Step 9: handler param coverage ---
echo "--- STEP 9: check_handler_param_coverage ---"
$PY connectus/check_handler_param_coverage.py --integration-id "$ID" --json
COV_RC=$?
echo "coverage rc=$COV_RC"
if [ $COV_RC -ne 0 ]; then
  echo "RESULT: $ID :: BLOCKED at STEP 9 (coverage pass:false, rc=$COV_RC)"
  exit 9
fi
echo "--- markpass 'handler param coverage' ---"
$PY $WS markpass "$ID" "handler param coverage"
MP9=$?
if [ $MP9 -ne 0 ]; then
  echo "RESULT: $ID :: BLOCKED at STEP 9 markpass (rc=$MP9)"
  exit 9
fi

# --- Step 10: run manifest make validate (self-executing gate) ---
echo "--- STEP 10: markpass 'run manifest make validate' (runs make validate) ---"
$PY $WS markpass "$ID" "run manifest make validate"
MP10=$?
if [ $MP10 -ne 0 ]; then
  echo "RESULT: $ID :: BLOCKED at STEP 10 (make validate failed, rc=$MP10)"
  exit 10
fi

echo "RESULT: $ID :: PASSED steps 8-10"
exit 0
