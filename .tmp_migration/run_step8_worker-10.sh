#!/bin/bash
# Step 8 (generated manifest) for a single integration.
# Usage: run_step8_worker-10.sh "<Integration ID>"
set -uo pipefail
ID="$1"
PY=.venv/bin/python
WS="connectus/workflow_state.py"
GEN="connectus/connectus_migration/manifest_generator.py"
CR="unified-connectors-content/connectors"

echo "##### STEP 8 for: $ID"

YML=$($PY "$WS" files "$ID" --format=paths | head -1)
echo "YML: $YML"

CTX=$($PY "$WS" context "$ID")
TITLE=$(echo "$CTX" | $PY -c 'import json,sys; print(json.load(sys.stdin)["connector_id"])')
echo "TITLE (connector_id): $TITLE"
SLUG=$(echo "$TITLE" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
echo "SLUG: $SLUG"

MAPPED=$($PY "$WS" show-step --raw "$ID" "Params to Capabilities")
AUTH=$($PY "$WS" show-step --raw "$ID" "Auth Details")

echo "----- running manifest_generator -----"
$PY "$GEN" "$YML" "$TITLE" "$MAPPED" "$AUTH" --connectors-root "$CR"
RC=$?
echo "generator exit: $RC"
if [ "$RC" -ne 0 ]; then
  echo "RESULT_STEP8: FAIL (generator rc=$RC)"
  exit "$RC"
fi

echo "----- set-connector-path -----"
$PY "$WS" set-connector-path "$ID" "connectors/$SLUG"
RC=$?
if [ "$RC" -ne 0 ]; then echo "RESULT_STEP8: FAIL (set-connector-path rc=$RC)"; exit "$RC"; fi

echo "----- markpass generated manifest -----"
$PY "$WS" markpass "$ID" "generated manifest"
RC=$?
if [ "$RC" -ne 0 ]; then echo "RESULT_STEP8: FAIL (markpass rc=$RC)"; exit "$RC"; fi

echo "RESULT_STEP8: PASS"
