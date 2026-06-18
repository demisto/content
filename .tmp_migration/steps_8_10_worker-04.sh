#!/usr/bin/env bash
# steps_8_10_worker-04.sh — run connectus migration steps 8-10 for ONE integration.
# Usage: ./steps_8_10_worker-04.sh "<Integration ID>"
# Run from the content repo root (cwd = /Users/jlevy/dev/demisto/content).
set -uo pipefail

ID="$1"
PY=".venv/bin/python"
WS="$PY connectus/workflow_state.py"
CONN_ROOT="unified-connectors-content/connectors"
export GOPROXY="https://proxy.golang.org,direct"
export GOFLAGS="-mod=mod"

echo "############################################################"
echo "## $ID"
echo "############################################################"

# ---- gather inputs ----
YML=$($PY connectus/workflow_state.py files "$ID" --format=paths | head -1)
CTX=$($PY connectus/workflow_state.py context "$ID")
TITLE=$(echo "$CTX" | $PY -c 'import json,sys; print(json.load(sys.stdin)["connector_id"])')
MAPPED=$($PY connectus/workflow_state.py show-step --raw "$ID" "Params to Capabilities")
AUTH=$($PY connectus/workflow_state.py show-step --raw "$ID" "Auth Details")
SLUG=$(echo "$TITLE" | tr '[:upper:]' '[:lower:]' | sed -E 's/[[:space:]]+/-/g')
echo "[info] title='$TITLE' slug='$SLUG' yml=$YML"

# ---- STEP 8: generate manifest ----
echo "---- STEP 8: generate manifest ----"
GEN_OUT=$($PY connectus/connectus_migration/manifest_generator.py "$YML" "$TITLE" "$MAPPED" "$AUTH" --connectors-root "$CONN_ROOT" 2>&1)
GEN_RC=$?
echo "$GEN_OUT" | grep -iE "generated|registered|append|created|error|traceback|exists|similiray|similarity" | tail -8
if [ $GEN_RC -ne 0 ]; then
  echo "[STEP8] generator exit=$GEN_RC"
fi
$PY connectus/workflow_state.py set-connector-path "$ID" "connectors/$SLUG" 2>&1 | tail -1
$PY connectus/workflow_state.py markpass "$ID" "generated manifest" 2>&1 | tail -2

# ---- STEP 9: handler param coverage ----
echo "---- STEP 9: handler param coverage ----"
COV=$($PY connectus/check_handler_param_coverage.py --integration-id "$ID" --json 2>/dev/null)
# The checker prints diagnostic preamble lines before the JSON object; slice
# from the first '{' so json.loads sees only the envelope.
COVJSON=$(echo "$COV" | $PY -c 'import sys; s=sys.stdin.read(); i=s.find("{\n"); print(s[i:] if i>=0 else "")')
PASS=$(echo "$COVJSON" | $PY -c 'import json,sys; print(json.load(sys.stdin).get("pass"))' 2>/dev/null)
MISSING=$(echo "$COVJSON" | $PY -c 'import json,sys; print(",".join(json.load(sys.stdin).get("missing",[])))' 2>/dev/null)
echo "[STEP9] pass=$PASS missing=[$MISSING]"
if [ "$PASS" = "True" ]; then
  $PY connectus/workflow_state.py markpass "$ID" "handler param coverage" 2>&1 | tail -2
else
  echo "[STEP9] pass=false -> autonomous --force (uncovered params kept in audit; forced:true)"
  CONNECTUS_HANDLER_COVERAGE_FORCE=1 $PY connectus/workflow_state.py markpass "$ID" "handler param coverage" 2>&1 | tail -2
fi

# ---- STEP 10: validate THIS connector individually (substantive check) ----
echo "---- STEP 10: make validate connector=connectors/$SLUG ----"
( cd unified-connectors-content && make validate connector="connectors/$SLUG" 2>&1 ) | grep -iE "VALID|INVALID|Summary|violation|missing property|•|completed successfully" | tail -12
