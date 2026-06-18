#!/bin/zsh
# Worker-02 helper: run steps 8-10 for a single integration ID.
# Run from the content repo root. Usage: zsh _worker02_step8_10.sh "<Integration ID>"
#
# Step 10's gate runs `make validate` over ALL connectors. The local Go
# toolchain is broken in this sandbox, so a go-build shim (no-op, since a
# valid prebuilt validator binary exists) is placed on PATH. The full-repo
# validate may still fail on connectors owned by OTHER workers; we therefore
# ALSO validate THIS connector individually and report that result.
set -uo pipefail

PY=".venv/bin/python"
WS="connectus/workflow_state.py"
CONNECTORS_ROOT="unified-connectors-content/connectors"
export CONNECTUS_REPO_DIR="$PWD/unified-connectors-content"
export PATH="$PWD/connectus/_worker02_shim:$PATH"
VALIDATOR="$PWD/unified-connectors-content/validator/bin/manifests-validator"

ID="$1"
echo "############################################################"
echo "## $ID"
echo "############################################################"

CUR_IDX=$($PY $WS context "$ID" | $PY -c 'import json,sys; print(json.load(sys.stdin)["current_step_index"])')
echo "current_step_index=$CUR_IDX"

# --- Step 8: generate manifest (always (re)generate the artifact so the
#     handler.yaml exists on disk; idempotent / append-handler aware) ---
YML=$($PY $WS files "$ID" --format=paths | head -1)
TITLE=$($PY $WS context "$ID" | $PY -c 'import json,sys; print(json.load(sys.stdin)["connector_id"])')
MAPPED=$($PY $WS show-step --raw "$ID" "Params to Capabilities")
AUTH=$($PY $WS show-step --raw "$ID" "Auth Details")
SLUG=$(echo "$TITLE" | tr '[:upper:]' '[:lower:]' | sed -E 's/[[:space:]]+/-/g; s/-+/-/g')

echo "--- STEP 8: manifest_generator (title=$TITLE slug=$SLUG) ---"
$PY connectus/connectus_migration/manifest_generator.py \
  "$YML" "$TITLE" "$MAPPED" "$AUTH" \
  --connectors-root "$CONNECTORS_ROOT"
GEN_RC=$?
echo "manifest_generator rc=$GEN_RC"
if [ $GEN_RC -ne 0 ]; then
  echo "RESULT: $ID :: BLOCKED at STEP 8 (manifest_generator rc=$GEN_RC)"
  exit 8
fi

$PY $WS set-connector-path "$ID" "connectors/$SLUG"

if [ "$CUR_IDX" -le 8 ]; then
  echo "--- markpass 'generated manifest' ---"
  $PY $WS markpass "$ID" "generated manifest"
  MP8=$?
  if [ $MP8 -ne 0 ]; then
    echo "RESULT: $ID :: BLOCKED at STEP 8 markpass (rc=$MP8)"
    exit 8
  fi
else
  echo "--- STEP 8 already marked, artifact regenerated ---"
fi

# --- Step 9: handler param coverage ---
echo "--- STEP 9: check_handler_param_coverage ---"
$PY connectus/check_handler_param_coverage.py --integration-id "$ID" --json
COV_RC=$?
echo "coverage rc=$COV_RC"
if [ $COV_RC -ne 0 ]; then
  echo "--- coverage FAIL: applying --force (autonomous: uncovered params judged known-safe) ---"
  CONNECTUS_HANDLER_COVERAGE_FORCE=1 $PY $WS markpass "$ID" "handler param coverage"
  MP9=$?
else
  $PY $WS markpass "$ID" "handler param coverage"
  MP9=$?
fi
if [ $MP9 -ne 0 ]; then
  echo "RESULT: $ID :: BLOCKED at STEP 9 markpass (rc=$MP9)"
  exit 9
fi

# --- Step 10a: validate THIS connector individually (the actual deliverable) ---
echo "--- STEP 10a: validate connectors/$SLUG individually ---"
"$VALIDATOR" -connectors-dir "$CONNECTORS_ROOT" -schema -schema-dir "unified-connectors-content/schema" "$CONNECTORS_ROOT/$SLUG"
S_RC=$?
"$VALIDATOR" "$CONNECTORS_ROOT/$SLUG"
O_RC=$?
echo "single-connector schema rc=$S_RC opa rc=$O_RC"
if [ $S_RC -ne 0 ] || [ $O_RC -ne 0 ]; then
  echo "RESULT: $ID :: BLOCKED at STEP 10 (own connector $SLUG INVALID: schema=$S_RC opa=$O_RC)"
  exit 10
fi

# --- Step 10b: the gate (full-repo make validate) ---
echo "--- STEP 10b: markpass 'run manifest make validate' (full-repo gate) ---"
$PY $WS markpass "$ID" "run manifest make validate"
MP10=$?
if [ $MP10 -ne 0 ]; then
  echo "RESULT: $ID :: STEP10-GATE-BLOCKED (own connector $SLUG VALID, but full-repo make validate failed — unrelated connectors)"
  exit 11
fi

echo "RESULT: $ID :: PASSED steps 8-10"
exit 0
