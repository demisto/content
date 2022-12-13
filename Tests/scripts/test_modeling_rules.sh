#!/bin/bash

${XSIAM_SERVERS_PATH:=xsiam_servers.json}

# Get XSIAM Tenant Config Details
XSIAM_SERVER_CONFIG=$(jq ".[\"$XSIAM_CHOSEN_MACHINE_ID\"]" < "$XSIAM_SERVERS_PATH")
XSIAM_URL=$(echo "$XSIAM_SERVER_CONFIG" | jq '.base_url')
AUTH_ID=$(echo "$XSIAM_SERVER_CONFIG" | jq ".[\"x-xdr-auth-id\"]")
API_KEY=$(jq ".[\"$XSIAM_CHOSEN_MACHINE_ID\"]" < "$XSIAM_API_KEYS")
XSIAM_TOKEN=$(echo "$XSIAM_TOKENS" | jq ".[\"$XSIAM_CHOSEN_MACHINE_ID\"]")

MODELING_RULES_TO_TEST="$(tr '\n' ' ' < "$ARTIFACTS_FOLDER"/modeling_rules_to_test.txt)"

echo "Testing Modeling Rules"
demisto-sdk modeling-rules test --xsiam-url="$XSIAM_URL" --auth-id="$AUTH_ID" --api-key="$API_KEY" --xsiam-token="$XSIAM_TOKEN" --non-interactive "$MODELING_RULES_TO_TEST"
