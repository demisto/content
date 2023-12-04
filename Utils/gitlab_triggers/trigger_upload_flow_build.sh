#!/usr/bin/env bash

if [ "$#" -lt "1" ]; then
  echo "Usage:
  $0 -ct <token>

  -ct, --ci-token             The ci gitlab token.
  [-b, --branch]              The branch name. Default is the current branch.
  [-gb, --bucket]             The name of the bucket to upload the packs to. Default is marketplace-dist-dev.
  [-gb2, --bucket_v2]         The name of the bucket to upload the marketplace v2 packs to. Default is marketplace-v2-dist-dev.
  [-gb3, --bucket_xpanse]     The name of the bucket to upload the xpanse marketplace packs to. Default is xpanse-dist-dev.
  [-gb4, --bucket_xsoar_saas] The name of th bucket to upload the xsoar_saas marketplace packs to. Default is marketplace-saas-dist-dev.
  [-f, --force]               Whether to trigger the force upload flow.
  [-p, --packs]               CSV list of pack IDs. Mandatory when the --force flag is on.
  [-ch, --slack-channel]      A slack channel to send notifications to. Default is dmst-bucket-upload.
  [-oa, --override-all]       If given, will override all packs during this upload flow.
  "
  exit 1
fi

_branch="$(git branch  --show-current)"
_bucket="${TEST_XDR_PREFIX}marketplace-dist-dev"
_bucket_v2="${TEST_XDR_PREFIX}marketplace-v2-dist-dev"
_bucket_xpanse="${TEST_XDR_PREFIX}xpanse-dist-dev"
_bucket_xsoar_saas="${TEST_XDR_PREFIX}marketplace-saas-dist-dev"
_force="false"
_slack_channel="dmst-bucket-upload"
_override_all_pack="false"

# Parsing the user inputs.

while [[ "$#" -gt 0 ]]; do
  case $1 in

  -ct|--ci-token) _ci_token="$2"
    shift
    shift;;

  -b|--branch) _branch="$2"
    shift
    shift;;

  -gb|--bucket) _bucket="$2"
    shift
    shift;;

  -gb2|--bucket_v2) _bucket_v2="$2"
    shift
    shift;;

  -gb3| --bucket_xpanse) _bucket_xpanse="$2"
    shift
    shift;;

  -gb4|--bucket_xsoar_saas) _bucket_xsoar_saas="$2"
    shift
    shift;;

  -f|--force) _force=true
    shift
    shift;;

  -p|--packs) _packs="$2"
    shift
    shift;;

  -ch|--slack-channel) _slack_channel="$2"
    shift
    shift;;

  -oa|--override-all) _override_all_pack="true"
    shift;;

  *)    # unknown option.
    shift;;
  esac
done


if [ -z "$_ci_token" ]; then
    echo "You must provide a ci token."
    exit 1
fi

if [ "$_force" == "true" ] && [ -z "$_packs" ]; then
    echo "You must provide a csv list of packs to force upload."
    exit 1
fi

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
source ${SCRIPT_DIR}/trigger_build_url.sh

curl -k -v --request POST \
  --form token="${_ci_token}" \
  --form ref="${_branch}" \
  --form "variables[BUCKET_UPLOAD]=true" \
  --form "variables[OVERRIDE_ALL_PACKS]=${_override_all_pack}" \
  --form "variables[SLACK_CHANNEL]=${_slack_channel}" \
  --form "variables[PACKS_TO_UPLOAD]=${_packs}" \
  --form "variables[FORCE_BUCKET_UPLOAD]=${_force}" \
  --form "variables[GCS_MARKET_BUCKET]=${_bucket}" \
  --form "variables[GCS_MARKET_V2_BUCKET]=${_bucket_v2}" \
  --form "variables[GCS_MARKET_XPANSE_BUCKET]=${_bucket_xpanse}" \
  --form "variables[GCS_MARKET_XSOAR_SAAS_BUCKET]=${_bucket_xsoar_saas}" \
  --form "variables[IFRA_ENV_TYPE]=Bucket-Upload" \
  --form "variables[TEST_UPLOAD]=false" \
  "$BUILD_TRIGGER_URL"
