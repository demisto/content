#!/usr/bin/env bash

if [ "$#" -lt "1" ]; then
  echo "Usage:
  $0 -ct <token>

  -ct, --ci-token             The ci token.
  [-b, --branch]              The branch name. Default is the current branch.
  [-gb, --bucket]             The name of the bucket to upload the packs to. Default is marketplace-dist-dev.
  [-gb2, --bucket_v2]         The name of the bucket to upload the marketplace v2 packs to. Default is marketplace-v2-dist-dev.
  [-gb3, --bucket_xpanse]     The name of the bucket to upload the xpanse marketplace packs to. Default is xpanse-dist-dev.
  [-gb4, --bucket_xsoar_saas] The name of th bucket to upload the xsoar_saas marketplace packs to. Default is marketplace-saas-dist-dev.
  [-f, --force]               Whether to trigger the force upload flow.
  [-p, --packs]               CSV list of pack IDs. Mandatory when the --force flag is on.
  [-ch, --slack-channel]      A slack channel to send notifications to. Default is dmst-bucket-upload.
  [-sbp, --storage-base-path] A path to copy from in this current upload, and to be used as a target destination. This path should look like upload-flow/builds/branch_name/build_number/content.
  [-dz, --create_dependencies_zip] Upload packs with dependencies zip
  [-o, --override_all_packs]  Whether to override all packs, and not just modified packs.
  "
  exit 1
fi

_branch="$(git branch  --show-current)"
_bucket="marketplace-dist-dev"
_bucket_v2="marketplace-v2-dist-dev"
_bucket_xpanse="xpanse-dist-dev"
_bucket_xsoar_saas="marketplace-saas-dist-dev"
_bucket_upload="true"
_slack_channel="dmst-bucket-upload"
_storage_base_path=""

# Parsing the user inputs.

while [[ "$#" -gt 0 ]]; do
  case $1 in

  -ct|--ci-token) _ci_token="$2"
    shift
    shift;;

  -b|--branch) _branch="$2"
    shift
    shift;;

  -gb|--bucket)
  if [ "$(echo "$2" | tr '[:upper:]' '[:lower:]')" == "marketplace-dist" ]; then
    echo "Only test buckets are allowed to use. Using marketplace-dist-dev instead."
  else
    _bucket=$2
  fi
    shift
    shift;;

  -gb2|--bucket_v2)
  if [ "$(echo "$2" | tr '[:upper:]' '[:lower:]')" == "marketplace-v2-dist" ]; then
    echo "Only test buckets are allowed to use. Using marketplace-v2-dist-dev instead."
  else
    _bucket_v2=$2
  fi
    shift
    shift;;

  -gb3|--bucket_xpanse)
  if [ "$(echo "$2" | tr '[:upper:]' '[:lower:]')" == "xpanse-dist" ]; then
    echo "Only test buckets are allowed to use. Using xpanse-dist-dev instead."
  else
    _bucket_xpanse=$2
  fi
    shift
    shift;;

  -gb4|--bucket_xsoar_saas)
  if [ "$(echo "$2" | tr '[:upper:]' '[:lower:]')" == "marketplace-saas-dist" ]; then
    echo "Only test buckets are allowed to use. Using marketplace-saas-dist-dev instead."
  else
    _bucket_xsoar_saas=$2
  fi
    shift
    shift;;

  -f|--force) _force=true
    _bucket_upload=""
    shift;;

  -p|--packs) _packs="$2"
    shift
    shift;;

  -ch|--slack-channel) _slack_channel="$2"
    shift
    shift;;

  -sbp|--storage-base-path) _storage_base_path="$2"
    shift
    shift;;

  -o|--override-all-packs) _override_all_packs=true
    shift;;

  -dz|--create_dependencies_zip) _create_dependencies_zip=true
    shift;;

  *)    # unknown option.
    shift;;
  esac
done


if [ -z "$_ci_token" ]; then
    echo "You must provide a ci token."
    exit 1
fi

if [ -n "$_force" ] && [ -z "$_packs" ]; then
    echo "You must provide a csv list of packs to force upload."
    exit 1
fi

if [ -n "$_force" ] && [ -n "$_storage_base_path" ]; then
    echo "Can not force upload while using a storage base path."
    exit 1
fi
if [ -n "$_storage_base_path" ] && [[ "$_storage_base_path" != *content ]]; then
  echo "$_storage_base_path"
  echo "The given storage base path should look like upload-flow/builds/branch_name/build_number/content.1"
  exit 1
fi

if [ -n "$_storage_base_path" ] && [[ "$_storage_base_path" != upload-flow* ]]; then
  echo $_storage_base_path
  echo "The given storage base path should look like upload-flow/builds/branch_name/build_number/content.2"
  exit 1
fi

_variables="variables[BUCKET_UPLOAD]=true"
if [ -n "$_force" ]; then
  _variables="variables[FORCE_BUCKET_UPLOAD]=true"
fi

if [ -z "$_override_all_packs" ]; then
  _override_all_packs=false
else
  _override_all_packs=true
fi

if [ -z "$_create_dependencies_zip" ]; then
  _create_dependencies_zip=false
fi

source Utils/gitlab_triggers/trigger_build_url.sh

curl --request POST \
  --form token="${_ci_token}" \
  --form ref="${_branch}" \
  --form "${_variables}" \
  --form "variables[SLACK_CHANNEL]=${_slack_channel}" \
  --form "variables[PACKS_TO_UPLOAD]=${_packs}" \
  --form "variables[GCS_MARKET_BUCKET]=${_bucket}" \
  --form "variables[GCS_MARKET_V2_BUCKET]=${_bucket_v2}" \
  --form "variables[GCS_MARKET_XPANSE_BUCKET]=${_bucket_xpanse}" \
  --form "variables[GCS_MARKET_XSOAR_SAAS_BUCKET]=${_bucket_xsoar_saas}" \
  --form "variables[IFRA_ENV_TYPE]=Bucket-Upload" \
  --form "variables[STORAGE_BASE_PATH]=${_storage_base_path}" \
  --form "variables[OVERRIDE_ALL_PACKS]=${_override_all_packs}" \
  --form "variables[CREATE_DEPENDENCIES_ZIP]=${_create_dependencies_zip}" \
  --form "variables[OVERRIDE_SDK_REF]=${DEMISTO_SDK_NIGHTLY}" \
  "$BUILD_TRIGGER_URL"
