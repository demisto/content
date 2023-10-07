#!/bin/bash


function compare_revision() {
  bucket_list_origin=($GCS_MARKET_BUCKET $GCS_MARKET_V2_BUCKET $GCS_MARKET_XPANSE_BUCKET)
  bucket_list_prod=($MARKETPLACE_XSOAR_PROD $MARKETPLACE_V2_PROD $MARKETPLACE_XPANSE_PROD)
  json_file_path="/content/packs/index.json"

  # Compare the revision fields for each pair of buckets
  for ((i = 0; i < ${#bucket_list_origin[@]}; i++)); do
    bucket1="${bucket_list_origin[$i]}"
    bucket2="${bucket_list_prod[$i]}-$1"

    echo "Comparing revisions for $bucket1 and $bucket2"

    gsutil cp "gs://$bucket1$json_file_path" $ARTIFACTS_FOLDER/sync/origin_index.json
    gsutil cp "gs://$bucket2$json_file_path" $ARTIFACTS_FOLDER/sync/prod_index.json

    revision_origin=$( jq -r '.revision' $ARTIFACTS_FOLDER/sync/origin_index.json)
    revision_prod=$( jq -r '.revision' $ARTIFACTS_FOLDER/sync/prod_index.json)

    # Compare the revisions
    if [ "$revision_origin" = "$revision_prod" ]; then
      echo "Revisions are the same: $revision_origin"
    else
      echo "Revisions are different: $revision_origin (in $bucket_list_origin) vs $revision_prod (in $bucket_list_prod-$1)"
      exit 1
    fi

    echo
  done
}

compare_revision "$1"

