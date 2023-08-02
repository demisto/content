#!/bin/bash

# Function to get the revision field from a JSON file in a bucket
function get_revision_field() {
  bucket=$1
  json_file_path="/content/packs/index.json"

  # Download the JSON file from the bucket and extract the revision field using jq
  revision=$(gsutil cat "gs://$bucket$json_file_path" | jq -r '.revision')
  echo "$revision"
}

function compare_revision() {
  bucket_list_origin=$1
  bucket_list_prod=$2

  # Compare the revision fields for each pair of buckets
  for ((i = 0; i < ${#bucket_list_origin[@]}; i++)); do
    bucket1="${bucket_list_origin[$i]}"
    bucket2="${bucket_list_prod[$i]}"

    echo "Comparing revisions for $bucket_list_origin and $bucket_list_prod"

    # Get the revision fields from the JSON files in the buckets
    revision1=$(get_revision_field "$bucket_list_origin")
    revision2=$(get_revision_field "$bucket_list_prod")

    # Compare the revisions
    if [ "$revision1" = "$revision2" ]; then
      echo "Revisions are the same: $revision1"
    else
      echo "Revisions are different: $revision1 (in $bucket_list_origin) vs $revision2 (in $bucket_list_prod)"
      exit 1
    fi

    echo
  done
}

bucket_list_origin=("gs://marketplace-dist" "gs://marketplace-v2-dist" "gs://xpanse-dist")
bucket_list_prod=("gs://marketplace-xsoar-dev" "gs://marketplace-xsiam-dev" "gs://marketplace-xpanse-dev")
buckets_list_us=("gs://marketplace-xsoar-prod-us", "gs://marketplace-xsiam-prod-us", "gs://marketplace-xpanse-prod-us")

compare_revision "$bucket_list_origin" "$bucket_list_prod"
compare_revision "$bucket_list_origin" "$buckets_list_us"
