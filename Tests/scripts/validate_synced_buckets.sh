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
  bucket_list_origin=("gs://marketplace-dist" "gs://marketplace-v2-dist" "gs://xpanse-dist")
  bucket_list_prod=("gs://marketplace-xsoar" "gs://marketplace-xsiam" "gs://marketplace-xpanse")
  json_file_path="/content/packs/index.json"

  # Compare the revision fields for each pair of buckets
  for ((i = 0; i < ${#bucket_list_origin[@]}; i++)); do
    bucket1="${bucket_list_origin[$i]}"
    bucket2="${bucket_list_prod[$i]}-$1"

    echo "Comparing revisions for $bucket1 and $bucket2"
    revision1=$(gsutil cat "gs://$bucket1$json_file_path" | jq -r '.revision')
    revision2=$(gsutil cat "gs://$bucket2$json_file_path" | jq -r '.revision')

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

compare_revision "$1"

