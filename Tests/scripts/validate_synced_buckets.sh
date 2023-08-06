#!/bin/bash


function compare_revision() {
  bucket_list_origin=("marketplace-dist" "marketplace-v2-dist" "xpanse-dist")
  bucket_list_prod=("marketplace-xsoar" "marketplace-xsiam" "marketplace-xpanse")
  json_file_path="/content/packs/index.json"

  # Compare the revision fields for each pair of buckets
  for ((i = 0; i < ${#bucket_list_origin[@]}; i++)); do
    bucket1="${bucket_list_origin[$i]}"
    bucket2="${bucket_list_prod[$i]}-$1"

    echo "Comparing revisions for $bucket1 and $bucket2"

    index_json_origin=$(gsutil cat "gs://$bucket1$json_file_path")
    index_json_prod=$(gsutil cat "gs://$bucket2$json_file_path")
    test=$(curl -s "gs://$bucket2$json_file_path")
    echo "$test test"
    revision1=$(echo "$index_json" | jq -r '.revision')
    revision2=$(echo "$index_json_prod" | jq -r '.revision')

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

