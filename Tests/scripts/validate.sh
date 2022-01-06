#!/usr/bin/env bash
set -e

echo "CI_COMMIT_BRANCH: $CI_COMMIT_BRANCH CI: $CI DEMISTO_README_VALIDATION: $DEMISTO_README_VALIDATION"

if [[ $CI_COMMIT_BRANCH = master ]] || [[ -n "${NIGHTLY}" ]] || [[ -n "${BUCKET_UPLOAD}" ]] || [[ -n "${DEMISTO_SDK_NIGHTLY}" ]]; then
    demisto-sdk validate -a --post-commit --id-set --id-set-path "$ARTIFACTS_FOLDER/unified_id_set.json"
elif [[ $CI_COMMIT_BRANCH =~ pull/[0-9]+ ]]; then
    demisto-sdk validate -g --post-commit --id-set --id-set-path "$ARTIFACTS_FOLDER/id_set.json"
elif [[ $CI_COMMIT_BRANCH = demisto/python ]] || [[ $CI_COMMIT_BRANCH = demisto/python3 ]]; then
    demisto-sdk validate -g --post-commit --id-set --id-set-path "$ARTIFACTS_FOLDER/unified_id_set.json" --no-conf-json
else
    demisto-sdk validate -g --post-commit --id-set --id-set-path "$ARTIFACTS_FOLDER/unified_id_set.json"
fi
