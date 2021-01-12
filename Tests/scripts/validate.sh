#!/usr/bin/env bash
set -e

echo "CIRCLE_BRANCH: $CIRCLE_BRANCH CI: $CI DEMISTO_README_VALIDATION: $DEMISTO_README_VALIDATION"

if [[ $CIRCLE_BRANCH = master ]] || [[ -n "${NIGHTLY}" ]] || [[ -n "${BUCKET_UPLOAD}" ]]; then
    demisto-sdk validate -a --id-set --id-set-path $CIRCLE_ARTIFACTS/unified_id_set.json
else
    demisto-sdk validate -g --post-commit --id-set --id-set-path $CIRCLE_ARTIFACTS/unified_id_set.json
fi
