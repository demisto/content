#!/usr/bin/env bash
set -ex

echo "CI_COMMIT_BRANCH: $CI_COMMIT_BRANCH CI: $CI DEMISTO_README_VALIDATION: $DEMISTO_README_VALIDATION"
if [[ $CI_COMMIT_BRANCH = master ]] || [[ -n "${NIGHTLY}" ]] || [[ -n "${BUCKET_UPLOAD}" ]] || [[ -n "${DEMISTO_SDK_NIGHTLY}" ]]; then
    if [ -n "${PACKS_TO_UPLOAD}" ]
        PACKS_LIST=""
        for item in $PACKS_TO_UPLOAD; do
        PACKS_LIST=$PACKS_LIST"Packs/"$item" "
        done
        echo "Packs upload - Validating only the supplied packs"
        echo "Packs path "$PACKS_LIST
        python3 -m demisto_sdk validate -i $PACKS_LIST --post-commit --graph --skip-pack-dependencies
    python3 -m demisto_sdk validate -a --post-commit --graph --skip-pack-dependencies
elif [[ $CI_COMMIT_BRANCH =~ pull/[0-9]+ ]]; then
    python3 -m demisto_sdk validate -g --post-commit --graph --skip-pack-dependencies
elif [[ $CI_COMMIT_BRANCH = demisto/python3 ]]; then
    python3 -m demisto_sdk validate -g --post-commit --no-conf-json --allow-skipped --graph --skip-pack-dependencies
else
    python3 -m demisto_sdk validate -g --post-commit --graph --skip-pack-dependencies
fi