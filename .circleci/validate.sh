#!/usr/bin/env bash
set -ex


echo "CI_COMMIT_BRANCH: $CI_COMMIT_BRANCH CI: $CI DEMISTO_README_VALIDATION: $DEMISTO_README_VALIDATION, CI_COMMIT_SHA: $CI_COMMIT_SHA, LAST_UPLOAD_COMMIT: $LAST_UPLOAD_COMMIT"
if [[ $CI_COMMIT_BRANCH = master ]] || [[ -n "${NIGHTLY}" ]] || [[ -n "${BUCKET_UPLOAD}" ]] || [[ -n "${DEMISTO_SDK_NIGHTLY}" ]]; then
    if [[ -n "${PACKS_TO_UPLOAD}" ]]; then
        echo "Packs upload - Validating only the supplied packs"
        PACKS_TO_UPLOAD_SPACED=${PACKS_TO_UPLOAD//,/ }
        for item in $PACKS_TO_UPLOAD_SPACED; do
            python3 -m demisto_sdk validate -i Packs/"$item" --post-commit --graph --skip-pack-dependencies --run-old-validate --skip-new-validate
        done
      else
        if [[ -n "${NIGHTLY}" && "${CI_COMMIT_BRANCH}" == "master" ]]; then
            PREV_VER=$LAST_UPLOAD_COMMIT
        else
            PREV_VER="origin/master"
        fi
        python3 -m demisto_sdk validate -a --graph --skip-pack-dependencies --prev-ver $PREV_VER --run-old-validate --skip-new-validate
    fi
elif [[ $CI_COMMIT_BRANCH =~ pull/[0-9]+ ]]; then
    python3 -m demisto_sdk validate -g --post-commit --graph --skip-pack-dependencies --run-old-validate --skip-new-validate
elif [[ $CI_COMMIT_BRANCH = demisto/python3 ]]; then
    python3 -m demisto_sdk validate -g --post-commit --no-conf-json --allow-skipped --graph --skip-pack-dependencies --run-old-validate --skip-new-validate
else
    python3 -m demisto_sdk validate -g --post-commit --graph --skip-pack-dependencies --run-old-validate --skip-new-validate
fi