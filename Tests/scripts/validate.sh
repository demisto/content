#!/usr/bin/env bash
set -e

echo "CI_COMMIT_BRANCH: $CI_COMMIT_BRANCH CI: $CI DEMISTO_README_VALIDATION: $DEMISTO_README_VALIDATION"

if [[ $CI_COMMIT_BRANCH = master ]] || [[ -n "${NIGHTLY}" ]] || [[ -n "${BUCKET_UPLOAD}" ]] || [[ -n "${DEMISTO_SDK_NIGHTLY}" ]]; then
    demisto-sdk validate -a --post-commit --id-set --id-set-path "$ARTIFACTS_FOLDER/unified_id_set.json"
elif [[ $CI_COMMIT_BRANCH =~ pull/[0-9]+ ]]; then
    demisto-sdk validate -g --post-commit --id-set --id-set-path "$ARTIFACTS_FOLDER/id_set.json"
else
    demisto-sdk validate -g --post-commit --id-set --id-set-path "$ARTIFACTS_FOLDER/unified_id_set.json"
fi

if [[ -n "${SDK_LINT_FILES_CHANGED}" ]]; then
    echo "lint files changed running lint"
    
    # python file (CommonServerPython lint is runnit over python 3 and 2)
    demisto-sdk lint -i ./Packs/Base/Scripts/CommonServerPython

    # ps file
    demisto-sdk lint -i ./Packs/Base/Scripts/CommonServerPowerShell
fi
