#!/usr/bin/env bash
set -e

echo "CIRCLE_BRANCH: $CIRCLE_BRANCH CHECK_BACKWARD: $CHECK_BACKWARD CI: $CI DEMISTO_README_VALIDATION: $DEMISTO_README_VALIDATION FEATURE_BRANCH: $FEATURE_BRANCH"

if [[ $CIRCLE_BRANCH = $FEATURE_BRANCH ]];
  then
    demisto-sdk validate -a --prev-ver origin/$FEATURE_BRANCH

elif [ "${CHECK_BACKWARD}" = "true" ] ;
  then
     demisto-sdk validate -g --post-commit  --prev-ver origin/$FEATURE_BRANCH

  else
     demisto-sdk validate -g --post-commit --no-backward-comp  --prev-ver origin/$FEATURE_BRANCH
fi
