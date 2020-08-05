#!/usr/bin/env bash
set -e

echo "CIRCLE_BRANCH: $CIRCLE_BRANCH CHECK_BACKWARD: $CHECK_BACKWARD CI: $CI DEMISTO_README_VALIDATION: $DEMISTO_README_VALIDATION"

if [ "${CHECK_BACKWARD}" = "true" ] ;
  then
     demisto-sdk validate -g --post-commit --prev-ver origin/new_freeze_4_1

  else
     demisto-sdk validate -g --post-commit --no-backward-comp --prev-ver origin/new_freeze_4_1
fi
