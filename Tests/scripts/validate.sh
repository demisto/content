#!/usr/bin/env bash
set -e

echo "CIRCLE_BRANCH: $CIRCLE_BRANCH CHECK_BACKWARD: $CHECK_BACKWARD CI: $CI DEMISTO_README_VALIDATION: $DEMISTO_README_VALIDATION"

if [[ $CIRCLE_BRANCH = master ]] || [[ -n "${NIGHTLY}" ]];
  then
    demisto-sdk validate -a

elif [ "${CHECK_BACKWARD}" = "true" ] ;
  then
     demisto-sdk validate -g --post-commit --prev-ver "upstream/64cac0b349187b861c4c717951a634de52caba03"

  else
     demisto-sdk validate -g --post-commit --no-backward-comp
fi
