#!/usr/bin/env bash
set -e

if [[ $CIRCLE_BRANCH = master ]];
  then
    demisto-sdk validate -a --prev-ver "freeze_4_1"

elif [ "${CHECK_BACKWARD}" = "true" ] ;
  then
     demisto-sdk validate -g --post-commit --prev-ver "freeze_4_1"
  else
     demisto-sdk validate -g --post-commit --no-backward-comp --prev-ver "freeze_4_1"
fi
