#!/usr/bin/env bash
set -e

if [[ $CIRCLE_BRANCH = master ]];
  then
    demisto-sdk validate -a --prev-ver "4.1_freeze"

elif [ "${CHECK_BACKWARD}" = "true" ] ;
  then
     demisto-sdk validate -g --post-commit  --prev-ver "4.1_freeze"

  else
     demisto-sdk validate -g --post-commit --no-backward-comp  --prev-ver "4.1_freeze"
fi
