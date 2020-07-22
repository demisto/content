#!/usr/bin/env bash
set -e

if [[ $CIRCLE_BRANCH = master ]];
  then
    demisto-sdk validate -a

elif [ "${CHECK_BACKWARD}" = "true" ] ;
  then
     demisto-sdk validate -g --post-commit

  else
     demisto-sdk validate -g --post-commit --no-backward-comp
fi
