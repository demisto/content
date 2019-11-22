#!/usr/bin/env bash

# Run bandit with a set of default parameters.
# Will not return an error code even if bandit returns so.
# This allows treating bandit as non-fatal.
#
# Arguments: python_files_directory
#
# Env: BANDIT_NO_FAIL: if set will always return a 0 return code. Can be used in nightly to not fail the build.

if [[ $# -lt 1 ]]; then
    echo "Usage: $BASH_SOURCE <python_files_directory>"
    echo "For example: $BASH_SOURCE ./Active_Directory_Query"
    exit 1
fi

DIRECTORY=$1

bandit -r $DIRECTORY 2>&1

res=$?

if [[ -n "${BANDIT_NO_FAIL}" ]]; then
    exit 0
fi

exit $res
