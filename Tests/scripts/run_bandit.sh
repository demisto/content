#!/usr/bin/env bash

# Run bandit with a set of default parameters.
# Will not return an error code even if bandit returns so.
# This allows treating bandit as non-fatal.
#
# Arguments: python_file

if [[ $# -lt 1 ]]; then
    echo "Usage: $BASH_SOURCE <python_file>"
    echo "For example: $BASH_SOURCE Active_Directory_Query.py"
    exit 1
fi

PY_FILE=$1

bandit -r $PY_FILE 2>&1

exit 0