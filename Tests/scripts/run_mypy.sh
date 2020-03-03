#!/usr/bin/env bash

# Run mypy with a set of default parameters. 
# Will not return an error code even if mypy returns so. 
# This allows treating mypy as non-fatal.
#
# Arguments: python_version python_file
#
# Env: MYPY_NO_FAIL: if set will always return a 0 return code. Can be used in nightly to not fail the build.

if [[ $# -lt 2 ]]; then
    echo "Usage: $BASH_SOURCE <python_version> <python_files>"
    echo "For example: $BASH_SOURCE 2.7 Active_Directory_Query.py"
    exit 1
fi

PY_VERSION=$1
PY_FILE=$2
PY_BACKUP=""

if [[ "$PY_VERSION" = "2.7" ]]; then
    # typing import if not present
    grep -E '^(from typing import|import typing)' "$PY_FILE" > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        PY_BACKUP="$PY_FILE.mypy_bak"
        mv "$PY_FILE" "$PY_BACKUP" || exit 2
        sed  -e '1s/^/from typing import *;/' "$PY_BACKUP" > "$PY_FILE" || exit 3
    fi
fi

mypy --python-version $PY_VERSION --check-untyped-defs --ignore-missing-imports \
    --follow-imports=silent --show-column-numbers --show-error-codes --pretty \
    --allow-redefinition $PY_FILE 2>&1

res=$?

if [[ -n "$PY_BACKUP" ]]; then
    mv "$PY_BACKUP" "$PY_FILE" || exit 4
fi

if [[ -n "${MYPY_NO_FAIL}" ]]; then
    exit 0
fi

exit $res
