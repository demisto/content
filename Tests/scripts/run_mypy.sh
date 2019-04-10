#!/usr/bin/env bash

# Run mypy with a set of default parameters. 
# Will not return an error code even if mypy returns so. 
# This allows treating mypy as non-fatal.
#
# Arguments: python_version python_files*
#
# Env: MYPY_NO_FAIL: if set will always return a 0 return code. Can be used in nightly to not fail the build.

if [[ $# -lt 2 ]]; then
    echo "Usage: $BASH_SOURCE <python_version> <python_files>+"
    echo "For example: $BASH_SOURCE 2.7 Active_Directory_Query.py"
    exit 1
fi

PY_VERSION=$1
shift

mypy --python-version $PY_VERSION --check-untyped-defs --ignore-missing-imports \
    --follow-imports=silent --custom-typing=typing  --show-column-numbers \
    --allow-redefinition $* 2>&1

res=$?

if [[ -n "${MYPY_NO_FAIL}" ]]; then
    exit 0
fi

exit $res
