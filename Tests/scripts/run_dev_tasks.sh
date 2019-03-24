#!/bin/sh

# Run pylint and pytest in the current directory. 
# Used by pkg_dev_tasks_in_docker.py to run pylint and pytest 
# inside a docker.

# Env variables:
# PYLINT_FILES: file names to pass to pylint
# PYLINT_SKIP: if set will skip pylint
# PYTEST_SKIP: if set will skip pytest

pylint_return=0
if [ -z "${PYLINT_SKIP}" ]; then
    echo "======== Running pylint on files: ${PYLINT_FILES} ==========="
    python -m pylint -E ${PYLINT_FILES}
    pylint_return=$?
fi

pytest_return=0
if [[ -z "${PYTEST_SKIP}" ]]; then
    echo "========= Running pytest ==============="
    python -m pytest -v
    pytest_return=$?
fi

if [ $pylint_return -ne 0 -o $pytest_return -ne 0 ]; then
    echo "=========== ERRORS FOUND ===========" 1>&2
    echo "pylint/pytest returned errors. pylint: [$pylint_return], pytest: [$pytest_return]" 1>&2
    echo "====================================" 1>&2
    exit 3 
fi
