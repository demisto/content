#!/bin/sh

# Run pylint and pytest in the current directory. 
# Used by pkg_dev_test_tasks.py to run pylint and pytest 
# inside a docker. Since this is meant to run inside a minimal docker
# image it uses sh and not bash. Additionally, script tries to keep it 
# simply and not use any shell utilities that may be missing in a minimal docker.

# Env variables:
# PYLINT_FILES: file names to pass to pylint
# PYLINT_SKIP: if set will skip pylint
# PYTEST_SKIP: if set will skip pytest
# PYTEST_FAIL_NO_TESTS: if set will fail if no tests are defined
# CPU_NUM: number of CPUs to run tests on

pylint_return=0
if [ -z "${PYLINT_SKIP}" ]; then
    echo "======== Running pylint on files: ${PYLINT_FILES} ==========="
    python -m pylint -E -e string -d duplicate-string-formatting-argument -f parseable --generated-members=requests.packages.urllib3,requests.codes.ok \
        ${PYLINT_FILES}
    pylint_return=$?
    echo "Pylint completed with status code: $pylint_return"
fi

if [ -z "${PYTEST_SKIP}" ]; then
    echo "========= Running pytest ==============="
fi

if [ -z "${PYTEST_SKIP}" -a -z "${PYTEST_FAIL_NO_TESTS}" ]; then
    echo "collecting tests..."
    collect_res=$(python -m pytest --collect-only 2>&1)
    case "$collect_res" in
        *"errors"*)
            echo "========== Errors while collecting tests. Will execute tests anyway... ========="
            echo "$collect_res"
        ;;
        *"collected 0 items"*)
            echo "========= No tests found. Skipping. ========"
            echo "========= Output of: pytest --collect-only ========"
            echo "$collect_res"
            echo "========= End of Output ========"
            PYTEST_SKIP=1
        ;;
    esac
fi

pytest_return=0
if [ -z "${PYTEST_SKIP}" ]; then
    python -m pytest -v -n="${CPU_NUM}"
    pytest_return=$?
    echo "Pytest completed with status code: $pytest_return"
fi

if [ $pylint_return -ne 0 -o $pytest_return -ne 0 ]; then
    echo "=========== ERRORS FOUND ===========" 1>&2
    echo "pylint/pytest returned errors. pylint: [$pylint_return], pytest: [$pytest_return]" 1>&2
    echo "====================================" 1>&2
    exit 3 
fi
