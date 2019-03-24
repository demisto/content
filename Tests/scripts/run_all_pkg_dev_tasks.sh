#!/usr/bin/env bash

# Find all package directories and run the pkg_dev_tasks_in_docker.py script
# Speciy any parameter to this script that will be passed to the pkg_dev_tasks_in_docker.py as is

CURRENT_DIR=`pwd`
SCRIPT_DIR=$(dirname ${BASH_SOURCE})
PKG_DEV_TASKS_DIR=${SCRIPT_DIR}
if [[ "${PKG_DEV_TASKS_DIR}" != /* ]]; then
    PKG_DEV_TASKS_DIR="${CURRENT_DIR}/${SCRIPT_DIR}"
fi

ERRORS_FOUND=false

for d in `find Scripts Integrations Beta_Integrations -type d -maxdepth 1 -mindepth 1`; do
    echo "**** `date`: Running dev tasks for: $d"
    ${PKG_DEV_TASKS_DIR}/pkg_dev_tasks_in_docker.py -d "$d" $*
    if [[ $? -ne 0 ]]; then
        ERRORS_FOUND=true
        echo "**** FAILED: $d"
    else
        echo "**** SUCCESS: $d"
    fi
done

if [[ "$ERRORS_FOUND" == "true" ]]; then
    echo "========== ERRORS FOUND WHILE RUNNING ALL PKG TASKS ===========" 1>&2
    exit 1
fi
exit 0