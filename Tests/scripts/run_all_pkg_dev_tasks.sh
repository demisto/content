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

SUCCESS_STATUS=""
FAIL_STATUS=""

for d in `find Integrations Scripts Beta_Integrations -type d -maxdepth 1 -mindepth 1`; do
    echo "**** `date`: Running dev tasks for: $d"
    ${PKG_DEV_TASKS_DIR}/pkg_dev_tasks_in_docker.py -d "$d" $*
    if [[ $? -ne 0 ]]; then
        FAIL_STATUS=`printf "${FAIL_STATUS}\n\t-$d"`        
    else
        SUCCESS_STATUS=`printf "${SUCCESS_STATUS}\n\t-$d"`
    fi
done
echo ""
if [[ -n "$SUCCESS_STATUS"  ]]; then
    echo "******* SUCCESS PKGS: *******" 
    echo "$SUCCESS_STATUS"
    echo ""
fi
if [[ -n "$FAIL_STATUS"  ]]; then
    echo "******* FAILED PKGS: *******"  1>&2
    echo "$FAIL_STATUS" 1>&2
    echo ""
    exit 1
fi
exit 0