#!/usr/bin/env bash

# Find all package directories and run the pkg_dev_tasks_in_docker.py script. Will run only against
# packages which have changed comparing in git. Unless SKIP_GIT_COMPARE_FILTER evn var is set.
# Speciy any parameter to this script that will be passed to the pkg_dev_tasks_in_docker.py as is

# Env vars:
# SKIP_GIT_COMPARE_FILTER: if set will not compare the git commit and run against all pkgs (nightly)

if [[ -z "${SKIP_GIT_COMPARE_FILTER}" ]]; then
    if [ -z "$CIRCLE_BRANCH" ]; then
        CIRCLE_BRANCH=$(git rev-parse --abbrev-ref HEAD)
        echo "CIRCLE_BRANCH set to: ${CIRCLE_BRANCH}"
    fi
    # default compare against master
    DIFF_COMPARE=origin/master...${CIRCLE_BRANCH}
    if [ "$CIRCLE_BRANCH" == "master" ]; then
        # on master we use the range obtained from CIRCLE_COMPARE_URL
        # example of comapre url: https://github.com/demisto/content/compare/62f0bd03be73...1451bf0f3c2a
        DIFF_COMPARE=$(echo "$CIRCLE_COMPARE_URL" | sed 's:^.*/compare/::g')    
        if [ -z "${DIFF_COMPARE}" ]; then
            echo "Failed: extracting diff compare from CIRCLE_COMPARE_URL: ${CIRCLE_COMPARE_URL}"
            exit 1
        fi                
    fi
fi

CURRENT_DIR=`pwd`
SCRIPT_DIR=$(dirname ${BASH_SOURCE})
PKG_DEV_TASKS_DIR=${SCRIPT_DIR}
if [[ "${PKG_DEV_TASKS_DIR}" != /* ]]; then
    PKG_DEV_TASKS_DIR="${CURRENT_DIR}/${SCRIPT_DIR}"
fi

ERRORS_FOUND=false

SUCCESS_STATUS=""
FAIL_STATUS=""

for d in `find Integrations Scripts Beta_Integrations -maxdepth 1 -mindepth 1 -type d -print | sort`; do
    if [[ -z "${DIFF_COMPARE}" ]] || [[ $(git diff $DIFF_COMPARE -- ${d}) ]]; then
        echo "**** `date`: Running dev tasks for: $d"
        ${PKG_DEV_TASKS_DIR}/pkg_dev_tasks_in_docker.py -d "$d" $*
        if [[ $? -ne 0 ]]; then
            FAIL_STATUS=`printf "${FAIL_STATUS}\n\t-$d"`        
        else
            SUCCESS_STATUS=`printf "${SUCCESS_STATUS}\n\t-$d"`
        fi
    fi
done
echo ""
if [[ -n "$SUCCESS_STATUS"  ]]; then
    echo "******* SUCCESS PKGS: *******" 
    echo "$SUCCESS_STATUS"
    echo ""
fi
if [[ -n "${FAIL_STATUS}"  ]]; then
    echo -e "******* FAILED PKGS: *******"  1>&2
    echo -e "\x1B[31m${FAIL_STATUS}\x1B[0m" 1>&2    
    echo ""
    exit 1
fi

if [ -z "$SUCCESS_STATUS" -a -z "$FAIL_STATUS" ]; then 
    echo "******* No changed pkgs found *******"
fi

exit 0