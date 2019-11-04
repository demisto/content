#!/usr/bin/env bash

# Find all package directories and run the pkg_dev_test_tasks.py script. Will run only against
# packages which have changed comparing in git. Unless SKIP_GIT_COMPARE_FILTER evn var is set.
# Speciy any parameter to this script that will be passed to the pkg_dev_test_tasks.py as is

# Env vars:
# SKIP_GIT_COMPARE_FILTER: if set will not compare the git commit and run against all pkgs (nightly)

if [[ -z "${SKIP_GIT_COMPARE_FILTER}" ]]; then
    if [ -z "$CIRCLE_BRANCH" ]; then
        CIRCLE_BRANCH=$(git rev-parse --abbrev-ref HEAD)
        echo "Using following branch for comparison: ${CIRCLE_BRANCH}"
    fi
    # default compare against master
    DIFF_COMPARE=origin/master...${CIRCLE_BRANCH}
    if [ "$CIRCLE_BRANCH" == "master" ]; then
        # on master we use the range obtained from CIRCLE_COMPARE_URL
        # example of comapre url: https://github.com/demisto/content/compare/62f0bd03be73...1451bf0f3c2a
        DIFF_COMPARE=$(echo "$CIRCLE_COMPARE_URL" | sed 's:^.*/compare/::g')    
        if [ -z "${DIFF_COMPARE}" ]; then
            echo "Failed: extracting diff compare from CIRCLE_COMPARE_URL: ${CIRCLE_COMPARE_URL} using instead: HEAD~1...HEAD"
            DIFF_COMPARE="HEAD~1...HEAD"            
        fi                
    fi
fi

NON_CI_MSG=$(cat <<-END
But not running in CI. Note that CI Build will run all tests. 
If you want to run the same logic as is done in CI. Run this script with CI=true env.
END
)

if [[ -n "${DIFF_COMPARE}" ]] && [[ $(git diff --name-status $DIFF_COMPARE Scripts/CommonServerPython | grep -v CHANGELOG ) ]]; then
    if [[ -n "$CI" ]]; then
        echo "CommonServerPython modified. Going to ignore git changes and run all tests"
        DIFF_COMPARE=""
    else
        echo ""
        echo "CommonServerPython modified. $NON_CI_MSG"
    fi
fi

if [[ -n "${DIFF_COMPARE}" ]] && [[ $(git diff --name-status $DIFF_COMPARE Tests/scripts/dev_envs ) ]]; then
    if [[ -n "$CI" ]]; then
        echo "Files in Tests/scripts/dev_envs modified. Going to ignore git changes and run all tests"
        DIFF_COMPARE=""
    else
        echo ""
        echo "Files in Tests/scripts/dev_envs modified. $NON_CI_MSG"
    fi
fi

if [[ -n "${DIFF_COMPARE}" ]] && [[ $(git diff --name-status $DIFF_COMPARE Tests/scripts/pkg_dev_test_tasks.py ) ]]; then
    if [[ -n "$CI" ]]; then
        echo "Tests/scripts/pkg_dev_test_tasks.py modified. Going to ignore git changes and run all tests"
        DIFF_COMPARE=""
    else
        echo ""
        echo "Tests/scripts/pkg_dev_test_tasks.py modified. $NON_CI_MSG"
    fi
fi

CURRENT_DIR=`pwd`
SCRIPT_DIR=$(dirname ${BASH_SOURCE})
PKG_DEV_TASKS_DIR=${SCRIPT_DIR}
if [[ "${PKG_DEV_TASKS_DIR}" != /* ]]; then
    PKG_DEV_TASKS_DIR="${CURRENT_DIR}/${SCRIPT_DIR}"
fi

DIFF_COMPARE="${DIFF_COMPARE}" ${PKG_DEV_TASKS_DIR}/run_parallel_pkg_dev_tasks.py $*
