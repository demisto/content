#!/usr/bin/env bash

# 
# Script will check all modified yml files and verify that the docker image used is from the demisto org
#
# Will always compare against master. If the current branch is master or release branches (19.* or 20.*) will do nothing.
#

if  [[ "$CIRCLE_BRANCH" == "master" ]] || [[ "$CIRCLE_BRANCH" == 19.* ]] || [[ "$CIRCLE_BRANCH" == 20.* ]]; then
    echo "Running on branch: $CIRCLE_BRANCH. Skipping docker image validation."
    exit 0
fi

INVALID=""
for yml_file in `git diff --diff-filter=d --name-only origin/master...$CIRCLE_BRANCH | grep -E '.yml$'`; do
    docker=`grep "dockerimage:" "$yml_file" | awk '{print $2}'`
    if [[ -n "$docker" ]] && [[ "$docker" != "''" ]] && [[ "$docker" != demisto/* ]]; then
        INVALID=`printf "${INVALID} \nInvalid docker image in $yml_file: \x1B[31m$docker\x1B[0m"`
    fi
done

if [[ -n "$INVALID" ]]; then
    echo -e "${INVALID}"
    echo ""
    echo ""
    echo "Docker images must be part of the demisto org in docker hub. See: https://hub.docker.com/u/demisto for a list of images. Or contribute a new image at: https://github.com/demisto/dockerfiles"  # disable-secrets-detection
    echo ""
    exit 1
fi
exit 0
