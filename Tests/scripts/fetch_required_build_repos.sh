#!/usr/bin/env bash
set +e

#######################################
# Check whether a branch exists in a remote git repository
# Arguments:
#   remote_url: The remote git repository URL
#   branch_name: The branch name to check
# Outputs:
#   0 if the branch exists in the remote git repository, 1 otherwise
#######################################
function branch_exists() {
    remote_url="$1"
    branch_name="$2"

    git ls-remote --heads "$remote_url" "$branch_name" --exit-code | grep "refs/heads/$branch_name" &> /dev/null
    return $?
}


#######################################
# Clone a branch from a remote git repository
# Arguments:
#   remote_url: The remote git repository URL
#   branch_name: The branch name to clone (if not found, 'master' will be used instead)
# Outputs:
#   None
#######################################
function clone_repository() {
    remote_url="$1"
    branch_name="$2"

    if branch_exists "$remote_url" "$branch_name"; then
        echo "Cloning '$branch_name' branch from '$remote_url'"
        git clone --depth=1 "$remote_url" --branch "$branch_name"
    else
        echo "'$branch_name' branch not found on '$remote_url', cloning 'master' instead"
        git clone --depth=1 "$remote_url"
    fi
}

# Replace slashes ('/') in the branch name, if exist, with underscores ('_')
BRANCH_NAME="${CI_COMMIT_BRANCH//\//_}"

# Set up paths  # TODO: Move this section to another, more appropriate file?
XSIAM_SERVERS_PATH="./xsiam_servers.json"
XSOAR_NG_SERVERS_PATH="./xsoar_ng_servers.json"
DEMISTO_LIC_PATH="./demisto.lic"
DEMISTO_PACK_SIGNATURE_UTIL_PATH="./signDirectory"
echo ${XSIAM_SERVERS_PATH} > "xsiam_servers_path"
echo ${XSOAR_NG_SERVERS_PATH} > "xsoar_ng_servers_path"
echo ${DEMISTO_LIC_PATH} > "demisto_lic_path"
echo ${DEMISTO_PACK_SIGNATURE_UTIL_PATH} > "demisto_pack_sig_util_path"

# Download build-required private repositories
echo "Fetching build-required private repositories using branch '$BRANCH_NAME'"

## Download 'gitlab-ci' from GitLab repository
clone_repository "https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/xsoar/gitlab-ci" "$BRANCH_NAME"
cp -r gitlab-ci/content .gitlab-internal  # If changing target path, make sure to replace it in other locations as well.
rm -rf gitlab-ci

## Download 'content-test-conf' from GitLab repository
clone_repository "https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/xsoar/content-test-conf" "$BRANCH_NAME"
cp -r ./content-test-conf/awsinstancetool ./Tests/scripts/awsinstancetool
cp -r ./content-test-conf/demisto.lic $DEMISTO_LIC_PATH
cp -r ./content-test-conf/signDirectory $DEMISTO_PACK_SIGNATURE_UTIL_PATH
cp -r ./content-test-conf/xsiam_servers.json $XSIAM_SERVERS_PATH
cp -r ./content-test-conf/xsoar_ng_servers.json $XSOAR_NG_SERVERS_PATH

if [[ "$NIGHTLY" == "true" || "$EXTRACT_PRIVATE_TESTDATA" == "true" ]]; then
    python ./Tests/scripts/extract_content_test_conf.py --content-path . --content-test-conf-path ./content-test-conf
fi

rm -rf ./content-test-conf

echo "Required repositories fetched successfully"
