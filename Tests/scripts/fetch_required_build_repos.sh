#!/usr/bin/env bash
set +e

# Replace slashes ('/') in the branch name, if exist, with underscores ('_')
UNDERSCORE_BRANCH="${CI_COMMIT_BRANCH//\//_}"

# Set up paths
XSIAM_SERVERS_PATH="./xsiam_servers.json"
XSOAR_NG_SERVERS_PATH="./xsoar_ng_servers.json"
DEMISTO_LIC_PATH="./demisto.lic"
DEMISTO_PACK_SIGNATURE_UTIL_PATH="./signDirectory"

echo ${XSIAM_SERVERS_PATH} > "xsiam_servers_path"
echo ${XSOAR_NG_SERVERS_PATH} > "xsoar_ng_servers_path"
echo ${DEMISTO_LIC_PATH} > "demisto_lic_path"
echo ${DEMISTO_PACK_SIGNATURE_UTIL_PATH} > "demisto_pack_sig_util_path"

# Download build-required private repositories
echo "Fetching build-required private repositories using branch '$UNDERSCORE_BRANCH'"

## Download 'gitlab-ci' from GitLab repository
echo "Cloning gitlab-ci ('$UNDERSCORE_BRANCH' branch):"
git clone --depth=1 https://gitlab-ci-token:"${CI_JOB_TOKEN}"@code.pan.run/xsoar/gitlab-ci.git --branch "$UNDERSCORE_BRANCH"
return_code="$?"

if [ $return_code != "0" ]; then
    echo "'$UNDERSCORE_BRANCH' branch not found on 'gitlab-ci', using 'master' instead"
    git clone --depth=1 https://gitlab-ci-token:"${CI_JOB_TOKEN}"@code.pan.run/xsoar/gitlab-ci.git
fi

cp -r ./gitlab-ci/content ./.gitlab-private
rm -rf ./gitlab-ci

## Download 'content-test-conf' from GitLab repository
echo "Cloning content-test-conf ('$UNDERSCORE_BRANCH' branch):"
git clone --depth=1 https://gitlab-ci-token:"${CI_JOB_TOKEN}"@code.pan.run/xsoar/content-test-conf.git --branch "$UNDERSCORE_BRANCH"
return_code="$?"

if [ $return_code != "0" ]; then
    echo "'$UNDERSCORE_BRANCH' branch not found on 'content-test-conf', using 'master' instead"
    git clone --depth=1 https://gitlab-ci-token:"${CI_JOB_TOKEN}"@code.pan.run/xsoar/content-test-conf.git
fi

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
