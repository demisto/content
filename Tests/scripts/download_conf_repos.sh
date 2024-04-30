#!/usr/bin/env bash
set +e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

clone_repository() {
  local host=$1
  local user=$2
  local token=$3
  local repo_name=$4
  local branch=$5
  local retry_count=$6
  local sleep_time=${7:-10}  # default sleep time is 10 seconds.
  local exit_code=0
  local i=1
  echo -e "${GREEN}Cloning ${repo_name} from ${host} branch:${branch} with ${retry_count} retries${NC}"
  if [ -z "${user}" ] && [ -z "${token}" ]; then
    user_info=""
  else
    user_info="${user}:${token}@"
    # If either user or token is not empty, then we need to add them to the url.
  fi
  for ((i=1; i <= retry_count; i++)); do
    git clone --depth=1 "https://${user_info}${host}/${repo_name}.git" --branch "${branch}" && exit_code=0 && break || exit_code=$?
    if [ ${i} -ne "${retry_count}" ]; then
      echo -e "${RED}Failed to clone ${repo_name} with branch:${branch}, exit code:${exit_code}, sleeping for ${sleep_time} seconds and trying again${NC}"
      sleep "${sleep_time}"
    else
      echo -e "${RED}Failed to clone ${repo_name} with branch:${branch}, exit code:${exit_code}, exhausted all ${retry_count} retries${NC}"
      break
    fi
  done
  return ${exit_code}
}

clone_repository_with_fallback_branch() {
  local host=$1
  local user=$2
  local token=$3
  local repo_name=$4
  local branch=$5
  local retry_count=$6
  local sleep_time=${7:-10}  # default sleep time is 10 seconds.
  local fallback_branch="${8:-master}"

  # Check if branch exists in the repository.
  echo -e "${GREEN}Checking if branch ${branch} exists in ${repo_name}${NC}"
  if [ -z "${user}" ] && [ -z "${token}" ]; then
    user_info=""
  else
    # If either user or token is not empty, then we need to add them to the url.
    user_info="${user}:${token}@"
  fi
  git ls-remote --exit-code --quiet --heads "https://${user_info}${host}/${repo_name}.git" "refs/heads/${branch}" 1>/dev/null 2>&1
  local branch_exists=$?

  if [ "${branch_exists}" -ne 0 ]; then
    echo -e "${RED}Branch ${branch} does not exist in ${repo_name}, defaulting to ${fallback_branch}${NC}"
    local exit_code=1
  else
    echo -e "${GREEN}Branch ${branch} exists in ${repo_name}, trying to clone${NC}"
    clone_repository "${host}" "${user}" "${token}" "${repo_name}" "${branch}" "${retry_count}" "${sleep_time}"
    local exit_code=$?
    if [ "${exit_code}" -ne 0 ]; then
      echo -e "${RED}Failed to clone ${repo_name} with branch:${branch}, exit code:${exit_code}${NC}"
    fi
  fi
  if [ "${exit_code}" -ne 0 ]; then
    # Trying to clone from fallback branch.
    echo -e "${RED}Trying to clone repository:${repo_name} with fallback branch ${fallback_branch}!${NC}"
    clone_repository "${host}" "${user}" "${token}" "${repo_name}" "${fallback_branch}" "${retry_count}" "${sleep_time}"
    local exit_code=$?
    if [ ${exit_code} -ne 0 ]; then
      echo -e "${RED}ERROR: Failed to clone ${repo_name} with fallback branch:${fallback_branch}, exit code:${exit_code}, exiting!${NC}"
      exit ${exit_code}
    else
      echo -e "${GREEN}Successfully cloned ${repo_name} with fallback branch:${fallback_branch}${NC}"
      return 0
    fi
  else
    echo -e "${GREEN}Successfully cloned ${repo_name} with branch:${branch}${NC}"
    return 0
  fi
}

TEST_UPLOAD_BRANCH_SUFFIX="-upload_test_branch-"
# Search for the branch name without the suffix of '-upload_test_branch-' in case it exists.
if [[ "${CI_COMMIT_BRANCH}" == *"${TEST_UPLOAD_BRANCH_SUFFIX}"* ]]; then
  # Using bash string pattern matching to search only the last occurrence of the suffix, that's why we use a single '%'.
  SEARCHED_BRANCH_NAME="${CI_COMMIT_BRANCH%"${TEST_UPLOAD_BRANCH_SUFFIX}"*}"
  echo "Found branch with suffix ${TEST_UPLOAD_BRANCH_SUFFIX} in branch name, using the branch ${SEARCHED_BRANCH_NAME} to clone content-test-conf and infra repositories"
else
  # default to CI_COMMIT_BRANCH when the suffix is not found.
  echo "Didn't find a branch with suffix ${TEST_UPLOAD_BRANCH_SUFFIX} in branch name, using the branch ${CI_COMMIT_BRANCH} to clone content-test-conf and infra repositories, with fallback to master"
  SEARCHED_BRANCH_NAME="${CI_COMMIT_BRANCH}"
fi
echo "Getting content-test-conf and infra repositories with branch:${SEARCHED_BRANCH_NAME}, with fallback to master"

SECRET_CONF_PATH="./conf_secret.json"
echo ${SECRET_CONF_PATH} > secret_conf_path

XSIAM_SERVERS_PATH="./xsiam_servers.json"
echo ${XSIAM_SERVERS_PATH} > xsiam_servers_path

XSOAR_NG_SERVERS_PATH="./xsoar_ng_servers.json"
echo ${XSOAR_NG_SERVERS_PATH} > xsoar_ng_servers_path

DEMISTO_LIC_PATH="./demisto.lic"
echo ${DEMISTO_LIC_PATH} > demisto_lic_path

DEMISTO_PACK_SIGNATURE_UTIL_PATH="./signDirectory"
echo ${DEMISTO_PACK_SIGNATURE_UTIL_PATH} > demisto_pack_sig_util_path

CI_SERVER_HOST=${CI_SERVER_HOST:-gitlab.xdr.pan.local} # disable-secrets-detection

clone_repository_with_fallback_branch "${CI_SERVER_HOST}" "gitlab-ci-token" "${CI_JOB_TOKEN}" "${CI_PROJECT_NAMESPACE}/content-test-conf" "${SEARCHED_BRANCH_NAME}" 3 10 "master"

cp ./content-test-conf/SecretActions/google_secret_manager_handler.py ./Tests/scripts
cp ./content-test-conf/SecretActions/SecretsBuild/add_secrets_file_to_build.py ./Tests/scripts
cp ./content-test-conf/SecretActions/SecretsBuild/merge_and_delete_dev_secrets.py ./Tests/scripts
cp -r ./content-test-conf/demisto.lic ${DEMISTO_LIC_PATH}
cp -r ./content-test-conf/signDirectory ${DEMISTO_PACK_SIGNATURE_UTIL_PATH}

echo "Cloning PrivatePacks"
cp -r ./content-test-conf/content/PrivatePacks/* ./Packs
echo "Cloned PrivatePacks"

if [[ "${NIGHTLY}" == "true" || "${EXTRACT_PRIVATE_TESTDATA}" == "true" ]]; then
    python ./Tests/scripts/extract_content_test_conf.py --content-path . --content-test-conf-path ./content-test-conf --missing-content-packs-test-conf "${ARTIFACTS_FOLDER_SERVER_TYPE}/missing_content_packs_test_conf.txt"
fi
rm -rf ./content-test-conf

clone_repository_with_fallback_branch "${CI_SERVER_HOST}" "gitlab-ci-token" "${CI_JOB_TOKEN}" "${CI_PROJECT_NAMESPACE}/infra" "${SEARCHED_BRANCH_NAME}" 3 10 "master"

cp -r ./infra/xsiam_servers.json $XSIAM_SERVERS_PATH
cp -r ./infra/xsoar_ng_servers.json $XSOAR_NG_SERVERS_PATH
cp -r ./infra/.gitlab/ci/name_mapping.json "${CI_PROJECT_DIR}/name_mapping.json"

mv ./infra/gcp ./gcp
rm -rf ./infra

set -e
echo "Successfully cloned content-test-conf and infra repositories"
