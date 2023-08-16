#!/usr/bin/env bash
set +e

clone_repository() {
  local repo_name=$1
  local branch=$2
  local retry_count=$3
  local sleep_time=$4
  local exit_code=0
  local i=1
  echo "Cloning ${repo_name} from branch: ${branch} with ${retry_count} retries"
  for ((i=1; i <= retry_count; i++)); do
    git clone --depth=1 "https://gitlab-ci-token:${CI_JOB_TOKEN}@code.pan.run/xsoar/${repo_name}.git" --branch "${branch}" && exit_code=0 && break || exit_code=$?
    if [ ${i} -ne "${retry_count}" ]; then
      echo "Failed to clone ${repo_name} with branch:${branch}, exit code:${exit_code}, sleeping for ${sleep_time} seconds and trying again"
      sleep "${sleep_time}"
    else
      echo "Failed to clone ${repo_name} with branch:${branch}, exit code:${exit_code}, exhausted all ${retry_count} retries"
      break
    fi
  done
  return ${exit_code}
}

clone_repository_with_fallback_branch() {
  local repo_name=$1
  local branch=$2
  local fallback_branch="${3:-master}"
  local retry_count=$4
  local sleep_time=${5:-10}  # default sleep time is 10 seconds.

  clone_repository "${repo_name}" "${branch}" "${retry_count}" "${sleep_time}"
  local exit_code=$?
  if [ ${exit_code} -ne 0 ]; then
    # Failed to clone with branch, try again with fallback_branch.
    echo "Failed to clone ${repo_name} with branch ${branch}, exit code:${exit_code}, trying to clone with branch ${fallback_branch}!"
    clone_repository "${repo_name}" "${fallback_branch}" "${retry_count}" "${sleep_time}"
    local exit_code=$?
    if [ ${exit_code} -ne 0 ]; then
      echo "Failed to clone ${repo_name} with branch:${fallback_branch}, exit code:${exit_code}, exiting!"
      exit ${exit_code}
    else
      echo "Successfully cloned ${repo_name} with branch:${fallback_branch}"
      return 0
    fi
  else
    echo "Successfully cloned ${repo_name} with branch:${branch}"
    return 0
  fi
}

# Replace slashes '/' in the branch name with underscores '_'.
UNDERSCORE_BRANCH=${CI_COMMIT_BRANCH//\//_}

echo "Getting conf from branch ${UNDERSCORE_BRANCH} (With fallback to master)"

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

clone_repository_with_fallback_branch "content-test-conf" "${UNDERSCORE_BRANCH}" "master" 3

cp ./content-test-conf/secrets_build_scripts/google_secret_manager_handler.py ./Tests/scripts
cp ./content-test-conf/secrets_build_scripts/add_secrets_file_to_build.py ./Tests/scripts
cp ./content-test-conf/secrets_build_scripts/merge_and_delete_dev_secrets.py ./Tests/scripts
cp -r ./content-test-conf/demisto.lic ${DEMISTO_LIC_PATH}
cp -r ./content-test-conf/signDirectory ${DEMISTO_PACK_SIGNATURE_UTIL_PATH}

if [[ "${NIGHTLY}" == "true" || "${EXTRACT_PRIVATE_TESTDATA}" == "true" ]]; then
    python ./Tests/scripts/extract_content_test_conf.py --content-path . --content-test-conf-path ./content-test-conf
fi
rm -rf ./content-test-conf

clone_repository_with_fallback_branch "infra" "${UNDERSCORE_BRANCH}" "master" 3

cp -r ./infra/xsiam_servers.json $XSIAM_SERVERS_PATH
cp -r ./infra/xsoar_ng_servers.json $XSOAR_NG_SERVERS_PATH

mv ./infra/gcp ./gcp
rm -rf ./infra

set -e
echo "Successfully downloaded configuration files"
