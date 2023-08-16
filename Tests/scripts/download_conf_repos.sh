#!/usr/bin/env bash
set +e

clone_repository() {
  local repo_name=$1
  local branch=$2
  local retry_count=$3
  local exit_code=0
  local i=1
  echo "clone ${repo_name} from branch: ${branch} with ${retry_count} retries"
  for ((i=1; i <= retry_count; i++)); do
    git clone --depth=1 "https://gitlab-ci-token:${CI_JOB_TOKEN}@${repo_name}.git" --branch "${branch}" && exit_code=0 && break || exit_code=$?
    if [ ${i} -ne "${retry_count}" ]; then
      echo "Failed to clone ${repo_name} with branch:${branch}, exit code:${exit_code}, sleeping for 10 seconds and trying again"
      sleep 10
    else
      echo "Failed to clone ${repo_name} with branch:${branch}, exit code:${exit_code}, exhausted all retries"
      break
    fi
  done
  if [ ${exit_code} -ne 0 ]; then
    branch="master"
    echo "Failed to clone ${repo_name} with branch:${branch}, will try to clone with branch:${branch}"
    for ((i=1; i <= retry_count; i++)); do
      git clone --depth=1 "https://gitlab-ci-token:${CI_JOB_TOKEN}@${repo_name}.git" --branch "${branch}" && exit_code=0 && break || exit_code=$?
      if [ ${i} -ne "${retry_count}" ]; then
        echo "Failed to clone ${repo_name} with branch:${branch}, exit code:${exit_code}, sleeping for 10 seconds and trying again"
        sleep 10
      else
        echo "Failed to clone ${repo_name} with branch:${branch}, exit code:${exit_code}, exhausted all retries"
        break
      fi
    done

    if [ ${exit_code} -ne 0 ]; then
      echo "Failed to clone ${repo_name} with branch:${branch}, exit code:${exit_code}, exiting!"
      exit ${exit_code}
    fi

  else
    echo "Successfully cloned ${repo_name} with branch:${branch}"
    exit 0
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

clone_repository "content-test-conf" "${UNDERSCORE_BRANCH}" 3

cp ./content-test-conf/secrets_build_scripts/google_secret_manager_handler.py ./Tests/scripts
cp ./content-test-conf/secrets_build_scripts/add_secrets_file_to_build.py ./Tests/scripts
cp ./content-test-conf/secrets_build_scripts/merge_and_delete_dev_secrets.py ./Tests/scripts
cp -r ./content-test-conf/demisto.lic ${DEMISTO_LIC_PATH}
cp -r ./content-test-conf/signDirectory ${DEMISTO_PACK_SIGNATURE_UTIL_PATH}

if [[ "${NIGHTLY}" == "true" || "${EXTRACT_PRIVATE_TESTDATA}" == "true" ]]; then
    python ./Tests/scripts/extract_content_test_conf.py --content-path . --content-test-conf-path ./content-test-conf
fi
rm -rf ./content-test-conf

clone_repository "infra" "${UNDERSCORE_BRANCH}" 3

cp -r ./infra/xsiam_servers.json $XSIAM_SERVERS_PATH
cp -r ./infra/xsoar_ng_servers.json $XSOAR_NG_SERVERS_PATH

mv ./infra/gcp ./gcp
rm -rf ./infra

set -e
echo "Successfully downloaded configuration files"
