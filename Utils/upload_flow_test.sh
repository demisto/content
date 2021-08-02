#!/usr/bin/env bash

# fail
# show fail message and quit
# :param $1: message
function fail() {
  echo "$1"
  git checkout Upload_flow_test_script # todo change to master 
  git branch -D "${content_branch}" # delete local branch
  exit 1
}

# check_arguments
# Check if the given argumentes are valid
function check_arguments {
  echo " Running - check_arguments"

  if [ -z "$sdk_branch_name" ]; then
    fail "You must provide sdk branch name."
  fi

  if [ -z "$gitlab_token" ] && [ -z "$circle_token" ]; then
    fail "At least one token [-gt, --gitlab-ci-token] or [-ct, --circle-ci-token] is required."
  fi

}

# copy_pack
# Copies a pack and changing the name in the files to the new name.
# :param $1: pack name
# :param $2: copied pack name
function create_new_pack {
  echo " Running - create_new_pack"

  if [ "$#" -ne 2 ]; then
    fail " Illegal number of parameters "
  fi

  pack_name=$1
  new_pack_name=$2

  original_path=$(pwd)
  pack_path="${CONTENT_PATH}/Packs/${pack_name}"
  new_pack_path="${CONTENT_PATH}/Packs/${new_pack_name}"

  cd "${CONTENT_PATH}" || fail
  cp -R "${pack_path}" "${new_pack_path}" || fail
  cd "${new_pack_path}" || fail
  find . -type f -name "*.json|*.yml" -exec sed -i "" "s/${pack_name}/${new_pack_name}/g" {} \;

  cd "${original_path}" || fail
}

# add_dependency
# Edits pack_metadata and adding Dependency to desired pack
# :param $1: pack to add dependencies to
# :param $2: pack to be depended on
function add_dependency {
  echo " Running - add_dependency"

  if [ "$#" -ne 2 ]; then
    fail " Illegal number of parameters "
  fi

  source_pack=$1
  pack_name=$2

  pack_path="${CONTENT_PATH}/Packs/${source_pack}/pack_metadata.json"

  sed -i "" "s/\"dependencies\": {/\"dependencies\": {\n\t${pack_name}: {\n\t\t\"mandatory\": true,\n\t\t\"display_name\": ${pack_name}\n\t},/g" "${pack_path}" || fail

}
# add_author_image
# Copies the author image from Base to desired pack
# :param $1: pack to add author image to
function add_author_image {
  echo " Running - add_author_image"

  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters "
  fi

  pack_name=$1
  echo "Adding Author image to ${pack_name}"
  cp "${CONTENT_PATH}/Packs/Base/Author_image.png" "${CONTENT_PATH}/Packs/${pack_name}" || fail
}


# add_1_0_0_release_note
# add 1_0_0 release note for given pack by copying the last available release note
# :param $1: pack name
function add_1_0_0_release_note {
  echo " Running - add_1_0_0_release_note"

  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters "
  fi

  pack_name=$1

  cd "${CONTENT_PATH}/Packs/${pack_name}/ReleaseNotes" || fail
  current_latest_note=$(ls -t | head -1)
  cp "${current_latest_note}" 1_0_0.md
  cd "${CONTENT_PATH}" || fail
}

# change_sdk_requirements
# changing the requirements file inorder to install the desired sdk branch
# :param $1: sdk branch name
# :param $2: requirements file
function change_sdk_requirements {
  echo " Running - change_sdk_requirements"

  if [ "$#" -ne 2 ]; then
    fail " Illegal number of parameters "
  fi

  sdk_branch=$1
  requirements_file_name=$2

  sed -i "" "s#demisto-sdk.*#git+https://github.com/demisto/demisto-sdk.git@${sdk_branch}#g" "${requirements_file_name}"
}

# enhancement_release_notes
# update release notes
# :param $1: pack name
function enhancement_release_notes {
  echo " Running - enhancement_release_notes"

  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters "
  fi

  pack_name=$1
  pack_path="${CONTENT_PATH}/Packs/${pack_name}"
  demisto-sdk update-release-notes -i "${pack_path}" --force --text "Adding release notes to check the upload flow" # Waiting for sdk fix
}


# change_integration_image
# Copies integration image from one to another
# :param $1: source pack name
# :param $2: dest pack name
function change_integration_image {
  echo " Running - change_integration_image"

  if [ "$#" -ne 2 ]; then
    fail " Illegal number of parameters "
  fi

  source_pack_name=$1
  dest_pack_name=$2

  source_integration_path="${CONTENT_PATH}/Packs/${source_pack_name}/Integrations/${source_pack_name}/${source_pack_name}_image.png"
  dest_integration_path="${CONTENT_PATH}/Packs/${dest_pack_name}/Integrations/${dest_pack_name}/${dest_pack_name}_image.png"
  cp "${source_integration_path}" "${dest_integration_path}"
}

# updating_old_release_notes
# adding text to the latest release note in pack
# :param $1: pack name
function updating_old_release_notes {
  echo " Running - updating_old_release_notes"

  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters "
  fi

  pack_name=$1

  path="${CONTENT_PATH}/Packs/${pack_name}/ReleaseNotes/"

  cd "${path}" || fail
  current_latest_note=$(ls -t | head -1)
  printf "\n#### Upload flow\n - Test\n" >>"${current_latest_note}"
  cd "${CONTENT_PATH}" || return
}

# set_pack_hidden
# set pack as hidden
# :param $1: pack name
function set_pack_hidden {
  echo " Running - set_pack_hidden "

  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters"
  fi

  pack_name=$1
  pack_metadata="${CONTENT_PATH}/Packs/${pack_name}/pack_metadata.json"
  if grep "\"hidden\": true"; then
    # pack is already hidden
    return
  elif grep "\"hidden\": false"; then
    # pack set hidden to false
    sed -i "" "s/\"hidden\": false/\"hidden\": true/g" ./Packs/Microsoft365Defender/pack_metadata.json
  else
    # pack hidden key is missing
    sed -i "" "s/{/{\n\"hidden\": true,\n/g" ./Packs/Microsoft365Defender/pack_metadata.json
  fi
}

# update_readme
# Update readme file
# :param $1: pack name
function update_integration_readme {
  echo " Running - update_integration_readme"
  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters "
  fi

  pack_name=$1

  readme_file="${CONTENT_PATH}/Packs/${pack_name}/Integration/${pack_name}/README.md"

  printf "\n#### Upload flow\n - Test\n" >>"${readme_file}"

}

# update_pack_ignore
# Update pack ignore file
# :param $1: pack name
function update_pack_ignore {
  echo " Running - update_pack_ignore"

  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters "
  fi

  pack_name=$1

  pack_ignore_file="${CONTENT_PATH}/Packs/${pack_name}/.pack-ignore"

  printf "\n[file:README.md]\nignore=RM104\n" >>"${pack_ignore_file}"

}

# add_pack_to_landing_page
# Add pack to the getting started landing page
# :param $1: pack name
function add_pack_to_landing_page {
  echo " Running - add_pack_to_landing_page"

  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters "
  fi

  pack_name=$1

  json_file="${CONTENT_PATH}/Tests/Marketplace/landingPage_sections.json"
  sed -i "" "s/\"Getting Started\":[/\"Getting Started\":[\n\"${pack_name}\",\n/g" "${json_file}"

}


## add_features
## Add features to pack metadata
## :param $1: pack name
#function add_features {
#  echo " Running - add_features"
#
#  if [ "$#" -ne 1 ]; then
#    fail " Illegal number of parameters "
#  fi
#
#  pack_name=$1
#  pack_metadata="${CONTENT_PATH}/Packs/${pack_name}/pack_metadata.json"
#
#  sed -i "" "s/\"Getting Started\":[/\"Getting Started\":[\n\"${pack_name}\",\n/g" "${pack_metadata}"
#
#}
function trigger_circle_ci() {
  cd "${CONTENT_PATH}" || fail
  cat ~/trigger_test_flow >/Users/iyeshaya/dev/demisto/content/Utils/trigger_test_upload_flow.sh
  ./Utils/trigger_test_upload_flow.sh -ct "${circle_token}" -b "${content_branch}" -db "true"
}
function trigger_gitlab_ci() {
  cd "${CONTENT_PATH}" || return
  ./Utils/trigger_test_upload_flow.sh -ct "${gitlab_token}" -g true -b "${content_branch}"
}




# parse inputs
if [ "$#" -lt "1" ]; then
  fail " Usage:
  [-b, --branch]                The sdk branch name.
  [-gt, --gitlab-ci-token]      The ci token for gitlab, if provided wil run gitlab pipeline.
  [-ct, --circle-ci-token]      The ci token for circle, if provided wil run circle pipeline.
  [-p, --path]                  The path of content, default is ~/dev/demistio/content
  "
fi

while [[ "$#" -gt 0 ]]; do
  case $1 in

  -b|--branch) sdk_branch_name="$2"
    shift
    shift;;

  -gt|--gitlab-ci-token) gitlab_token="$2"
    shift
    shift;;

  -ct|--circle-ci-token) circle_token="$2"
    shift
    shift;;
  *)    # unknown option.
    shift;;
  esac
done

check_arguments

CONTENT_PATH="$HOME/dev/demisto/content"

content_branch="${sdk_branch_name}_uploadFlow_test"
base_pack_name="HelloWorld"
new_pack_name="${base_pack_name}New"

cd "${CONTENT_PATH}" || fail



git checkout master
git pull
git checkout -b "${content_branch}" || fail

# Setup
change_sdk_requirements "${sdk_branch_name}" "dev-requirements-py3.txt"

# New Pack
create_new_pack "${base_pack_name}" "${new_pack_name}"
add_dependency "${new_pack_name}" "${base_pack_name}"
add_author_image "${new_pack_name}"
add_1_0_0_release_note "${new_pack_name}"

# Existing pack
enhancement_release_notes "${base_pack_name}"
change_integration_image "PaloAltoNetworks_IoT" "${base_pack_name}"
updating_old_release_notes "Base"
enhancement_release_notes "Base"
updating_old_release_notes "${base_pack_name}"
add_1_0_0_release_note "${base_pack_name}"
set_pack_hidden "Microsoft365Defender"
updating_old_release_notes "${new_pack_name}" # Update release notes in content that are not in the bucket
update_integration_readme "Microsoft365Defender"
update_pack_ignore "Microsoft365Defender"
# todo  Add feature to the pack metadata

# External changes
add_pack_to_landing_page "${new_pack_name}"
# todo  Change sdk to sdk master

#cat ~/config_temp > /Users/iyeshaya/dev/demisto/content/.circleci/config.yml # todo remove

#git commit -am "Adding changes"
#git push origin "${sdk_branch_name}_uploadFlow_test"
#
#if [ -n "$circle_token" ]; then
#  trigger_circle_ci
#fi
#
#if [ -n "$gitlab_token" ]; then
#  trigger_gitlab_ci
#fi

#git checkout master
