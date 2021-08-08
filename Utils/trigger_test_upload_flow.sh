#!/usr/bin/env bash

# This script creates new branch with changes that will test the upload flow with given sdk and content branches.
# Note: This script creates new remote branch, please delete the branch once the pipeline finished.

# fail
# show fail message and quit
# :param $1: message
function fail() {
  echo "$1"
  git checkout "${content_branch_name}"
  git branch -D "${new_content_branch}" # delete local branch
  exit 1
}

# check_arguments
# Check if the given arguments are valid
function check_arguments {
  echo " Running - check_arguments"

  if [ -z "$content_branch_name" ]; then
    content_branch_name=$(git branch --show-current)
  fi

  if [ -z "$sdk_branch_name" ]; then
    sdk_branch_name="master"
  fi

  if [ -z "$gitlab_token" ] && [ -z "$circle_token" ]; then
    fail "At least one token [-gt, --gitlab-ci-token] or [-ct, --circle-ci-token] is required."
  fi

  if [ -n "$force" ] && [ -z "$packs" ]; then
    fail "You must provide a csv list of packs to force upload."
  fi
}

# copy_pack
# Copies a pack and changing the name in the files to the new name.
# :param $1: pack name
# :param $2: suffix for new pack name
# :param $3: possible names for renaming array
function create_new_pack {
  echo " Running - create_new_pack"

  local pack_name=$1
  local new_pack_suffix=$2
  shift
  shift
  local names_array=("$@")

  local new_pack_name="${pack_name}${new_pack_suffix}"
  local original_path=$(pwd)
  local pack_path="${CONTENT_PATH}/Packs/${pack_name}"
  local new_pack_path="${CONTENT_PATH}/Packs/${new_pack_name}"

  cp -R "${pack_path}" "${new_pack_path}" || fail
  cd "${new_pack_path}" || fail

 rename_files_and_folders "$pack_name" "$new_pack_name" "true"

  for original_name in names_array; do
    new_name="${original_name}${new_pack_suffix}"
    rename_files_and_folders $original_name $new_name
  done

  cd "${original_path}" || fail
  git add "$new_pack_path"

  git commit --untracked-files=no -am  "Created new pack - $new_pack_name"
}

# rename_files_and_folders
# Change all files and folder to the new name.
# :param $1: pack name.
# :param $2: new pack name.
# :param $3: change occurrence inside files
function rename_files_and_folders {

  if [ "$#" -ne 3 ] && [ "$#" -ne 2 ]; then
    fail " Illegal number of parameters "
  fi

  local pack_name=$1
  local new_pack_name=$2
  # Rename inside files
  if [ $3 != "false" ]; then
    find . -type f \( -name "*.py" -o -name "*.yml" -o -name "*.json" \) -exec sed -i "" "s/${pack_name}/${new_pack_name}/g" {} \;
  fi

  find . -type d -mindepth 1 -maxdepth 1 | \
  while read -r folder;
  do
    cd "$folder" || continue ;
    find . -type f -maxdepth 1 -name  "*${pack_name}*" -exec sh -c 'mv $1 "${1//$2/$3}"' sh {} "$pack_name" "$new_pack_name"  \;
    rename_files_and_folders "$pack_name" "$new_pack_name" "false";
    cd ../;
    if [ "$folder" != "${folder//$pack_name/$new_pack_name}" ]; then
      mv "$folder" "${folder//$pack_name/$new_pack_name}"
    fi
  done

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

  local source_pack=$1
  local pack_name=$2

  pack_path="${CONTENT_PATH}/Packs/${source_pack}/pack_metadata.json"

  sed -i "" "s/\"dependencies\": {/\"dependencies\": {\n\t\t\"${pack_name}\": {\n\t\t\t\"mandatory\": true,\n\t\t\t\"display_name\": \"${pack_name}\"\n\t\t},/g" "${pack_path}" || fail
  git commit --untracked-files=no -am  "Added dependency for - $pack_name to $source_pack pack"

}

# add_author_image
# Copies the author image from Base to desired pack
# :param $1: pack to add author image to
function add_author_image {
  echo " Running - add_author_image"

  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters "
  fi


  local pack_name=$1
  cp "${CONTENT_PATH}/Packs/Base/Author_image.png" "${CONTENT_PATH}/Packs/${pack_name}" || fail

  git add "${CONTENT_PATH}/Packs/${pack_name}/Author_image.png"
  git commit --untracked-files=no -am  "Added author image for - $pack_name"

}

# add_1_0_0_release_note
# add 1_0_0 release note for given pack by copying the last available release note
# :param $1: pack name
function add_1_0_0_release_note {
  echo " Running - add_1_0_0_release_note"

  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters "
  fi

  local pack_name=$1

  cd "${CONTENT_PATH}/Packs/${pack_name}/ReleaseNotes" || fail
  current_latest_note=$(ls -t | head -1)
  cp "${current_latest_note}" 1_0_0.md
  git add 1_0_0.md
  cd "${CONTENT_PATH}" || fail

  git commit --untracked-files=no -am  "Added release note 1_0_0.md to - $pack_name"

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

  local sdk_branch=$1
  local requirements_file_name=$2

  sed -i "" "s#demisto-sdk.*#git+https://github.com/demisto/demisto-sdk.git@${sdk_branch}#g" "${requirements_file_name}"

  git commit --untracked-files=no -am  "Change sdk in $requirements_file_name to be $sdk_branch"

}

# enhancement_release_notes
# update release notes
# :param $1: pack name
function enhancement_release_notes {
  echo " Running - enhancement_release_notes"

  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters "
  fi

  local pack_name=$1
  local pack_path="${CONTENT_PATH}/Packs/${pack_name}"
  demisto-sdk update-release-notes -i "${pack_path}" --force --text "Adding release notes to check the upload flow"

  git commit --untracked-files=no -am  "Added release note $pack_name"

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

  local source_pack_name=$1
  local dest_pack_name=$2

  local source_integration_path="${CONTENT_PATH}/Packs/${source_pack_name}/Integrations/${source_pack_name}/${source_pack_name}_image.png"
  local dest_integration_path="${CONTENT_PATH}/Packs/${dest_pack_name}/Integrations/${dest_pack_name}/${dest_pack_name}_image.png"
  cp "${source_integration_path}" "${dest_integration_path}"

  git commit --untracked-files=no -am  "Copied integration image from  $source_pack_name to $dest_pack_name"

}

# updating_old_release_notes
# adding text to the latest release note in pack
# :param $1: pack name
function updating_old_release_notes {
  echo " Running - updating_old_release_notes"

  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters "
  fi

  local pack_name=$1

  local path="${CONTENT_PATH}/Packs/${pack_name}/ReleaseNotes/"

  cd "${path}" || fail
  local current_latest_note=$(ls -t | head -1)
  printf "\n#### Upload flow\n - Test\n" >>"${current_latest_note}"
  cd "${CONTENT_PATH}" || return

  git commit --untracked-files=no -am "Updated release note - $current_latest_note"

}

# set_pack_hidden
# set pack as hidden
# :param $1: pack name
function set_pack_hidden {
  echo " Running - set_pack_hidden "

  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters"
  fi

  local pack_name=$1
  local pack_metadata="${CONTENT_PATH}/Packs/${pack_name}/pack_metadata.json"
  if grep "\"hidden\": true" "${pack_metadata}"; then
    # pack is already hidden
    return
  elif grep "\"hidden\": false" "${pack_metadata}"; then
    # pack set hidden to false
    sed -i "" "s/\"hidden\": false/\"hidden\": true/g" "${pack_metadata}"
  else
    # pack hidden key is missing
    sed -i "" "s/{/{\n\t\"hidden\": true,\n/g" "${pack_metadata}"
  fi

  git commit --untracked-files=no -am "Set pack - $current_latest_note to be hidden"

}

# update_readme
# Update readme file
# :param $1: pack name
function update_integration_readme {
  echo " Running - update_integration_readme"
  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters "
  fi

  local pack_name=$1

  local readme_file="${CONTENT_PATH}/Packs/${pack_name}/Integrations/${pack_name}/README.md"

  printf "\n#### Upload flow\n - Test\n" >>"${readme_file}"

  git commit --untracked-files=no -am "Updated integration - $pack_name README.md file"

}

# update_pack_ignore
# Update pack ignore file
# :param $1: pack name
function update_pack_ignore {
  echo " Running - update_pack_ignore"

  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters "
  fi

  local pack_name=$1

  local pack_ignore_file="${CONTENT_PATH}/Packs/${pack_name}/.pack-ignore"

  printf "\n[file:README.md]\nignore=RM104\n" >>"${pack_ignore_file}"

  git commit --untracked-files=no -am "Updated to pack ignore - $pack_name"


}

# add_pack_to_landing_page
# Add pack to the getting started landing page
# :param $1: pack name
function add_pack_to_landing_page {
  echo " Running - add_pack_to_landing_page"

  if [ "$#" -ne 1 ]; then
    fail " Illegal number of parameters "
  fi

  local pack_name=$1
  local json_file="${CONTENT_PATH}/Tests/Marketplace/landingPage_sections.json"

  sed -i "" "s/\"Getting Started\":\[/\"Getting Started\":\[\n\"${pack_name}\",\n/g" "${json_file}" || fail
  sed -i "" "s/\"Featured\":\[/\"Featured\":\[\n\"${pack_name}\",\n/g" "${json_file}" || fail

  git commit --untracked-files=no -am "Added $pack_name to landing page"

}

# trigger_circle_ci
# Trigger Circleci uploading packs workflow.
# :circle_token: The ci token for circle.
# :content_branch: Content branch to upload from.
# :bucket: The name of the bucket to upload the packs to.
# :force: Whether to trigger the force upload flow.
# :packs: CSV list of pack IDs.
# :slack_channel: A slack channel to send notifications to.
function trigger_circle_ci {
  trigger_build_url="https://circleci.com/api/v2/project/github/demisto/content/pipeline"

  post_data=$(cat <<-EOF
  {
    "branch": "${new_content_branch}",
    "parameters": {
      "gcs_market_bucket": "${bucket}",
      "bucket_upload": "${bucket_upload}",
      "force_pack_upload": "${force}",
      "packs_to_upload": "${packs}",
      "slack_channel": "${slack_channel}"
    }
  }
  EOF
  )
  curl \
  --header "Accept: application/json" \
  --header "Content-Type: application/json" \
  -k \
  --data "${post_data}" \
  --request POST ${trigger_build_url} \
  --user "$circle_token:"
}

# trigger_gitlab_ci
# Trigger GitLabci uploading packs workflow.
# :gitlab_token: The ci token for gitlab.
# :new_content_branch: Content branch to upload from.
# :bucket: The name of the bucket to upload the packs to.
# :packs: CSV list of pack IDs.
# :slack_channel: A slack channel to send notifications to.
function trigger_gitlab_ci {
  variables="variables[BUCKET_UPLOAD]=true"
  if [ -n "$_force" ]; then
    variables="variables[FORCE_BUCKET_UPLOAD]=true"
  fi

  source Utils/gitlab_triggers/trigger_build_url.sh

  curl --request POST \
    --form token="${gitlab_token}" \
    --form ref="${new_content_branch}" \
    --form "${variables}" \
    --form "variables[SLACK_CHANNEL]=${slack_channel}" \
    --form "variables[PACKS_TO_UPLOAD]=${packs}" \
    --form "variables[GCS_MARKET_BUCKET]=${bucket}" \
    --form "variables[IFRA_ENV_TYPE]=Bucket-Upload" \
    "$BUILD_TRIGGER_URL"

}


# Define default arguments
CONTENT_PATH="$HOME/dev/demisto/content"
base_pack_name="HelloWorld"
bucket="marketplace-dist-dev"
bucket_upload="true"
slack_channel="dmst-bucket-upload"

# parse inputs
if [ "$#" -lt "1" ]; then
  fail "
  [-sb, --sdk-branch]           The sdk branch name, if empty will run the version specified in the requirements file.
  [-cb, --content-branch]       The content branch name, if empty will run on master branch.
  [-gt, --gitlab-ci-token]      The ci token for gitlab, if provided wil run gitlab pipeline.
  [-ct, --circle-ci-token]      The ci token for circle, if provided wil run circle pipeline.
  [-p, --path]                  The path of content, default is ~/dev/demistio/content
  [-gb, --bucket]               The name of the bucket to upload the packs to. Default is marketplace-dist-dev.
  [-f, --force]                 Whether to trigger the force upload flow.
  [-p, --packs]                 CSV list of pack IDs. Mandatory when the --force flag is on.
  [-ch, --slack-channel]        A slack channel to send notifications to. Default is dmst-bucket-upload.
  "
fi

while [[ "$#" -gt 0 ]]; do
  case $1 in

  -sb|--sdk-branch) sdk_branch_name="$2"
    shift
    shift;;

  -cb|--content-branch) content_branch_name="$2"
    shift
    shift;;

  -gt|--gitlab-ci-token) gitlab_token="$2"
    shift
    shift;;

  -ct|--circle-ci-token) circle_token="$2"
    shift
    shift;;

  -gb|--bucket)
    if [ "$(echo "$2" | tr '[:upper:]' '[:lower:]')" == "marketplace-dist" ]; then
      echo "Only test buckets are allowed to use. Using marketplace-dist-dev instead."
    else
      bucket=$2
    fi
    shift
    shift;;

  -f|--force) force=true
    bucket_upload=""
    shift;;

  -p|--packs) packs="$2"
    shift
    shift;;

  -ch|--slack-channel) slack_channel="$2"
    shift
    shift;;

  *)    # unknown option.
    shift;;
  esac
done

# Setup
cd "${CONTENT_PATH}" || fail
check_arguments

new_content_branch="${sdk_branch_name}_${content_branch_name}_UploadFlow_test"
new_suffix="New"
new_pack_name="${base_pack_name}${new_suffix}"

git checkout "$content_branch_name" || fail
git pull || fail

existed_in_remote=$(git ls-remote --heads origin "${new_content_branch}")
existed_in_local=$(git branch --list "${new_content_branch}")

# Deletes the remote branch if exists
if [[ -z ${existed_in_remote} ]]; then
  git push origin --delete "${new_content_branch}"
fi
# Deletes the local branch if exists
if [[ -z ${existed_in_local} ]]; then
  git branch -D "${new_content_branch}" # delete local branch
fi

git checkout -b "${new_content_branch}" || fail
git commit --untracked-files=no -am "Initial commit"

# Changes
change_sdk_requirements "${sdk_branch_name}" "dev-requirements-py3.txt"

# New Pack
array=("Hello_World" "Hello World" "helloworld" "Sanity_Test")
create_new_pack "${base_pack_name}" "${new_suffix}" "${array[@]}"
add_dependency "${new_pack_name}" "Viper"
add_author_image "${new_pack_name}"
add_1_0_0_release_note "${new_pack_name}"

## Existing pack
enhancement_release_notes "Viper"
change_integration_image "PaloAltoNetworks_IoT" "Viper"
updating_old_release_notes "Base"
enhancement_release_notes "Base"
updating_old_release_notes "Viper"
add_1_0_0_release_note "Viper"
set_pack_hidden "Microsoft365Defender"
updating_old_release_notes "Viper" # Update release notes in content that are not in the bucket
update_integration_readme "Microsoft365Defender"
update_pack_ignore "Microsoft365Defender"

# External changes
add_pack_to_landing_page "${new_pack_name}"

git push origin "${new_content_branch}"

if [ -n "$circle_token" ]; then
  trigger_circle_ci
fi

if [ -n "$gitlab_token" ]; then
  trigger_gitlab_ci
fi
echo ""

git checkout "${content_branch_name}"
git branch -D "${new_content_branch}"

if [ -d "$new_pack_path" ]; then
  rm -r "$new_pack_path"
fi

echo ""
echo "Please run the following commands once the pipelines are finished"
echo "git push origin --delete ${new_content_branch}"
