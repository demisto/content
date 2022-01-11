#!/usr/bin/env bash

# This script creates new branch with changes that will test the upload flow with given sdk and content branches.
# Note: This script creates new remote branch, please delete the branch once the pipeline finished.

##############################################################
##                   Functions - start                      ##
##############################################################

# fail
# show fail message and quit
# :param $1: message
# :param $2: Skip deleting branch
function fail {
  echo "$1"
  if [ -z $2 ]; then
    git checkout "${content_branch_name}"
    git branch -D "${new_content_branch}" # delete local branch
  fi
  exit 1
}

# check_arguments
# Check if the given arguments are valid
function check_arguments {
  echo " Running - check_arguments"

  if [ -z "$content_branch_name" ]; then
    content_branch_name=$(git branch --show-current)
  fi

  if [ -z "$gitlab_token" ] && [ -z "$circle_token" ]; then
    fail "At least one token [-gt, --gitlab-ci-token] or [-ct, --circle-ci-token] is required." "skip"
  fi

  if [ -n "$force" ] && [ -z "$packs" ]; then
    fail "You must provide a csv list of packs to force upload." "skip"
  fi

  if [ -z "$production" ] && [ "$(echo "$bucket" | tr '[:upper:]' '[:lower:]')" == "marketplace-dist" ]; then
    fail "Only test buckets are allowed to use. Using marketplace-dist-dev instead."
  fi

  if [ -n "$production" ]; then
    echo "Uploading to production bucket."
  fi
}

# create_new_pack
# Copies a pack and changing the name in the files to the new name.
# :param $1: pack name
# :param $2: new pack name
# :param $3: possible names for renaming array
# :return: New pack's name.
function create_new_pack {
  echo " Running - create_new_pack"

  local pack_name=$1
  local new_pack_suffix=$2
  shift
  shift
  local names_array=("$@")

  local original_path=$(pwd)
  local new_pack_name="${pack_name}${new_pack_suffix}"
  local pack_path="${CONTENT_PATH}/Packs/${pack_name}"
  local new_pack_path="${CONTENT_PATH}/Packs/${new_pack_name}"

  rm -rf "${new_pack_path}"
  cp -R "${pack_path}" "${new_pack_path}" || fail
  cd "${new_pack_path}" || fail

 rename_files_and_folders "$pack_name" "$new_pack_name"

  for original_name in "${names_array[@]}"; do
    new_name="${original_name}${new_pack_suffix}"
    rename_files_and_folders "$original_name" "$new_name"
  done

  update_conf_json_file $pack_name $new_pack_name
  update_pack_version "${new_pack_path}/pack_metadata.json" "1.0.0"

  cd "${original_path}" || fail
  git add "$new_pack_path"

  git commit --untracked-files=no -am  "Created new pack - $new_pack_name" --no-verify

}

# update_pack_version
# update the version on the pack metadata
# :param $1: pack metadta path
# :param $2: new version
# :return:
function update_pack_version {
  local pack_metadata=$1
  local new_version=$2

  python - << EOF
import json

with open('${pack_metadata}') as f:
  metadata = json.load(f)
  metadata['currentVersion'] = "${new_version}"

with open('${pack_metadata}','w') as f:
  json.dump(metadata,f)
EOF

}

# update_conf_json_file
# Add new playbooks to the conf.json file
# :param $1: original name
# :param $2: new name
# :return:
function update_conf_json_file {
  local pack_name=$1
  local new_pack_name=$2

  python - << EOF
import json

def copy_and_replace_dict(dictionary,original_name, new_name):
    return {k: v.replace(original_name, new_name) if isinstance(v,str) else v for k,v in dictionary.items()}

with open('${CONTENT_PATH}/Tests/conf.json') as f:
  conf_file = json.load(f)
  relevant_tests = [copy_and_replace_dict(d,"$pack_name","$new_pack_name") for d in conf_file.get('tests') if d.get('integrations') == "$pack_name" and "$pack_name" in d.get('playbookID','')]
  conf_file['tests'] += relevant_tests

with open('${CONTENT_PATH}/Tests/conf.json', 'w') as f:
  json.dump(conf_file,f)
EOF

}

# rename_files_and_folders
# Change all files and folder to the new name.
# :param $1: pack name.
# :param $2: new pack name.
# :param $3: skip change occurrence inside files flag
function rename_files_and_folders {

  if [ "$#" -ne 3 ] && [ "$#" -ne 2 ]; then
    fail " Illegal number of parameters "
  fi

  local pack_name=$1
  local new_pack_name=$2
  # Rename inside files
  if [ -z $3 ]; then
    find . -type f \( -name "*.py" -o -name "*.yml" -o -name "*.json" \) -exec sed -i "" "s/${pack_name}/${new_pack_name}/g" {} \;
  fi

  find . -type d -mindepth 1 -maxdepth 1 | \
  while read -r folder;
  do
    cd "$folder" || continue ;
    find . -type f -maxdepth 1 -name  "*${pack_name}*" -exec sh -c 'mv $1 "${1//$2/$3}"' sh {} "$pack_name" "$new_pack_name"  \;
    rename_files_and_folders "$pack_name" "$new_pack_name" "true";
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
  git commit --untracked-files=no -am  "Added dependency for - $pack_name to $source_pack pack" --no-verify

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
  git commit --untracked-files=no -am  "Added author image for - $pack_name" --no-verify

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

  git commit --untracked-files=no -am  "Added release note 1_0_0.md to - $pack_name" --no-verify

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

  git commit --untracked-files=no -am  "Change sdk in $requirements_file_name to be $sdk_branch" --no-verify

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

  git commit --untracked-files=no -am  "Added release note $pack_name" --no-verify

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

  git commit --untracked-files=no -am  "Copied integration image from  $source_pack_name to $dest_pack_name" --no-verify

}

# updating_old_release_notes
# adding text to the second latest release note in pack
# :param $1: pack name
# :param $2: release note number
function updating_old_release_notes {
  echo " Running - updating_old_release_notes"

  if [ "$#" -ne 2 ]; then
    fail " Illegal number of parameters "
  fi

  local pack_name=$1

  local path="${CONTENT_PATH}/Packs/${pack_name}/ReleaseNotes/"

  cd "${path}" || fail
  printf "\n#### Upload flow\n - Test\n" >>"${2}.md"
  cd "${CONTENT_PATH}" || return

  git commit --untracked-files=no -am "Updated release note - ${2}" --no-verify

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

  git commit --untracked-files=no -am "Set pack - $current_latest_note to be hidden" --no-verify

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

  git commit --untracked-files=no -am "Updated integration - $pack_name README.md file" --no-verify

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

  printf "\n[file:1_0_1.md]\nignore=RM104\n" >>"${pack_ignore_file}"

  git commit --untracked-files=no -am "Updated to pack ignore - $pack_name" --no-verify


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

  git commit --untracked-files=no -am "Added $pack_name to landing page" --no-verify

}

# trigger_circle_ci
# Trigger Circleci uploading packs workflow.
# :param 1: content branch
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
    "branch": "$1",
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
# :param 1: content branch
# :gitlab_token: The ci token for gitlab.
# :new_content_branch: Content branch to upload from.
# :bucket: The name of the bucket to upload the packs to.
# :packs: CSV list of pack IDs.
# :slack_channel: A slack channel to send notifications to.
function trigger_gitlab_ci {
  echo "pushing the current branch to gitlab and sleeping for 60 seconds"
  git push https://code.pan.run/xsoar/content.git "${new_content_branch}" # disable-secrets-detection
  sleep 60
  trigger_build_url="https://code.pan.run/api/v4/projects/2596/trigger/pipeline"  # disable-secrets-detection

  variables="variables[BUCKET_UPLOAD]=true"
  if [ -n "$_force" ]; then
    variables="variables[FORCE_BUCKET_UPLOAD]=true"
  fi

  curl --request POST \
    --form token="${gitlab_token}" \
    --form ="$1" \
    --form "${variables}" \
    --form "variables[SLACK_CHANNEL]=${slack_channel}" \
    --form "variables[PACKS_TO_UPLOAD]=${packs}" \
    --form "variables[GCS_MARKET_BUCKET]=${bucket}" \
    --form "variables[IFRA_ENV_TYPE]=Bucket-Upload" \
    "$trigger_build_url"

}

##############################################################
##                   Functions - end                        ##
##############################################################

# Define default arguments
CONTENT_PATH="$HOME/dev/demisto/content"
bucket="marketplace-dist-dev"
bucket_upload="true"
slack_channel="dmst-bucket-upload"
base_pack_name="HelloWorld"
new_pack_suffix="New"
new_pack_name="${base_pack_name}${new_pack_suffix}"
pack_names_and_ids=("Hello_World" "Hello World" "helloworld" "Sanity_Test") # All the possible ids inside Hello World pack.

# parse inputs
if [ "$#" -lt "1" ]; then
  fail "
  [-sb, --sdk-branch]           The sdk branch name, if empty will run the version specified in the requirements file.
  [-cb, --content-branch]       The content branch name, if empty will run on master branch.
  [-gt, --gitlab-ci-token]      The ci token for gitlab, if provided will run gitlab pipeline.
  [-ct, --circle-ci-token]      The ci token for circle, if provided will run circle pipeline.
  [-gb, --bucket]               The name of the bucket to upload the packs to. Default is marketplace-dist-dev.
  [-f, --force]                 Whether to trigger the force upload flow.
  [-p, --packs]                 CSV list of pack IDs. Mandatory when the --force flag is on.
  [-ch, --slack-channel]        A slack channel to send notifications to. Default is dmst-bucket-upload.
  [-cp, --content-path]         The path of content, default is ~/dev/demistio/content
  [-pr, --production]           Whether to trigger the production upload flow.
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
    bucket=$2
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

  -cp|--content-path) CONTENT_PATH="$2"
    shift
    shift;;

  -pr|--production) production=true
    shift
    shift;;

  *)    # unknown option.
    shift;;
  esac
done

# Setup
cd "${CONTENT_PATH}" || fail

check_arguments

# If production flag is set - upload master branch
if [ -n "$production" ]; then
  slack_channel="dmst-content-team"
  bucket="marketplace-dist"

  if [ -n "$gitlab_token" ]; then
    trigger_gitlab_ci "master"
  fi

  if [ -n "$circle_token" ]; then
    trigger_circle_ci "master"
  fi

  exit 0
fi

content_hash=$(git rev-parse --short origin/${content_branch_name})
if [ -n "$sdk_branch_name" ]; then
  sdk_hash=$(git rev-parse --short origin/${sdk_branch_name})
else
  sdk_hash="latest_sdk_release"
fi
new_content_branch="${sdk_hash}_${content_hash}_UploadFlow_test"

#git checkout "$content_branch_name" || fail
git pull -q

existed_in_remote=$(git ls-remote --heads origin "${new_content_branch}")
existed_in_local=$(git branch --list "${new_content_branch}")

# Deletes the remote branch if exists
if [ -n "${existed_in_remote}" ]; then
  git push origin --delete "${new_content_branch}"
fi
# Deletes the local branch if exists
if [ -n "${existed_in_local}" ]; then
  git branch -D "${new_content_branch}" # delete local branch
fi

##############################################################
##                   Branch Changes - start                 ##
##############################################################
git checkout -b "${new_content_branch}" || fail "" "skip"

if [ -n "$sdk_branch_name" ]; then
  change_sdk_requirements "${sdk_branch_name}" "dev-requirements-py3.txt"
fi

# New Pack
create_new_pack "${base_pack_name}" "${new_pack_suffix}" "${pack_names_and_ids[@]}" # Creates new pack HelloWorldNew
add_dependency "Viper" "${new_pack_name}" # Viper is now dependent on a new pack that is not in the bucket.
add_author_image "${new_pack_name}"
add_1_0_0_release_note "${new_pack_name}"

## Existing pack
enhancement_release_notes "ZeroFox" # Add new release note to ZeroFox.
change_integration_image "PaloAltoNetworks_IoT" "Armis" # New integration image to Armis.
updating_old_release_notes "Box" "2_1_2" # Changing existing release note.
enhancement_release_notes "Box" # Adding new release note.
updating_old_release_notes "Base" "1_13_13" # Updating aggregated release note.
add_1_0_0_release_note "BPA"
set_pack_hidden "Microsoft365Defender"
update_integration_readme "Maltiverse"
update_pack_ignore "MISP"

# External changes
add_pack_to_landing_page "Trello"

##############################################################
##                   Branch Changes - End                   ##
##############################################################

git push --set-upstream origin "${new_content_branch}"

if [ -n "$circle_token" ]; then
  trigger_circle_ci "${new_content_branch}"
fi

if [ -n "$gitlab_token" ]; then
  trigger_gitlab_ci "${new_content_branch}"
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
