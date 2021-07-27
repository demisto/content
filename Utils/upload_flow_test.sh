#!/usr/bin/env bash

function fail {
    echo "$1"
    exit 1
}

function check_arguments {
    if [ -z "$sdk_branch_name" ]; then
      fail "You must provide sdk branch name."
    fi

    if [ -z "$gitlab_token" ] && [ -z "$circle_token" ]; then
      fail "At least one token [-gt, --gitlab-ci-token] or [-ct, --circle-ci-token] is required."
    fi

}

function Enhancement_RN {
    demisto-sdk update-release-notes -i "${pack_path}" --force --text "Adding release notes to check the upload flow" # Waiting for sdk fix
}

function updating_old_release_notes {
  cd "${pack_path}/ReleaseNotes" || return
  current_latest_note=$(ls -t | head -1)
  printf "\n#### Upload flow\n - Test\n" >> "${latest_note}"
  cd "${content_path}" || return
}

function create_new_pack {
  echo "creating new pack - ${new_pack_name}"
  cd "${content_path}" || fail
  cp -R "${pack_path}" "${content_path}/Packs/${new_pack_name}" || fail
  cd "${content_path}/Packs/${new_pack_name}" || fail
  find . -type f -name "*.json|*.yml" -exec sed -i "" "s/${base_pack_name}/${new_pack_name}/g" {} \;
}

function add_author_image {
  echo "Adding Author image to ${base_pack_name}"
  cp "${content_path}/Packs/Base/Author_image.png" "${content_path}/Packs/${new_pack_name}"
}

function Adding_dependecy {

}



function trigger_circle_ci {
  cd "${content_path}" || fail
  cat ~/trigger_test_flow > /Users/iyeshaya/dev/demisto/content/Utils/trigger_test_upload_flow.sh
  ./Utils/trigger_test_upload_flow.sh -ct "${circle_token}" -b "${content_branch}" -db "true"
}
function trigger_gitlab_ci {
  cd "${content_path}" || return
 ./Utils/trigger_test_upload_flow.sh -ct "${gitlab_token}" -g true -b "${content_branch}"
}






# parse inputs
if [ "$#" -lt "1" ]; then
  fail "Usage:
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












requirements_file="dev-requirements-py3.txt"
content_path="$HOME/dev/demisto/content"

content_branch="${sdk_branch_name}_uploadFlow_test"
#content_branch="uploadFlow_test_script"
base_pack_name="HelloWorld"
pack_path="${content_path}/Packs/${base_pack_name}"
new_pack_name="${base_pack_name}_new"

cd "${content_path}" || fail
#cat /Users/iyeshaya/dev/demisto/content/.circleci/config.yml >  ~/config_temp

#git checkout master
#git pull
#git checkout -b "${content_branch}" || fail
#

# changing the requirements file inorder to install the desired sdk branch on the pipline
sed -i "" "s#demisto-sdk.*#git+https://github.com/demisto/demisto-sdk.git@${sdk_branch_name}#g" "${requirements_file}"

#add_new_release_note
create_new_pack

# Enhancement
# Change image
cp "${content_path}/Packs/Palo_Alto_Networks_WildFire/Integrations/Palo_Alto_Networks_WildFire_v2/Palo_Alto_Networks_WildFire_v2_image.png" "${content_path}/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld_image.png"



#cat ~/config_temp > /Users/iyeshaya/dev/demisto/content/.circleci/config.yml
#git commit -am "Addding changes"
#git push origin "${sdk_branch_name}_uploadFlow_test"

if [ -n "$circle_token" ]; then
  trigger_circle_ci
fi

if [ -n "$gitlab_token" ]; then
  trigger_gitlab_ci
fi

#git stash
#git checkout uploadFlow_test_script
