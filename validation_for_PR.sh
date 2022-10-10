#!/bin/bash

# Author : Dhaval Jain, Harsh Panchal
# Created Date : 15th September 2022

NC='\033[0m'
RED='\e[1;31m'
GREEN='\e[1;32m'
YELLOW='\e[1;33m'
BLUE='\e[1;34m'
GREY='\e[1;37m'

usage="$(basename "$0") -- script to automate certification checks.
Arguments:
    -p,     integration directory name
    -t,     test playbook name expected to be present in conf.json
    -u,     type of update, possible values are revision, minor, major
    example: sh validation_for_PR_2.sh -p GoogleCloudSCC -t GoogleCloudSCC-Test -u minor"

while getopts 'u:p:t:h' OPTION;
do
    case "$OPTION" in
        u) 
            update_type=$OPTARG
            echo -e "${BLUE}Current update type: $update_type${NC}"
            ;;
        p)
            integration_dir_name=$OPTARG
            echo -e "${BLUE}Current integration directory name: $integration_dir_name${NC}"
            ;;
        t)
            test_playbook_name=$OPTARG
            echo -e "${BLUE}$test_playbook_name${NC}"
            ;;
        h) 
            echo "$usage"
            exit
            ;;
        ?)
            echo "Script $usage: $(basename $0)"
            exit 1
            ;;
    esac
done

#Checking if the current user is crestdatasystems or not
echo -e "${GREY}====================CHECKING USERNAME====================${NC}"
is_user_crest=`git config --list | grep 'user.name=crestdatasystems' | wc -l`
if (( $is_user_crest <= 0 ))
then
    echo -e "${RED}Aborting! Username should be crestdatasystems${NC}"
    exit 1
fi

# Checking if the current branch is master
echo -e "${GREY}====================CHECKING BRANCH====================${NC}"
current_branch_name=`git rev-parse --abbrev-ref HEAD`
if [[ $current_branch_name == "master" ]]
then
    echo -e "${RED}Aborting! You're on master branch.${NC}"
    exit 1
fi

# Checking whether the file entry exists in the conf.json file or not
echo -e "${GREY}====================CHECKING TESTPLAYBOOK====================${NC}"
no_of_lines_with_test_playbook_in_it=`cat Tests/conf.json | grep $test_playbook_name | wc -l`
if (( $no_of_lines_with_test_playbook_in_it <= 0 ))
then
    echo -e "${YELLOW}Warning: Playbook ID with the name $test_playbook_name not found in conf.json${NC}"
else
    echo -e "${GREEN}Found the Playbook ID with the name $test_playbook_name in the conf.json${NC}"
fi


# Variables
path_to_pack="Packs/$integration_dir_name"

# Running dos2unix command on the pack files
echo -e "${GREY}====================CONVERT DOS2UNIX====================${NC}"
cd $path_to_pack && find . -type f -print0 | xargs -0 dos2unix
# Going back to the content directory
cd ../..


# Adding the contents to the current branch
echo -e "${GREY}====================STAGGING FILES====================${NC}"
echo -e "${BLUE}Adding the contents of $integration_dir_name directory to staging area of $current_branch_name branch.${NC}"
git add $path_to_pack


# Running secrets 
echo -e "${GREY}====================RUNNING SECRETS====================${NC}"
echo -e "${BLUE}Running secrets on the recently changed files.${NC}"
if ( ! demisto-sdk secrets )
then
    # Unstaging files from staging area
    echo -e "${GREY}====================UNSTAGGING FILES====================${NC}"
    git reset HEAD -- .
    exit 1
fi

# Unstaging files from staging area
echo -e "${GREY}====================UNSTAGGING FILES====================${NC}"
git reset HEAD -- .


# Checking whether we have anything related to the docker image in .pack-ignore
echo -e "${GREY}====================CHECKING PACKIGNORE====================${NC}"
contains_docker_code=`cat $path_to_pack/.pack-ignore | grep DO | wc -l`
if (( $contains_docker_code > 0 ))
then
    echo -e "${RED}Aborting! Found error code for docker in .pack-ignore${NC}"
    exit 1
fi


# Validating the pack files
echo -e "${GREY}====================RUNNING VALIDATION====================${NC}"
export DEMISTO_README_VALIDATION=True
validate_output=$(demisto-sdk validate -i $path_to_pack)
exit_code=$?
if (( $exit_code > 0 ))
then
    docker_error_106=`echo $validate_output | grep "DO106" | wc -l`
    if (( $docker_error_106 > 0 ))
    then
        echo -e "${BLUE}Updating docker image to the latest one${NC}"
        demisto-sdk format -ud -i "$path_to_pack/Integrations/$integration_dir_name/$integration_dir_name.yml"
    fi
    exit 1
fi

# update release notes
echo -e "${GREY}====================UPDATING RELEASE NOTES====================${NC}"
if [ ! -z ${update_type+x} ]
then
    if [[ "$update_type" = "major" ]] || [[ "$update_type" = "minor" ]] || [[ "$update_type" = "revision" ]];
    then
        demisto-sdk update-release-notes -i $integration_dir_name -u $update_type
    fi
fi
echo -e "${BLUE}Task completed successfully${NC}"

# Restoring all the changes back, if anything goes wrong
# git reset .


# shift "$(($OPTIND -1))"