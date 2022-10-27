#!/usr/bin/env bash

# Load external functions
# shellcheck disable=SC1091
source "${0%/*}/adopt_utils.bash"

# Set to terminate script and retrieve original env in case of any error
init_wd=$(pwd)
init_branch="$(git rev-parse --abbrev-ref HEAD)"
trap '{ reset_env $init_branch $init_wd; exit 1; }' SIGHUP SIGINT SIGQUIT SIGILL

main(){
	# Check that arguments were passed
	validate_inputs "$@"

	option=$1
	pack_name=$2

	echo "Initializing Pack Adoption..."


	os=$(detect_os)
	echo "✓ Detected OS '$os'."

	dependencies=("git" "python3" "demisto-sdk" "jq" "sed")
	check_dependencies "$os" "${dependencies[@]}"
	echo "✓ All dependencies met."

	root_repo=$(get_repo_root)
	echo "✓ Found git repository in '$root_repo'."

	pack_path=$(get_pack_path "$pack_name" "$root_repo")
	echo "✓ Pack '$pack_name' exists."

	reset_to_master "$init_branch"

	# Generate branch name
	# Check if branch exists and delete if it does
	# Create new branch
	branch=$(get_branch "$pack_name" "$option")
	check_branch "$branch"
	create_adopt_branch "$branch"
	echo "✓ Branch '$branch' created."

	adopt "$option" "$pack_path" "$branch" "$os"

	reset_env "$init_branch" "$init_wd"
	exit 0

}


main "$@"