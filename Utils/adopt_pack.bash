#!/usr/bin/env bash

# Load external functions
# shellcheck disable=SC1091
source "${0%/*}/adopt_utils.bash"

# Set to terminate script in case of any error
set -e -o pipefail

main(){
	# Check that arguments were passed
	validate_inputs "$@"

	option=$1
	pack_name=$2

	echo "Initializing Pack Adoption..."
	init_wd=$(pwd)

	os=$(detect_os)
	echo "✓ Detected OS '$os'."

	dependencies=("git" "python3" "demisto-sdk")
	check_dependencies "$os" "${dependencies[@]}"
	echo "✓ All dependencies met."

	root_repo=$(get_repo_root)
	echo "✓ Found git repository in '$root_repo'."

	pack_path=$(get_pack_path "$pack_name" "$root_repo")
	echo "✓ Pack '$pack_name' exists."

	init_branch="$(git rev-parse --abbrev-ref HEAD)"
	reset_to_master "$init_branch"

	branch=$(get_branch "$pack_name" "$option")
	create_adopt_branch "$branch"
	echo "✓ Branch created."

	adopt "$option" "$pack_path" "$branch" "$os"

	reset_env "$init_branch" "$init_wd"
	exit 0

}


main "$@"