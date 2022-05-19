#!/bin/bash

#######################################
# Check if we're running supported OS (darwin || linux)
# Globals:
#   None
# Arguments:
#   None
#######################################
detect_os() {

	os=$(uname -s)

	if [ "$os" == "Darwin" ]; then
		echo "Mac OS"
	elif [ "$os" == "Linux" ]; then
		echo "$os"
	else
		echo "✗ Unsupported OS. Terminating"
		exit 1
	fi


}

#######################################
# Verify dependencies exist
# Globals:
#   None
# Arguments:
#   dependencies: array of dependencies
#######################################
check_dependencies(){

	dependencies=$1

	for d in "${dependencies[@]}"; 
	do
		if ! command -v "$d" &> /dev/null
		then
			echo "'$d' could not be found. Please install it, reload the shell and try again. Exiting..."
			exit 1
		else
			echo "✓ Dependency '$d' found."
		fi
	done

}

#######################################
# Verify we're in the content repo
# Globals:
#   None
# Arguments:
#   None
#######################################
get_repo_root(){
	inside_git_repo="$(git rev-parse --is-inside-work-tree 2>/dev/null)"
	if [ "$inside_git_repo" ]; then
		repo_root="$(git rev-parse --show-toplevel)"
		echo "$repo_root"
	else
		echo "✗ git repo cannot be found in current work tree."
		echo "Make sure that you're running this script from within the content repository path"
		exit 1
	fi
}

#######################################
# Verify Pack path exists and return path
# Globals:
#   None
# Arguments:
#   $1: The name of the Pack from argument
#   $2: The root git repository path
#######################################
get_pack_path(){
	# Check if pack exists
	pack_name=$1
	root_repo=$2
	dir="$root_repo/Packs/$pack_name"

	if [ ! -d "$dir" ] 
	then
		echo "✗ Cannot find Pack name '$pack_name' in directory '$dir'" 
		exit 1
	else
		echo "$dir"
	fi
}


#######################################
# Create new branch
# Globals:
#   pack_name
# Arguments:
#   None
#######################################
create_adopt_branch(){
	git checkout -q -b "$1"
}


#######################################
# Create branch name based on pack
# Globals:
#   None
# Arguments:
#   $1: Pack name
#   $2: Option
#######################################
get_branch(){
	pack_name=$1
	opt=$2
	branch_name="partner-$pack_name-adopt-$opt"
	echo "$branch_name"
}


#######################################
# Add and Commit changes
# Globals:
#   None
# Arguments:
#   $1: Path to Pack README
#   $2: Path to Pack release note
#   $3: Path to Pack metadata
#######################################
commit(){

	readme=$1
	release_note=$2
	pack_metadata=$3

	git add "$readme" "$release_note" "$pack_metadata" &> /dev/null
	git commit -m "$pack_name adoption started" &> /dev/null

}

#######################################
# Push changes
# Globals:
#   None
# Arguments:
#   $1: Branch
#######################################
push(){

	# Get the git user to construct open PR URL
	user=$(git remote get-url --all origin | cut -d ":" -f2 | cut -d"/" -f1)
	branch=$1
	git push --set-upstream origin "$branch" &> /dev/null

	echo "https://github.com/$user/content/pull/new/$branch"

}



#######################################
# Attempt to reset to master/main branch
# Globals:
#   None
# Arguments:
#   $1: Current branch
#######################################
reset_to_master(){
	# Check that we're on master/main
	# If on master/main, create new adopt branch
	# If not, see if there are any untracked files and attempt to checkout master/main if none
	branch=$1
	if [ "$branch" != "master" ] && [ "$branch" != "main" ]; then
		echo "✗ Not on master/main branch.";
		untracked_files=$(git --no-pager  diff --name-only | wc -l | tr -d '[:space:]')
	
		# Check if there are any untracked files
		# If there are, terminate
		# If there aren't, attempt to checkout master/main
		if [ "$untracked_files" -gt 0 ]; then
			echo "✗ Cannot checkout master/main branch since there are $untracked_files untracked files:"
			git status | grep -i modified | cut -d ":" -f2
			echo "Please run 'git stash/revert/reset' and rerun."
			exit 1
		else
			echo "No untracked changes done, attempting to change to master/main branch..."
			if git show-ref --quiet refs/heads/master; then
				echo "Checking out master branch..."
				git checkout master
			elif git show-ref --quiet refs/heads/main; then
				echo "Checking out main branch..."
				git checkout main
			else
				echo "Could not find references to main/master HEAD. Terminating..."
				exit 1	
			fi
		fi
	fi
}

#######################################
# Get the adoption complete formatted date for adoption according to OS
# Globals:
#   os: the string representing the operating system
# Arguments:
#   None
#######################################
get_move_date(){

	if [ "$os" == "Mac OS" ] 
	then
		date -v "+90d" "+%B %d, %Y"
	else
		date -d "+90 days" "+%B %d, %Y"
	fi
	
}

#######################################
# Get today's date formatted date for adoption according to OS
# Globals:
#   os: the string representing the operating system
# Arguments:
#   None
#######################################
get_today_date(){

	if [ "$os" == "Mac OS" ] 
	then
		date "+%B %d, %Y"
	else
		date "+%B %d, %Y"
	fi
	
}

#######################################
# Append adoption message to top of README.md 
# Globals:
#   None
# Arguments:
#   $1: the path to the Pack README.md
#   $2: the message to write to the top of the README.md
#######################################
add_msg_to_readme(){

	readme=$1
	message=$2

	if [ "$os" == "Mac OS" ] 
	then
		sed -i '' "1s/^/$message\n\n/g" "$readme"
	else
		sed -i "1s/^/$message\n\n/" "$readme"
	fi

}

#######################################
# Append adoption message to release note 
# Globals:
#   None
# Arguments:
#	$1: the option to add as release note
#   $2: the path to the Pack release nope
#######################################
add_msg_to_rn(){
	opt=$1
	rn=$2

	if [[ "$opt" == "complete" ]]; then
		message="- Completed Adoption process."
	else
		message="- Started Adoption process."
	fi

	if [ "$os" == "Mac OS" ] 
	then
		sed -i '' "2s/.*/$message/" "$rn"
	else
		sed -i "2s/.*/$message/" "$rn"
	fi

}


#######################################
# Get Pack email
# Globals:
#   None
# Arguments:
#   $1: Pack path
#######################################
get_pack_email(){

	pack_metadata="$1"
	email=$(jq -r '.email' "$pack_metadata")

	echo "$email"

}

#######################################
# Get support link
# Globals:
#   None
# Arguments:
#   $1: Pack path
#######################################
get_pack_version(){

	pack_metadata="$1"
	version=$(jq '.currentVersion' "$pack_metadata")

	echo "$version"

}

#######################################
# Perform adoption steps mentioned in https://xsoar.pan.dev/docs/partners/adopt#process
# 1) Create release notes and add message there
# 2) Bump version
# 3) Add message to README
# Globals:
#   None
# Arguments:
#   $1: Whether to start or complete adoption process
#   $2: Path to Pack
#   $3: Git branch that will hold all changes
#######################################
adopt() {
	option=$1
	dir=$2
	branch=$3

	readme="$dir/README.md"
	pack_metadata="$dir/pack_metadata.json"
	pack_name=$(basename "$dir")
	

	# Bump version and create release note file
	demisto-sdk update-release-notes --input "$dir" --force --update-type "documentation" &> /dev/null
	release_note=$(git --no-pager  diff --name-only --cached)
	

	pack_version=$(get_pack_version "$pack_metadata")
	
	echo "✓ Pack version bumped to $pack_version in '$pack_metadata'"
	echo "✓ Release note created in '$release_note'"

	# Add release note to second line (replacing documentation bullet)
	add_msg_to_rn "$option" "$release_note"
	release_note_name=$(basename "$release_note")
	echo "✓ Release note '$release_note_name' updated."

	# Add message to README
	if [[ "$option" == "start" ]]; then
		message="Note: Support for this Pack will be moved to Partner starting $(get_move_date)."
	else
		support_email=$(get_pack_email "$pack_metadata")
		message="Note: Support for this Pack was moved to Partner starting $(get_today_date). In case of any issues arise, please contact the Partner directly at $support_email."
	fi

	add_msg_to_readme "$readme" "$message"
	echo "✓ Adoption $option message added to README.md"

	commit "$readme" "$release_note" "$pack_metadata"
	echo "✓ Changes committed."

	pr_url=$(push "$branch")
	echo "✓ Branch pushed upstream."

	echo "All done here!"
	echo "Please visit $pr_url and fill out the Pull Request to complete the process"

}

#######################################
# Validate inputs
# Globals:
#   None
# Arguments:
#   script inputs
#######################################
validate_inputs(){
	if [[ $# -ne 2 ]]
	then
		echo "Expecting 2 inputs, got $#"
		usage
	else
		option=$1
		pack_name=$2

		# Verify options
		if [[ "$option" != "start" ]] && [[ "$option" != "complete" ]];
		then
			echo "Expecting either 'start' or 'complete' as input, received '$option'"
			usage
		fi
	fi
}


#######################################
# Prints usage and exits
# Globals:
#   None
# Arguments:
#   $0: Program name
#######################################
usage(){
	echo "Usage: $0 start|complete pack_name"
	exit 1
}

#######################################
# Reset environment to before script
# Globals:
#   None
# Arguments:
#   $1: Branch name
#   $2: Working directory
#######################################
reset_env(){
	
	git checkout "$1" &> /dev/null
	cd "$2" || "Failed change directories back to '$2', error code $?"; exit 1

}