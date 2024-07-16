#!/usr/bin/env bash

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
		echo "✗ '$os' OS is not supported by this automation."
		echo "To complete your pack adoption please follow the steps detailed in the following article: https://xsoar.pan.dev/docs/partners/adopt#process"
		exit 1
	fi
}

#######################################
# Verify dependencies exist
# Globals:
#   None
# Arguments:
#   $1: The OS
#   $2: array of dependencies

#######################################
check_dependencies(){

	os=$1
	shift

	dependencies=("$@")

	for d in "${dependencies[@]}";
	do
		if ! command -v "$d" &> /dev/null
		then
			echo "✗ $d was not found in the system or in the PATH."

			# If git not found and running on a Mac
			if [ "$d" == "git" ] && [ "$os" == "Mac OS" ]
			then
				echo "Install git by visiting https://git-scm.com/download/mac"
				exit 1
			# If git not found and running on Linux
			elif [ "$d" == "git" ] && [ "$os" == "Linux" ]
			then
				echo "Install git by visiting https://git-scm.com/download/linux"
				exit 1
			# If Python was not found on Mac OS
			elif [ "$d" == "python3" ] && [ "$os" == "Mac OS" ]
			then
				echo "Install Python by visiting https://www.python.org/downloads/macos/"
				exit 1
			# If Python was not found on Linux
			elif [ "$d" == "python3" ] && [ "$os" == "Linux" ]
			then
				echo "Install Python by visiting https://www.python.org/downloads/source/"
				exit 1
			# If Demisto SDK was not found, install it
			elif [ "$d" == "demisto-sdk" ]
			then
				echo "Installing $d..."
				install_sdk
			fi
		else
			echo "✓ Dependency '$d' found."
		fi
	done

}

#######################################
# Install demisto-sdk
# Globals:
#   None
# Arguments:
#   None
#######################################
install_sdk(){

	if pip3 install demisto-sdk &> /dev/null
	then
		echo "✓ demisto-sdk installed successfully."
	else
		echo "✗ Error installing demisto-sdk. Scroll up to see error message. If you have a problem installing it, report it https://github.com/demisto/demisto-sdk/issues"
		exit 1
	fi
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
		echo "Make sure that you're running this script from within the Content repository path"
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
# Check if branch exists and delete if it does
# Globals:
#   None
# Arguments:
#   $1: Branch name
#######################################
check_branch(){

	if git show-ref --quiet "refs/heads/$1"
	then
		printf "\t- Branch '%s' exists, will be deleted and recreated...\n" "$1"
		if git branch -D --quiet "$1"
		then
			printf "\t- ✓ Branch '%s' deleted\n" "$1"
		else
			printf "\t- ✗ Error deleting branch '%s'. Terminating..." "$1"
			exit 1
		fi

	else
		echo "✓ Branch '$1' doesn't exist"
	fi
}


#######################################
# Add and Commit changes
# Globals:
#   None
# Arguments:
#   $1: Option
#   $2: README
#   $3: Release Note
#   $4: Pack metadata
#######################################
commit(){

	git add "$2" "$3" "$4"
	git commit -m "$pack_name adoption $1" -q

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
			printf "\t- No untracked changes done, attempting to checkout to master/main branch...\n"
			if git show-ref --quiet refs/heads/master; then
				printf "\t- Checking out master branch...\n"
				git checkout --quiet master
			elif git show-ref --quiet refs/heads/main; then
				printf "\t- Checking out main branch...\n"
				git checkout --quiet main
			else
				printf "\t-Could not find references to main/master HEAD. Terminating...\n"
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
# Handles empty README file
# Globals:
#   None
# Arguments:
#   $1: the path to the Pack README.md
#   $2: the message to write to the top of the README.md
#######################################
add_msg_to_readme(){

	readme=$1
	message=$2
	os="$(detect_os)"

	# Check if README exists, create if not
	[ ! -f "$readme" ] && touch "$readme"

	# The file is empty
	if ! [[ -s "$readme" ]]; then
		echo "$message" > "$readme"
	else
		if [ "$os" == "Mac OS" ]; then
			sed -i '' "1s/^/$message\n\n/" "$readme"
		else
			sed -i "1s/^/$message\n\n/" "$readme"
		fi
	fi
}

#######################################
# Append adoption message to release note
# Globals:
#   None
# Arguments:
#	$1: the option to add as release note
#   $2: the path to the Pack release nope
#   $3: OS
#######################################
add_msg_to_rn(){
	opt=$1
	rn=$2
	os=$3

	if [[ "$opt" == "complete" ]]; then
		message="- Completed adoption process."
	else
		message="- Started adoption process."
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
#   $1: Path to pack_metadata
#######################################
get_pack_email(){

	email=$(jq -r '.email' "$1")

	echo "$email"

}

#######################################
# Set Pack email
# Globals:
#   None
# Arguments:
#   $1: Path to pack_metadata
#######################################
set_pack_email(){

	pack_metadata="$1"
	echo -n "Enter the email to your support site: "
	read -r email

	jq ". | select(.email) .email=\"$email\"" "$pack_metadata" > "${pack_metadata}.bak" && rm "$pack_metadata" && mv "${pack_metadata}.bak" "$pack_metadata" &> /dev/null
	echo "✓ Email field set in pack_metadata.json."

}

#######################################
# Set support type in pack metadata
# Globals:
#   None
# Arguments:
#   $1: Path to pack_metadata
#   $2: Support type ('xsoar', 'partner')
#######################################
set_pack_support_type(){

	pack_metadata="$1"
	type="$2"

	jq ". | select(.support) .support=\"$type\"" "$pack_metadata" > "${pack_metadata}.bak" && rm "$pack_metadata" && mv "${pack_metadata}.bak" "$pack_metadata" &> /dev/null
	echo "✓ Support type '$type' set in pack_metadata.json."

}


#######################################
# Set pack author in pack metadata
# Globals:
#   None
# Arguments:
#   $1: Path to pack_metadata
#######################################
set_pack_author(){

	pack_metadata="$1"

	echo -n "Enter your organization/company's name: "
	read -r author

	jq ". | select(.author) .author=\"$author\"" "$pack_metadata" > "${pack_metadata}.bak" && rm "$pack_metadata" && mv "${pack_metadata}.bak" "$pack_metadata" &> /dev/null
	echo "✓ Author set in pack_metadata.json."

}

#######################################
# Set Author Image (if provided)
# Globals:
#   None
# Arguments:
#   $1: Pack path
#######################################
set_author_image(){

	pack_dir="$1"
	echo -n "Enter a URL to download the author image. If you do not have a URL, just press enter and make sure to add it manually according to https://xsoar.pan.dev/docs/packs/packs-format#author_imagepng: "
	read -r author_image_url
	if [ -n "$author_image_url" ]
	then
		echo "Attempting to download image from $author_image_url..."
		wget --no-check-certificate --quiet -O "$pack_dir/Author_image.png" "$author_image_url"
		exit_code=$?

		if [ $exit_code -eq 4 ]
		then
			rm "$pack_dir/Author_image.png"
			echo "✗ Author image download failed. Check that '$author_image_url' is a valid URL."
			echo "Make sure to manually add it according to https://xsoar.pan.dev/docs/packs/packs-format#author_imagepng"
		else
			echo "✓ Author image downloaded to '$pack_dir/Author_image.png'"
		fi
	fi
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
# Set support URL to pack_metadata
# Globals:
#   None
# Arguments:
#   $1: Path to pack_metadata
#######################################
set_pack_support_url(){

	pack_metadata="$1"
	echo -n "Enter a URL to your support site: "
	read -r url

	jq ". | select(.url) .url=\"$url\"" "$pack_metadata" > "${pack_metadata}.bak" && rm "$pack_metadata" && mv "${pack_metadata}.bak" "$pack_metadata" &> /dev/null
	echo "✓ URL field set in pack_metadata.json."

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
#   $4: OS
#######################################
adopt() {
	option=$1
	dir=$2
	branch=$3
	os=$4

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
	add_msg_to_rn "$option" "$release_note" "$os"
	release_note_name=$(basename "$release_note")
	echo "✓ Release note '$release_note_name' updated."

	# If we're completing adoption, we need to request some additional
	# paramaters to be set in the Pack metadata.
	if [[ "$option" == "start" ]]; then
		message="Note: Support for this Pack will be moved to Partner starting $(get_move_date)."
	else
		set_pack_support_type "$pack_metadata" "partner"
		set_pack_author "$pack_metadata"
		set_pack_support_url "$pack_metadata"
		set_pack_email "$pack_metadata"

		support_email=$(get_pack_email "$pack_metadata")
		set_author_image "$dir"
		message="Note: Support for this Pack was moved to Partner starting $(get_today_date). In case of any issues arise, please contact the Partner directly at $support_email."
	fi

	add_msg_to_readme "$readme" "$message"
	echo "✓ Adoption $option message added to README.md"

	commit "$option" "$readme" "$release_note" "$pack_metadata"
	echo "✓ Changes committed."

	pr_url=$(push "$branch")
	echo "✓ Branch pushed upstream."

	printf "\nAll done here!\n\n"
	echo "Please visit ====> $pr_url <==== and fill out the Pull Request details to complete the adoption process"

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
			echo "Error: Expecting either 'start' or 'complete' as input, received '$option'"
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