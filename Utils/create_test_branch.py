import argparse
from git import Repo, Head
from pathlib import Path

def create_new_branch(repo: Repo, new_branch_name:str) -> Head:      
    branch = repo.create_head(new_branch_name)
    branch.checkout()
    print(f"Created new branch {repo.active_branch}")
    return branch

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("-p","--path", nargs="?", help="Content directory path, default is current directory.", default='.')
    parser.add_argument("-cb","--content-branch", nargs="?", help="The content branch name, if empty will run on current branch.")
    return parser.parse_args()

if __name__ == "__main__":

    args = parse_arguments()
    repo = Repo(args.path)
    if args.content_branch:
        original_branch = args.content_branch
        repo.git.checkout(original_branch)
    else:
        original_branch = repo.active_branch
    
    new_branch_name = f"{original_branch}_upload_test_branch_{repo.active_branch.object.hexsha}"
    branch = create_new_branch(repo, new_branch_name)
    Path("./test.txt").write_text("Hello!")
    repo.git.add("test.txt")
    repo.git.commit(m=f"Added Test file")
    repo.git.push('--set-upstream', 'https://code.pan.run/xsoar/content.git', branch)
    repo.git.checkout(original_branch)
    """
    # parse inputs
if [ "$#" -lt "1" ]; then
  fail "
  [-sb, --sdk-branch]           The sdk branch name, if empty will run the version specified in the requirements file.
  [-cb, --content-branch]       The content branch name, if empty will run on master branch.
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

  *)    # unknown option.
    shift;;
  esac
done


# change_sdk_requirements
# changing the requirements file inorder to install the desired sdk branch
# :param $1: sdk branch name
# :param $2: requirements file
function change_sdk_requirements {
  if [ "$#" -ne 2 ]; then
    fail " Illegal number of parameters "
  fi

  local sdk_branch=$1
  local requirements_file_name=$2

  sed -i "" "s#demisto-sdk.*#git+https://github.com/demisto/demisto-sdk.git@${sdk_branch}#g" "${requirements_file_name}"

  git commit --untracked-files=no -am  "Change sdk in $requirements_file_name to be $sdk_branch" --no-verify

}

if [ -z "$content_branch_name" ]; then
  content_branch_name=$(git branch --show-current)
fi



git pull -q 
content_hash=$(git rev-parse --short origin/${content_branch_name})
if [ -n "$sdk_branch_name" ]; then
  sdk_hash=$(git rev-parse --short origin/${sdk_branch_name})
else
  sdk_hash="latest_sdk_release"
fi
new_content_branch="${sdk_hash}_${content_hash}_UploadFlow_test"



git checkout -b "This_is_testing_branch"
touch test.txt
git add test.txt
git commit -m "This is message"
git push https://code.pan.run/xsoar/content.git
    """