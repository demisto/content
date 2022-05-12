import argparse
import shutil
from git import Repo, Head
from pathlib import Path
import subprocess
from shutil import rmtree
import os


def create_new_pack():
    """
        Creates new pack with given pack name
    """
    print("Creating new pack TestUploadFlow...", end='')
    content_path = Path(__file__).parent.parent.parent
    source_path = Path(__file__).parent / 'TestUploadFlow'
    dest_path = content_path / 'Packs' / 'TestUploadFlow'
    shutil.copytree(source_path, dest_path)
    subprocess.call(['demisto-sdk', 'format', '-i', dest_path], stdout=subprocess.DEVNULL)
    print("Done")


def create_new_branch(repo: Repo, new_branch_name: str) -> Head:
    branch = repo.create_head(new_branch_name)
    branch.checkout()
    print(f"Created new branch {repo.active_branch}")
    return branch


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", nargs="?", help="Content directory path, default is current directory.", default='.')
    parser.add_argument("-cb", "--content-branch", nargs="?",
                        help="The content branch name, if empty will run on current branch.")
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
    
    create_new_pack()
    
    repo.git.commit(m=f"Added Test file")
    repo.git.push('--set-upstream', 'https://code.pan.run/xsoar/content.git', branch)
    repo.git.checkout(original_branch)

