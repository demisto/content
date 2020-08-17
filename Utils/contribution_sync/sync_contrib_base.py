import os
import sys
import requests
from github import Github, enable_console_debug_logging
from github.Repository import Repository
from typing import List, Bool


def get_master_commit_sha(repo: Repository) -> str:
    '''Return the sha commit of the master branch

    Args:
        repo (Repository): The repository whose master branch will be queried

    Returns:
        (str): The commit sha of the master branch's HEAD
    '''
    branch_data = repo.get_branch('master')
    commit_sha = branch_data.commit.sha
    return commit_sha


def get_branch_names_with_contrib(repo: Repository) -> List[str]:
    '''Return the list of branches that have the prefix of "contrib/"

    Args:
        repo (Repository): The repository whose branches will be searched and listed

    Returns:
        (List[str]): List of branch names that have the "contrib/" prefix
    '''
    branch_names = []
    for branch in repo.get_branches():
        if branch.name.startswith('contrib/'):
            branch_names.append(branch.name)
    return branch_names


def is_pr(branch_name: str) -> Bool:
    '''Returns whether a branch has a PR for it

    Args:
        branch_name (str): The name of the branch to check

    Returns:
        Bool: True if there is a PR for the branch, False otherwise
    '''
    response = requests.get(
        f"https://api.github.com/repos/demisto/content/pulls?head=demisto:{branch_name}",
        verify=False, headers={'Accept': 'application/json'}
    )
    if response.status_code == 200 and len(response.json()) > 0:
        return True
    return False


def main():
    debug_mode = len(sys.argv) >= 2 and 'debug' in sys.argv[1].casefold
    if debug_mode:
        enable_console_debug_logging
    gh = Github(os.getenv('GITHUB_TOKEN'), verify=False)
    organization = 'demisto'
    repo = 'content'
    content_repo = gh.get_repo(f'{organization}/{repo}')

    list_of_all_branches = []
    master_sha = get_master_commit_sha(content_repo)
    contrib_branches = get_branch_names_with_contrib(content_repo)
    for branch_name in contrib_branches:
        if not is_pr(branch_name):
            list_of_all_branches.append(branch_name)
            git_ref = content_repo.get_git_ref(f'heads/{branch_name}')
            print(f'Updating branch "{branch_name}" to sha "{master_sha}"')
            git_ref.edit(master_sha, force=True)

    if debug_mode:
        print(f'{list_of_all_branches=}')


if __name__ == "__main__":
    main()
