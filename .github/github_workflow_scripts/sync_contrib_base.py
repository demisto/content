#!/usr/bin/env python3
import argparse
import os
import sys
import urllib3
from github import Github, enable_console_debug_logging
from github.Repository import Repository
from typing import List


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_master_commit_sha(repo: Repository) -> str:  # noqa: E999
    '''Return the sha commit of the master branch

    Args:
        repo (Repository): The repository whose master branch will be queried

    Returns:
        (str): The commit sha of the master branch's HEAD
    '''
    branch_data = repo.get_branch('master')
    commit_sha = branch_data.commit.sha
    return commit_sha


def arguments_handler() -> argparse.Namespace:
    """
    Validates and parses script arguments.
    Returns:
        Namespace: Parsed arguments object.

     """
    parser = argparse.ArgumentParser(description='Run update for base branch of the external PR.')
    parser.add_argument('-b', '--branch_name', help='The branch name.')
    return parser.parse_args()


def get_branch_names_with_contrib(repo: Repository) -> List[str]:  # noqa: E999
    '''Return the list of branches that have the prefix of "contrib/" and that are base branches of open PRs

    Args:
        repo (Repository): The repository whose branches will be searched and listed

    Returns:
        (List[str]): List of branch names that have the "contrib/" prefix and are base branches of open PRs
    '''
    branch_names = []
    open_prs_head_refs = {open_pr.head.ref for open_pr in repo.get_pulls(state='OPEN')}
    for branch in repo.get_branches():
        if branch.name.startswith('contrib/'):
            prs_with_branch_as_base = repo.get_pulls(state='OPEN', base=branch.name)
            if prs_with_branch_as_base.totalCount >= 1 and branch.name not in open_prs_head_refs:
                branch_names.append(branch.name)
    return branch_names


def update_branch(content_repo, branch_name, master_sha):
    git_ref = content_repo.get_git_ref(f'heads/{branch_name}')
    print(f'Updating branch "{branch_name}" to sha "{master_sha}"')
    git_ref.edit(master_sha)


def main():
    args = arguments_handler()
    ref_branch = args.branch_name
    debug_mode = len(sys.argv) >= 2 and 'debug' in sys.argv[1].casefold()
    if debug_mode:
        enable_console_debug_logging()
    gh = Github(os.getenv('CONTENTBOT_GH_ADMIN_TOKEN'), verify=False)
    organization = 'demisto'
    repo = 'content'
    content_repo = gh.get_repo(f'{organization}/{repo}')

    master_sha = get_master_commit_sha(content_repo)
    if ref_branch:
        # Case this flow was triggered on a specific branch
        contrib_base_branches = [ref_branch]
    else:
        # Case we are running scheduled job - detect all contrib/ base branches.
        contrib_base_branches = get_branch_names_with_contrib(content_repo)

    print(f'Updating {contrib_base_branches=}')
    for branch_name in contrib_base_branches:
        update_branch(content_repo, branch_name, master_sha)


if __name__ == "__main__":
    main()
