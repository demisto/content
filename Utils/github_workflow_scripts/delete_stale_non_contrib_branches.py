#!/usr/bin/env python3

import os
import sys
import urllib3
from blessings import Terminal
from github import Github, enable_console_debug_logging
from github.Repository import Repository
from typing import List
from dateparser import parse
from datetime import datetime, timezone
from utils import timestamped_print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print


def get_non_contributor_stale_branch_names(repo: Repository) -> List[str]:  # noqa: E999
    """Return the list of branches that do not have the prefix of "contrib/" without open pull requests
    and that have not been updated for 2 months (stale). Protected branches are excluded from consideration.

    Args:
        repo (Repository): The repository whose branches will be searched and listed

    Returns:
        (List[str]): List of branch names that are stale and don't have the "contrib/" prefix
    """
    # set now with GMT timezone
    now = datetime.now(timezone.min)
    branch_names = []
    all_branches = repo.get_branches()
    print(f'{all_branches.totalCount=}')
    for branch in all_branches:
        # Make sure the branch is not prefixed with contrib
        if not branch.name.startswith('contrib/'):
            if branch.protected:
                print(f"Skipping branch {branch.name} because it is a protected branch")
                continue
            # Make sure HEAD commit is stale
            if (last_modified := branch.commit.commit.last_modified) and (
                    last_commit_datetime := parse(last_modified)):
                elapsed_days = (now - last_commit_datetime).days
                # print(f'{elapsed_days=}')
                if elapsed_days >= 60:
                    associated_open_prs = branch.commit.get_pulls()  # type: ignore[attr-defined]
                    associated_open_prs = [pr for pr in associated_open_prs if pr.state == 'open']
                    if len(associated_open_prs) < 1:
                        branch_names.append(branch.name)
            else:
                print(f"Couldn't load HEAD for {branch.name}")
    return branch_names


def is_suitable_for_pr(repo: Repository, head: str, base: str = 'master') -> bool:
    """Checks if a PR can be created for a given head branch

    We compare the branch commits to determine if we should create a PR from the head branch.
    Sometimes people create a branch but never push commits to the branch. In
    those cases, there are no changes from which to create a PR against the base
    branch, and therefore we should not try to create a PR from that branch. We
    should simply delete it.

    Args:
        repo (Repository): The repo to query.
        head (str): The name of the head branch for a potential PR.
        base (str, optional): The name of the base branch to merge the head branch into. Defaults to 'master'.

    Returns:
        bool: True if the head branch is ahead of the base branch by one or more commits, False otherwise.
    """
    comparison = repo.compare(base, head)
    if comparison.ahead_by > 0:
        return True
    return False


def main():
    debug_mode = len(sys.argv) >= 2 and 'debug' in sys.argv[1].casefold()
    t = Terminal()
    if debug_mode:
        enable_console_debug_logging()
    gh = Github(os.getenv('CONTENTBOT_GH_ADMIN_TOKEN'), verify=False)
    organization = 'demisto'
    repo = 'content'
    content_repo = gh.get_repo(f'{organization}/{repo}')

    stale_non_contrib_branches = get_non_contributor_stale_branch_names(content_repo)
    for branch_name in stale_non_contrib_branches:
        try:
            base_branch = 'master'
            if not is_suitable_for_pr(content_repo, branch_name):
                print(f'Branch {branch_name} is not ahead of {base_branch} '
                      'and therefore not suited for a posterity PR')
                print(f'Deleting stale branch {branch_name} without creating a postery PR')
                content_repo.get_git_ref(f'heads/{branch_name}').delete()
            else:
                print(f'Creating PR for {branch_name}')
                title = branch_name
                body = (f'## Description\r\nPosterity PR Created for the branch "{branch_name}"'
                        ' so that it may be restored if necessary')
                pr = content_repo.create_pull(title=title, body=body, base=base_branch, head=branch_name, draft=False)
                print(f'{t.cyan}Posterity PR Created - {pr.html_url}{t.normal}')
                pr.add_to_labels('stale-branch')
                pr.edit(state='closed')
                print(f'{t.cyan}Posterity PR Closed{t.normal}')
                print(f'Deleting {branch_name}')
                branch_ref = content_repo.get_git_ref(f'heads/{branch_name}')
                branch_ref.delete()
        except Exception as e:
            print(f"{t.red}Deletion of {branch_name} encountered an issue: {str(e)}{t.normal}")

    if debug_mode:
        print(f'{stale_non_contrib_branches=}')


if __name__ == "__main__":
    main()
