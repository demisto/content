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


def get_stale_branch_names_with_contrib(repo: Repository) -> List[str]:  # noqa: E999
    """Return the list of branches that have the prefix of "contrib/" without open pull requests
    and that have not been updated for 2 months (stale)

    Args:
        repo (Repository): The repository whose branches will be searched and listed

    Returns:
        (List[str]): List of branch names that are stale and have the "contrib/" prefix
    """
    # set now with GMT timezone
    now = datetime.now(timezone.min)
    organization = 'demisto'
    branch_names = []
    for branch in repo.get_branches():
        # Make sure the branch is contrib
        if branch.name.startswith('contrib/'):
            prs_with_branch_as_base = repo.get_pulls(state='OPEN', base=branch.name)
            prs_with_branch_as_head = repo.get_pulls(state='OPEN', head=f'{organization}:{branch.name})')

            # Make sure there are no open prs pointing to/from the branch
            if prs_with_branch_as_base.totalCount < 1 and prs_with_branch_as_head.totalCount < 1:
                # Make sure HEAD commit is stale
                if (last_modified := branch.commit.commit.last_modified) and (
                        last_commit_datetime := parse(last_modified)):
                    elapsed_days = (now - last_commit_datetime).days
                    if elapsed_days >= 60:
                        branch_names.append(branch.name)
                else:
                    print(f"Couldn't load HEAD for {branch.name}")
    return branch_names


def main():
    debug_mode = len(sys.argv) >= 2 and 'debug' in sys.argv[1].casefold()
    t = Terminal()
    if debug_mode:
        enable_console_debug_logging()
    gh = Github(os.getenv('CONTENTBOT_GH_ADMIN_TOKEN'), verify=False)
    organization = 'demisto'
    repo = 'content'
    content_repo = gh.get_repo(f'{organization}/{repo}')

    stale_contrib_branches = get_stale_branch_names_with_contrib(content_repo)
    for branch_name in stale_contrib_branches:
        try:
            print(f'Deleting {branch_name}')
            branch_ref = content_repo.get_git_ref(f'heads/{branch_name}')
            branch_ref.delete()
        except Exception as e:
            print(f"{t.red}Deletion of {branch_name} encountered an issue: {str(e)}{t.normal}")

    if debug_mode:
        print(f'{stale_contrib_branches=}')


if __name__ == "__main__":
    main()
