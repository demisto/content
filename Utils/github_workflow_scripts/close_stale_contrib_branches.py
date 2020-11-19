#!/usr/bin/env python3

import os
import sys
import urllib3
import inspect
from github import Github, enable_console_debug_logging
from github.Repository import Repository
from typing import List
from dateparser import parse
from datetime import datetime, timezone
from demisto_sdk.commands.common.tools import run_command, print_error, print_warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_stale_branch_names_with_contrib(repo: Repository) -> List[str]:  # noqa: E999
    """Return the list of branches that have the prefix of "contrib/" without open pull requests
    and that have not been updated for 2 months (stale)

    Args:
        repo (Repository): The repository whose branches will be searched and listed

    Returns:
        (List[str]): List of branch names that are stale and have the "contrib/" prefix
    """
    now = datetime.now(timezone.min)
    branch_names = []
    for branch in repo.get_branches():
        if branch.name.startswith('contrib/'):
            prs_with_branch_as_base = repo.get_pulls(state='OPEN', base=branch.name)
            if prs_with_branch_as_base.totalCount < 1:
                # load all members
                inspect.getmembers(branch.commit)

                # check if HEAD commit is stale
                if (last_modified := branch.commit.last_modified) and (last_commit_datetime := parse(last_modified)):
                    elapsed_days = (now - last_commit_datetime).days
                    if elapsed_days >= 60:
                        branch_names.append(branch.name)
                        if len(branch_names) > 1:
                            break
                else:
                    print_warning(f"Couldn't load HEAD for {branch.name}")
    return branch_names


def main():
    debug_mode = len(sys.argv) >= 2 and 'debug' in sys.argv[1].casefold()
    if debug_mode:
        enable_console_debug_logging()
    gh = Github(os.getenv('CONTENTBOT_GH_ADMIN_TOKEN'), verify=False)
    organization = 'demisto'
    repo = 'content'
    content_repo = gh.get_repo(f'{organization}/{repo}')

    stale_contrib_branches = list(set(get_stale_branch_names_with_contrib(content_repo)))
    for branch_name in stale_contrib_branches:
        try:
            print(f'Deleting {branch_name}')
            run_command(f"git push origin --delete {branch_name}", exit_on_error=False)
        except RuntimeError as e:
            # check delete was successful
            if '[deleted]' not in str(e):
                print_error(f"Deletion of {branch_name} encountered an issue:\n{str(e)}")

    if debug_mode:
        print(f'{stale_contrib_branches=}')


if __name__ == "__main__":
    main()
