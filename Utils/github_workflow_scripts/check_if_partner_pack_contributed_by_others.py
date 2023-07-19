#!/usr/bin/env python3
import json
import os

from pathlib import Path

import urllib3
from blessings import Terminal
from github import Github
from git import Repo
from github.Repository import Repository

from utils import get_env_var, timestamped_print, Checkout
from demisto_sdk.commands.common.tools import get_pack_metadata, get_pack_name


def main():
    """Handles External PRs (PRs from forks)

    Performs the following operations:
    1. If the external PR's base branch is master we create a new branch and set it as the base branch of the PR.
    2. Labels the PR with the "Contribution" label. (Adds the "Hackathon" label where applicable.)
    3. Assigns a Reviewer.
    4. Creates a welcome comment

    Will use the following env vars:
    - CONTENTBOT_GH_ADMIN_TOKEN: token to use to update the PR
    - EVENT_PAYLOAD: json data from the pull_request event
    """
    t = Terminal()

    payload_str = get_env_var('EVENT_PAYLOAD')
    if not payload_str:
        raise ValueError('EVENT_PAYLOAD env variable not set or empty')
    payload = json.loads(payload_str)
    print(f'{t.cyan}Processing PR started{t.normal}')

    org_name = 'demisto'
    repo_name = 'content'
    gh = Github(get_env_var('CONTENTBOT_GH_ADMIN_TOKEN'), verify=False)
    content_repo = gh.get_repo(f'{org_name}/{repo_name}')

    pr_number = payload.get('pull_request', {}).get('number')
    pr = content_repo.get_pull(pr_number)

    pr_files = [file.filename for file in pr.get_files()]
    print(f'{pr_files=} for {pr_number=}')

    fork_owner = os.getenv('GITHUB_ACTOR')
    print(f'fork owner is {fork_owner}')

    sys.exit(1)

if __name__ == "__main__":
    main()
