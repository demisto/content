#!/usr/bin/env python3

import json

import urllib3
from blessings import Terminal
from github import Github
from utils import get_env_var, timestamped_print, post_ai_review_introduction
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)
print = timestamped_print


def main():
    """Handles Internal PRs (non-fork PRs from organization members)

    Posts the AI reviewer introduction comment.

    Will use the following env vars:
    - CONTENTBOT_GH_ADMIN_TOKEN: token to use to update the PR
    - EVENT_PAYLOAD: json data from the pull_request event
    """
    t = Terminal()
    payload_str = get_env_var("EVENT_PAYLOAD")
    if not payload_str:
        raise ValueError("EVENT_PAYLOAD env variable not set or empty")
    payload = json.loads(payload_str)
    print(f"{t.cyan}Processing Internal PR started{t.normal}")

    org_name = "demisto"
    repo_name = "content"
    gh = Github(get_env_var("CONTENTBOT_GH_TOKEN"), verify=False)
    content_repo = gh.get_repo(f"{org_name}/{repo_name}")
    pr_number = payload.get("pull_request", {}).get("number")
    pr = content_repo.get_pull(pr_number)

    post_ai_review_introduction(pr, None, t)
    print(f"{t.cyan}Finished processing Internal PR{t.normal}")


if __name__ == "__main__":
    main()
