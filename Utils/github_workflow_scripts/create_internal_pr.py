#!/usr/bin/env python3

import json
import os
from datetime import datetime
from typing import List, Optional

import urllib3
from blessings import Terminal
from github import Github
from github.Repository import Repository

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# override print so we have a timestamp with each print
org_print = print

REVIEWERS = ['guyfreund', 'reutshal', 'barchen1']
HACKATHON_BODY_MESSAGE = 'Hackathon Award Categories'
WELCOME_MSG = 'Thank you for your contribution. Your generosity and caring are unrivaled! Rest assured - our content ' \
              'wizard @{selected_reviewer} will very shortly look over your proposed changes. '


def timestamped_print(*args, **kwargs):
    org_print(datetime.now().strftime("%H:%M:%S.%f"), *args, **kwargs)


print = timestamped_print


class EnvVariableError(Exception):
    def __init__(self, env_var_name: str):
        super().__init__(f'{env_var_name} env variable not set or empty')


def get_env_var(env_var_name: str, default_val: Optional[str] = None) -> str:
    """Thin wrapper around 'os.getenv'

    Raises:
        EnvVariableError: If the environment variable is not set or empty and no default value was passed.

    Args:
        env_var_name (str): The environment variable to fetch
        default_val (Optional[str], optional): The value to return should the environment variable be unset
            or empty. Defaults to None.

    Returns:
        str: The value of the environment variable
    """
    env_var_val = os.getenv(env_var_name)
    if not env_var_val:
        if default_val is not None:
            return default_val
        raise EnvVariableError(env_var_name)
    return env_var_val


def determine_reviewer(potential_reviewers: List[str], repo: Repository) -> str:
    """Checks the number of open PRs that have either been assigned to a user or a review was requested
    from the user for each potential reviewer and returns the user with the smallest amount

    Args:
        potential_reviewers (List): The github usernames from which a reviewer will be selected
        repo (Repository): The relevant repo

    Returns:
        str: The github username to assign to a PR
    """
    pulls = repo.get_pulls(state='OPEN')
    assigned_prs_per_potential_reviewer = {reviewer: 0 for reviewer in potential_reviewers}
    for pull in pulls:
        assignees = set([assignee.login for assignee in pull.assignees])
        requested_reviewers, _ = pull.get_review_requests()
        requested_reviewers = set([requested_reviewer.login for requested_reviewer in requested_reviewers])
        combined_list = assignees.union(requested_reviewers)
        for reviewer in potential_reviewers:
            if reviewer in combined_list:
                assigned_prs_per_potential_reviewer[reviewer] = assigned_prs_per_potential_reviewer.get(reviewer) + 1
    selected_reviewer = sorted(assigned_prs_per_potential_reviewer, key=assigned_prs_per_potential_reviewer.get)[0]
    return selected_reviewer


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
    print(f'{t.cyan}event payload: {payload}{t.normal}')

    org_name = 'demisto'
    repo_name = 'content'
    gh = Github(get_env_var('CONTENTBOT_GH_ADMIN_TOKEN'), verify=False)
    content_repo = gh.get_repo(f'{org_name}/{repo_name}')
    pr_number = payload.get('pull_request', {}).get('number')
    merged_pr = content_repo.get_pull(pr_number)
    merged_pr_url = merged_pr.html_url
    body = f'## Original External PR\r\n[external pull request]({merged_pr_url})\r\n\r\n'
    title = merged_pr.title
    body += merged_pr.body
    base_branch = 'master'
    head_branch = merged_pr.base.ref
    pr = content_repo.create_pull(title=title, body=body, base=base_branch, head=head_branch, draft=False)

    labels = [label.name for label in merged_pr.labels]
    docs_approved_label = 'docs-approved'
    if docs_approved_label in labels:
        pr.add_to_labels(docs_approved_label)
    else:
        pr.add_to_assignees('kirbles19')

    merged_by = merged_pr.merged_by.login
    reviewers, _ = merged_pr.get_review_requests()
    reviewers_logins = [reviewer.login for reviewer in reviewers]
    # request reviews from the same people as in the merged PR
    new_pr_reviewers = [merged_by] if merged_by else reviewers_logins
    pr.create_review_request(reviewers=new_pr_reviewers)

    # assign same users as in the merged PR
    assignees = [assignee.login for assignee in merged_pr.assignees if assignee.login != 'kirbles19']
    pr.add_to_assignees(*assignees)




if __name__ == "__main__":
    main()
