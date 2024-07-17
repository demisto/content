#!/usr/bin/env python3

import json

import urllib3
from blessings import Terminal
from github import Github
from handle_external_pr import EXTERNAL_LABEL

from utils import (
    get_env_var,
    timestamped_print,
    get_doc_reviewer,
    get_content_roles
)
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)
print = timestamped_print
INTERNAL_LABEL = "Internal PR"


def main():
    """Creates Internal PRs from Merged External PRs

    Performs the following operations:
    1. Creates new PR.
        A) Uses body of merged external PR as the body of the new PR.
        B) Uses base branch of merged external PR as head branch of the new PR to master.
        C) Adds 'docs-approved' label if it was on the merged external PR.
        D) Requests review from the same users as on the merged external PR.
        E) Add the same labels that the external PR had to the internal PR (including contribution label).
        F) Assigns the same users as on the merged external PR.

    Will use the following env vars:
    - CONTENTBOT_GH_ADMIN_TOKEN: token to use to update the PR
    - EVENT_PAYLOAD: json data from the pull_request event
    """
    t = Terminal()
    payload_str = get_env_var('EVENT_PAYLOAD')
    if not payload_str:
        raise ValueError('EVENT_PAYLOAD env variable not set or empty')
    payload = json.loads(payload_str)
    print(f'{t.cyan}Creation of Internal PR started{t.normal}')

    org_name = 'demisto'
    repo_name = 'content'
    gh = Github(get_env_var('CONTENTBOT_GH_ADMIN_TOKEN'), verify=False)
    content_repo = gh.get_repo(f'{org_name}/{repo_name}')
    pr_number = payload.get('pull_request', {}).get('number')
    merged_pr = content_repo.get_pull(pr_number)
    merged_pr_url = merged_pr.html_url
    body = f'## Original External PR\r\n[external pull request]({merged_pr_url})\r\n\r\n'
    title = merged_pr.title
    if '## Contributor' not in merged_pr.body:
        merged_pr_author = merged_pr.user.login
        body += f'## Contributor\r\n@{merged_pr_author}\r\n\r\n'
    body += merged_pr.body
    base_branch = 'master'
    head_branch = merged_pr.base.ref
    pr = content_repo.create_pull(title=title, body=body, base=base_branch, head=head_branch, draft=False)
    print(f'{t.cyan}Internal PR Created - {pr.html_url}{t.normal}')

    # labels should already contain the contribution label from the external PR.
    # We want to replace the 'External PR' with 'Internal PR' label
    labels = [label.name.replace(EXTERNAL_LABEL, INTERNAL_LABEL) for label in merged_pr.labels]
    for label in labels:
        pr.add_to_labels(label)
        print(f'{t.cyan}"{label}" label added to the Internal PR{t.normal}')

    merged_by = merged_pr.merged_by.login
    reviewers, _ = merged_pr.get_review_requests()
    reviewers_logins = [reviewer.login for reviewer in reviewers]
    # request reviews from the same people as in the merged PR
    new_pr_reviewers = [merged_by] if merged_by else reviewers_logins
    pr.create_review_request(reviewers=new_pr_reviewers)
    print(f'{t.cyan}Requested review from {new_pr_reviewers}{t.normal}')

    # Set PR assignees
    assignees = [assignee.login for assignee in merged_pr.assignees]

    # Un-assign the tech writer (cause the docs reviewed has already been done on the external PR)
    content_roles = get_content_roles()
    if content_roles:

        try:
            doc_reviewer = get_doc_reviewer(content_roles)

            if doc_reviewer in assignees:
                print(f"Unassigning tech writer '{doc_reviewer}' from internal PR...")
                assignees.remove(doc_reviewer)
                print(f"Tech writer '{doc_reviewer}' unassigned")

        except ValueError as ve:
            print(f"{str(ve)}. Skipped tech writer unassignment.")

    else:
        print("Unable to get content roles. Skipping tech writer unassignment...")

    pr.add_to_assignees(*assignees)
    print(f'{t.cyan}Assigned users {assignees}{t.normal}')

    # remove branch protections
    print(f'{t.cyan}Removing protection from branch "{head_branch}"{t.normal}')
    contrib_branch = content_repo.get_branch(head_branch)
    contrib_branch.remove_protection()
    contrib_branch.remove_required_status_checks()
    contrib_branch.remove_required_pull_request_reviews()


if __name__ == "__main__":
    main()
