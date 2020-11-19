#!/usr/bin/env python3

import json

import urllib3
from blessings import Terminal
from github import Github

from utils import get_env_var, timestamped_print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print


def main():
    """Creates Internal PRs from Merged External PRs

    Performs the following operations:
    1. Creates new PR.
        A) Uses body of merged external PR as the body of the new PR.
        B) Uses base branch of merged external PR as head branch of the new PR to master.
        C) Adds 'docs-approved' label if it was on the merged external PR, otherwise assigns 'kirbles19' as a reviewer.
        D) Requests review from the same users as on the merged external PR.
        E) Assigns the same users as on the merged external PR.

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
    body += merged_pr.body
    base_branch = 'master'
    head_branch = merged_pr.base.ref
    pr = content_repo.create_pull(title=title, body=body, base=base_branch, head=head_branch, draft=False)
    print(f'{t.cyan}Internal PR Created - {pr.html_url}{t.normal}')

    labels = [label.name for label in merged_pr.labels]
    docs_approved_label = 'docs-approved'
    if docs_approved_label in labels:
        pr.add_to_labels(docs_approved_label)
        print(f'{t.cyan}"docs-approved" label added{t.normal}')
    else:
        pr.add_to_assignees('kirbles19')
        print(f'{t.cyan}"kirbles19" user assigned{t.normal}')

    merged_by = merged_pr.merged_by.login
    reviewers, _ = merged_pr.get_review_requests()
    reviewers_logins = [reviewer.login for reviewer in reviewers]
    # request reviews from the same people as in the merged PR
    new_pr_reviewers = [merged_by] if merged_by else reviewers_logins
    pr.create_review_request(reviewers=new_pr_reviewers)
    print(f'{t.cyan}Requested review from {new_pr_reviewers}{t.normal}')

    # assign same users as in the merged PR
    assignees = [assignee.login for assignee in merged_pr.assignees if assignee.login != 'kirbles19']
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
