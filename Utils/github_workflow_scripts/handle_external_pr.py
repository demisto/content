#!/usr/bin/env python3

import json
from typing import List

import urllib3
from blessings import Terminal
from github import Github
from github.Repository import Repository

from utils import get_env_var, timestamped_print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print

REVIEWERS = ['Bargenish', 'esharf', 'DeanArbel']
WELCOME_MSG = 'Thank you for your contribution. Your generosity and caring are unrivaled! Rest assured - our content ' \
              'wizard @{selected_reviewer} will very shortly look over your proposed changes. '


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

    org_name = 'demisto'
    repo_name = 'content'
    gh = Github(get_env_var('CONTENTBOT_GH_ADMIN_TOKEN'), verify=False)
    content_repo = gh.get_repo(f'{org_name}/{repo_name}')
    pr_number = payload.get('pull_request', {}).get('number')
    pr = content_repo.get_pull(pr_number)

    # Add 'Contribution' Label to PR
    contribution_label = 'Contribution'
    pr.add_to_labels(contribution_label)
    print(f'{t.cyan}Added "Contribution" label to the PR{t.normal}')

    # check base branch is master
    if pr.base.ref == 'master':
        print(f'{t.cyan}Determining name for new base branch{t.normal}')
        branch_prefix = 'contrib/'
        new_branch_name = f'{branch_prefix}{pr.head.label.replace(":", "_")}'
        existant_branches = content_repo.get_git_matching_refs(f'heads/{branch_prefix}')
        potential_conflicting_branch_names = [branch.ref.lstrip('refs/heads/') for branch in existant_branches]
        # make sure new branch name does not conflict with existing branch name
        while new_branch_name in potential_conflicting_branch_names:
            # append or increment digit
            if not new_branch_name[-1].isdigit():
                new_branch_name += '-1'
            else:
                digit = str(int(new_branch_name[-1]) + 1)
                new_branch_name = f'{new_branch_name[:-1]}{digit}'
        master_branch_commit_sha = content_repo.get_branch('master').commit.sha
        # create new branch
        print(f'{t.cyan}Creating new branch "{new_branch_name}"{t.normal}')
        content_repo.create_git_ref(f'refs/heads/{new_branch_name}', master_branch_commit_sha)
        # update base branch of the PR
        pr.edit(base=new_branch_name)
        print(f'{t.cyan}Updated base branch of PR "{pr_number}" to "{new_branch_name}"{t.normal}')

    # assign reviewers / request review from
    reviewer_to_assign = determine_reviewer(REVIEWERS, content_repo)
    pr.add_to_assignees(reviewer_to_assign)
    pr.create_review_request(reviewers=[reviewer_to_assign])
    print(f'{t.cyan}Assigned user "{reviewer_to_assign}" to the PR{t.normal}')
    print(f'{t.cyan}Requested review from user "{reviewer_to_assign}"{t.normal}')

    # create welcome comment
    body = WELCOME_MSG.format(selected_reviewer=reviewer_to_assign)
    pr.create_issue_comment(body)
    print(f'{t.cyan}Created welcome comment{t.normal}')


if __name__ == "__main__":
    main()
