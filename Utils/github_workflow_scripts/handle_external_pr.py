#!/usr/bin/env python3
import argparse
import json
from typing import List

import urllib3
from blessings import Terminal
from github import Github
from github.Repository import Repository

from utils import get_env_var, timestamped_print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print

REVIEWERS = ['GuyAfik', 'merit-maita', 'samuelFain']
MARKETPLACE_CONTRIBUTION_PR_AUTHOR = 'xsoar-bot'
WELCOME_MSG = 'Thank you for your contribution. Your generosity and caring are unrivaled! Rest assured - our content ' \
              'wizard @{selected_reviewer} will very shortly look over your proposed changes.'

WELCOME_MSG_WITH_GFORM = 'Thank you for your contribution. Your generosity and caring are unrivaled! Make sure to ' \
                         'register your contribution by filling the [Contribution Registration]' \
                         '(https://forms.gle/XDfxU4E61ZwEESSMA) form, ' \
                         'so our content wizard @{selected_reviewer} will know the proposed changes are ready to be ' \
                         'reviewed.'

XSOAR_SUPPORT_LEVEL = 'Xsoar Support Level'
PARTNER_SUPPORT_LEVEL = 'Partner Support Level'
COMMUNITY_SUPPORT_LEVEL = 'Community Support Level'
CONTRIBUTION_LABEL = 'Contribution'


def parse_changed_files_names() -> argparse.Namespace:
    """
    Run_doc_review script gets the files that were changed in the PR as a string (default delimiter is ';').
    This function is in charge of parsing the info and separate the files names.

    Returns: an argparse.Namespace object which includes the changed files names and the delimiter argument.
    """
    parser = argparse.ArgumentParser(description="Parse the changed files names.")
    parser.add_argument(
        "-c",
        "--changed_files",
        help="The files that are passed to handle external PR (passed as one string).",
    )
    parser.add_argument(
        "-d",
        "--delimiter",
        help="the delimiter that separates the changed files names (determined in"
        " the call to tj-actions/changed-files in "
        "handle external PR script).",
    )
    args = parser.parse_args()

    return args


def determine_reviewer(potential_reviewers: List[str], repo: Repository) -> str:
    """Checks the number of open 'Contribution' PRs that have either been assigned to a user or a review
    was requested from the user for each potential reviewer and returns the user with the smallest amount

    Args:
        potential_reviewers (List): The github usernames from which a reviewer will be selected
        repo (Repository): The relevant repo

    Returns:
        str: The github username to assign to a PR
    """
    label_to_consider = 'contribution'
    pulls = repo.get_pulls(state='OPEN')
    assigned_prs_per_potential_reviewer = {reviewer: 0 for reviewer in potential_reviewers}
    for pull in pulls:
        # we only consider 'Contribution' prs when computing who to assign
        pr_labels = [label.name.casefold() for label in pull.labels]
        if label_to_consider not in pr_labels:
            continue
        assignees = {assignee.login for assignee in pull.assignees}
        requested_reviewers, _ = pull.get_review_requests()
        reviewers_info = {requested_reviewer.login for requested_reviewer in requested_reviewers}
        combined_list = assignees.union(reviewers_info)
        for reviewer in potential_reviewers:
            if reviewer in combined_list:
                assigned_prs_per_potential_reviewer[reviewer] = assigned_prs_per_potential_reviewer.get(reviewer, 0) + 1
    print(f'{assigned_prs_per_potential_reviewer=}')
    selected_reviewer = sorted(assigned_prs_per_potential_reviewer,
                               key=assigned_prs_per_potential_reviewer.get)[0]  # type: ignore
    print(f'{selected_reviewer=}')
    return selected_reviewer


def get_highest_support_label(found_labels):
    if 'xsoar' in found_labels:
        return XSOAR_SUPPORT_LEVEL
    elif 'partner' in found_labels:
        return PARTNER_SUPPORT_LEVEL
    else:
        return COMMUNITY_SUPPORT_LEVEL


def get_support_level_label(pack_metadata_files) -> str:
    try:
        return get_highest_support_label(
            [json.loads(pack_metadata_path).get('support') for pack_metadata_path in pack_metadata_files]
        )
    except Exception as e:
        print(f'Could not retrieve support label, {e}')
        return ''


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

    parser_args = parse_changed_files_names()
    print(f'{parser_args.changed_files=}')
    changed_files_list = parser_args.changed_files.split(parser_args.delimiter)

    labels_to_add = [CONTRIBUTION_LABEL]
    if support_label := get_support_level_label(changed_files_list):
        labels_to_add.append(support_label)

    # Add 'Contribution' + support Label to the external PR
    for label in labels_to_add:
        pr.add_to_labels(label)
        print(f'{t.cyan}Added "{label}" label to the PR{t.normal}')

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

    # create welcome comment (only users who contributed through Github need to have that contribution form filled)
    message_to_send = WELCOME_MSG if pr.user.login == MARKETPLACE_CONTRIBUTION_PR_AUTHOR else WELCOME_MSG_WITH_GFORM
    body = message_to_send.format(selected_reviewer=reviewer_to_assign)
    pr.create_issue_comment(body)
    print(f'{t.cyan}Created welcome comment{t.normal}')


if __name__ == "__main__":
    main()
