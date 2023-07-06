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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print

REVIEWERS = ['mmhw', 'maimorag', 'anas-yousef']
MARKETPLACE_CONTRIBUTION_PR_AUTHOR = 'xsoar-bot'
WELCOME_MSG = 'Thank you for your contribution. Your generosity and caring are unrivaled! Rest assured - our content ' \
              'wizard @{selected_reviewer} will very shortly look over your proposed changes.'

WELCOME_MSG_WITH_GFORM = 'Thank you for your contribution. Your generosity and caring are unrivaled! Make sure to ' \
                         'register your contribution by filling the [Contribution Registration]' \
                         '(https://forms.gle/XDfxU4E61ZwEESSMA) form, ' \
                         'so our content wizard @{selected_reviewer} will know the proposed changes are ready to be ' \
                         'reviewed.'

XSOAR_SUPPORT_LEVEL_LABEL = 'Xsoar Support Level'
PARTNER_SUPPORT_LEVEL_LABEL = 'Partner Support Level'
COMMUNITY_SUPPORT_LEVEL_LABEL = 'Community Support Level'
CONTRIBUTION_LABEL = 'Contribution'


def determine_reviewer(potential_reviewers: list[str], repo: Repository) -> str:
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


def get_packs_support_levels(pack_dirs: set[str]) -> set[str]:
    """
    Get the pack support levels from the pack metadata.

    Args:
        pack_dirs (set): paths to the packs that were changed
    """
    packs_support_levels = set()

    for pack_dir in pack_dirs:
        if pack_support_level := get_pack_metadata(pack_dir).get('support'):
            print(f'Pack support level for pack {pack_dir} is {pack_support_level}')
            packs_support_levels.add(pack_support_level)
        else:
            print(f'Could not find pack support level for pack {pack_dir}')

    return packs_support_levels


def get_packs_support_level_label(file_paths: list[str], external_pr_branch: str) -> str:
    """
    Get The contributions' support level label.

    The review level of a contribution PR (and thus the support level label) is determined according
    to the support level of the edited/new pack that was contributed.
    If the contribution PR contains more than one pack, the review level
    (and thus the support level label) is determined according to the pack with the highest support level.

    The strictest review (support) level is XSOAR, then partner, and the least strict level is community.

    The support level of a certain pack is defined in the pack_metadata.json file.

    Args:
        file_paths(str): file paths
        external_pr_branch (str): the branch of the external PR.

    Returns:
        highest support level of the packs that were changed, empty string in case no packs were changed.
    """
    pack_dirs_to_check_support_levels_labels = set()

    for file_path in file_paths:
        try:
            if 'Packs' in file_path and (pack_name := get_pack_name(file_path)):
                pack_dirs_to_check_support_levels_labels.add(f'Packs/{pack_name}')
        except Exception as err:
            print(f'Could not retrieve pack name from file {file_path}, {err=}')

    print(f'{pack_dirs_to_check_support_levels_labels=}')

    # # we need to check out to the contributor branch in his forked repo in order to retrieve the files cause workflow
    # runs on demisto master while the contributions changes are on the contributors branch
    print(
        f'Trying to checkout to forked branch {external_pr_branch} '
        f'to retrieve support level of {pack_dirs_to_check_support_levels_labels}'
    )
    try:
        fork_owner = os.getenv('GITHUB_ACTOR')
        with Checkout(
            repo=Repo(Path().cwd(), search_parent_directories=True),
            branch_to_checkout=external_pr_branch,
            # in marketplace contributions the name of the owner should be xsoar-contrib
            fork_owner=fork_owner if fork_owner != 'xsoar-bot' else 'xsoar-contrib'
        ):
            packs_support_levels = get_packs_support_levels(pack_dirs_to_check_support_levels_labels)
    except Exception as error:
        # in case we were not able to checkout correctly, fallback to the files in the master branch to retrieve support labels
        # in case those files exist.
        print(f'Received error when trying to checkout to {external_pr_branch} \n{error=}')
        print('Trying to retrieve support levels from the master branch')
        packs_support_levels = get_packs_support_levels(pack_dirs_to_check_support_levels_labels)

    print(f'{packs_support_levels=}')
    return get_highest_support_label(packs_support_levels) if packs_support_levels else ''


def get_highest_support_label(packs_support_levels: set[str]) -> str:
    """
    Get the highest support level.

    xsoar - highest support level of review, support level with the highest dev standards.
    partner - support level of review for partner packs.
    community - usually an individual contributor, lowest support level possible.
    """
    if 'xsoar' in packs_support_levels:
        return XSOAR_SUPPORT_LEVEL_LABEL
    elif 'partner' in packs_support_levels:
        return PARTNER_SUPPORT_LEVEL_LABEL
    else:
        return COMMUNITY_SUPPORT_LEVEL_LABEL


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

    labels_to_add = [CONTRIBUTION_LABEL]
    if support_label := get_packs_support_level_label(pr_files, pr.head.ref):
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
        potential_conflicting_branch_names = [branch.ref.removeprefix('refs/heads/') for branch in existant_branches]
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
