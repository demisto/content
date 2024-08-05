#!/usr/bin/env python3
import json
from pathlib import Path
import sys
import urllib3
from blessings import Terminal
from github import Github
from git import Repo
from github.PullRequest import PullRequest
from github.Repository import Repository
from demisto_sdk.commands.common.tools import get_pack_metadata, get_yaml
from demisto_sdk.commands.content_graph.objects.base_content import BaseContent
from demisto_sdk.commands.content_graph.objects.integration import Integration
from demisto_sdk.commands.common.content_constant_paths import CONTENT_PATH
from random import randint
import re

from utils import (
    get_env_var,
    timestamped_print,
    Checkout,
    get_content_reviewers,
    get_support_level,
    get_content_roles,
    get_metadata
)
from demisto_sdk.commands.common.tools import get_pack_name
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)
print = timestamped_print

MARKETPLACE_CONTRIBUTION_PR_AUTHOR = 'xsoar-bot'
WELCOME_MSG = 'Thank you for your contribution. Your generosity and caring are unrivaled! Rest assured - our content ' \
              'wizard @{selected_reviewer} will very shortly look over your proposed changes.\n' \
              'For your convenience, here is a [link](https://xsoar.pan.dev/docs/contributing/sla) to the contributions ' \
              'SLAs document.'

WELCOME_MSG_WITH_GFORM = 'Thank you for your contribution. Your generosity and caring are unrivaled! Make sure to ' \
                         'register your contribution by filling the [Contribution Registration]' \
                         '(https://forms.gle/XDfxU4E61ZwEESSMA) form, ' \
                         'so our content wizard @{selected_reviewer} will know the proposed changes are ready to be ' \
                         'reviewed.\nFor your convenience, here is a [link](https://xsoar.pan.dev/docs/contributing/sla) ' \
                         'to the contributions SLAs document.'

XSOAR_SUPPORT_LEVEL_LABEL = 'Xsoar Support Level'
PARTNER_SUPPORT_LEVEL_LABEL = 'Partner Support Level'
COMMUNITY_SUPPORT_LEVEL_LABEL = 'Community Support Level'
CONTRIBUTION_LABEL = 'Contribution'
EXTERNAL_LABEL = "External PR"
SECURITY_LABEL = "Security Review"
TIM_LABEL = "TIM Review"
TIM_TAGS = "Threat Intelligence Management"
TIM_CATEGORIES = "Data Enrichment & Threat Intelligence"
SECURITY_CONTENT_ITEMS = [
    "Playbooks",
    "IncidentTypes",
    "IncidentFields",
    "IndicatorTypes",
    "IndicatorFields",
    "Layouts",
    "Classifiers",
    "Wizards",
    "Dashboards",
    "Triggers"
]
PR_AUTHOR_PATTERN = '## Contributor\n@(.*)'
LABELS_TO_SKIP_PR_REVIEW = {'contribution on hold'}


def get_location_of_reviewer(assigned_prs_per_potential_reviewer: dict) -> int:
    """Check if there is more than one reviewer with the lowest number of assigned contribution PRs.
        If yes, choose one randomly.
        If no, choose the one with the lowest number of assigned contribution PRs.

        Args:
            assigned_prs_per_potential_reviewer (dict): A dict of the reviewers and the amount of assigned PRs each has.
            an example of this dictionary:
            {
                'reviewer1': 1,
                'reviewer2': 2,
                'reviewer3': 3,
            }

        Returns:
            int: The location of the chosen assignee in the sorted array.
    """
    values = sorted([assigned_prs_per_potential_reviewer[key] for key in assigned_prs_per_potential_reviewer])
    while len(values) > 1:
        equal = all(reviewer == values[0] for reviewer in values)
        if equal:
            return randint(0, len(values) - 1)
        values.pop(len(values) - 1)
    return 0


def skip_pr_from_count_for_reviewer(pr: PullRequest, pr_labels: list[str]) -> bool:
    """ Checks if the current PR has the label "contribution on hold" or pr is in draft state,
        if so - the PR won't be counted for the PR count to determine reviewer

        Args:
            pr (PullRequest): The PR
            pr_labels (list): The PR labels

        Returns:
            bool: if PR need to be skipped
    """
    pr_labels_set = set(pr_labels)
    if pr.draft or LABELS_TO_SKIP_PR_REVIEW.issubset(pr_labels_set):
        print(f'PR number {pr.number} with draft status {pr.draft} and labels {pr_labels_set} will be skipped from count ')
        return True
    return False


def determine_random_reviewer(potential_reviewers: list[str], repo: Repository) -> str:
    """Checks the number of open 'Contribution' PRs that have been assigned to a user
    for each potential reviewer and returns the user with the smallest amount.
    If all the reviewers have the same amount, it will select one randomly.

    Args:
        potential_reviewers (List): The github usernames from which a reviewer will be selected
        repo (Repository): The relevant repo

    Returns:
        str: The github username to assign to a PR
    """
    if len(potential_reviewers) == 1:
        print(f'There is only 1 potential reviewer {potential_reviewers}')
        return potential_reviewers[0]
    label_to_consider = 'contribution'
    pulls = repo.get_pulls(state='OPEN')
    assigned_prs_per_potential_reviewer = {reviewer: 0 for reviewer in potential_reviewers}
    for pull in pulls:
        # we only consider 'Contribution' prs when computing who to assign
        pr_labels = [label.name.casefold() for label in pull.labels]
        if label_to_consider not in pr_labels or skip_pr_from_count_for_reviewer(pull, pr_labels):
            continue
        assignees = {assignee.login for assignee in pull.assignees}
        for reviewer in potential_reviewers:
            if reviewer in assignees:
                assigned_prs_per_potential_reviewer[reviewer] = assigned_prs_per_potential_reviewer.get(reviewer, 0) + 1
    print(f'{assigned_prs_per_potential_reviewer=}')
    n = get_location_of_reviewer(assigned_prs_per_potential_reviewer)
    print(f'the chosen location in the sorted array is: {n}')
    selected_reviewer = sorted(assigned_prs_per_potential_reviewer,
                               key=assigned_prs_per_potential_reviewer.get)[n]  # type: ignore
    print(f'{selected_reviewer=}')
    return selected_reviewer


def packs_to_check_in_pr(file_paths: list[str]) -> set:
    """
    The function gets all files in the PR and returns the packs that are part of the PR

    Arguments:
        - param file_paths: the file paths of the PR files
    Returns:
        - set of all packs that are part of the PR
    """
    pack_dirs_to_check = set()

    for file_path in file_paths:
        try:
            if 'Packs' in file_path and (pack_name := get_pack_name(file_path)):
                pack_dirs_to_check.add(f'Packs/{pack_name}')
        except Exception as err:
            print(f'Could not retrieve pack name from file {file_path}, {err=}')

    print(f'{pack_dirs_to_check=}')
    return pack_dirs_to_check


def get_packs_support_level_label(file_paths: list[str], external_pr_branch: str, remote_fork_owner: str,
                                  repo_name: str = 'content') -> str:
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
        remote_fork_owner: the remote fork owner
        repo_name(str): the name of the forked repo (without the owner)

    Returns:
        highest support level of the packs that were changed, empty string in case no packs were changed.
    """
    pack_dirs_to_check_support_levels_labels = packs_to_check_in_pr(file_paths)
    print(f'{pack_dirs_to_check_support_levels_labels=}')

    # # we need to check out to the contributor branch in his forked repo in order to retrieve the files cause workflow
    # runs on demisto master while the contributions changes are on the contributors branch
    print(
        f'Trying to checkout to forked branch {external_pr_branch} '
        f'to retrieve support level of {pack_dirs_to_check_support_levels_labels}'
    )
    try:
        with Checkout(
            repo=Repo(Path().cwd(), search_parent_directories=True),
            branch_to_checkout=external_pr_branch,
            # in marketplace contributions the name of the owner should be xsoar-contrib
            fork_owner=remote_fork_owner if remote_fork_owner != 'xsoar-bot' else 'xsoar-contrib',
            repo_name=repo_name
        ):
            packs_support_levels = get_support_level(pack_dirs_to_check_support_levels_labels)
    except Exception as error:
        # in case we were not able to checkout correctly, fallback to the files in the master branch to retrieve support labels
        # in case those files exist.
        print(f'Received error when trying to checkout to {external_pr_branch} \n{error=}')
        print('Trying to retrieve support levels from the master branch')
        packs_support_levels = get_support_level(pack_dirs_to_check_support_levels_labels)

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


def is_requires_security_reviewer(pr_files: list[str]) -> bool:
    """
    Checks whether a security engineer is needed in the review.

    Arguments:
        - `pr_files`: ``List[str]``: The list of files changed in the Pull Request. Will be used to determine
        whether a security engineer is required for the review.

    Returns: `bool` whether a security engineer should be assigned
    """

    for pr_file in pr_files:
        for item in SECURITY_CONTENT_ITEMS:
            if item in Path(pr_file).parts:
                return True

    return False


def check_if_item_is_tim(content_object: BaseContent | None) -> bool:
    """
    Checks whether a given object (graph object) is a feed or related to TIM

    Arguments:
        - `content_object`: ``BaseContent``: Content object taken from the graph

    Returns: `bool` whether the content object is a feed or has the relevant tags/categories
    """
    if isinstance(content_object, Integration) and content_object.is_feed:
        return True
    try:
        pack = content_object.in_pack  # type: ignore
        tags = pack.tags
        categories = pack.categories
        if TIM_TAGS in tags or TIM_CATEGORIES in categories:
            return True
    except Exception as er:
        print(f"The pack is not TIM: {er}")
    finally:
        return False


def check_files_of_pr_manually(pr_files: list[str]) -> bool:
    """
    If the checkout of the branch has failed, this function will go over the files and check whether the contribution
    need to be reviewed by TIM owner

    Arguments:
        - `pr_files`: ``List[str]``: The list of files changed in the Pull Request. Will be used to determine
        whether a security engineer is required for the review.

    Returns: `bool` whether a security engineer should be assigned
    """
    pack_dirs_to_check = packs_to_check_in_pr(pr_files)
    pack_metadata_list = get_metadata(pack_dirs_to_check)
    for file in pr_files:
        if "yml" in file and "Integrations" in file:
            content_yml = get_yaml(file_path=file)
            is_feed = content_yml.get("script").get("feed", "False")
            print(f'Is it a feed: {is_feed}')
            if is_feed:
                return True
    for pack_metadata in pack_metadata_list:
        print(f'the metadata is: {pack_metadata}')
        tags = pack_metadata.get("tags")
        categories = pack_metadata.get("categories")
        if TIM_TAGS in tags or TIM_CATEGORIES in categories:  # type: ignore
            return True
    return False


def is_tim_content(pr_files: list[str], external_pr_branch: str, remote_fork_owner: str, repo_name: str) -> bool:
    """
    Checks if tim reviewer needed, if the pack is new and not part of Master.
    First the remote branch is going to be checked out and then verified for the data

    Arguments:
        - `pr_files`: ``List[str]``: The list of files changed in the Pull Request. Will be used to determine
        whether a security engineer is required for the review.
        - 'external_pr_branch': str : name of branch to checkout
        - 'remote_fork_owner' (str) : name of the remote owner for checkout
        - 'repo_name': str : name of repository

    Returns: `bool` whether a security engineer should be assigned
    """
    try:
        with Checkout(
            repo=Repo(Path().cwd(), search_parent_directories=True),
            branch_to_checkout=external_pr_branch,
            # in marketplace contributions the name of the owner should be xsoar-contrib
            fork_owner=remote_fork_owner if remote_fork_owner != 'xsoar-bot' else 'xsoar-contrib',
            repo_name=repo_name
        ):
            for file in pr_files:
                if 'CONTRIBUTORS.json' in file or 'Author_image' in file or 'README.md' in file or ".pack-ignore" in file:
                    continue
                content_object = BaseContent.from_path(CONTENT_PATH / file)
                is_tim_needed = check_if_item_is_tim(content_object)
                if is_tim_needed:
                    return True
    except Exception as er:
        print(f"couldn't checkout branch to get metadata, error is {er}")
        # if the checkout didn't work for any reason, will try to go over files manually
        return check_files_of_pr_manually(pr_files)
    return False


def is_tim_reviewer_needed(pr_files: list[str], support_label: str, external_pr_branch: str,
                           remote_fork_owner: str, repo_name: str) -> bool:
    """
    Checks whether the PR need to be reviewed by a TIM reviewer.
    It check the yml file of the integration - if it has the feed: True
    If not, it will also check if the pack has the TIM tag or the TIM category
    The pack that will be checked are only XSOAR or Partner support

    Arguments:
    - pr_files: tThe list of files changed in the Pull Request
    - support_label: the support label of the PR - the highest one.
    - 'external_pr_branch' (str) : name of the external branch to checkout
    - 'remote_fork_owner' (str) : name of the remote owner for checkout
    - 'repo_name' (str) : name of the external repository

    Returns: True or false if tim reviewer needed
    """
    if support_label in (XSOAR_SUPPORT_LEVEL_LABEL, PARTNER_SUPPORT_LEVEL_LABEL):
        return is_tim_content(pr_files, external_pr_branch, remote_fork_owner, repo_name)
    return False


def get_user_from_pr_body(pr: PullRequest) -> str:
    """
    Get user from PR that was opened from XSOAR UI by searching for the substring "Contribytor\n@" in the body of the PR
    Arguments:
    - pr - the opened PR

    Returns:
    - Found User
    """
    body = pr.body
    matcher = re.search(PR_AUTHOR_PATTERN, body)
    if matcher:
        return matcher.groups()[0]
    return ""


def find_all_open_prs_by_user(content_repo: Repository, pr_creator: str, pr_number: str) -> list:
    """
    find all open pr's that were opened by the same user as the current PR, excluding current PR
    Arguments:
    - content_repo: the content repository
    - pr_creator: the author of the current PR
    - pr_number: number of the current PR

    Returns:
    - list of all open PR's with similar author as the current PR
    """
    print(f'PR author is: {pr_creator}')
    all_prs = content_repo.get_pulls()
    similar_prs = []
    for pr in all_prs:
        if pr.number == pr_number:  # Exclude current PR
            continue
        existing_pr_author = get_user_from_pr_body(pr) if pr.user.login in ["xsoar-bot", "content-bot"] else pr.user.login
        if existing_pr_author == pr_creator:
            similar_prs.append(pr)
    print(f'PR\'s by the same author: {similar_prs}')
    return similar_prs


def reviewer_of_prs_from_current_round(other_prs_by_same_user: list, content_reviewers: list[str]) -> str:
    """
    Get all PR's that are currently open from the same author, filter the list and return reviewer if reviewer is part
    of the current contribution round
    The check for reviewer is done with assignees because reviewers list after initial review is empty.
    Arguments:
    - other_prs_by_same_user - list of opened PR's

    Returns:
    - Reviewer of the found pr's
    """
    content_reviewers_set = set(content_reviewers)
    for pr in other_prs_by_same_user:
        print(f'the requested assignees are : {pr.assignees}')
        assignee_names = {assignee.login for assignee in pr.assignees}
        existing_reviewer = content_reviewers_set.intersection(assignee_names)
        if existing_reviewer:
            return existing_reviewer.pop()
        else:
            print("There are other PR's by same author, but their reviewer is not in the current contribution round")
    return ''


def find_reviewer_to_assign(content_repo: Repository, pr: PullRequest, pr_number: str, content_reviewers: list[str]) -> str:
    """
    Gets the content repo, PR and pr_number. Will return reviewer to assign
    Argument:
    - content_repo - the content repository
    - pr - current new PR
    - pr_number - number of current_pr
    - content_reviewers - the list of content reviewers

    Returns:
    - Reviewer to assign
    """
    if pr.user.login in ["xsoar-bot", "content-bot"]:
        pr_creator = get_user_from_pr_body(pr)
    else:
        pr_creator = pr.user.login

    other_prs_by_same_user = find_all_open_prs_by_user(content_repo, pr_creator, pr_number)

    reviewer_to_assign = reviewer_of_prs_from_current_round(other_prs_by_same_user, content_reviewers)
    if reviewer_to_assign:
        print(f'The reviewer from other PR\'s by similar author is: {reviewer_to_assign}')
        content_reviewer = reviewer_to_assign
    else:
        print('The reviewer is going to be determined randomly')
        content_reviewer = determine_random_reviewer(content_reviewers, content_repo)
        print(f'Determined random reviewer, who is: {content_reviewer}')
    return content_reviewer


def main():
    """Handles External PRs (PRs from forks)

    Performs the following operations:
    1. If the external PR's base branch is master we create a new branch and set it as the base branch of the PR.
    2. Labels the PR with the "Contribution" label. (Adds the "Hackathon" label where applicable.)
    3. Assigns a Reviewer, a Security Reviewer if needed and a TIM Reviewer if needed.
    4. Creates a welcome comment
    5. Checks if community contributed to Partner or XSOAR packs and asks the contributor to add themselves to contributors.md

    Will use the following env vars:
    - CONTENTBOT_GH_ADMIN_TOKEN: token to use to update the PR
    - EVENT_PAYLOAD: json data from the pull_request event
    """
    t = Terminal()

    payload_str = get_env_var('EVENT_PAYLOAD')
    if not payload_str:
        raise ValueError('EVENT_PAYLOAD env variable not set or empty')
    payload: dict = json.loads(payload_str)
    print(f'{t.cyan}Processing PR started{t.normal}')

    org_name = 'demisto'
    repo_name = 'content'
    gh = Github(get_env_var('CONTENTBOT_GH_ADMIN_TOKEN'), verify=False)
    content_repo = gh.get_repo(f'{org_name}/{repo_name}')

    pr_number = payload.get('pull_request', {}).get('number')
    repo_name = payload.get('pull_request', {}).get('head', {}).get('repo', {}).get('name')

    print(f'{t.cyan}PR origin repo: {repo_name} {t.normal}')

    pr = content_repo.get_pull(pr_number)

    pr_files = [file.filename for file in pr.get_files()]
    print(f'{pr_files=} for {pr_number=}')
    remote_fork_owner = pr.head.repo.full_name.split('/')[0]
    labels_to_add = [CONTRIBUTION_LABEL, EXTERNAL_LABEL]
    if support_label := get_packs_support_level_label(pr_files, pr.head.ref, remote_fork_owner, repo_name):
        labels_to_add.append(support_label)

    # Add the initial labels to PR:
    # - Contribution
    # - External PR
    # - Support Label
    for label in labels_to_add:
        pr.add_to_labels(label)
        print(f'{t.cyan}Added "{label}" label to the PR{t.normal}')

    # check base branch is master
    if pr.base.ref == 'master':
        print(f'{t.cyan}Determining name for new base branch{t.normal}')
        branch_prefix = 'contrib/'
        new_branch_name = f'{branch_prefix}{pr.head.label.replace(":", "_")}'
        existing_branches = content_repo.get_git_matching_refs(f'heads/{branch_prefix}')
        potential_conflicting_branch_names = [branch.ref.removeprefix('refs/heads/') for branch in existing_branches]
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

    # Parse PR reviewers from JSON and assign them
    # Exit if JSON doesn't exist or not parsable
    content_roles = get_content_roles()

    if not content_roles:
        print("Unable to retrieve the content roles. Exiting...")
        sys.exit(1)

    content_reviewers, security_reviewer, tim_reviewer = get_content_reviewers(content_roles)

    print(f"Content Reviewers: {','.join(content_reviewers)}")
    print(f"Security Reviewer: {security_reviewer}")
    print(f"TIM Reviewer: {tim_reviewer}")

    content_reviewer = find_reviewer_to_assign(content_repo, pr, pr_number, content_reviewers)

    pr.add_to_assignees(content_reviewer)
    reviewers = [content_reviewer]

    # Add a security architect reviewer if the PR contains security content items
    if is_requires_security_reviewer(pr_files):
        if isinstance(security_reviewer, list):
            security_reviewer = determine_random_reviewer(security_reviewer, content_repo)
        # else security_reviewer is a string of a single reviewer, just add it to the list of reviewers
        print(f'The selected security reviewer {security_reviewer}')
        reviewers.append(security_reviewer)
        pr.add_to_assignees(security_reviewer)
        pr.add_to_labels(SECURITY_LABEL)

    # adding TIM reviewer
    if is_tim_reviewer_needed(pr_files, support_label, pr.head.ref, remote_fork_owner, repo_name):
        reviewers.append(tim_reviewer)
        pr.add_to_labels(TIM_LABEL)

    pr.create_review_request(reviewers=reviewers)
    print(f'{t.cyan}Assigned and requested review from "{",".join(reviewers)}" to the PR{t.normal}')

    # create welcome comment (only users who contributed through Github need to have that contribution form filled)
    message_to_send = WELCOME_MSG if pr.user.login == MARKETPLACE_CONTRIBUTION_PR_AUTHOR else WELCOME_MSG_WITH_GFORM
    body = message_to_send.format(selected_reviewer=content_reviewer)
    pr.create_issue_comment(body)
    print(f'{t.cyan}Created welcome comment{t.normal}')

    print('contributors.md section')
    print(f'pack path: {pr_files[0]}')
    ver = get_pack_metadata(pr_files[0]).get('currentVersion')
    print(f'version is: {ver}')
    if pr.user.login == MARKETPLACE_CONTRIBUTION_PR_AUTHOR:
        contributors_body = 'Thanks for contributing to the XSOAR marketplace. To receive credit for your generous' \
                            ' contribution, please ask the reviewer to update your information in the pack contributors file.' \
                            ' See more information here [link](https://xsoar.pan.dev/docs/packs/packs-format#contributorsjson)'
    else:
        contributors_body = f'Hi @{pr.user.login}, thanks for contributing to the XSOAR marketplace. To receive ' \
            f'credit for your generous contribution please follow this [link]' \
            f'(https://xsoar.pan.dev/docs/packs/packs-format#contributorsjson).'
    if XSOAR_SUPPORT_LEVEL_LABEL or COMMUNITY_SUPPORT_LEVEL_LABEL in labels_to_add and ver != '1.0.0':
        pr.create_issue_comment(contributors_body)


if __name__ == "__main__":
    main()
