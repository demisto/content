import json
from abc import ABC, abstractmethod
from enum import Enum
from packaging.version import Version
from typing import List, Tuple
import urllib3
import argparse
from blessings import Terminal
from github import Github
from github.PullRequest import PullRequest
from github.Repository import Repository
import sys
from utils import timestamped_print
from datetime import datetime, timedelta
from git import Repo, GitCommandError
from demisto_sdk.commands.common.tools import get_pack_names_from_files, get_pack_name
import os

urllib3.disable_warnings()

print = timestamped_print

'''@@ -2,7 +2,7 @@
     "name": "Common Types",
     "description": "This Content Pack will get you up and running in no-time and provide you with the most commonly used incident & indicator fields and types.",
     "support": "xsoar",
-    "currentVersion": "3.3.47",
+    "currentVersion": "3.3.48",
     "author": "Cortex XSOAR",
     "url": "https://www.paloaltonetworks.com/cortex",
     "email": "",'''
ORGANIZATION_NAME = 'demisto'
REPO_MANE = 'content'
BASE = 'master'

SKIPPING_MESSAGE = 'Skipping Auto-Bumping release notes.'
NOT_UPDATE_RN_LABEL = 'ignore-auto-bump-version'
LAST_SUITABLE_UPDATE_TIME_DAYS = 14
RELEASE_NOTES_DIR = "ReleaseNotes"
PACK_METADATA_FILE = 'pack_metadata.json'
NOT_XSOAR_SUPPORTED_PACK = 'Pack is not xsoar supported'


# todo: skip reasons class
class SkipReason(str, Enum):
    NOT_XSOAR_SUPPORTED_PACK = 'Pack is not xsoar supported'
    LAST_MODIFIED_TIME = 'The PR was not updated in last {} days.'


# todo:dataclass
class ConditionResult:
    def __int__(self, should_skip, reason):
        self._should_skip = should_skip
        self._reason = reason


# todo: class for Base Condition
class BaseCondition(ABC):

    @property
    @abstractmethod
    def skip_reason(self) -> SkipReason:
        raise NotImplementedError

    @abstractmethod
    def check(self, **kwargs) -> ConditionResult:
        raise NotImplementedError


class LastModifiedCondition(BaseCondition):
    LAST_SUITABLE_UPDATE_TIME_DAYS = 14

    @property
    def skip_reason(self) -> SkipReason:
        return SkipReason.LAST_MODIFIED_TIME.format(self.LAST_SUITABLE_UPDATE_TIME_DAYS)

    def check(self, **kwargs) -> ConditionResult:
        pass


class PackSupportCondition(BaseCondition):
    @property
    def skip_reason(self) -> SkipReason:
        return SkipReason.NOT_XSOAR_SUPPORTED_PACK

    def check(self, **kwargs) -> ConditionResult:
        pass


class checkout:
    """Checks out a given branch.
    When the context manager exits, the context manager checks out the
    previously current branch.
    """

    def __init__(self, repo: Repo, branch_to_checkout: str):
        """Initializes instance attributes.
        Arguments:
            repo: git repo object
            branch_to_checkout: The branch to check out.
        """
        self.repo = repo
        self.repo.remote().fetch()
        self._original_branch = self.repo.active_branch.name
        self._branch_to_checkout = branch_to_checkout

    def __enter__(self):
        """Checks out the given branch"""
        self.repo.git.checkout(self._branch_to_checkout)
        return self

    def __exit__(self, *args):
        """Checks out the previous branch"""
        self.repo.git.checkout(self._original_branch)


def arguments_handler():
    """ Validates and parses script arguments.

     Returns:
        Namespace: Parsed arguments object.

     """
    parser = argparse.ArgumentParser(description='Autobump release notes version for packs where .')
    parser.add_argument('-g', '--github_token', help='The GitHub token to authenticate the GitHub client.')
    return parser.parse_args()


def has_conflict_on_given_files(pr: PullRequest, repo: Repo,
                                files_check_to_conflict_with: list) -> Tuple[bool, list]:
    """Checks if a pull request contains merge conflicts with a local branch.
    Arguments:
        pr: The pull request branch to check for merge conflicts.
        repo: The name of the local branch to check against.
        files_check_to_conflict_with:
    Returns:
        True if the pull request contains merge conflicts with specified files only.
    """
    pr_branch = pr.head.ref
    conflicting_files = []
    conflict_only_with_given_files = True
    try:
        repo.git.merge(f'origin/{pr_branch}', '--no-ff', '--no-commit')
    except GitCommandError as e:
        error = e.stdout
        conflicting_files = [line.replace('Auto-merging ', '').strip()
                             for line in error.splitlines() if 'Auto-merging ' in line]
        for file_name in conflicting_files:
            if file_name not in files_check_to_conflict_with:
                conflict_only_with_given_files = False
    repo.git.merge('--abort')
    return (conflict_only_with_given_files and conflicting_files), conflicting_files


def autobump_release_notes(packs_rn_to_update_in_this_pr):
    pass


def main():
    options = arguments_handler()
    github_token = options.github_token

    t = Terminal()

    git_repo_obj = Repo(os.getcwd())
    git_repo_obj.remote().fetch()

    github_client: Github = Github(github_token, verify=False)
    github_repo_obj: Repository = github_client.get_repo(f'{ORGANIZATION_NAME}/{REPO_MANE}')

    for pr in github_repo_obj.get_pulls(state='open', sort='created', base=BASE):
        pr_number = pr.number
        pr_branch = pr.head.ref
        pr_files = list(pr.get_files())
        pr_files_names = [f.filename for f in pr_files]
        print(f'{t.yellow}Looking on pr {pr_number=}: {pr.updated_at=}, {pr_branch=}')
        if pr.updated_at < datetime.now() - timedelta(days=LAST_SUITABLE_UPDATE_TIME_DAYS):
            print(f'{t.red}The PR {pr_number} was not updated in last {LAST_SUITABLE_UPDATE_TIME_DAYS} days.'
                  f'{SKIPPING_MESSAGE}')
            continue
        if NOT_UPDATE_RN_LABEL in [label.name for label in pr.labels]:
            print(f'{t.red}Label {NOT_UPDATE_RN_LABEL} exist in PR {pr_number}. {SKIPPING_MESSAGE}')
            continue

        # todo: check that both rn and metadata files changed at the pr for same pack
        if f"/{RELEASE_NOTES_DIR}/" not in ' '.join(pr_files_names):
            print(f'{t.red}No changes were detected on {RELEASE_NOTES_DIR} directory in PR {pr_number}. '
                  f'{SKIPPING_MESSAGE}')
            continue

        changed_rn_files = [f for f in pr_files_names if RELEASE_NOTES_DIR in f]
        changed_metadata_files = [f for f in pr_files_names if PACK_METADATA_FILE in f]
        conflict_only_rn_and_metadata, conflict_files = has_conflict_on_given_files(
            pr, git_repo_obj,
            changed_metadata_files + changed_rn_files
        )
        if not conflict_only_rn_and_metadata:
            print(f'{t.red}The pr {pr_number} has conflicts not only at {RELEASE_NOTES_DIR} and {PACK_METADATA_FILE}. '
                  f'The conflicting files are: {conflict_files}.'
                  f'{SKIPPING_MESSAGE}')
            continue

        packs_rn_to_update_in_this_pr = set()
        for conflict_file in conflict_files:
            # todo check if already cheked
            pack = get_pack_name(conflict_file)
            metadata_file = conflict_file if PACK_METADATA_FILE in conflict_file \
                else f'Packs/{pack}/{PACK_METADATA_FILE}'
            with open(metadata_file) as f:
                base_pack_metadata = json.load(f)
            with checkout(git_repo_obj, pr_branch):
                with open(metadata_file) as f:
                    branch_pack_metadata = json.load(f)
            if base_pack_metadata.get('support') != 'xsoar':
                print(NOT_XSOAR_SUPPORTED_PACK)
                continue
            if Version(base_pack_metadata.get('currentVersion', '1.0.0')).major != Version(
                    branch_pack_metadata.get('currentVersion', '1.0.0')).major:
                print('todo: Different major.')
                continue
            if '99' in f"{base_pack_metadata.get('currentVersion', '1.0.0')}, {base_pack_metadata.get('currentVersion', '1.0.0')}":
                print('todo: 99 error.')
                continue

            # conditions are done! now should find witch version to bump
            # todo: check how to bump? minor, revision?
            head_sha = pr.head.sha

            for file in pr_files:
                path = file.filename
                patch = file.patch
                # todo maybe better to take base?
                for diff_line in patch.splitlines():
                    if '"currentVersion": ' in diff_line and diff_line.startswith('+'):
                        new_version = diff_line
                        old_version = ''
            packs_rn_to_update_in_this_pr.add(pack)

        print('got here')
        with checkout(git_repo_obj, pr_branch):
            autobump_release_notes(packs_rn_to_update_in_this_pr)

    # todo: slack notify success or print success logs
    sys.exit(0)


if __name__ == "__main__":
    main()
