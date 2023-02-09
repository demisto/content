import json
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

ORGANIZATION_NAME = 'demisto'
REPO_MANE = 'content'
BASE = 'master'

SKIPPING_MESSAGE = 'Skipping Auto-Bumping release notes.'
NOT_UPDATE_RN_LABEL = 'ignore-auto-bump-version'
LAST_SUITABLE_UPDATE_TIME_DAYS = 14
RELEASE_NOTES_DIR = "ReleaseNotes"
PACK_METADATA_FILE = 'pack_metadata.json'
NOT_XSOAR_SUPPORTED_PACK = 'Pack is not xsoar supported'
"""
  stdout: 'Auto-merging pyproject.toml
CONFLICT (content): Merge conflict in pyproject.toml
Auto-merging poetry.lock
CONFLICT (content): Merge conflict in poetry.lock
Auto-merging Tests/scripts/infrastructure_tests/test_collect_tests.py
CONFLICT (content): Merge conflict in Tests/scripts/infrastructure_tests/test_collect_tests.py
Auto-merging Tests/scripts/collect_tests/constants.py
CONFLICT (content): Merge conflict in Tests/scripts/collect_tests/constants.py
Auto-merging Tests/Marketplace/marketplace_services.py
CONFLICT (content): Merge conflict in Tests/Marketplace/marketplace_services.py
Auto-merging Tests/Marketplace/marketplace_constants.py
CONFLICT (content): Merge conflict in Tests/Marketplace/marketplace_constants.py
Auto-merging .gitlab/ci/global.yml
CONFLICT (content): Merge conflict in .gitlab/ci/global.yml
Automatic merge failed; fix conflicts and then commit the result.'
"""


# todo: skip reasons class


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


def conflict_only_in_rn_metadata_files(pr: PullRequest, repo: Repo,
                                       allowed_conflicting_files: list) -> Tuple[bool, list]:
    """Checks if a pull request contains merge conflicts with a local branch.
    Arguments:
        pr: The pull request branch to check for merge conflicts.
        repo: The name of the local branch to check against.
        allowed_conflicting_files:
    Returns:
        True if the pull request contains merge conflicts with the specified branch and false otherwise.
    """
    pr_branch = pr.head.ref
    try:
        repo.git.merge(f'origin/{pr_branch}', '--no-ff', '--no-commit')
    except GitCommandError as e:
        error = e.stdout
        conflicting_files = [line.replace('Auto-merging ', '') for line in error.split('\n') if 'Auto-merging ' in line]
        for file_name in conflicting_files:
            if file_name not in allowed_conflicting_files:
                return False, conflicting_files
        # todo: change
        return True, conflicting_files
    return False, []


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
        if f"/{RELEASE_NOTES_DIR}/" not in ' '.join(pr_files_names):
            print(f'{t.red}No changes were detected on {RELEASE_NOTES_DIR} directory in PR {pr_number}. '
                  f'{SKIPPING_MESSAGE}')
            continue
        changed_rn_files = [f for f in pr_files_names if RELEASE_NOTES_DIR in f]
        changed_metadata_files = [f for f in pr_files_names if PACK_METADATA_FILE in f]
        conflict_only_rn_and_metadata, conflict_files = conflict_only_in_rn_metadata_files(
            pr, git_repo_obj,
            changed_metadata_files + changed_rn_files
        )
        if not conflict_only_rn_and_metadata:
            print(f'{t.red}The pr {pr_number} has conflicts not only at {RELEASE_NOTES_DIR} and {PACK_METADATA_FILE}. '
                  f'The conflicting files are: {conflict_files}.'
                  f'{SKIPPING_MESSAGE}')
            continue

        conflicting_metadata_files = [f for f in conflict_files if PACK_METADATA_FILE in f]
        packs_rn_to_update_in_this_pr = set()
        for metadata_file in conflicting_metadata_files:
            pack = get_pack_name(metadata_file)
            with open(metadata_file) as f:
                base_pack_metadata = json.load(f)
            with checkout(git_repo_obj, pr_branch):
                with open(metadata_file) as f:
                    branch_pack_metadata = json.load(f)
            if base_pack_metadata.get('support') != 'xsoar':
                print(NOT_XSOAR_SUPPORTED_PACK)
                continue
            if Version(base_pack_metadata.get('currentVersion', '1.0.0')).major != Version(branch_pack_metadata.get('currentVersion', '1.0.0')).major:
                print('todo: Different major.')
                continue
            if '99' in f"{base_pack_metadata.get('currentVersion', '1.0.0')}, {base_pack_metadata.get('currentVersion', '1.0.0')}":
                print('todo: 99 error.')
                continue
            # todo: check how to bump? minor, revision?
            head_sha = pr.head.sha
            for file in pr_files:
                path = file.filename
                patch = file.patch
                contents = github_repo_obj.get_contents(path, ref=head_sha)
                content = contents.decoded_content.decode()
                # todo: debug and see the content and patch here
                print(f'{content}, {patch}')

            packs_rn_to_update_in_this_pr.add(pack)

        print('got here')
        with checkout(git_repo_obj, pr_branch):
            autobump_release_notes(packs_rn_to_update_in_this_pr)

    # todo: slack notify success or print success logs
    sys.exit(0)


if __name__ == "__main__":
    main()
