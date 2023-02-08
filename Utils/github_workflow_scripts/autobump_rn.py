from typing import List
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
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print = timestamped_print

ORGANIZATION_NAME = 'demisto'
REPO_MANE = 'content'
BASE = 'master'

SKIPPING_MESSAGE = 'Skipping Auto-Bumping release notes.'
NOT_UPDATE_RN_LABEL = 'ignore-auto-bump-version'
LAST_SUITABLE_UPDATE_TIME_DAYS = 700
RELEASE_NOTES_DIR = "ReleaseNotes"
PACK_METADATA_FILE = 'pack_metadata.json'

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


def conflict_only_in_rn_metadata_files(pr: PullRequest, repo: Repo) -> bool:
    """Checks if a pull request contains merge conflicts with a local branch.
    Arguments:
        pr: The pull request branch to check for merge conflicts.
        repo: The name of the local branch to check against.
    Returns:
        True if the pull request contains merge conflicts with the specified branch and false otherwise.
    """
    rn_conflict_exists = False
    pr_branch = pr.head.ref
    try:
        repo.git.merge(pr_branch, '--no-ff', '--no-commit')
    except GitCommandError as e:
        error = e.stdout
        conflicting_files = [line.replace('Auto-merging ', '') for line in error.split('\n') if 'Auto-merging ' in line]
        if len(conflicting_files) != 2 or f"\\{RELEASE_NOTES_DIR}\\" not in ' '.join(conflicting_files) or\
                f"\\{PACK_METADATA_FILE}" not in ' '.join(conflicting_files):
            rn_conflict_exists = False
        else:
            rn_conflict_exists = True
    return rn_conflict_exists


def check_metadata_conditions():
    # todo: check xsoar supported
    # todo: check update version (not 99)
    # todo: check major in master
    # todo print log why skip and return false
    pass


def autobump_release_notes():
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
        elif NOT_UPDATE_RN_LABEL in [label.name for label in pr.labels]:
            print(f'{t.red}Label {NOT_UPDATE_RN_LABEL} exist in PR {pr_number}. {SKIPPING_MESSAGE}')
        elif f"\\{RELEASE_NOTES_DIR}\\" not in ' '.join(pr_files_names):
            print(f'{t.red}No changes were detected on {RELEASE_NOTES_DIR} directory in PR {pr_number}. '
                  f'{SKIPPING_MESSAGE}')
        elif not conflict_only_in_rn_metadata_files(pr, git_repo_obj):
            print(f'{t.red}The pr {pr_number} has conflicts not only at {RELEASE_NOTES_DIR} and {PACK_METADATA_FILE}. '
                  f'{SKIPPING_MESSAGE}')
        elif not check_metadata_conditions():
            print('todo')
        else:
            print('got here')
            with checkout(git_repo_obj, pr_branch):
                autobump_release_notes()

    # todo: slack notify success or print success logs
    sys.exit(0)


if __name__ == "__main__":
    main()
