#!/usr/bin/env python3

import os
import sys
import json
from datetime import datetime
from typing import Any
from collections.abc import Generator, Iterable
from pathlib import Path
from demisto_sdk.commands.common.tools import get_pack_metadata

from git import Repo

CONTENT_ROOT_PATH = os.path.abspath(os.path.join(__file__, '../../..'))  # full path to content root repo
CONTENT_ROLES_PATH = Path(os.path.join(CONTENT_ROOT_PATH, ".github", "content_roles.json"))

DOC_REVIEWER_KEY = "DOC_REVIEWER"
CONTRIBUTION_REVIEWERS_KEY = "CONTRIBUTION_REVIEWERS"
CONTRIBUTION_SECURITY_REVIEWER_KEY = "CONTRIBUTION_SECURITY_REVIEWER"
TIM_REVIEWER_KEY = "TIM_REVIEWER"

# override print so we have a timestamp with each print
org_print = print
CallArgs = Iterable[tuple[Any] | tuple[Any, dict]]


def load_json(file_path: str | Path) -> dict:
    """ Reads and loads json file.

    Args:
        file_path (str): full path to json file.

    Returns:
        dict: loaded json file.

    """
    try:
        if file_path and os.path.exists(file_path):
            with open(file_path) as json_file:
                result = json.load(json_file)
        else:
            result = {}
        return result
    except json.decoder.JSONDecodeError:
        return {}


def timestamped_print(*args, **kwargs):
    org_print(datetime.now().strftime('%H:%M:%S.%f'), *args, **kwargs)


def iter_flatten_call_args(
    call_args: CallArgs,
) -> Generator:
    for arg in call_args:
        if isinstance(arg, tuple):
            if isinstance(arg[0], tuple):  # nested tuple
                yield arg[0][0]
            else:
                yield arg[0]

        elif isinstance(arg, str):
            yield arg
        else:
            raise ValueError("Unexpected call arg type")


def flatten_call_args(call_args: CallArgs) -> tuple[Any, ...]:
    return tuple(iter_flatten_call_args(call_args))


class EnvVariableError(Exception):
    def __init__(self, env_var_name: str):
        super().__init__(f'{env_var_name} env variable not set or empty')


def get_env_var(env_var_name: str, default_val: str | None = None) -> str:
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


class Checkout:  # pragma: no cover
    """Checks out a given branch.
    When the context manager exits, the context manager checks out the
    previously current branch.
    """

    def __init__(self, repo: Repo, branch_to_checkout: str, fork_owner: str | None = None, repo_name: str = 'content'):
        """Initializes instance attributes.
        Arguments:
            repo: git repo object
            branch_to_checkout: The branch or commit hash to check out.
            fork_owner (str): The owner of the forked repository.
                Leave it as None if the branch is in the same repository.
            repo_name (str): the name of the forked repo (without the owner)
        """
        self.repo = repo

        if fork_owner:
            forked_remote_name = f'{fork_owner}_{repo_name}_{branch_to_checkout}_remote'
            url = f"https://github.com/{fork_owner}/{repo_name}"
            try:
                self.repo.create_remote(name=forked_remote_name, url=url)
                print(f'Successfully created remote {forked_remote_name} for repo {url}')  # noqa: T201
            except Exception as error:
                print(f'could not create remote from {url}, {error=}')  # noqa: T201
                # handle the case where the name of the forked repo is not content
                if github_event_path := os.getenv("GITHUB_EVENT_PATH"):
                    try:
                        payload = json.loads(github_event_path)
                    except ValueError:
                        print('failed to load GITHUB_EVENT_PATH')  # noqa: T201
                        raise ValueError(f'cannot checkout to the forked branch {branch_to_checkout} of the owner {fork_owner}')
                    # forked repo name includes fork_owner + repo name, for example foo/content.
                    forked_repo_name = payload.get("pull_request", {}).get("head", {}).get("repo", {}).get("full_name")
                    self.repo.create_remote(name=forked_remote_name, url=f"https://github.com/{forked_repo_name}")
                else:
                    raise

            forked_remote = self.repo.remote(forked_remote_name)
            forked_remote.fetch(branch_to_checkout)
            self.branch_to_checkout = f'refs/remotes/{forked_remote_name}/{branch_to_checkout}'
        else:
            self.branch_to_checkout = branch_to_checkout
            self.repo.remote().fetch(branch_to_checkout)

        try:
            self._original_branch = self.repo.active_branch.name
        except TypeError:
            self._original_branch = self.repo.git.rev_parse('HEAD')

    def __enter__(self):
        """Checks out the given branch"""
        self.repo.git.checkout(self.branch_to_checkout)
        print(f'Checked out to branch {self.branch_to_checkout}')  # noqa: T201
        return self

    def __exit__(self, *args):
        """Checks out the previous branch"""
        self.repo.git.checkout(self._original_branch)
        print(f"Checked out to original branch {self._original_branch}")  # noqa: T201


class ChangeCWD:
    """
    Temporary changes the cwd to the given dir and then reverts it.
    Use with 'with' statement.
    """

    def __init__(self, directory):
        self.current = Path().cwd()
        self.directory = directory

    def __enter__(self):
        os.chdir(self.directory)

    def __exit__(self, *args):
        os.chdir(self.current)


def get_content_reviewers(content_roles: dict[str, Any]) -> tuple[list[str], str, str]:
    """
    Retrieve the content reviewers from the JSON file

    Args:
        - `content_roles` (``dict[str, Any]``): The current content team roles and members.

    Return:
        - `list[str]` of content reviewers GitHub usernames.
        - `str` of security reviewer GitHub username.
    """

    try:
        contribution_reviewers: list[str] = content_roles[CONTRIBUTION_REVIEWERS_KEY]
        security_reviewer: str = content_roles[CONTRIBUTION_SECURITY_REVIEWER_KEY]
        tim_reviewer: str = content_roles[TIM_REVIEWER_KEY]

        if not isinstance(contribution_reviewers, list):
            print(f"'{CONTRIBUTION_REVIEWERS_KEY}' is not an array. Terminating...")  # noqa: T201
            sys.exit(1)

        if not isinstance(security_reviewer, str) or not security_reviewer:
            print(f"'{CONTRIBUTION_SECURITY_REVIEWER_KEY}' is not a string. Terminating...")  # noqa: T201
            sys.exit(1)

        if not isinstance(tim_reviewer, str) or not tim_reviewer:
            print(f"'{TIM_REVIEWER_KEY}' is not a string. Terminating...")  # noqa: T201
            sys.exit(1)

        if not contribution_reviewers or not security_reviewer:
            print("No contribution or  reviewers")  # noqa: T201
            sys.exit(1)

        return contribution_reviewers, security_reviewer, tim_reviewer
    except KeyError as ke:
        print(f"Error parsing reviewers: {str(ke)}.")  # noqa: T201
        sys.exit(1)


def get_support_level(pack_dirs: set[str]) -> set[str]:
    """
    Get the pack support levels from the pack metadata.

    Args:
        pack_dirs (set): paths to the packs that were changed
    """
    packs_support_levels = set()

    for pack_dir in pack_dirs:
        if pack_support_level := get_pack_metadata(pack_dir).get('support'):
            print(f'Pack support level for pack {pack_dir} is {pack_support_level}')  # noqa: T201
            packs_support_levels.add(pack_support_level)
        else:
            print(f'Could not find pack support level for pack {pack_dir}')  # noqa: T201

    return packs_support_levels


def get_doc_reviewer(content_roles: dict[str, Any]) -> str:
    """
    Retrieve the doc reviewer from content roles JSON/`dict`.

    Args:
        - `content_roles` (``dict[str, Any]``): The current content team roles and members.

    Return:
        - `str` of document reviewer GitHub username.
        If there's an error in retrieving the tech writer/doc reviewer, we raise a `ValueError`
    """

    if not (reviewer := content_roles.get(DOC_REVIEWER_KEY)):
        raise ValueError("Cannot get doc reviewer")
    return reviewer
