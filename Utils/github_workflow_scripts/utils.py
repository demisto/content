#!/usr/bin/env python3

import os
import json
from datetime import datetime
from typing import Any, Generator, Iterable, Optional, Tuple, Union
from pathlib import Path

from git import Repo

CONTENT_ROOT_PATH = os.path.abspath(os.path.join(__file__, '../../..'))  # full path to content root repo

# override print so we have a timestamp with each print
org_print = print
CallArgs = Iterable[Union[Tuple[Any], Tuple[Any, dict]]]


def load_json(file_path: str) -> dict:
    """ Reads and loads json file.

    Args:
        file_path (str): full path to json file.

    Returns:
        dict: loaded json file.

    """
    try:
        if file_path and os.path.exists(file_path):
            with open(file_path, 'r') as json_file:
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


def flatten_call_args(call_args: CallArgs) -> Tuple[Any, ...]:
    return tuple(iter_flatten_call_args(call_args))


class EnvVariableError(Exception):
    def __init__(self, env_var_name: str):
        super().__init__(f'{env_var_name} env variable not set or empty')


def get_env_var(env_var_name: str, default_val: Optional[str] = None) -> str:
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

    def __init__(self, repo: Repo, branch_to_checkout: str, fork_owner: Optional[str] = None, repo_name: str = 'content'):
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
                print(f'Successfully created remote {forked_remote_name} for repo {url}')
            except Exception as error:
                print(f'could not create remote from {url}, {error=}')
                # handle the case where the name of the forked repo is not content
                if github_event_path := os.getenv("GITHUB_EVENT_PATH"):
                    try:
                        payload = json.loads(github_event_path)
                    except ValueError:
                        print('failed to load GITHUB_EVENT_PATH')
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
        print(f'Checked out to branch {self.branch_to_checkout}')
        return self

    def __exit__(self, *args):
        """Checks out the previous branch"""
        self.repo.git.checkout(self._original_branch)
        print(f"Checked out to original branch {self._original_branch}")


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
