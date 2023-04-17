#!/usr/bin/env python3

import os
import json
from datetime import datetime
from typing import Optional

from git import Repo

CONTENT_ROOT_PATH = os.path.abspath(os.path.join(__file__, '../../..'))  # full path to content root repo

# override print so we have a timestamp with each print
org_print = print


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

    def __init__(self, repo: Repo, branch_to_checkout: str):
        """Initializes instance attributes.
        Arguments:
            repo: git repo object
            branch_to_checkout: The branch or commit hash to check out.
        """
        self.repo = repo
        self.repo.remote().fetch(branch_to_checkout)
        self._branch_to_checkout = branch_to_checkout
        try:
            self._original_branch = self.repo.active_branch.name
        except TypeError:
            self._original_branch = self.repo.git.rev_parse('HEAD')

    def __enter__(self):
        """Checks out the given branch"""
        self.repo.git.checkout(self._branch_to_checkout)
        return self

    def __exit__(self, *args):
        """Checks out the previous branch"""
        self.repo.git.checkout(self._original_branch)
