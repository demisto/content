import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import ansible_runner

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast, Callable

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

''' CLIENT CLASS '''


class TidyClient:
    def __init__(self, ip: str, user: str, password: str = ""):
        self.endpoint = ip
        self.user = user
        self.password = password

    def test(self):
        pass

    def _execute(self, extra_vars: Dict[str, str]):
        thread, runner = ansible_runner.run_async(
            private_data_dir='',
            playbook='playbook.yml',
            roles_path='roles',
            inventory=f"demisto-{self.user} ansible_host={self.endpoint} ansible_user={self.user}"
                      f" ansible_password={self.password}",
            verbosity=2,
            extravars=extra_vars)

        return thread, runner

    def homebrew(self):
        pass

    def python(self):
        pass

    def golang(self):
        pass

    def git(self):
        pass

    def github_ssh_key(self):
        pass

    def env_vars(self):
        pass

    def zsh(self):
        pass


''' HELPER FUNCTIONS '''


''' COMMAND FUNCTIONS '''


def test_module(client: TidyClient):
    pass


def tidy_homebrew_command(client: TidyClient):
    pass


def tidy_python_command(client: TidyClient):
    pass


def tidy_golang_command(client: TidyClient):
    pass


def tidy_git_command(client: TidyClient):
    pass


def tidy_github_ssh_key_command(client: TidyClient):
    pass


def tidy_env_vars_command(client: TidyClient):
    pass


def tidy_zsh_command(client: TidyClient):
    pass


''' MAIN FUNCTION '''


def main() -> None:
    # Commands definition
    command = demisto.command()
    commands: Dict[str, Callable] = {
        "test-module": test_module,
        "tidy-python": tidy_python_command,
        "tidy-golang": tidy_golang_command,
        "tidy-git": tidy_git_command,
        "tidy-homebrew": tidy_homebrew_command,
        "tidy-github-ssh-key": tidy_github_ssh_key_command,
        "tidy-env-vars": tidy_env_vars_command,
        "tidy-zsh": tidy_zsh_command,
    }

    # Enpoint definition
    proxy = demisto.params().get('proxy', False)

    ip = demisto.getParam("ip") or demisto.getArg("ip")
    user = demisto.getParam("user") or demisto.getArg("user")
    password = demisto.getParam("password") or demisto.getArg("password")

    demisto.debug(f'Command being called is {command}')

    # Command execution
    client = TidyClient(ip=ip, user=user, password=password)
    try:
        return_results(commands[command](client, **demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
